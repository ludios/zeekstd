#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs results data zeekstd/lib/examples
cp scripts/interop_probe.rs zeekstd/lib/examples/interop_probe.rs
cargo build --manifest-path zeekstd/Cargo.toml --offline --locked --release -p zeekstd_cli > logs/build.log 2>&1
cargo build --manifest-path zeekstd/Cargo.toml --offline --locked --release -p zeekstd --example interop_probe > logs/probe-build.log 2>&1
cargo test --manifest-path zeekstd/Cargo.toml --offline --locked -p zeekstd --lib > logs/upstream-lib.log 2>&1
cargo test --manifest-path zeekstd/Cargo.toml --offline --locked -p zeekstd_cli > logs/upstream-cli.log 2>&1
python3 scripts/run_matrix.py inputs
for stage in cli library large special; do
    python3 scripts/run_matrix.py "$stage" > "logs/$stage-progress.log" 2>&1
done
python3 scripts/followups.py > logs/followups-progress.log 2>&1
python3 scripts/extended.py > logs/extended-progress.log 2>&1
python3 scripts/recovery_checks.py > logs/recovery-progress.log 2>&1
python3 scripts/audit_dependencies.py > logs/dependency-audit-progress.log 2>&1
python3 scripts/corpus.py > logs/corpus-progress.log 2>&1
python3 scripts/summarize.py > logs/summary.txt
