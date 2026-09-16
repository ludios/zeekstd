# Task

Answer this question from the owner of the zeekstd project, empirically:

> despite ai-code-reviews/, assuming we're not reading hostile compressed blobs, is this good
> enough to use to store data? like I'm mostly concerned about whether standard zstd tools will be
> able to decompress everything I write with this. maybe some emperical tests would help with
> standard tools?

They intend to store a large number of files with this, long term. The load-bearing worry is
recoverability: if zeekstd is ever unavailable or buggy, can the ordinary `zstd` tooling that
ships with every distro still get their bytes back, exactly?

## Independence

This must be an independent assessment. Other AI agents have reviewed this project, and their
reports have been deliberately withheld from you so that your conclusions are your own. Do not go
looking for them:

- Work only inside `/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad/codex-independent-interop` (this directory). The tree to examine is `/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad/codex-independent-interop/zeekstd`, an
  extract of commit 5f381f268d52f52869c91270200d30746efa8295 with the prior-review directory
  removed. There is no git history here, by design.
- Do not read, build in, or modify `/home/at/code/rust/zeekstd`, the live checkout. It contains
  those reports and a git history whose commit messages summarize them.
- The tree does contain `lib/tests/known_bugs.rs`, which cites an earlier review of
  malformed/hostile-input handling. That subject is explicitly out of scope for this question, so
  treat the file as ordinary source and do not chase the document it names.

Form your own view. If you end up agreeing with conventional wisdom, say so because your own
tests showed it.

## Scope

In scope:

- Can the standard tools decompress everything zeekstd writes, byte for byte? That is the core
  question. Vary whatever knobs the CLI and the library expose on the write side and check the
  output against the standard tools. Design your own matrix; be systematic about which dimensions
  matter and say why you chose them.
- Is what zeekstd writes correct and self-consistent as a zstd stream and as a seekable archive?
- Anything else that bears on "is it safe to keep my data in this format", given non-hostile input.

Out of scope:

- Adversarial or corrupted input handling, fuzzing, resource-exhaustion on malformed archives.
  Assume the archives being read are the ones zeekstd itself wrote, on working storage.
- Style, performance, API aesthetics.
- The CLI's file-handling behaviour (clobbering, overwrite prompts) is a lower priority than the
  format/interop question; mention it only if you trip over something that risks data.

## Empirical requirements

Actually run things; do not reason from source alone, and label anything you could not execute.

Available on this machine: the `zstd` 1.5.7 CLI and its friends (`zstd`, `unzstd`, `zstdcat`,
`zstdmt`, `pzstd`, `zstdgrep`), `python3` (without the `zstandard` or `pyzstd` modules),
`sha256sum`, `cmp`, `hyperfine`, `gcc`, `go`, and a Rust toolchain. Cargo must run `--offline`
`--locked`; the registry cache is populated. If you want a second independent oracle, the
`zstd-safe` dependency has a `seekable` feature that exposes Meta's reference implementation of
the seekable format from zstd's `contrib/`; you may also write C against the bundled libzstd.

Compare by hashing the decompressed output against the original input, not by exit status alone.

Resources: 32 cores, ~35 GB RAM available, ~6.8 TB free on /tmp. Multi-gigabyte inputs are
affordable and worth including if you think size matters here. There is no time pressure; be
thorough, but stop when further tests stop being informative.

## Deliverable

Write your report to `/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad/codex-independent-interop/report.md`. Structure it as you see fit, but it must contain:

1. A direct verdict on the owner's question, up front, in their terms: would you store data this
   way, and can the standard tools read it back?
2. The test matrix you actually ran, with results, in a form a human can audit.
3. Every case where a standard tool could not read zeekstd's output: the exact commands, the tool
   output, and your diagnosis of whether it is a zeekstd defect, a limitation of the standard
   tool, or expected behaviour of the format. Say what a user should do about each one.
4. The limits of your testing: what you did not cover, what rests on reading rather than running,
   and what would change your verdict.

Keep the repro scripts and logs next to the report so the work can be re-run.

Do not commit anything anywhere, and leave the live checkout untouched.
