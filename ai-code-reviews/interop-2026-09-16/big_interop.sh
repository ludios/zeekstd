#!/usr/bin/env bash
set -u
S=/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad
Z=/home/at/code/rust/zeekstd/target/release/zeekstd
D=$S/data; O=$S/out
RESULTS=$S/big_results.tsv
: > "$RESULTS"
pass=0; fail=0
rec() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"; if [ "$1" = PASS ]; then pass=$((pass+1)); else fail=$((fail+1)); fi; }
sha() { sha256sum | cut -d' ' -f1; }
t() { date +%s; }
# check NAME ARCHIVE INPUT [PREFIX]  (prefix -> zstd -D PREFIX --memory=<prefix size>)
check() {
  local name=$1 arc=$2 inp=$3 pfx=${4:-}
  local want; want=$(cat "$inp.sha256")
  local zargs=() zkargs=()
  if [ -n "$pfx" ]; then zargs=(-D "$pfx" --memory=$(stat -c %s "$pfx")); zkargs=(--patch-apply "$pfx"); fi
  local got t0
  t0=$(t); got=$(zstd -q -d -c "${zargs[@]}" "$arc" 2>"$O/$name.zstd-d.err" | sha)
  if [ "$got" = "$want" ]; then rec PASS zstd-d "$name" "ok $(( $(t)-t0 ))s"; else rec FAIL zstd-d "$name" "sha mismatch: $(head -c 200 "$O/$name.zstd-d.err")"; fi
  if zstd -q -t "${zargs[@]}" "$arc" 2>"$O/$name.zstd-t.err"; then rec PASS zstd-t "$name" ok; else rec FAIL zstd-t "$name" "$(head -c 200 "$O/$name.zstd-t.err")"; fi
  if out=$(zstd -l "$arc" 2>&1); then rec PASS zstd-l "$name" "$(echo "$out" | tail -1 | tr -s ' ')"; else rec FAIL zstd-l "$name" "$out"; fi
  if [ -z "$pfx" ]; then
    got=$(zstdcat "$arc" 2>/dev/null | sha)
    if [ "$got" = "$want" ]; then rec PASS zstdcat "$name" ok; else rec FAIL zstdcat "$name" "sha mismatch"; fi
    got=$(pzstd -q -d -c "$arc" 2>"$O/$name.pzstd.err" | sha)
    if [ "$got" = "$want" ]; then rec PASS pzstd-d "$name" ok; else rec FAIL pzstd-d "$name" "sha mismatch: $(head -c 200 "$O/$name.pzstd.err")"; fi
  fi
  got=$($Z d -q -c "${zkargs[@]}" "$arc" 2>"$O/$name.zk-d.err" | sha)
  if [ "$got" = "$want" ]; then rec PASS zeekstd-d "$name" ok; else rec FAIL zeekstd-d "$name" "sha mismatch: $(head -c 200 "$O/$name.zk-d.err")"; fi
  if out=$($Z l -r "$arc" 2>&1); then rec PASS zeekstd-l "$name" "$(echo "$out" | tail -1 | tr -s ' ' | cut -c1-80)"; else rec FAIL zeekstd-l "$name" "$(echo "$out" | tail -1)"; fi
}
seekcheck() {
  local name=$1 arc=$2 inp=$3 from=$4 to=$5 pfx=${6:-}
  local zkargs=(); [ -n "$pfx" ] && zkargs=(--patch-apply "$pfx")
  local want got
  want=$(tail -c +$((from+1)) "$inp" | head -c $((to-from)) | sha)
  got=$($Z d -q -c --from "$from" --to "$to" "${zkargs[@]}" "$arc" 2>"$O/$name.seek.err" | sha)
  if [ "$got" = "$want" ]; then rec PASS seek "$name" "[$from,$to)"; else rec FAIL seek "$name" "[$from,$to) $(head -c 200 "$O/$name.seek.err")"; fi
}
compress() {
  local name=$1 inp=$2; shift 2
  rm -f "$O/$name.zst"; local t0; t0=$(t)
  if $Z c -q "$@" "$inp" -o "$O/$name.zst" 2>"$O/$name.c.err"; then rec PASS compress "$name" "$(stat -c %s "$O/$name.zst") bytes $(( $(t)-t0 ))s"; return 0
  else rec FAIL compress "$name" "$(head -c 200 "$O/$name.c.err")"; return 1; fi
}

# 5 GiB + 1 random, default 2 MiB frames -> 2561 frames, compressed offsets past 4 GiB
n=big_def_rnd5g; compress $n $D/rnd5g_plus1 -l 1 && { check $n $O/$n.zst $D/rnd5g_plus1; seekcheck $n $O/$n.zst $D/rnd5g_plus1 4294967295 4294968320; seekcheck $n $O/$n.zst $D/rnd5g_plus1 5368709120 5368709121; seekcheck $n $O/$n.zst $D/rnd5g_plus1 2097151 2097153; }
# same input, -s 3G -> capped at the 1 GiB max frame size
n=big_s3g_rnd5g; compress $n $D/rnd5g_plus1 -l 1 -s 3G && { check $n $O/$n.zst $D/rnd5g_plus1; seekcheck $n $O/$n.zst $D/rnd5g_plus1 1073741823 1073741825; seekcheck $n $O/$n.zst $D/rnd5g_plus1 5368709119 5368709121; }
# 3 GiB repetitive text, 512 KiB frames -> 6144 frames
n=big_s512k_text3g; compress $n $D/text3g -s 512K && { check $n $O/$n.zst $D/text3g; seekcheck $n $O/$n.zst $D/text3g 2147483000 2147484000; seekcheck $n $O/$n.zst $D/text3g 0 1; }
rm -f $O/big_def_rnd5g.zst $O/big_s3g_rnd5g.zst

# large prefix: 200 MiB -> window log 28 (256 MiB) which is above zstd's default 128 MiB decoder limit
python3 - <<'PY'
import os
S='/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad/data'
base=bytearray(os.urandom(200<<20))
open(f'{S}/pfx200m','wb').write(base)
for i in range(0,len(base),65536): base[i:i+5]=b'PATCH'
open(f'{S}/pfx200m_modified','wb').write(base)
PY
sha256sum < $D/pfx200m_modified | cut -d' ' -f1 > $D/pfx200m_modified.sha256
n=big_patch200m; compress $n $D/pfx200m_modified --patch-from $D/pfx200m -l 1 && {
  check $n $O/$n.zst $D/pfx200m_modified $D/pfx200m
  want=$(cat $D/pfx200m_modified.sha256)
  # variants: what exactly does standard zstd need?
  got=$(zstd -q -d -c --patch-from=$D/pfx200m $O/$n.zst 2>$O/$n.v1.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d --patch-from" $n ok || rec FAIL "zstd-d --patch-from" $n "$(head -c 150 $O/$n.v1.err)"
  got=$(zstd -q -d -c -D $D/pfx200m $O/$n.zst 2>$O/$n.v2.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d -D (no --memory)" $n ok || rec FAIL "zstd-d -D (no --memory)" $n "$(head -c 150 $O/$n.v2.err)"
  got=$(zstd -q -d -c -D $D/pfx200m --long=28 $O/$n.zst 2>$O/$n.v3.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d -D --long=28" $n ok || rec FAIL "zstd-d -D --long=28" $n "$(head -c 150 $O/$n.v3.err)"
  got=$(zstd -q -d -c -D $D/pfx200m --memory=256MB $O/$n.zst 2>$O/$n.v4.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d -D --memory=256MB" $n ok || rec FAIL "zstd-d -D --memory=256MB" $n "$(head -c 150 $O/$n.v4.err)"
  seekcheck $n $O/$n.zst $D/pfx200m_modified 2097000 2200000 $D/pfx200m
}
# small prefix (3 MiB) multi-frame, the same variant matrix, so the answer is documented for the common case too
n=big_patch3m; compress $n $D/pfx3m_modified --patch-from $D/pfx3m && {
  want=$(cat $D/pfx3m_modified.sha256)
  got=$(zstd -q -d -c --patch-from=$D/pfx3m $O/$n.zst 2>$O/$n.v1.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d --patch-from" $n ok || rec FAIL "zstd-d --patch-from" $n "$(head -c 150 $O/$n.v1.err)"
  got=$(zstd -q -d -c -D $D/pfx3m $O/$n.zst 2>$O/$n.v2.err | sha); [ "$got" = "$want" ] && rec PASS "zstd-d -D (no --memory)" $n ok || rec FAIL "zstd-d -D (no --memory)" $n "$(head -c 150 $O/$n.v2.err)"
  zstd -q -t -D $D/pfx3m $O/$n.zst && rec PASS "zstd-t -D" $n ok || rec FAIL "zstd-t -D" $n "exit"
  got=$(pzstd -q -d -c -D $D/pfx3m $O/$n.zst 2>$O/$n.v5.err | sha); [ "$got" = "$want" ] && rec PASS "pzstd-d -D" $n ok || rec FAIL "pzstd-d -D" $n "$(head -c 150 $O/$n.v5.err)"
}
echo "PASS=$pass FAIL=$fail"
grep FAIL "$RESULTS"
echo DONE
