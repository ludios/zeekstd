#!/usr/bin/env bash
# Empirical interop: everything zeekstd's CLI writes must be decodable by the standard zstd tools.
set -u
S=/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad
Z=/home/at/code/rust/zeekstd/target/release/zeekstd
D=$S/data; O=$S/out
RESULTS=${RESULTS:-$S/cli_results.tsv}
: > "$RESULTS"
pass=0; fail=0
rec() { # status check case detail
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"
  if [ "$1" = PASS ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
}
sha() { sha256sum | cut -d' ' -f1; }

# check NAME ARCHIVE INPUT [PREFIX]
check() {
  local name=$1 arc=$2 inp=$3 pfx=${4:-}
  local want; want=$(cat "$inp.sha256")
  local zargs=() zkargs=()
  if [ -n "$pfx" ]; then zargs=(--patch-from="$pfx"); zkargs=(--patch-apply "$pfx"); fi

  local got
  got=$(zstd -q -d -c "${zargs[@]}" "$arc" 2>"$O/$name.zstd-d.err" | sha)
  if [ "$got" = "$want" ]; then rec PASS zstd-d "$name" ok; else rec FAIL zstd-d "$name" "sha mismatch: $(head -c 200 "$O/$name.zstd-d.err")"; fi

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

  if out=$($Z l "$arc" 2>&1); then rec PASS zeekstd-l "$name" "$(echo "$out" | tail -1 | tr -s ' ' | cut -c1-80)"; else rec FAIL zeekstd-l "$name" "$(echo "$out" | tail -1)"; fi
}

# seekcheck NAME ARCHIVE INPUT FROM TO [PREFIX] : compare zeekstd range read against the raw file
seekcheck() {
  local name=$1 arc=$2 inp=$3 from=$4 to=$5 pfx=${6:-}
  local zkargs=(); [ -n "$pfx" ] && zkargs=(--patch-apply "$pfx")
  local want got
  want=$(tail -c +$((from+1)) "$inp" | head -c $((to-from)) | sha)
  got=$($Z d -q -c --from "$from" --to "$to" "${zkargs[@]}" "$arc" 2>"$O/$name.seek.err" | sha)
  if [ "$got" = "$want" ]; then rec PASS seek "$name" "[$from,$to)"; else rec FAIL seek "$name" "[$from,$to) $(head -c 200 "$O/$name.seek.err")"; fi
}

# compress NAME INPUT [zeekstd args...] -> $O/NAME.zst ; returns nonzero on failure
compress() {
  local name=$1 inp=$2; shift 2
  rm -f "$O/$name.zst"
  if $Z c -q "$@" "$inp" -o "$O/$name.zst" 2>"$O/$name.c.err"; then rec PASS compress "$name" "$(stat -c %s "$O/$name.zst") bytes"; return 0
  else rec FAIL compress "$name" "$(head -c 200 "$O/$name.c.err")"; return 1; fi
}

inputs=(empty one small100 rnd1k rnd1m rnd2m_exact rnd2m_plus1 text6m_exact mixed10m zeros64m)

# 1. defaults (level 3, 2 MiB uncompressed frames, checksums on)
for f in "${inputs[@]}"; do n="def_$f"; compress $n $D/$f && check $n $O/$n.zst $D/$f; done
# 2. no checksum
for f in one rnd2m_plus1 mixed10m; do n="nochk_$f"; compress $n $D/$f --no-checksum && check $n $O/$n.zst $D/$f; done
# 3. tiny uncompressed frames
for f in small100 rnd1m text6m_exact; do n="s1k_$f"; compress $n $D/$f -s 1K && check $n $O/$n.zst $D/$f; done
n=s1_small100; compress $n $D/small100 -s 1 && check $n $O/$n.zst $D/small100   # 1-byte frames
# 4. compressed-size policy
for f in rnd1m mixed10m zeros64m; do n="cpol64k_$f"; compress $n $D/$f -s 64K --frame-size-policy compressed && check $n $O/$n.zst $D/$f; done
n=cpol1_small100; compress $n $D/small100 -s 1 --frame-size-policy compressed && check $n $O/$n.zst $D/small100
# 5. levels
for l in 1 19 22; do n="l${l}_mixed10m"; compress $n $D/mixed10m -l $l && check $n $O/$n.zst $D/mixed10m; done
n=l19_s4k_text6m; compress $n $D/text6m_exact -l 19 -s 4K && check $n $O/$n.zst $D/text6m_exact
# 6. detached seek table (Head format in side file; data file is plain frames)
for f in empty mixed10m; do
  n="head_$f"; rm -f $O/$n.zst $O/$n.st
  if $Z c -q --seek-table-file $O/$n.st $D/$f -o $O/$n.zst 2>$O/$n.c.err; then rec PASS compress $n "data $(stat -c %s $O/$n.zst) B, table $(stat -c %s $O/$n.st) B"
    want=$(cat $D/$f.sha256)
    got=$(zstd -q -d -c $O/$n.zst | sha); [ "$got" = "$want" ] && rec PASS zstd-d $n ok || rec FAIL zstd-d $n "sha mismatch"
    zstd -q -t $O/$n.zst && rec PASS zstd-t $n ok || rec FAIL zstd-t $n "exit $?"
    got=$(zstd -q -d -c $O/$n.st | sha); [ "$got" = "$(printf '' | sha)" ] && rec PASS zstd-d-tablefile $n "decodes to empty" || rec FAIL zstd-d-tablefile $n "not empty"
    got=$($Z d -q -c --seek-table-file $O/$n.st $O/$n.zst | sha); [ "$got" = "$want" ] && rec PASS zeekstd-d $n ok || rec FAIL zeekstd-d $n "sha mismatch"
  else rec FAIL compress $n "$(head -c 200 $O/$n.c.err)"; fi
done
# 7. stdin -> stdout
n=stdin_mixed10m; if cat $D/mixed10m | $Z c -q -c > $O/$n.zst 2>$O/$n.c.err; then rec PASS compress $n "$(stat -c %s $O/$n.zst) bytes"; check $n $O/$n.zst $D/mixed10m; else rec FAIL compress $n "$(head -c 200 $O/$n.c.err)"; fi
n=stdin_empty; if $Z c -q -c < $D/empty > $O/$n.zst 2>$O/$n.c.err; then rec PASS compress $n "$(stat -c %s $O/$n.zst) bytes"; check $n $O/$n.zst $D/empty; else rec FAIL compress $n "$(head -c 200 $O/$n.c.err)"; fi
# 8. patch-from (prefix) : standard zstd must decode with --patch-from
for p in pfx512 pfx1m pfx3m; do n="patch_${p}"; compress $n $D/pfx3m_modified --patch-from $D/$p && check $n $O/$n.zst $D/pfx3m_modified $D/$p; done
n=patch_pfx3m_s256k; compress $n $D/pfx3m_modified --patch-from $D/pfx3m -s 256K && check $n $O/$n.zst $D/pfx3m_modified $D/pfx3m
n=patch_pfx3m_nommap; compress $n $D/pfx3m_modified --patch-from $D/pfx3m --no-mmap-prefix && check $n $O/$n.zst $D/pfx3m_modified $D/pfx3m
n=patch_pfx100; compress $n $D/pfx3m_modified --patch-from $D/pfx100 && check $n $O/$n.zst $D/pfx3m_modified $D/pfx100
# 9. seeks across frame boundaries (zeekstd-only feature, checked against raw bytes)
seekcheck def_rnd2m_plus1 $O/def_rnd2m_plus1.zst $D/rnd2m_plus1 2097000 2097153
seekcheck def_mixed10m $O/def_mixed10m.zst $D/mixed10m 2097151 6291457
seekcheck s1k_text6m_exact $O/s1k_text6m_exact.zst $D/text6m_exact 1023 3073
seekcheck cpol64k_mixed10m $O/cpol64k_mixed10m.zst $D/mixed10m 5000000 5100000
seekcheck patch_pfx3m $O/patch_pfx3m.zst $D/pfx3m_modified 2097000 2200000 $D/pfx3m
seekcheck s1_small100 $O/s1_small100.zst $D/small100 3 7

echo "PASS=$pass FAIL=$fail"
grep -c FAIL "$RESULTS" >/dev/null && grep FAIL "$RESULTS"
