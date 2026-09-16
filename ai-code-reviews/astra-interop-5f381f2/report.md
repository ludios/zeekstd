# Would I keep data in zeekstd archives?

**Yes, using ordinary, self-contained compression and the default appended `Foot` seek table. On this evidence I would store data that way. Standard `zstd` recovered the exact original bytes, including files over 4 GiB; recovery did not depend on zeekstd.** I would keep the CLI's checksums enabled, verify newly written archives with standard zstd against an original SHA-256, and retain those hashes.

**“Everything it can write works with an unqualified `zstd -d`” is not true.** Patches/dictionaries require the original dependency; large windows require a higher decoder memory limit. Multi-frame patches expose a particularly inconvenient stock-zstd limitation. I also reproduced two destructive CLI output-path collisions. Those qualifications matter if “store a large number of files” means unattended processing.

Across **751 successfully completed, self-contained, non-colliding writer cases**, plain `zstd -dc` recovered **750/750 ordinary-window archives** exactly. The remaining archive used an explicitly selected 256 MiB window: plain zstd refused it, and `--memory=256MB` recovered it exactly. All **23 dependency-bearing archives** were also recovered exactly with their bases/dictionaries and the appropriate procedure. **I found no malformed compressed frame or incorrect seek-table entry in those 774 archives.** This is empirical evidence for this build, not a proof about every possible input or compression context.

For the owner's intended use, my choice would be: default CLI compression, appended table, no `--patch-from`, distinct input/output paths, and successful external decompression/hash verification before discarding an original. The library default differs: its frame checksums are **off** unless `checksum_flag(true)` is requested.

## What was examined

The supplied extract identified as commit `5f381f268d52f52869c91270200d30746efa8295`, library 0.6.2, CLI 0.4.5. I did not inspect the live checkout, git history, or withheld reviews. I did not run the hostile-input integration tests. All work and artifacts are in this workspace; no commits were made and no production source was changed. The only added Rust source in the extract is the test example copied from `scripts/interop_probe.rs`.

Platform: Linux x86-64; installed zstd and pzstd **1.5.7**; bundled libzstd **1.5.7**; Rust 1.100.0-nightly. Full version strings, executable and lockfile hashes are in [logs/environment.txt](logs/environment.txt); examined source fingerprints are in [logs/source-sha256.txt](logs/source-sha256.txt). Every Cargo invocation used `--offline --locked`.

The independent work consists of **777 writer attempts: 776 successes and one rejected unsupported compression-context setting**. Of the successes, 774 are the non-colliding archives above and two deliberately reproduce destructive path collisions. There were **2,098 SHA-256 comparisons, 2,035 passing**. The 63 non-passing comparisons are the deliberately exercised limits, controls, and collisions detailed below—not 63 unexplained corrupt archives. There are also 46 successful `zstd -t` checks; exit status alone was never the criterion for byte recovery.

## Test method and audit trail

For every successful writer case, the Python harness ran standard `zstd -d -c`, streamed all stdout through SHA-256, and compared it with the input's SHA-256. It recorded exit status, decompressed length, exact argument vector, stdin redirection, stderr, and both hashes. It did not accept a matching prefix or a successful exit as sufficient.

For standard appended seek tables, a separate Rust helper used **Meta's reference seekable implementation**, exposed by `zstd-safe`'s `seekable` feature, rather than zeekstd's decoder. It:

- Read the seek table using the reference implementation and checked each compressed frame boundary against libzstd's frame scanner.
- Checked table length, frame count, offsets, total uncompressed size, zero descriptor bits, available frame content sizes, and actual frame-checksum flags.
- Reconstructed the entire input through the reference decoder, with an independent SHA-256 comparison.
- Made out-of-order reads around frame boundaries, EOF, interior positions, and—on sufficiently large inputs—`0xffffffff` and `0x100000000`, comparing those bytes directly against the original.

**726 original archives passed that reference check.** Another **12 alternate-layout cases** passed after an independent Python parser moved only their table metadata into the standard appended `Foot` layout. Across those 738 checks there were **17,768 successful random-read comparisons**. The converted archives preserve the compressed data frames byte-for-byte; this tests the table contents, not native reference-decoder support for `Head`.

All 23 dependency-bearing archives received an additional independent table parse and **261 individual-frame SHA-256 comparisons** against the corresponding original slices. This checks each frame's actual decoded size and content, rather than just the sum of the table's sizes.

The reference seekable code is an independent implementation of the seek-table/seek logic, **not a different zstd codec**: it and the installed CLI both use zstd 1.5.7. Likewise, `unzstd`, `zstdcat`, and `zstdmt` are useful invocation checks, not three independent codecs.

Machine-auditable results:

- [results/archives.csv](results/archives.csv): one row per writer attempt, exact producer command, expected hash, plain-zstd and reference results, successful recovery commands' roles.
- [results/commands.csv](results/commands.csv): every command, stdout byte count/hash, stderr, result, and duration.
- `logs/{cli,library,large,special,followups,extended,recovery,dependency-audit,corpus}.jsonl`: original structured command records, with individual stderr files alongside them.
- [results/summary.json](results/summary.json): counts by test stage.
- The appendix below includes **every non-passing command**, exact output and hashes; it is also available separately as [results/failure-transcripts.md](results/failure-transcripts.md).

## Matrix actually run

The broad matrix covers data distribution, frame creation, compression level and checksums. Separate boundary tests exercise empty files, exact frame endings and streaming block sizes. Library tests vary call boundaries because correct behavior with a large CLI buffer does not establish correct behavior with one-byte buffers or short writes. Large tests exercise the hard per-frame cap and both compressed and uncompressed offsets beyond 32 bits.

| Group | Actual dimensions | Writer cases | Result |
|---|---|---:|---|
| CLI factorial | 262,161-byte text, all-byte-value pattern, seeded random, mixed; compressed/uncompressed policy; frame thresholds 127, 4,096, 131,072, 2,097,152; levels −5, 0, 1, 3, 9, 19, 22; checksums off/on | 448 | Plain zstd and reference: all exact |
| Input boundaries | Sizes 0, 1, 2, 126–128, 255–257, 4,095–4,097, 131,071–131,073, 2,097,151–2,097,153, 4,194,304–4,194,305; default 2 MiB framing; both checksum settings | 40 | Both decoders: all exact |
| Tiny CLI frames | Thresholds 1, 2, 3, 9; both policies; 262,161-byte all-byte-value input | 8 | Both decoders: all exact; up to 262,161 frames |
| CLI I/O and sidecars | Empty, mixed, 4,194,305-byte input × file/stdin input × file/stdout output × appended/separate table | 24 | Plain zstd: all exact; all 12 appended cases reference-exact |
| Library streaming | `RawEncoder`/`Encoder` × both policies × input/output chunk pairs (1,1), (7,3), (127,13), (4,093,131,591), (131,072,262,144) × both checksums × plain/flush/manual frame endings/both; 4,096-byte threshold | 160 | Both decoders: all exact; `Encoder` sink additionally accepts at most 7 bytes per write |
| Library table layouts | Raw/writer × `Foot`/`Head` × appended/separate × empty/mixed; one-byte raw output/serialization buffer | 16 | Plain zstd: all exact; four standard layouts reference-exact, other 12 exact after independent table conversion |
| Library context | Defaults; content-size flag off; pledged size; pledged size + content-size off; window logs 10 and 27; two workers | 7 attempts | Six exact with both decoders; workers setting rejected before output creation |
| Partial epilogue → flush | Raw output buffers 1, 13, 127; both checksums; start manual ending, complete pending ending with `flush()` | 6 | Both decoders: all exact |
| Every positive level | CLI levels 1 through 22 on mixed input, 4,096-byte frames | 22 | Both decoders: all exact |
| Extreme accepted levels | CLI levels −2,147,483,648; −131,072; −1; 23; 100; 2,147,483,647 | 6 | Both decoders: all exact; these are accepted/clamped zstd settings, not evidence of distinct algorithms for every number |
| Large inputs | 4 GiB + 17 zero bytes and 4 GiB + 1,048,593 seeded-random bytes; uncompressed 2 MiB, uncompressed `u32::MAX`, compressed `u32::MAX`; additionally raw library/compressed `u32::MAX` on random data | 7 | Both decoders: all exact, including random reads beyond 4 GiB |
| Large input/high levels | 300 MiB zeros, CLI levels 19, 20, 22, requested `u32::MAX` frame size | 3 | Both decoders: all exact with default decoder limits |
| Explicit large window | Library window log 28, 1 GiB frame threshold, 300 MiB zeros | 1 | Default CLI and reference memory-limit rejection; plain zstd with 256 MiB limit exact |
| Natural text | Supplied 10,192,446-byte Dickens corpus: level 3/uncompressed 2 MiB; level 3/compressed 64 KiB; level 19/uncompressed 2 MiB; level 22/uncompressed 1 GiB | 4 | Both decoders: all exact |
| CLI patch options | 4,194,576-byte base; 2,097,305-byte related input; both policies × mmap/no mmap × appended/separate × checksum off/on | 16 | All exact with `zstd -D BASE`; default decompression fails; multi-frame `--patch-from` fails |
| Library dependencies | Raw/writer × raw dictionary/reapplied prefix; 131,072-byte frames | 4 | All exact with `zstd -D BASE`; same multi-frame `--patch-from` limitation |
| Trained dictionary | Raw/writer; trained 4 KiB ID-bearing dictionary; 65,200-byte input; 4,096-byte frames | 2 | Missing dictionary rejected; both exact with `-D` |
| Large CLI patch base | 129 MiB base; 2,097,305-byte related input; 131,072-byte frames | 1 | Dictionary-size, memory, and prefix-lifetime limits; all bytes recovered by ordinary zstd per frame, described below |
| Forced path collisions | Input equals output; sidecar equals compressed output | 2 | Both commands return success; first loses original data, second creates invalid output |

Additional invocation checks: **46 cases each** with `unzstd -c`, `zstdcat`, `zstdmt -dc`, `pzstd -dc`, and `zstd -dc` fed through stdin all matched input SHA-256. The same 46 passed `zstd -t` and `zstd -lv`. They span all CLI I/O/sidecar cases, all library table-layout cases, and the six large CLI cases. `zstdgrep -a archival` on text split across 127-byte frames matched the SHA-256 of ordinary `grep` on the input.

The supplied unit/CLI suites also passed: **54 library unit tests, 20 CLI integration tests**. Those are supporting checks, not the basis for the independent recovery result. Their logs are `logs/upstream-lib.log` and `logs/upstream-cli.log`.

### Large-file evidence

| Input | Input/output SHA-256 | Selected reference observations |
|---|---|---|
| 4,294,967,313 zero bytes | `0a05f7ccc43a8e6c830fd3b8ad9dfc0129ce8f65fd6cc96be998988a1871fe21` | 2,049 frames at 2 MiB; five frames with either `u32::MAX` policy |
| 4,296,015,889 random bytes | `aac41671866e65a667a408dedf77b52b5b0a4d996c7bf612f1272493e3e1a32d` | 4,296,140,854 compressed data bytes with 2 MiB framing; both kinds of offsets cross 4 GiB |

With either requested `u32::MAX` threshold the largest **actual uncompressed frame was 1,073,741,824 bytes**. That confirms the writer's 1 GiB cap in execution. The compressed-threshold policy is approximate: it need not produce frames as small as the requested byte threshold. That affected frame sizes, not correctness.

## Failures, diagnoses, and what to do

Exact commands and all stderr are reproduced in the appendix. The following groups account for every non-passing result.

### 1. Missing dictionary or patch base: expected dependency, not frame corruption

For the small raw-prefix/dictionary cases, plain decompression reported:

```text
results/patch-u-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected
```

The trained dictionaries instead reported `Dictionary mismatch`. The decoder's wording alone does not diagnose corrupt bytes: these frames reference external data. Standard zstd recovered all 22 small-base/trained-dictionary cases exactly when given the same dependency:

```sh
zstd -d -c -D data/prefix.bin results/patch-u-mmap-prefix-side0-c1.zst
zstd -d -c -D data/trained.dict results/trained-writer.zst
```

For the patch example, the recovered 2,097,305 bytes hash to `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`, exactly the input. **Action:** preserve and identify the exact dependency, or avoid dictionaries/patches for self-contained archival storage. A `.zst` suffix does not make a patch self-contained.

### 2. Multi-frame `zstd --patch-from`: stock-tool limitation

This command appears appropriate but failed after emitting only **131,072 bytes** of the 2,097,305-byte original:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-mmap-prefix-side0-c1.zst
```

It reported `Data corruption detected`. The first-frame-only hash was `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`, which is not the input hash. The same failure occurred in all eight uncompressed-policy CLI patch cases and all four library dependency cases. The eight compressed-policy patches happened to fit into one frame and succeeded with `--patch-from`.

**Diagnosis is supported by a stock-zstd control:** I made two separate patches with standard `zstd --patch-from`, verified each separately, concatenated them, and observed the identical failure at the second frame. `zstd -D BASE` decoded the concatenation correctly. This demonstrates a limitation in applying the prefix across frames in this installed CLI, rather than an invalid zeekstd frame. Zeekstd itself decoded both tested CLI patch policies exactly with its `--patch-apply` option.

**Action:** with these small raw bases, use `zstd -D BASE`. For larger bases, use the per-frame recovery procedure below. Do not assume that one successful frame or some output on stdout means the patch was recovered.

### 3. Large windows: default decoder limit, not invalid format

The library can retain a caller-selected `CCtx` window. My explicit window-log-28 case wrote a valid stream requiring 256 MiB, and default zstd printed:

```text
results/large-window.zst : Decoding error (36) : Frame requires too much memory for decoding
results/large-window.zst : Window size larger than maximum : 268435456 > 134217728
results/large-window.zst : Use --long=28 or --memory=256MB
```

The reference seekable decoder also refused that window with its default limit. This command recovered all 314,572,800 bytes with the correct SHA-256:

```sh
zstd -d -c --memory=256MB results/large-window.zst
```

**Action:** retain the needed memory setting with unusually configured archives, or stay within the default decoder window limit. This was not caused merely by a large file or a large requested frame: the ordinary 4 GiB files and the 300 MiB level-22 CLI case decoded with default limits.

### 4. Large patch bases combine three stock-tool constraints

With `data/prefix-129m.bin` (135,266,304 bytes), zeekstd successfully wrote 17 frames. `zstd -D` refused the base:

```text
zstd: error 34 : Dictionary file data/prefix-129m.bin is too large (> 33554432 bytes)
```

Adding `--memory=512MB` did **not** lift that dictionary-file limit. Using `--patch-from` bypassed the dictionary-file rejection but first hit the 256 MiB window limit. Adding `--memory=256MB` then got through the first frame before the same multi-frame prefix failure described above. The 17 initial single-frame attempts without the memory setting also failed with the window-limit message.

**Recovery was executed successfully, not just proposed.** Reapplying `--patch-from` separately to each frame, with `--memory=256MB`, recovered every frame and the exact full-file SHA-256. The retained helper uses only Python's standard library and the ordinary zstd command, and reads the intact standard `Foot` table to locate frames:

```sh
python3 scripts/recover_patch.py results/large-prefix.zst data/prefix-129m.bin 256MB > restored.bin
sha256sum data/patched.bin restored.bin
```

Both hashes were `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`. A separate 261-frame audit includes this archive and verifies each table entry against the corresponding original slice. **Diagnosis:** external dependency plus standard CLI limits, with valid frames and table. **Action:** preserve the base and recovery procedure; for straightforward long-term recovery, avoid creating patch-dependent archives in the first place.

### 5. `Head` and detached tables: stream-compatible, not native reference-seekable layout

Meta's reference seekable decoder rejected an appended `Head` table and a data file whose `Foot` table was separate:

```text
ERROR: zstd: Unknown frame descriptor
```

In both cases **standard sequential zstd decompression already recovered all bytes exactly**. Standard zstd skips the metadata or does not need a detached table at all. The reference seekable decoder expects the standard footer/table at the end of the same file. Independently parsing and converting/reappending the metadata made all 12 alternate-layout test cases reference-decodable with correct bytes and random reads.

**Diagnosis:** expected layout incompatibility for reference random access, not lost payload. `Head` is a zeekstd extension; it should not be described as universally compatible seek metadata. **Action:** use default appended `Foot` for maximum seekable-format interoperability. Loss of a detached table does not prevent sequential `zstd -dc` recovery of the data file.

### 6. Two-worker context: rejected build capability, no archive produced

The library accepts a preconfigured `CCtx`, but `CParameter::NbWorkers(2)` failed in this bundled build with:

```text
ERROR: zstd: Unsupported parameter
```

That call happened before creating an output file. **Diagnosis:** an unavailable libzstd build capability, not a successfully written incompatible archive. **Action:** handle the error; I make no empirical claim about the library's worker-enabled output on a differently configured build. `zstdmt` decoding is a different matter and passed its 46 cases.

### 7. Forced path aliases: actual CLI data-loss defects

I noticed output files are created after opening the input, without an identity check, and reproduced the consequences on expendable copies:

```sh
zeekstd/target/release/zeekstd compress -q -f results/collision-input.bin -o results/collision-input.bin
```

This returned success and replaced the 4,096-byte original with a valid archive of **zero bytes**. Standard zstd also returned success, but its empty-output hash did not match the original. This is why exit status is insufficient as the recovery test. Once that original has been overwritten, decompressing the resulting archive cannot restore it.

```sh
zeekstd/target/release/zeekstd compress -q -f data/mixed.bin -o results/collision-sidecar.zst --seek-table-file results/collision-sidecar.zst
```

This also returned success; the two output writers collided. Standard zstd reported:

```text
zstd: results/collision-sidecar.zst: unsupported format
```

**Diagnosis:** zeekstd CLI file-handling defects under forced aliases, separate from its normal frame encoder. **Action:** ensure input, compressed output, sidecar and dependency paths are distinct; do not use `--force` to override that requirement. An implementation fix should reject identical underlying files, including aliases, before truncation. Only exact same-path cases were executed; hard-link/symlink variants were not tested. These two cases are why I would not give blanket approval to an unattended command generator without external verification.

## What the evidence says about the format

The successful payload recovery does not rely on zeekstd's decoder: its writer delegates compression to libzstd and appends a zstd skippable frame containing its seek table. My stream and table checks confirm that mechanism in the tested outputs. The normal `Foot` table is accepted by Meta's seekable implementation even though zeekstd puts optional integrity checksums in the data frames, not in table entries. Descriptor zero means no optional table checksums; the reference decoder accepts that.

Source inspection agrees with the observations: `RawEncoder::end_frame` logs compressed/uncompressed sizes, `Encoder::finish()` ends the final frame and writes `Foot`, and the serializer emits the skippable header and footer. The library's public low-level API still requires correct use: drain returned progress, finish the last frame, serialize the table, and check errors. `reset_frame` explicitly discards progress; `into_seek_table` by itself is not a substitute for completing output. I did not treat intentionally abandoned or unfinished library sessions as archival files.

The hashes establish recovery of file **contents**. This format does not, by these tests, preserve directory structure, filenames, permissions, timestamps or extended attributes. Store that metadata separately or put files in an appropriate container before compression if it matters to the archive.

## Limits and what would change the verdict

- This is one supplied source snapshot on one 64-bit Linux platform, one Rust toolchain and zstd 1.5.7. I did not execute older distro zstd versions, alternate codec implementations, Windows, 32-bit targets, `no_std` builds, or future releases. Tool aliases do not broaden that version coverage.
- The matrix is broad but finite. The main data distributions are deterministic synthetic data plus the supplied Dickens text. The largest payload is 4,296,015,889 bytes; the largest frame count tested is 262,161. I did not approach the source's 134,217,728-frame limit, petabyte totals, or allocation limits.
- `EncodeOptions` exposes an arbitrary compression context. I exercised window size, content-size flag, pledged size, workers rejection, raw/trained dictionaries, prefix use, checksum and levels; I did not enumerate every zstd strategy, experimental parameter or incompatible combination. A caller can create output with extra decoder requirements through that context.
- Sidecar contents and `Head` contents were independently checked, but reference seekability required table conversion as described. The large-window archive was recovered with the CLI's raised limit; its full reference-seekable recovery was **not** executed successfully because that helper retained the reference default memory limit.
- I excluded hostile/malformed input testing, fuzzing, damaged storage and corrupted archives, as requested. I did not simulate power loss, durability/fsync failures, disk-full conditions or mid-write crashes. Successfully finished archives on working storage are the central result.
- The source-level lifecycle observations above are not exhaustive tests of every misuse, reset sequence, custom `Write` error, or custom context. Short successful writes and normal flush/finalization sequences were tested. The supplied unit suite provides additional checks but is not an independent guarantee.
- The forced-path defects are real and should be fixed or prevented by the caller. Other file-handling behavior was not systematically audited.

I would revise the positive format verdict if an ordinary, successfully finished, self-contained archive failed a standard-zstd hash comparison, or if reference/table checks found a wrong frame length or offset. I would also re-run the matrix for a change to framing, finalization, prefix handling, table serialization, libzstd version or build features. I would not infer “safe as the sole unverified copy” from a finite successful test suite.

## Re-running the assessment

From this workspace root:

```sh
bash scripts/run_all.sh
```

This builds with `--offline --locked`, copies the retained probe into `zeekstd/lib/examples`, runs the specified upstream tests and every independent stage, and recreates structured logs and CSV summaries. It needs roughly 25 GiB of working disk space for this retained corpus, outputs and build artifacts; the large tests process many times that amount through hashing. It deliberately reproduces errors on named expendable collision fixtures. It does not touch the live checkout or use git.

Run stages individually with `python3 scripts/run_matrix.py cli`, `library`, `large`, or `special`; the other stages have their own scripts. `inputs` must run before the small matrices, `library` before the layout conversions in `followups.py`, and `large` before `extended.py`. The complete wrapper preserves that order. `scripts/summarize.py` regenerates the CSVs, counts and standalone failure appendix.

The initial helper compilation needed API-signature corrections, and the first secondary zeekstd-patch check mistakenly used `--patch-from` instead of `--patch-apply`. The corrected helper and command were run successfully. The superseded patch-check log is retained as `logs/followups-initial.jsonl.saved`; it is excluded from final counts. No unavailable test is presented as passing.

## Appendix: every non-passing command

The generated transcripts below include the producer where applicable, the exact command, complete stderr, output length, observed SHA-256 and expected SHA-256. Commands stream stdout into the harness's hasher. Cases are classified in sections 1–7 above; the stock-zstd concatenation is a control rather than zeekstd output.

### 1. context-workers=2 / encode

Command under test:

```sh
zeekstd/target/release/examples/interop_probe encode data/mixed.bin results/context-workers=2.zst workers=2
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Stderr:

```text
ERROR: zstd: Unsupported parameter
```

### 2. large-window / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/window-input.bin results/large-window.zst window=28 frame=1073741824 checksum=1
```

Command under test:

```sh
zstd -d -c results/large-window.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `17a88af83717f68b8bd97873ffcf022c8aed703416fe9b08e0fa9e3287692bf0`.

Stderr:

```text
results/large-window.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-window.zst : Window size larger than maximum : 268435456 > 134217728 
results/large-window.zst : Use --long=28 or --memory=256MB 
```

### 3. large-window / reference

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/window-input.bin results/large-window.zst window=28 frame=1073741824 checksum=1
```

Command under test:

```sh
zeekstd/target/release/examples/interop_probe oracle results/large-window.zst data/window-input.bin
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `17a88af83717f68b8bd97873ffcf022c8aed703416fe9b08e0fa9e3287692bf0`.

Stderr:

```text
ERROR: zstd: Frame requires too much memory for decoding
```

### 4. patch-u-mmap-prefix-side0-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c results/patch-u-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 5. patch-u-mmap-prefix-side0-c0 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 6. patch-u-mmap-prefix-side0-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c results/patch-u-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 7. patch-u-mmap-prefix-side0-c1 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 8. patch-u-mmap-prefix-side1-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-mmap-prefix-side1-c0.zst --seek-table-file results/patch-u-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-u-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 9. patch-u-mmap-prefix-side1-c0 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-mmap-prefix-side1-c0.zst --seek-table-file results/patch-u-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 10. patch-u-mmap-prefix-side1-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-mmap-prefix-side1-c1.zst --seek-table-file results/patch-u-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-u-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 11. patch-u-mmap-prefix-side1-c1 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-mmap-prefix-side1-c1.zst --seek-table-file results/patch-u-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 12. patch-u-no-mmap-prefix-side0-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-no-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c results/patch-u-no-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 13. patch-u-no-mmap-prefix-side0-c0 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-no-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-no-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 14. patch-u-no-mmap-prefix-side0-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-no-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c results/patch-u-no-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 15. patch-u-no-mmap-prefix-side0-c1 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-no-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-no-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 16. patch-u-no-mmap-prefix-side1-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-no-mmap-prefix-side1-c0.zst --seek-table-file results/patch-u-no-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-u-no-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 17. patch-u-no-mmap-prefix-side1-c0 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 --no-checksum data/patched.bin -o results/patch-u-no-mmap-prefix-side1-c0.zst --seek-table-file results/patch-u-no-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-no-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 18. patch-u-no-mmap-prefix-side1-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-no-mmap-prefix-side1-c1.zst --seek-table-file results/patch-u-no-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-u-no-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 19. patch-u-no-mmap-prefix-side1-c1 / zstd-patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy uncompressed -s 131072 data/patched.bin -o results/patch-u-no-mmap-prefix-side1-c1.zst --seek-table-file results/patch-u-no-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/patch-u-no-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-u-no-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 20. patch-c-mmap-prefix-side0-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy compressed -s 131072 --no-checksum data/patched.bin -o results/patch-c-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c results/patch-c-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 21. patch-c-mmap-prefix-side0-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy compressed -s 131072 data/patched.bin -o results/patch-c-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c results/patch-c-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 22. patch-c-mmap-prefix-side1-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy compressed -s 131072 --no-checksum data/patched.bin -o results/patch-c-mmap-prefix-side1-c0.zst --seek-table-file results/patch-c-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-c-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 23. patch-c-mmap-prefix-side1-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --mmap-prefix --frame-size-policy compressed -s 131072 data/patched.bin -o results/patch-c-mmap-prefix-side1-c1.zst --seek-table-file results/patch-c-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-c-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 24. patch-c-no-mmap-prefix-side0-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy compressed -s 131072 --no-checksum data/patched.bin -o results/patch-c-no-mmap-prefix-side0-c0.zst
```

Command under test:

```sh
zstd -d -c results/patch-c-no-mmap-prefix-side0-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-no-mmap-prefix-side0-c0.zst : Decoding error (36) : Data corruption detected 
```

### 25. patch-c-no-mmap-prefix-side0-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy compressed -s 131072 data/patched.bin -o results/patch-c-no-mmap-prefix-side0-c1.zst
```

Command under test:

```sh
zstd -d -c results/patch-c-no-mmap-prefix-side0-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-no-mmap-prefix-side0-c1.zst : Decoding error (36) : Data corruption detected 
```

### 26. patch-c-no-mmap-prefix-side1-c0 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy compressed -s 131072 --no-checksum data/patched.bin -o results/patch-c-no-mmap-prefix-side1-c0.zst --seek-table-file results/patch-c-no-mmap-prefix-side1-c0.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-c-no-mmap-prefix-side1-c0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-no-mmap-prefix-side1-c0.zst : Decoding error (36) : Data corruption detected 
```

### 27. patch-c-no-mmap-prefix-side1-c1 / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix.bin --no-mmap-prefix --frame-size-policy compressed -s 131072 data/patched.bin -o results/patch-c-no-mmap-prefix-side1-c1.zst --seek-table-file results/patch-c-no-mmap-prefix-side1-c1.zst.table
```

Command under test:

```sh
zstd -d -c results/patch-c-no-mmap-prefix-side1-c1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/patch-c-no-mmap-prefix-side1-c1.zst : Decoding error (36) : Data corruption detected 
```

### 28. dependency-raw-dict / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-raw-dict.zst api=raw dict=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c results/dependency-raw-dict.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-raw-dict.zst : Decoding error (36) : Data corruption detected 
```

### 29. dependency-raw-dict / zstd-patch

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-raw-dict.zst api=raw dict=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/dependency-raw-dict.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-raw-dict.zst : Decoding error (36) : Data corruption detected 
```

### 30. dependency-raw-prefix / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-raw-prefix.zst api=raw prefix=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c results/dependency-raw-prefix.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-raw-prefix.zst : Decoding error (36) : Data corruption detected 
```

### 31. dependency-raw-prefix / zstd-patch

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-raw-prefix.zst api=raw prefix=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/dependency-raw-prefix.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-raw-prefix.zst : Decoding error (36) : Data corruption detected 
```

### 32. dependency-writer-dict / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-writer-dict.zst api=writer dict=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c results/dependency-writer-dict.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-writer-dict.zst : Decoding error (36) : Data corruption detected 
```

### 33. dependency-writer-dict / zstd-patch

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-writer-dict.zst api=writer dict=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/dependency-writer-dict.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-writer-dict.zst : Decoding error (36) : Data corruption detected 
```

### 34. dependency-writer-prefix / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-writer-prefix.zst api=writer prefix=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c results/dependency-writer-prefix.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-writer-prefix.zst : Decoding error (36) : Data corruption detected 
```

### 35. dependency-writer-prefix / zstd-patch

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/patched.bin results/dependency-writer-prefix.zst api=writer prefix=data/prefix.bin frame=131072 checksum=1
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/dependency-writer-prefix.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/dependency-writer-prefix.zst : Decoding error (36) : Data corruption detected 
```

### 36. layout-writer-head-side0-mixed / reference-layout

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/mixed.bin results/layout-writer-head-side0-mixed.zst api=writer format=head separate=0 frame=4096 out=1
```

Command under test:

```sh
zeekstd/target/release/examples/interop_probe oracle results/layout-writer-head-side0-mixed.zst data/mixed.bin
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `9133033c40f1929082731128344adf46ef6fed1969e977951d94bab8c87fd71b`.

Stderr:

```text
ERROR: zstd: Unknown frame descriptor
```

### 37. layout-writer-foot-side1-mixed / reference-layout

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/mixed.bin results/layout-writer-foot-side1-mixed.zst api=writer format=foot separate=1 frame=4096 out=1
```

Command under test:

```sh
zeekstd/target/release/examples/interop_probe oracle results/layout-writer-foot-side1-mixed.zst data/mixed.bin
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `9133033c40f1929082731128344adf46ef6fed1969e977951d94bab8c87fd71b`.

Stderr:

```text
ERROR: zstd: Unknown frame descriptor
```

### 38. control-concat / patch

Command under test:

```sh
zstd -d -c --patch-from=data/prefix.bin results/control-concat.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `a7196e613557fc801c4c9ac44c55d7e1790a6525c08e8a36d3226f18af261d7c`.

Stderr:

```text
results/control-concat.zst : Decoding error (36) : Data corruption detected 
```

### 39. trained-raw / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/dictionary-input.bin results/trained-raw.zst api=raw dict=data/trained.dict frame=4096 checksum=1
```

Command under test:

```sh
zstd -d -c results/trained-raw.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `25f6ec3f7735e1623de4fc5e9778f1537f87e481d3544800eac28ec7222ce6b5`.

Stderr:

```text
results/trained-raw.zst : Decoding error (36) : Dictionary mismatch 
```

### 40. trained-writer / zstd

Producer:

```sh
zeekstd/target/release/examples/interop_probe encode data/dictionary-input.bin results/trained-writer.zst api=writer dict=data/trained.dict frame=4096 checksum=1
```

Command under test:

```sh
zstd -d -c results/trained-writer.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `25f6ec3f7735e1623de4fc5e9778f1537f87e481d3544800eac28ec7222ce6b5`.

Stderr:

```text
results/trained-writer.zst : Decoding error (36) : Dictionary mismatch 
```

### 41. collision-input / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f results/collision-input.bin -o results/collision-input.bin
```

Command under test:

```sh
zstd -d -c results/collision-input.bin
```

Exit: 0; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `fdc7155e74706895b7d3a7353e2cdad8873e03eaffab625815c2261facb46062`.

Stderr:

```text
(empty)
```

### 42. collision-sidecar / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f data/mixed.bin -o results/collision-sidecar.zst --seek-table-file results/collision-sidecar.zst
```

Command under test:

```sh
zstd -d -c results/collision-sidecar.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `9133033c40f1929082731128344adf46ef6fed1969e977951d94bab8c87fd71b`.

Stderr:

```text
zstd: results/collision-sidecar.zst: unsupported format 
```

### 43. large-prefix / zstd

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c results/large-prefix.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/large-prefix.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix.zst : Window size larger than maximum : 268435456 > 134217728 
results/large-prefix.zst : Use --long=28 or --memory=256MB 
```

### 44. large-prefix / dict

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c -D data/prefix-129m.bin results/large-prefix.zst
```

Exit: 34; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
zstd: error 34 : Dictionary file data/prefix-129m.bin is too large (> 33554432 bytes) 
```

### 45. large-prefix / dict-memory

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --memory=512MB -D data/prefix-129m.bin results/large-prefix.zst
```

Exit: 34; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
zstd: error 34 : Dictionary file data/prefix-129m.bin is too large (> 33554432 bytes) 
```

### 46. large-prefix / patch

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/large-prefix.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix.zst : Use --long=28 or --memory=256MB 
```

### 47. large-prefix / frame-0

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-0.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Stderr:

```text
results/large-prefix-frame-0.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-0.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-0.zst : Use --long=28 or --memory=256MB 
```

### 48. large-prefix / frame-1

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-1.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `13584743fd9de9fec9ae39d23cdd756efe9e41b7e65b2af6e924e8f4785bfba1`.

Stderr:

```text
results/large-prefix-frame-1.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-1.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-1.zst : Use --long=28 or --memory=256MB 
```

### 49. large-prefix / frame-2

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-2.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `ed13de8bcb2cdac4fd04bee5dbfb41194aa65b8774e149a8a3657db164d1fb14`.

Stderr:

```text
results/large-prefix-frame-2.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-2.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-2.zst : Use --long=28 or --memory=256MB 
```

### 50. large-prefix / frame-3

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-3.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `ef6c20a0a16b0ab4a7e130d4044b3febca4dc271ca3b50e57bba6ad1c028bb33`.

Stderr:

```text
results/large-prefix-frame-3.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-3.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-3.zst : Use --long=28 or --memory=256MB 
```

### 51. large-prefix / frame-4

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-4.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `52efb982e678ffe1406497980764890619f7771458f5ad940a6eaeeaad33f228`.

Stderr:

```text
results/large-prefix-frame-4.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-4.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-4.zst : Use --long=28 or --memory=256MB 
```

### 52. large-prefix / frame-5

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-5.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `f2dac86ecd6917e8730f3ad05d7e6bac565f43de61de8504422a86ab40e75f5a`.

Stderr:

```text
results/large-prefix-frame-5.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-5.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-5.zst : Use --long=28 or --memory=256MB 
```

### 53. large-prefix / frame-6

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-6.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `d8feb6a201236a46d36164dba70bc05ae5c298ff2ca997693701317bf63bd865`.

Stderr:

```text
results/large-prefix-frame-6.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-6.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-6.zst : Use --long=28 or --memory=256MB 
```

### 54. large-prefix / frame-7

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-7.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `1833579b7655d771d45d3cce1d9b2c976311a25386d0ef2cf7531841aafc1b0e`.

Stderr:

```text
results/large-prefix-frame-7.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-7.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-7.zst : Use --long=28 or --memory=256MB 
```

### 55. large-prefix / frame-8

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-8.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `b165c56a955b06546a3c4443a132c941bebb2030ad95865fad732f18f91c1284`.

Stderr:

```text
results/large-prefix-frame-8.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-8.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-8.zst : Use --long=28 or --memory=256MB 
```

### 56. large-prefix / frame-9

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-9.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `e81a72a3e479cc8ee8700216be283f757027129ada94adc77e6c7d6fb8facbe6`.

Stderr:

```text
results/large-prefix-frame-9.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-9.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-9.zst : Use --long=28 or --memory=256MB 
```

### 57. large-prefix / frame-10

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-10.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `e94d20675031480c4ec953c598f40dc3a70944e5ab73bb639c72d58ea0cf9340`.

Stderr:

```text
results/large-prefix-frame-10.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-10.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-10.zst : Use --long=28 or --memory=256MB 
```

### 58. large-prefix / frame-11

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-11.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `7d12227be9ec82c3395b25d9b0f1bf5664440b077933ce25f0d860094138ce6f`.

Stderr:

```text
results/large-prefix-frame-11.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-11.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-11.zst : Use --long=28 or --memory=256MB 
```

### 59. large-prefix / frame-12

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-12.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `b028134e2c7088b6408fc1921c1aab330abe4f5e71722d614ebcc8ca525becb4`.

Stderr:

```text
results/large-prefix-frame-12.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-12.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-12.zst : Use --long=28 or --memory=256MB 
```

### 60. large-prefix / frame-13

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-13.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `e7e659b3bffa479eee8ec0ee301c59e0e61045dde1d95fbefd90f13e770d9595`.

Stderr:

```text
results/large-prefix-frame-13.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-13.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-13.zst : Use --long=28 or --memory=256MB 
```

### 61. large-prefix / frame-14

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-14.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `f91d641721bf146dddc9670ab6141bdd8afa0ffba0cee8ea599300c4925f6669`.

Stderr:

```text
results/large-prefix-frame-14.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-14.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-14.zst : Use --long=28 or --memory=256MB 
```

### 62. large-prefix / frame-15

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-15.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `51d8547c5bcceb77127166af3748028b9e4f18f782a6eb2cb9eecd526c3792ae`.

Stderr:

```text
results/large-prefix-frame-15.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-15.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-15.zst : Use --long=28 or --memory=256MB 
```

### 63. large-prefix / frame-16

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --patch-from=data/prefix-129m.bin results/large-prefix-frame-16.zst
```

Exit: 1; stdout bytes: 0; SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Expected SHA-256: `b50fd6b1f61f6636f2d4a1c8104b6fbe927cfc918b158c5cb1174fa1c78cb19f`.

Stderr:

```text
results/large-prefix-frame-16.zst : Decoding error (36) : Frame requires too much memory for decoding 
results/large-prefix-frame-16.zst : Window size larger than maximum : 268435456 > 135266304 
results/large-prefix-frame-16.zst : Use --long=28 or --memory=256MB 
```

### 64. large-prefix / patch-memory

Producer:

```sh
zeekstd/target/release/zeekstd compress -q -f --patch-from data/prefix-129m.bin -s 131072 data/patched.bin -o results/large-prefix.zst
```

Command under test:

```sh
zstd -d -c --memory=256MB --patch-from=data/prefix-129m.bin results/large-prefix.zst
```

Exit: 1; stdout bytes: 131072; SHA-256: `415f21afc096ff45dfb0a02fa6cb96d323af5e3494d1890f11a13050360b4e3f`.

Expected SHA-256: `476e2c53639eb2adb0c25562559edfc2a4772795163f5eeff89cef260ba7482a`.

Stderr:

```text
results/large-prefix.zst : Decoding error (36) : Data corruption detected 
```

