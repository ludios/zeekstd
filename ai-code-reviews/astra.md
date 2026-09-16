# Summary by Claude Fable 5.1

Review run on 2026-09-11 with Codex CLI (gpt-6-astra, reasoning effort xhigh) against commit 6038504. Codex's full report follows below, verbatim.

Codex's verdict: **not yet safe as the sole storage path for production archives.** It found 20 issues, 9 of them High, and confirmed nearly all with repros against the locked zstd 1.5.7 and the reference seekable implementation. I spot-checked the top ones against the source and they hold up.

**The ones that matter most for storing lots of files:**

- **Checksums can be silently skipped on a full read** ([decode.rs:221-258](../lib/src/decode.rs#L221-L258)). The loop stops when the declared output size is reached, not when zstd reports frame end. If the frame trailer lands past an input-buffer boundary, a flipped payload byte decompresses with exit 0. Repro'd in debug and release CLI.
- **Seek table sizes are trusted blindly** ([seek_table.rs:189](../lib/src/seek_table.rs#L189), [decode.rs:206](../lib/src/decode.rs#L206)). A table that declares 12 bytes instead of 13 silently truncates the restore. Wrong per-frame sizes make seeks return bytes from the wrong record.
- **Decoder spins forever on EOF** ([decode.rs:221](../lib/src/decode.rs#L221)). A read returning zero bytes leaves the outer loop with no progress check. A truncated archive, or a table declaring one extra byte, hangs a worker until killed.
- **`from_reader` parses unread buffer bytes as entries** ([seek_table.rs:476](../lib/src/seek_table.rs#L476)). It passes the whole buffer to the parser regardless of how many bytes the reader returned. Short reads on a valid detached table yield wrong sizes. Truncated sidecars are accepted.
- **`with_num_frames` allocates 16x too much** ([seek_table.rs:109](../lib/src/seek_table.rs#L109)). It multiplies by `size_of::<Entry>()` before passing to `Vec::with_capacity`, which already takes an element count. A 9-byte forged footer claiming max frames requests 32 GiB and aborts the process.
- **CLI can destroy the source** ([command.rs:45-230](../cli/src/command.rs#L45-L230)). Output equal to input, or a hard link of it, gets truncated before reading. `zeekstd c f -o f -f` exits 0 leaving an empty archive. Outputs and sidecars are also truncated before the input is validated, so a failed restore wipes the previous good copy.
- **CLI decompress never flushes stdout** ([decompress.rs:107](../cli/src/decompress.rs#L107)). Redirecting to `/dev/full` exits 0 with nothing written.
- **Error recovery corrupts** ([encode.rs:648-779](../lib/src/encode.rs#L648-L779)). A partial write followed by an error keeps the whole buffer, so retrying resends the prefix. The decoder advances its offset before surfacing a read error, so a retry loses bytes.

The Medium tier has a few you'd hit in practice: header reads capped under 17 bytes panic on a slice, valid zero-frame archives from the reference tool panic, `Encoder::flush` doesn't flush zstd's internal buffer, legacy table checksums are ignored where the reference decoder rejects, and prefixes under 512 bytes fail with an out-of-bound window log.

**Two housekeeping notes.** The `assert!` at [decode.rs:803](../lib/src/decode.rs#L803) is inside the test module and never ships. Also, while Codex ran, `lib/src/encode.rs` and `lib/src/error.rs` were edited in the worktree to add a `FrameSizeTooSmall` error that rejects `Uncompressed(0)`. Codex did not make those edits, and its log confirms no patch calls; they were since committed as 4a9d548 on branch frame-size-0. Codex notes that change does not also reject `Compressed(0)`, which has the same runaway-empty-frames behavior.

Codex's repro harness, logs, and a snapshot of the reviewed commit were kept in the session scratchpad next to the report.

---

# zeekstd production-storage code review

Reviewed commit: `6038504d75d9802f1b8c5b71556b6d59cce97254` (`zeekstd` 0.6.2, CLI 0.4.5). Line numbers below refer to that commit.

**Assessment: I would not yet use this version as the sole storage/recovery path for production archives.** Confirmed problems include successful decompression of corrupted or truncated content, lost output errors, destructive CLI output handling, and malformed-input resource exhaustion.

I read all requested library, CLI, integration-test, fuzz, specification, README, and changelog files, plus benchmarks and build/CI configuration. Verification used the locked Zstd 1.5.7 dependency and its bundled reference seekable implementation on x86_64 Linux.

**Workspace note:** The worktree was initially clean. I did not modify or delete tracked files. During the review, concurrent edits appeared in `lib/src/encode.rs` and `lib/src/error.rs`; I preserved them. Consequently, the final worktree is not clean of those external source changes. A snapshot of the reviewed commit and all repros are retained in the requested scratch directory.

## Critical

No Critical finding confirmed. This does not establish memory safety for every adversarial input or FFI recovery path.

## High

### 1. Full decompression can skip the final frame checksum and return corrupted bytes successfully

**Severity:** High. **Confidence:** High; confirmed with the library and debug/release CLI.

**Locations:** `lib/src/decode.rs:221`, `lib/src/decode.rs:242`, `lib/src/decode.rs:248`, `lib/src/decode.rs:258`; misleading guarantee at `lib/src/decode.rs:425`.

The loop stops when the declared decompressed offset limit is reached, without requiring Zstd to report frame completion. If the payload ends at an input-buffer boundary, the checksum can remain unread. This happens even during complete-file decompression, although the documentation only exempts ranges ending inside a frame from checksum verification.

**Repro:** Compress 131,066 deterministic incompressible bytes with the CLI's default checksums. The frame is 131,079 bytes; its checksum starts at offset 131,075, exactly the decoder input-buffer size. Flip a raw payload byte. Both debug and release CLI return exit status 0 and all 131,066 bytes, including the changed byte. A one-byte-read library repro similarly returns `Iello, storage!` after corrupting `Hello, storage!`, despite its checksum.

**Production impact:** Ordinary full-file restore can silently accept bit rot. Enabling checksums does not currently guarantee that complete-frame reads verify them.

**Suggested fix:** Track Zstd frame completion independently of output progress. At a requested frame/file boundary, consume and validate the complete frame trailer before reporting EOF. Keep intentional mid-frame range behavior explicit.

**Verification:** `checksum` harness case; `cli_repros.py`; release confirmation in `release-results.log`.

### 2. Seek table sizes are trusted without checking actual frame boundaries, allowing silent truncation and wrong seeks

**Severity:** High. **Confidence:** High; confirmed.

**Locations:** `lib/src/seek_table.rs:189`, `lib/src/seek_table.rs:218`, `lib/src/decode.rs:165`, `lib/src/decode.rs:206`, `lib/src/decode.rs:248`.

Parser verification checks the entry count, but decoding does not compare each frame's actual compressed/decompressed lengths with its entry. The table's total decompressed size becomes an unconditional stopping point. The summed compressed sizes are also not checked against the data/seek-table boundary.

**Repros:**

- Change a valid archive's declared output length from 13 to 12. The CLI successfully restores `hello storag` instead of `hello storage`, with exit status 0.
- Create two frames containing `abc` and `XYZ`, then change their declared decompressed sizes from `(3, 3)` to `(2, 4)`. A full read succeeds with six bytes, but seeking to decompressed offset 2 returns `X`, where the real concatenated data contains `c`.

**Production impact:** A damaged table or incorrectly paired sidecar can silently shorten a restore or return the wrong record. Successful full decompression currently does not validate the index used by later random reads.

**Suggested fix:** Validate actual frame lengths against entries during full verification; check aggregate compressed boundaries for attached tables. Offer an explicit archive/index verification operation and require verified metadata where trustworthy random access matters.

**Verification:** Library `checksum` case and CLI short-size repro. No claim that arbitrary forged indexes can be authenticated without scanning or independent integrity metadata.

### 3. `SeekTable::from_reader` parses unread buffer bytes as real entries

**Severity:** High. **Confidence:** High; confirmed on valid short reads and truncated input.

**Locations:** `lib/src/seek_table.rs:461`, `lib/src/seek_table.rs:476`, `lib/src/seek_table.rs:481`, `lib/src/seek_table.rs:487`; CLI caller `cli/src/decompress.rs:25`.

The reader's byte count is used only to test for zero. `parse_entries(&buf)` then processes the entire allocated buffer, including zero-filled or stale bytes beyond the valid input. Remaining-byte accounting measures these fabricated entries as consumed.

**Repro:** Serialize a one-frame Head table with sizes `(123, 456)`. A reader returning one byte per call produces a successful table with sizes `(123, 0)`. Truncating the same 25-byte table to 18 bytes also succeeds with `(123, 0)`.

**Production impact:** Detached seek tables can become silently incorrect during loading, even when the original stream is valid. Truncated sidecars can be accepted and make restores appear empty or misdirect seeks. The 0.6.2 short-read fix does not cover this function.

**Suggested fix:** Track the valid buffer length, parse only complete entries within it, preserve partial entries, and require every declared entry byte. Retry interrupted reads.

**Verification:** `readers` harness case.

### 4. CLI input/output aliases can destroy the source, sometimes with exit status 0

**Severity:** High. **Confidence:** High; confirmed for identical paths and hard links.

**Locations:** `cli/src/command.rs:45`, `cli/src/command.rs:78`, `cli/src/command.rs:167`, `cli/src/command.rs:181`, `cli/src/command.rs:205`, `cli/src/command.rs:230`.

Output creation truncates files without checking whether they identify an input, prefix, sidecar, or another output. Overwrite approval or `--force` permits the truncation.

**Repro:** `zeekstd c original -o original -fq` opens the source, truncates it through the output handle, reads EOF, and exits successfully after replacing the original with an empty archive. A hard-linked output behaves identically. Decompressing an archive onto itself truncates the archive before parsing it and then fails.

**Production impact:** An output-path mistake or alias in a batch can destroy the only source copy. The successful empty-archive case is especially dangerous to automation.

**Suggested fix:** Reject file-identity collisions among all inputs and outputs before any truncation, including hard links and symlinks. Use temporary outputs and commit completed results safely. Do not make source-identity protection conditional on the overwrite flag.

**Verification:** CLI repros; all destructive tests operated exclusively on scratch files.

### 5. CLI destroys existing outputs and sidecars before the operation is validated or completes

**Severity:** High. **Confidence:** High; confirmed.

**Locations:** `cli/src/command.rs:61`, `cli/src/command.rs:78`, `cli/src/command.rs:181`, `cli/src/command.rs:205`, `cli/src/command.rs:230`, `cli/src/command.rs:322`, `cli/src/command.rs:342`.

Decompression creates its output before opening/parsing the input. Compression creates a sidecar before resolving the output overwrite decision and creates outputs before loading the prefix. Processing writes directly into final destination files, so errors leave empty or partial replacements.

**Repros:** Decompressing a nonexistent input with `-f -o previous-backup` fails but leaves the previous backup empty. During compression with two existing output files, answering `y` to replacing the sidecar and `n` to replacing the data file destroys the old sidecar even though the operation is canceled.

**Production impact:** A failed backup refresh or restore can destroy the previous good result. Losing a detached table can remove random-access capability for its otherwise intact data file.

**Suggested fix:** Validate inputs/options and resolve all overwrite decisions first. Write to exclusive temporary files and publish only successful results; define how paired data/table updates are committed. Use atomic no-clobber creation where overwrite is disallowed: the current existence-check/`File::create` sequence also races with other creators.

**Verification:** Both destruction scenarios reproduced. The concurrent-creation race is established by code reading, not a race stress test.

### 6. CLI decompression loses final stdout errors and can report success after writing nothing

**Severity:** High. **Confidence:** High; confirmed.

**Locations:** `cli/src/decompress.rs:107`, `cli/src/decompress.rs:116`, `cli/src/command.rs:156`, `cli/src/command.rs:344`.

Decompression writes its last bytes but never flushes the supplied writer. Rust stdout can buffer those bytes; errors during later shutdown flushing do not propagate through this command's result.

**Repro:** Restore a small archive containing `hello storage` with stdout redirected to `/dev/full`. Decompression exits 0 with no diagnostic even though the destination accepts no data. Compression to the same destination correctly fails because its finish path flushes.

**Production impact:** Restore pipelines can report success despite incomplete or completely missing output.

**Suggested fix:** Explicitly flush the writer and propagate the error before reporting successful decompression.

**Verification:** CLI `/dev/full` repro.

### 7. Untrusted frame counts trigger oversized allocation before file validation

**Severity:** High. **Confidence:** High; allocation size and process abort confirmed.

**Locations:** `lib/src/seek_table.rs:106`, `lib/src/seek_table.rs:109`, `lib/src/seek_table.rs:155`, `lib/src/seek_table.rs:168`, `lib/src/seek_table.rs:381`.

`Entries::with_num_frames` multiplies the requested element count by `size_of::<Entry>()` and passes the result to `Vec::with_capacity`, which already expects elements. For 16-byte entries this requests about **256 bytes per frame instead of 16**. Allocation occurs from the footer before checking whether the file could contain the claimed table. Allocation failure aborts rather than returning an error.

**Repro:** A nine-byte footer claiming 10,000 frames requests 2,560,000 bytes before returning an offset error. Claiming the accepted maximum, 134,217,728 frames, requests **34,359,738,368 bytes (32 GiB)**. With a 256 MiB address-space limit, this aborts the process.

**Production impact:** Tiny malformed archives can kill a service or CLI process; large legitimate tables unnecessarily pressure allocator/address-space limits. This is the requested allocation size, not a claim that Linux immediately makes the entire allocation resident.

**Suggested fix:** Reserve `num_frames + 1` entries using fallible allocation, validate available table size before allocation where possible, and impose configurable frame-count/memory limits for streaming readers.

**Verification:** Allocator-instrumented harness and memory-limited subprocess.

### 8. Decoder spins forever at EOF when the declared output cannot be produced

**Severity:** High. **Confidence:** High; confirmed in the library and CLI.

**Locations:** `lib/src/decode.rs:221`, `lib/src/decode.rs:223`, `lib/src/decode.rs:242`.

An EOF read sets the input length to zero. The inner decompression loop then does nothing, but the outer loop continues because the requested output offset has not been reached. There is no EOF error or progress check.

**Repros:** Increase a valid archive's declared decompressed length by one byte. The CLI hangs until killed. A truncated data stream supplied with its detached seek table behaves the same way. A guarded source verified nine consecutive EOF reads before deliberately terminating the repro with an injected error.

**Production impact:** A damaged archive can monopolize a worker/core indefinitely and stop unattended restore or verification jobs.

**Suggested fix:** Track input, output, and frame-completion progress. Permit necessary Zstd flushing with empty input, then return an unexpected-EOF/corruption error if the declared output cannot be completed. Never retry permanent EOF indefinitely.

**Verification:** `eof` harness case and one-second CLI timeout. Tested valid detached streams with tiny buffers completed successfully; I am not claiming every short read causes a hang.

### 9. Recovering from I/O errors can duplicate compressed bytes or lose decompressed bytes

**Severity:** High. **Confidence:** High; both directions confirmed.

**Locations:** `lib/src/encode.rs:648`, `lib/src/encode.rs:660`, `lib/src/encode.rs:779`, `lib/src/decode.rs:223`, `lib/src/decode.rs:258`, `lib/src/decode.rs:512`.

Output flushing uses `write_all`, but retains the entire buffer if that call partially writes and then fails. Retrying flush resends the already-written prefix. Input decoding can likewise advance its offset and fill part of the caller's buffer, then return an error from a later source read without reporting the bytes already produced.

**Repros:**

- A writer accepts five bytes, then returns `WouldBlock`, then recovers. Retrying `Encoder::flush` and finishing succeeds, but produces 61 bytes while reporting 56; reference decompression reports corruption.
- While decoding `hello storage`, inject `Interrupted` after the first output byte. The failed read has already advanced the decoder to offset 1. Retrying returns only `ello storage`.

The adapters also convert underlying I/O errors to `ErrorKind::Other`; normal interruption-retry behavior therefore does not work. Rust's `Write` contract requires consumed input to be reported, which the write path can also violate when flushing fails after compression has consumed input. [Rust I/O contract](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write).

**Production impact:** Recovery from transient storage/transport errors can corrupt archives or silently omit restored bytes. Ordinary short writes that eventually succeed are handled; partial success followed by an error is the problematic case.

**Suggested fix:** Preserve the unwritten suffix and exact counters across errors. Return successful partial read/write progress before surfacing a pending error; preserve underlying I/O kinds and retry `Interrupted` internally where appropriate.

**Verification:** `flush` and `interrupted` harness cases. The CLI's compression input loop also fails immediately on `Interrupted` at `cli/src/compress.rs:64` by code reading.

## Medium

### 10. Seekable table parsing rejects valid short reads and can panic

**Severity:** Medium. **Confidence:** High; confirmed.

**Locations:** `lib/src/seek_table.rs:391`, `lib/src/seek_table.rs:392`, `lib/src/seek_table.rs:401`, `lib/src/seek_table.rs:412`.

The initial header loop repeatedly reads into the beginning of the buffer while accumulating the byte count, overwriting earlier bytes. Separately, Head format assumes at least 17 valid bytes even though that loop only ensures eight.

**Repro:** A valid one-frame Head table with reads capped at 8, 9, or 16 bytes panics when slicing `buf[17..read]`. One- or four-byte reads reject valid Head and Foot tables as an unknown frame descriptor.

**Production impact:** Valid custom readers, remote-file adapters, and unusual I/O fragmentation can crash or fail archive loading.

**Suggested fix:** Accumulate into the unused buffer suffix and require the entire format-specific prefix before slicing. Track only initialized, actually read bytes.

**Verification:** `readers` harness case; panics caught outside the library.

### 11. Legacy seek-table checksums are silently discarded

**Severity:** Medium, integrity/interoperability limitation. **Confidence:** High; confirmed against the reference implementation.

**Locations:** `lib/src/seek_table.rs:154`, `lib/src/seek_table.rs:189`, `lib/src/seek_table.rs:202`; intentional policy at `seekable_format.md:54` and `seekable_format.md:155`.

The parser recognizes 12-byte legacy entries but skips their checksum fields entirely. Legacy archives whose integrity protection resides in the table therefore lose that protection when decoded by zeekstd.

**Repro:** Generate an archive with the reference seekable compressor and table checksums enabled. Change its table checksum. Zeekstd successfully decodes it; the reference decoder reports `Data corruption detected`.

**Production impact:** Importing reference-format archives can silently weaken corruption detection. This is intentional under the repository's modified specification, rather than an accidental violation of that local document. It is nevertheless a material limitation of the README's compatibility claim. The upstream format defines the field as the low 32 bits of XXH64. [Upstream seekable specification](https://raw.githubusercontent.com/facebook/zstd/v1.5.7/contrib/seekable_format/zstd_seekable_compression_format.md).

**Suggested fix:** Retain and verify legacy checksums when complete frames are decoded, or explicitly expose unsupported verification and provide a strict rejection/verification option.

**Verification:** `legacy` harness case and reference decoder comparison.

### 12. A valid zero-frame archive panics or fails instead of decoding to empty output

**Severity:** Medium. **Confidence:** High; confirmed in debug, release, and reference controls.

**Locations:** `lib/src/seek_table.rs:916`, `lib/src/seek_table.rs:918`, `lib/src/decode.rs:206`, `lib/src/decode.rs:404`, `cli/src/command.rs:257`, `cli/src/command.rs:412`, `cli/src/command.rs:440`.

The parser accepts an empty table, but frame lookup subtracts one from zero. Decoding performs that lookup before noticing there is no output to produce. CLI listing also assumes a last frame exists.

**Repro:** A 17-byte Foot table containing zero frames is accepted and decoded to zero bytes by the reference implementation. Debug zeekstd panics on subtraction; release library decoding returns a frame-index error. Release CLI summary listing still panics at its `expect`.

**Production impact:** Legitimate empty archives can fail imports or crash batch listing. Zeekstd's own encoder emits an empty Zstd frame, so its empty-input roundtrip happens to work and does not exercise this case.

**Suggested fix:** Handle zero frames explicitly in lookup, decoder initialization/empty reads, setters, and listing. Use the stored total sizes for summaries instead of querying a nonexistent last frame.

**Verification:** `empty` harness case and debug/release CLI repros.

### 13. Zero frame-size policies emit empty frames without consuming input

**Severity:** Medium. **Confidence:** High; confirmed at the reviewed commit.

**Locations:** `lib/src/encode.rs:280`, `lib/src/encode.rs:317`, `lib/src/encode.rs:537`, `lib/src/encode.rs:648`, `cli/src/args.rs:222`.

Both `Compressed(0)` and `Uncompressed(0)` initially satisfy the frame-complete predicate. Every compression step ends another empty frame without consuming any source data. The higher-level encoder keeps looping because output progress is nonzero.

**Repro:** Repeated raw calls with input `a` return zero consumed bytes and another nine-byte frame each time. The CLI accepts `--frame-size 0` and continues producing empty frames until interrupted, allocation fails, or the frame-count limit is reached.

**Production impact:** A bad configuration can consume substantial CPU, memory, and output space while processing none of the intended data.

**Suggested fix:** Reject zero for both policies during construction, or consistently define zero as a documented default.

**Verification:** `zero-policy` harness case and bounded CLI run. Concurrent worktree edits observed during review add rejection for `Uncompressed(0)`; the observed edit does not reject `Compressed(0)`.

### 14. Large output lengths can overflow decoder buffer arithmetic on 32-bit targets

**Severity:** Medium. **Confidence:** High by code reading; no 32-bit execution available.

**Locations:** `lib/src/decode.rs:234`, `lib/src/decode.rs:237`, `lib/src/decode.rs:238`; related malformed-header arithmetic at `lib/src/seek_table.rs:178`.

The decoder clamps a large remaining output length to `usize::MAX`, then adds `output_progress`. On a 32-bit target, an archive with more than 4 GiB still remaining and a partially filled caller buffer makes this addition overflow. Debug builds panic; release arithmetic can wrap the slice endpoint below its start and also panic.

**Scenario:** A read produces one byte, then needs another compressed-input chunk while more than `u32::MAX` output bytes remain. The next iteration computes `1 + usize::MAX` before applying `min(buf.len())`.

The parser also adds eight to an untrusted `u32` frame size after converting to `usize`; sufficiently large header values overflow on 32-bit debug builds.

**Production impact:** Large archives that work on 64-bit systems can fail on 32-bit consumers; malformed headers expose another arithmetic panic.

**Suggested fix:** Compute available caller-buffer space first, clamp remaining output to that space, and only then add the bounded amount. Use checked header-size arithmetic.

**Verification:** Code and arithmetic analysis only. The successful 64-bit large-file tests do not cover this target-specific issue.

### 15. `Encoder::flush` does not flush data buffered inside Zstd

**Severity:** Medium. **Confidence:** High; confirmed.

**Locations:** `lib/src/encode.rs:340`, `lib/src/encode.rs:779`, `lib/src/encode.rs:796`.

The implementation flushes only zeekstd's output buffer and the downstream writer. It never invokes Zstd's streaming flush directive, so accepted input can remain entirely inside the compression context.

**Repro:** Write `hello` through an encoder and successfully call `flush`. Zero compressed bytes have reached the underlying writer.

**Production impact:** Callers using the standard flush contract for visibility, streaming handoff, or checkpointing cannot rely on the result. This is separate from whether a file has been synced to durable storage.

**Suggested fix:** Drain `ZSTD_e_flush` completely, accounting for compressed frame bytes, then drain zeekstd's buffer and flush the wrapped writer. [Rust flush contract](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.flush).

**Verification:** `flush` harness case. `finish()` does finalize and flush normally; this finding concerns `flush()` itself.

### 16. Automatically mapped mutable prefix files can crash the CLI with SIGBUS

**Severity:** Medium. **Confidence:** High for the reproduced crash.

**Locations:** `cli/src/args.rs:9`, `cli/src/args.rs:175`, `cli/src/command.rs:378`, `cli/src/command.rs:382`.

The CLI automatically memory-maps prefix files of at least 1 MiB, without ensuring that the mapped file stays unchanged. Another process can truncate it while compression/decompression still references the mapping. File-backed mapping requires precautions against concurrent modification. [memmap2 safety requirements](https://docs.rs/memmap2/0.9.10/memmap2/struct.MmapOptions.html#safety).

**Repro:** Start release compression with a 2 MiB prefix and stdin input. After observing the mapping, truncate the scratch prefix and supply input. The CLI exits on signal 7, SIGBUS, without a Rust error.

**Production impact:** Concurrent maintenance or rewriting of prefix files can crash patch jobs and leave partial outputs. This requires concurrent prefix modification; ordinary immutable-prefix use was not shown unsafe.

**Suggested fix:** Default to an owned snapshot, or make mapping an explicit option with an immutable-file requirement and enforce that requirement where feasible. `--no-mmap-prefix` avoids this mapping-specific failure.

**Verification:** Controlled subprocess repro in `mmap-results.log`; no broader memory-corruption exploit claimed.

### 17. Small prefix files fail because their size is used as an invalid Zstd window setting

**Severity:** Medium. **Confidence:** High; compression failure confirmed, corresponding decoder path inspected.

**Locations:** `cli/src/compress.rs:31`, `cli/src/compress.rs:33`, `cli/src/decompress.rs:54`, `cli/src/decompress.rs:56`.

For nonempty prefixes, the CLI sets the window log to `len.ilog2() + 1`. Prefixes of 1–511 bytes produce values below Zstd's accepted minimum. Such a prefix is valid content; its length should not itself require an invalid compression parameter.

**Repro:** Prefix sizes 1, 100, and 511 fail with `Parameter is out of bound`; 512, 1,024, and 2,048 succeed. Failure occurs after output creation, compounding finding 5.

**Production impact:** Patch workflows processing many heterogeneous files unexpectedly fail on small originals.

**Suggested fix:** Respect Zstd's parameter bounds, choose a valid window large enough for the prefix, and validate before opening outputs. Do not unnecessarily constrain decoder windows based solely on prefix length.

**Verification:** CLI prefix-size matrix; decoder-side parameter selection verified by code reading.

### 18. Decoder reuse after a Zstd error lacks the required recovery guard

**Severity:** Medium. **Confidence:** High for the API-contract violation; memory-safety consequences not demonstrated.

**Locations:** `lib/src/decode.rs:206`, `lib/src/decode.rs:243`, `lib/src/decode.rs:352`.

The decoder propagates a Zstd error without poisoning or resetting its context. A subsequent read can invoke `decompress_stream` again without a reset. Zstd requires resetting a context before reuse when an error has left its state undefined. [Zstd streaming API contract](https://raw.githubusercontent.com/facebook/zstd/v1.5.7/lib/zstd.h).

**Scenario and impact:** An application catches an error from a corrupt frame and retries the same decoder. The safe public API permits reuse that the underlying C API does not guarantee is valid. This matters when services attempt to recover from bad archives within a long-lived process.

**Suggested fix:** Poison the decoder after a Zstd failure and require explicit reset, or implement a well-defined automatic reset/restart policy.

**Verification:** Code reading and the bundled C API contract only. No memory-safety exploit was demonstrated, and I am not claiming every error leaves the context in an undefined state.

## Low

### 19. Serializer can panic on a legitimate empty output buffer

**Severity:** Low. **Confidence:** High; confirmed for both formats.

**Locations:** `lib/src/seek_table.rs:67`, `lib/src/seek_table.rs:72`, `lib/src/seek_table.rs:967`, `lib/src/seek_table.rs:1055`.

The descriptor-byte write does not check whether the output buffer is empty. For an empty table, serialize the first 12 bytes, then call `write_into(&mut [])`: it indexes byte zero of an empty slice and panics. The same path is exposed by `Serializer`'s `Read` implementation.

**Production impact:** Generic buffer-management code can crash at a valid zero-capacity boundary; the CLI's normal serializer buffers do not trigger this repro.

**Suggested fix:** Return zero immediately for an empty destination and bounds-check the descriptor write consistently with other fields.

**Verification:** `serializer` harness case.

### 20. CLI frame-count range arithmetic overflows before validation

**Severity:** Low. **Confidence:** High; debug/release behavior confirmed.

**Location:** `cli/src/command.rs:254`.

`from_frame + additional_frames` uses unchecked `u32` addition. `list --from-frame 2 --num-frames 4294967295` panics in debug builds; release builds wrap the computed end to zero and report the misleading error that the start exceeds the end.

**Production impact:** Invalid automated requests produce a panic or an incorrect diagnostic rather than a clean bounds error. No release-mode silent data corruption was demonstrated here.

**Suggested fix:** Use checked addition and validate the requested range against the table before printing.

**Verification:** CLI repro on both profiles.

## Nits / style

- `--no-progress` is parsed at `cli/src/args.rs:148` but is never consulted when building progress bars.
- The comment at `cli/src/args.rs:8` says 128 MiB; the constant is 1 MiB.
- `--to-frame` help advertises `last`, while `LastFrame::from_str` accepts `end` (`cli/src/args.rs:79`, `cli/src/args.rs:257`, `cli/src/args.rs:315`).
- One test named for the standard encoder calls the raw cycle helper (`lib/src/lib.rs:328`), and one Foot-named test uses Head (`lib/src/lib.rs:339`). Correcting these would make coverage claims clearer.
- Clippy completes successfully with warnings about collapsible conditions, test counters, and deprecated manifest lint spellings.

## Production readiness and panic / FFI assessment

The requested assertion at **`lib/src/decode.rs:803` is test-only**: its enclosing module starts under `#[cfg(test)]` at line 581. It cannot execute in a production build, regardless of archive contents. Most nearby `assert!`/`unwrap` calls are likewise tests or doctests. The real runtime panics are documented above: short-read slicing, zero-frame arithmetic/listing, allocation failure, serializer empty buffers, and target-specific arithmetic.

The runtime `expect("Resetting session never fails")` calls at `lib/src/decode.rs:252`, `lib/src/decode.rs:356`, and `lib/src/encode.rs:506` agree with the bundled Zstd implementation: a valid context's `SessionOnly` reset returns zero. I found no corrupted-input route making those particular resets fail. Entry conversions and last-entry expectations are protected by private table construction/count invariants on the reviewed 32/64-bit types. Context `create()` allocation panics are documented, and fallible option constructors exist.

No explicit `unsafe` block exists in the library; its compression operations go through zstd-safe, and prefix lifetime bounds retain the referenced bytes appropriately. The CLI's explicit unsafe mapping has the confirmed concurrent-modification failure in finding 16.

For production storage, fix the High findings before relying on restore success or checksums. Library checksums are **off by default** (`lib/src/encode.rs:146`), whereas CLI checksums are enabled by default (`cli/src/compress.rs:41`). Explicitly enable library checksums after fixing verification, maintain independently verified content digests and recoverable copies, and define atomic publication/durability requirements. Neither a frame checksum nor a successful `flush` alone is an archival durability guarantee.

There are useful positive results: cumulative offsets use `u64`; the frame-count cap keeps their sums below overflow; encoded table sizes fit `u32` under the imposed cap; uncompressed frame policies are capped at 1 GiB. A 4 GiB + 17-byte encode/decode, 1 GiB frames, 300,000 entries containing maximum `u32` sizes, and real file seeks past compressed offset 4 GiB all passed on x86_64. These controls do not negate the malformed-input and 32-bit issues.

## Test and fuzz coverage gaps

Checks run successfully against the starting source:

- `cargo test --workspace --locked --offline`: 33 library tests, 11 CLI unit tests, 20 CLI integration tests, and 41 doctests passed.
- `cargo test -p zeekstd --no-default-features --locked --offline`: 27 tests and 30 doctests passed.
- `cargo build -p zeekstd_cli --release --locked --offline`: passed.
- `cargo clippy --workspace --all-targets --locked --offline`: passed with warnings.

The two fuzz targets first compress arbitrary payloads with a fixed 100-byte frame size, then decode their own valid output. They do not directly fuzz malformed archives/tables, checksum corruption, or I/O behavior. The seek target creates fresh decoders and excludes EOF offsets; it does not exercise sequences of reads and seeks on one decoder. No sustained fuzz campaign or 32-bit execution was performed in this review.

Priority additions are direct malformed-table/frame fuzzing; every truncation point; controlled 1–17-byte reads; interrupted/erroring readers and partial/erroring writers; frame trailers split across reads; zero/empty/skippable frames; repeated seeks and changing limits; both table formats and legacy checksums; configurable allocation limits; 32-bit builds; and CLI source aliases, output-error/flush handling, and paired-file failures. Use reference decoding and independent content hashes as oracles, not only zeekstd roundtrips.

The maximum 134,217,728-frame archive was not constructed. Its allocation behavior and relevant size arithmetic were checked separately; the practical many-entry test used 300,000 entries.

## Specification and reference interoperability

- Normal Foot archives successfully roundtrip in both directions between zeekstd and the bundled reference seekable implementation. Basic wire compatibility is present.
- Local specification requirements for frame sizes and offsets (`seekable_format.md:143`, `seekable_format.md:148`) motivate validating entries against actual frames. Existing parser checks establish table structure, not index/data agreement.
- Reserved descriptor bits are rejected and the two unused low bits are ignored, as required by the local and upstream specifications.
- Head is a zeekstd extension, explicitly incompatible with prior decoders in `seekable_format.md:70`. Detached Head tables are not standard reference seekable archives. `Encoder::finish_format(Head)` also appends a Head table after data, while the provided Head table reader expects the table at offset zero; this combination needs clearer restriction/documentation. Use the separate-table workflow for Head.
- Legacy checksum skipping follows the local modified specification but differs from reference integrity verification, as confirmed in finding 11. The README's unqualified “fully compatible” language should distinguish wire decoding from checksum behavior and Head-format support.
- Zero-frame tables are accepted by the reference implementation but mishandled by zeekstd, as confirmed in finding 12. Valid skippable frames and offsets beyond 4 GiB worked in the sparse-file control.

Reproduction sources and logs are retained alongside this report: `review_harness/`, `review_snapshot/`, `cli_repros.py`, `harness-results.log`, `cli-results.log`, `release-results.log`, `interrupted-results.log`, `interop-results.log`, `large-results.log`, and `mmap-results.log`. `concurrent-worktree-changes.diff` records the external source edits observed during review.
