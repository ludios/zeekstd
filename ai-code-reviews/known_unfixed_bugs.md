# Known unfixed bugs

Findings from the Codex review of 6038504 (`astra.md` in this directory, numbering kept) that are
still open in the library at 977fc5c, checked on 2026-09-16. CLI-only findings, 4, 5, 6, 16, 17 and
20 plus the CLI half of 12, are left out on purpose. Every entry has a test that asserts the wanted
behaviour. Tests that fail today are marked `#[ignore]`; those of 14 and 18 pass here for the
reasons given in their entries.

- `lib/tests/known_bugs.rs`: `cargo test -p zeekstd --test known_bugs -- --ignored`

When a fix lands, drop the `#[ignore]` from its test and delete the entry here.

Fixed since the review and therefore not listed: 1, 2 and 8 (92c2102), 9 (7aaf00e), 13 (06f093f),
the 16x overallocation of 7 (11b509a) and the decoder arithmetic of 14 (92c2102). The two repros
Codex gave for 2 and 8 are kept as regression tests in `lib/tests/known_bugs.rs`.

## High

### 3. `SeekTable::from_reader` parses unread buffer bytes as entries

`from_reader` in `lib/src/seek_table.rs` hands the whole buffer to `parse_entries` regardless of
how many bytes the last `read` returned. A reader that returns one byte per call turns the entry
`(123, 456)` into `(123, 0)`, and a Head table truncated to 18 of 25 bytes is accepted.

Tests: `from_reader_survives_one_byte_reads`, `from_reader_rejects_truncated_table`.

Fix: track how much of the buffer is filled and parse only that, as `from_seekable_format` does.

### 7. Frame counts from the header are trusted before the source is checked

`Parser::from_bytes` reserves `num_frames + 1` entries before anything shows that the source can
hold that many. The 16x factor is gone, but a 17-byte source claiming ten million frames still
requests 160 MB, the maximum frame count requests 2 GiB, and the reservation is infallible, so an
allocation failure aborts the process.

Test: `forged_frame_count_does_not_allocate_before_validation`.

Fix: check the declared table size against the source length before reserving, and reserve with
`try_reserve` so that a refusal becomes an error.

## Medium

### 10. `from_seekable_format` breaks on short reads

The header loop reads into the start of the buffer on every iteration, so each short read
overwrites the previous one. Reads of 1 or 4 bytes then fail with `Unknown frame descriptor`. For
`Head` tables the code slices `buf[17..read]` after only 8 bytes are guaranteed, so reads of 8, 9
or 16 bytes panic.

Tests: `short_reads_parse_head_table`, `short_reads_parse_foot_table`.

Fix: read into `buf[read..]` and require the full format prefix, 8 bytes for `Foot` and 17 for
`Head`, before slicing.

### 11. Legacy seek table checksums are ignored

`parse_entries` skips the checksum of 12-byte legacy entries. `seekable_format.md` declares this as
policy, but the reference decoder rejects a legacy archive with a corrupted table checksum while
zeekstd decodes it. This is a decision, not an oversight: either verify the checksum, the low 32
bits of XXH64 over each frame's decompressed content, or qualify the README's compatibility claim.

Test: `corrupted_legacy_table_checksum_is_rejected`, which also checks the reference decoder.

### 12. Zero-frame archives panic

The reference implementation writes a 17-byte archive for empty input and decodes it to nothing.
`frame_index_at` computes `num_frames() - 1` for the empty table, so decoding and lookups panic
in debug builds and return a frame index error in release builds.

Tests: `zero_frame_archive_decodes_to_nothing`, `zero_frame_table_lookups_do_not_panic`.

Fix: return 0 from `frame_index_at` for an empty table and make the decoder finish without reading
when nothing is to be produced.

### 14. Skippable header size overflows on 32-bit targets

`verify_skippable_header` adds 8 to a size that comes from an untrusted `u32`. On 32-bit targets
a value near `u32::MAX` overflows `usize`, which panics in debug builds. No 32-bit toolchain is
installed here, so this rests on code reading. `oversized_skippable_header_is_rejected` passes on
64-bit and would catch it on a 32-bit CI job.

Fix: `checked_add`, or compare in `u64`.

### 15. `Encoder::flush` does not flush data buffered inside zstd

The `Write` impl flushes zeekstd's output buffer and the writer but never asks zstd to flush, so
input held in the compression context stays there. Writing `hello` and flushing delivers zero bytes
to the writer.

Test: `flush_pushes_accepted_input_to_the_writer`.

Fix: drain `ZSTD_e_flush` through `compress_stream2` until it reports 0, add the output to the
frame's compressed size, then flush the buffer and the writer.

### 18. Decoder reuse after a zstd error has no guard

The decoder neither resets nor poisons its context after `decompress_stream` fails, while
`zstd.h` says the state may be undefined after an error. Observed behaviour is benign: every later
call keeps returning an error. `decoder_keeps_failing_after_a_zstd_error` passes and stays as a
guard, so this entry is a contract violation without a demonstrated effect.

Fix: remember the failure and return an error from `decompress` until `reset` is called.

## Low

### 19. Serializer panics on an empty output buffer

The descriptor byte in `write_integrity` is written as `buf[buf_pos]` without checking the buffer
length, unlike the fields around it. Serializing an empty table into a 12-byte buffer and then
into an empty one panics. The `Read` impl of `Serializer` reaches the same code.

Tests: `serializer_accepts_empty_buffer_foot`, `serializer_accepts_empty_buffer_head`.

Fix: return 0 for an empty buffer and bounds-check the descriptor write like the other fields.

## Nits still present

- In `lib/src/lib.rs`, `cycle_custom_compressed_frame_size_std` calls `test_cycle` instead of
  `test_cycle_std`, and `cycle_stand_alone_seek_table_foot_custom_compressed_frame_size` uses
  `Format::Head`.
- The README's compatibility claim does not mention ignored legacy checksums or that `Head` is a
  zeekstd extension, and `Encoder::finish_format(Head)` appends a table after the data where
  `from_seekable_format(Head)` will not look for it.
