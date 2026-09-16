# Known unfixed bugs

Findings from the Codex review of 6038504 (`astra.md` in this directory, numbering kept) that are
still open in the library at 977fc5c, checked on 2026-09-16. CLI-only findings, 4, 5, 6, 16, 17 and
20 plus the CLI half of 12, are left out on purpose. Every entry has a test that asserts the wanted
behaviour. Tests that fail today are marked `#[ignore]`; those of 14 and 18 pass here for the
reasons given in their entries.

- `lib/tests/known_bugs.rs`: `cargo test -p zeekstd --test known_bugs -- --ignored`

When a fix lands, drop the `#[ignore]` from its test and delete the entry here.

Fixed since the review and therefore not listed: 1, 2 and 8 (92c2102), 9 (7aaf00e), 13 (06f093f),
3, 10, 15 and the library half of 12 (2026-09-16), 7 (11b509a and 2026-09-16) and the decoder arithmetic of 14 (92c2102). The two repros
Codex gave for 2 and 8 are kept as regression tests in `lib/tests/known_bugs.rs`.

## Medium

### 11. Legacy seek table checksums are ignored

`parse_entries` skips the checksum of 12-byte legacy entries. `seekable_format.md` declares this as
policy, but the reference decoder rejects a legacy archive with a corrupted table checksum while
zeekstd decodes it. This is a decision, not an oversight: either verify the checksum, the low 32
bits of XXH64 over each frame's decompressed content, or qualify the README's compatibility claim.

Test: `corrupted_legacy_table_checksum_is_rejected`, which also checks the reference decoder.

### 14. Skippable header size overflows on 32-bit targets

`verify_skippable_header` adds 8 to a size that comes from an untrusted `u32`. On 32-bit targets
a value near `u32::MAX` overflows `usize`, which panics in debug builds. No 32-bit toolchain is
installed here, so this rests on code reading. `oversized_skippable_header_is_rejected` passes on
64-bit and would catch it on a 32-bit CI job.

Fix: `checked_add`, or compare in `u64`.

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
