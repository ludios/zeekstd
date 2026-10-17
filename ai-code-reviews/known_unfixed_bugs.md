# Known unfixed bugs

Findings from the Codex review of 6038504 (`astra.md` in this directory, numbering kept) that are
still open in the library at 977fc5c, checked on 2026-09-16. CLI-only findings, 4, 5, 6, 16, 17 and
20 plus the CLI half of 12, are left out on purpose. Every entry has a test that asserts the wanted
behaviour. Tests that fail today are marked `#[ignore]`; that of 14 passes here for the reason
given in its entry. Entry 21 came later, from the property tests.

- `lib/tests/known_bugs.rs`: `cargo test -p zeekstd --test known_bugs -- --ignored`

When a fix lands, drop the `#[ignore]` from its test and delete the entry here.

Fixed since the review and therefore not listed: 1, 2 and 8 (92c2102), 9 (7aaf00e), 13 (06f093f),
3, 10, 15, 19 and the library half of 12 (2026-09-16), 7 (11b509a and 2026-09-16), the decoder
arithmetic of 14 (92c2102), and 18 (2026-10-17: the decoder keeps returning the error of a failed
decompression or a disagreeing frame until it is reset). The two repros Codex gave for 2 and 8 are
kept as regression tests in `lib/tests/known_bugs.rs`.

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

### 21. A frame declared empty at either end of a read is never checked

Found by the property tests on 2026-10-17. The decoder reads a frame whose seek table entry says it
is empty only between other frames of a read: `frame_index_decomp` skips such frames at the read's
start, and the decoder stops before one at its limit, so that a read bounded by `upper_frame` over
a source holding only the requested frames does not reach past them. A size entry zeroed by
corruption therefore drops its frame from a whole read without an error when it is the first or
the last frame, and the default frame size of 2 MiB is one flipped bit from zero. An empty archive,
one empty frame, is never read at all. Frames declared empty between others are read and verified,
and a wrong entry of any other value is caught at the frame's end.

Decision (2026-10-17): kept, as a positional range cannot tell "through frame k" from "through the
archive's end" when empty frames share the position. The fix would bound reads by frame index, so
that a whole read also checks the frames at its ends, while `set_offset` at a frame boundary would
verify the empty frames there too, which byte-range fetches would have to include.

Test: `zeroed_size_entry_at_either_end_is_noticed`.

## Nits still present

- In `lib/src/lib.rs`, `cycle_custom_compressed_frame_size_std` calls `test_cycle` instead of
  `test_cycle_std`, and `cycle_stand_alone_seek_table_foot_custom_compressed_frame_size` uses
  `Format::Head`.
- The README's compatibility claim does not mention ignored legacy checksums or that `Head` is a
  zeekstd extension, and `Encoder::finish_format(Head)` appends a table after the data where
  `from_seekable_format(Head)` will not look for it.
