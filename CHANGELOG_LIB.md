# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- zstd-safe's default features, among them zstd's dictionary builder and its decoders of pre-1.0
  frame formats. `Decoder` used to decompress a frame in the formats of zstd 0.4 to 0.7; it now
  rejects it, unless another crate in the build turns the zstd-safe or zstd `legacy` feature on

### Fixed

- `RawEncoder::compress`, and so `Encoder::compress` after an `end_frame` that failed to write,
  finishes a pending frame ending before it consumes more input. That input used to go into a zstd
  frame of its own that the seek table counted as part of the previous one, which made the archive
  undecodable
- `Decoder` keeps returning the error of a failed decompression or of a frame that disagrees with
  its seek table until `Decoder::reset` or a `Decoder::set_offset` backwards or into another frame.
  Retrying after a disagreeing frame used to return bytes from elsewhere in the frame as if they
  were the requested ones
- `Decoder` rejects a frame that holds more than its seek table entry says once it reaches the
  entry's end. It used to decompress on into what the table declares to be the following frames, so
  a read that ended there returned the frame's surplus as their content without an error: one
  flipped bit in the size of the next-to-last frame cut a whole-archive read short, checksums or not
- `Decoder::decompress` returns the bytes from complete frames that it placed in the buffer before
  a read from the source failed or found it ended, and that error on the call after. It used to
  return an unexpected-EOF error right away and leave the bytes unreported. If the read was for the
  trailer of the frame the last bytes came from, the call fails and takes them back instead, so
  that a retry produces them again; it used to return them, and a caller reading a known length
  never saw the error
- `Decoder` rejects a frame whose compressed size differs from its seek table entry once it reaches
  the frame's end, as it does for the decompressed size. A changed compressed-size entry used to
  pass a whole read unnoticed, and a seek that it sent onto another frame of the same decompressed
  size returned that frame's content as the requested one

## [7.0.0]

The first version of the ludios fork, which has its own version line from here on. It contains
upstream 0.6.2 and the upstream fixes after it up to 9c6533b.

### Fixed

- `Serializer::write_into` returns 0 for an empty buffer instead of panicking
- `Encoder`'s `Write::flush` now also flushes the data zstd holds for the current frame, so
  everything written before the call reaches the writer
- A seek table with zero frames, which the reference implementation writes for empty input, is
  decoded to empty output instead of panicking. `SeekTable::frame_index_comp` and
  `SeekTable::frame_index_decomp` return 0 for an empty table
- `SeekTable::from_seekable_format` no longer fails or panics when the source returns fewer than
  17 bytes per read
- `SeekTable::from_reader` parses only the bytes the reader returned. Short reads no longer turn
  unread buffer space into entries, a truncated seek table is rejected, and interrupted reads are
  retried
- Parsing a seek table no longer reserves memory for the number of frames its header claims
  before any entry was read. Entries are allocated as they arrive, and an allocation failure is
  reported as a zstd memory allocation error instead of aborting the process
- `RawEncoder::with_opts` now returns an error if `FrameSizePolicy` has a frame size of 0
- `Decoder` verifies the checksum of a frame that ends at the offset limit even when the frame
  trailer arrives in a later read than the frame's content
- `Decoder` returns an error instead of looping forever when the seekable source ends inside a
  frame
- `Decoder` returns an error when a frame's decompressed size differs from its seek table entry
  instead of silently truncating or misaligning the output
- `Encoder` no longer corrupts the archive when a write to its writer fails partway and the caller
  retries: bytes the writer accepted are not resent, input consumed before the failure is reported
  as consumed instead of failing the call, and the error surfaces on the next call
- `Decoder::decompress` reports the bytes it already placed in the output buffer when a later read
  from the source fails, instead of dropping them; the error surfaces on the next call
- The `Seekable` impl for `Read + Seek` sources retries reads that fail with
  `ErrorKind::Interrupted`

### Added

- `RawEncoder::flush` flushes the compression context into an output buffer without ending the
  frame. A frame ending that `RawEncoder::end_frame` left pending is finished instead
- `VERSION`, this crate's version, so that a program can record which zeekstd wrote a
  compressed file

The `Error` struct has changed:

- The method `Error::is_invalid_frame_size_policy()` was added
- The method `Error::is_unexpected_eof()` was added
- The method `Error::is_frame_size_mismatch()` was added
- `From<Error> for std::io::Error` was implemented. It hands back the original IO error, so that
  callers can act on its kind, and reports an unexpected end of the source as
  `ErrorKind::UnexpectedEof`. The `Write` impl of `Encoder` and the `Read` impl of `Decoder` use it
  instead of wrapping every error as `ErrorKind::Other`

### Changed

- zstd-safe was updated from 7 to 8. `EncodeOptions` and `DecodeOptions` now take the zstd-safe 8
  `CCtx` and `DCtx`, so callers that pass their own contexts must use zstd-safe 8 as well.
  A context that zstd reported an error for now returns it from every later call until it is
  reset, by `Decoder::reset` or a `Decoder::set_offset` backwards or into another frame, or by
  `RawEncoder::reset_frame`. zstd-safe and zstd-sys are now licensed BSD-3-Clause instead of MIT
  or Apache-2.0

## [0.6.2]

### Fixed

- Fix a seek table decoding bug where it gets populated with wrong data when the read buffer gets
  only partially filled.

## [0.6.1]

### Fixed

- Decoding no longer panics due to wrong slice indexing when the output buffer is partially filled

## [0.6.0]

### Fixed

- The `read()` function of the implementation of the `Seekable` trait for `BytesWrapper` no longer
  panics due to wrong internal range boundaries
- Fixed a problem where frames were not logged in the seek table when the frame epilogue exactly
  filled the output buffer in use

### Added

- New enum `OffsetFrom` with the variants `Start(u64)` and `End(i64)`. Works similar to
  `std::io::SeekFrom`
- New structs `CompressionProgress` and `EpilogueProgress`, which are used to indicate the progress
  of a compression/epilogue writing step
- Added the `std` feature, which is enabled by default. Disabling the `std` feature limits
  higher-level features of zeekstd, but also allows it to run in `no_std` programs

### Changed

The `Seekable` trait has changed in an incompatible way:

- The method `Seekable::seek_table_footer()` was removed
- The method `Seekable::seek_to_seek_table_start()` was removed
- The method `Seekable::set_offset()` now returns `Result<u64>` where the `u64` value is the new
  offset position form the start of the seekable object
- The type of `offset` in `Seekable::set_offset()` changed from `u64` to `OffsetFrom`
- The method `Seekable::seek_table_integrity()` was added

The `RawEncoder` struct has changed in an incompatible way:

- The methods `RawEncoder::compress()` and `RawEncoder::compress_with_prefix` now return
  `Result<CompressionProgress>` instead of `Result<(u64, u64)>`
- The method `RawEncoder::end_frame()` now returns `Result<EpilogueProgress>` instead of
  `Result<(u64, u64)>`

The `EncodeOptions` struct has changed in an incompatible way:

- The method `EncodeOptions::into_raw()` was renamed to `EncodeOptions::into_raw_encoder()`

The `SeekTable` struct has changed in an incompatible way:

- The method `SeekTable::from_seekable_format()` was added
- The method `SeekTable::from_bytes()` was removed. Use `SeekTable::from_seekable()` or
  `SeekTable::from_seekable_format()` together with the `BytesWrapper` struct instead

The `Error` struct changed in an incompatible way:

- The function `Error::other()` was removed
- The method `Error::is_other()` was removed

## [0.5.1]

### Added

- Use property testing

### Fixed

- Parsing a seek table with 1022 frames does not falsely yield a "corruption detected" error anymore

## [0.5.0]

### Added

- Implement decompression from an arbitrary byte offset up to an offset limit
  - `offset` and `offset_limit` can be set on `DecodeOptions` and `Decoder`
  - All values are decompressed offsets
  - If `offset` is not the beginning of a frame, the decoder will decompress everything from the
    last frame start up to `offset` to an internal buffer
  - The decoder will stop decompression when reaching `offset_limit`. The checksum of the last frame
    will not be verified, except `offset_limit` is exactly the end of a frame
  - Only bytes in the requested range are returned from `read` and `decompress` calls
- Implement `std::io::Seek` for `Decoder`

### Changed

- `Decoder::set_lower_frame` and `Decoder::set_upper_frame` return a `Result` now
