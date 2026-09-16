# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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

The `Error` struct has changed:

- The method `Error::is_invalid_frame_size_policy()` was added
- The method `Error::is_unexpected_eof()` was added
- The method `Error::is_frame_size_mismatch()` was added
- `From<Error> for std::io::Error` was implemented. It hands back the original IO error, so that
  callers can act on its kind, and reports an unexpected end of the source as
  `ErrorKind::UnexpectedEof`. The `Write` impl of `Encoder` and the `Read` impl of `Decoder` use it
  instead of wrapping every error as `ErrorKind::Other`

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
