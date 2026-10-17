// Model-output: Claude Opus 5.5
//! This crate provides a Rust implementation of the Zstandard Seekable Format, as outlined in
//! the [specification].
//!
//! The seekable format splits compressed data into a series of independent "frames", each
//! compressed individually, so that decompression of a section in the middle of a compressed file
//! only requires zstd to decompress at most a frame's worth of extra data, instead of the entire
//! file.
//!
//! The frames are appended, so that the decompression of the entire payload still regenerates the
//! original content, using any compliant zstd decoder.
//!
//! Zeekstd uses bindings from the [zstd_safe] crate.
//!
//! # Getting Started
//!
//! - The [`RawEncoder`] and [`Encoder`] compress data.
//! - The [`Decoder`] performs seekable decompression.
//! - The [`SeekTable`] holds information of the frames of a seekable comressed file, it gets
//!   created and updated automatically during compression.
//!
//! [specification]: https://github.com/rorosen/zeekstd/blob/main/seekable_format.md
//! [zstd_safe]: https://docs.rs/zstd-safe/latest/zstd_safe/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod decode;
mod encode;
mod error;
pub mod seek_table;
mod seekable;

pub use decode::{DecodeOptions, Decoder};
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use encode::Encoder;
pub use encode::{
    CompressionProgress, EncodeOptions, EpilogueProgress, FrameSizePolicy, RawEncoder,
};
pub use error::{Error, Result};
pub use seek_table::SeekTable;
pub use seekable::{BytesWrapper, OffsetFrom, Seekable};
// Re-export as it's part of the API.
pub use zstd_safe::CompressionLevel;

/// The version of this crate. It goes up with every change to what the crate writes or to what
/// it accepts when reading, so that a program can record which zeekstd wrote a compressed file.
/// What gets written also depends on the linked libzstd, `zstd_safe::version_string()`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The magic number of the seek table integrity field.
pub const SEEKABLE_MAGIC_NUMBER: u32 = 0x8F92_EAB1;
/// The maximum number of frames in a seekable compressed file.
pub const SEEKABLE_MAX_FRAMES: u32 = 0x0800_0000;
/// The size of the seek table integrity field.
pub const SEEK_TABLE_INTEGRITY_SIZE: usize = 9;
/// The maximum size of the uncompressed data of a frame.
pub const SEEKABLE_MAX_FRAME_SIZE: usize = 0x4000_0000;
/// The size of the skippable frame header.
///
/// Skippable magic number (4 bytes) + frame size field (4 bytes)
pub(crate) const SKIPPABLE_HEADER_SIZE: usize = 8;

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
#[cfg(feature = "std")]
pub struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::seek_table::Format;

    use super::*;

    pub const INPUT: &str = include_str!("./lib.rs");

    fn test_cycle(frame_size_policy: Option<FrameSizePolicy>) {
        let mut seekable = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        let mut in_progress = 0;
        while in_progress < INPUT.len() {
            let progress = encoder
                .compress(&INPUT.as_bytes()[in_progress..], &mut buf)
                .unwrap();
            seekable.extend(&buf[..progress.out_progress()]);
            in_progress += progress.in_progress();
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.out_progress()]);
            if prog.data_left() == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            seekable.extend(&buf[..n]);
        }

        let wrapper = BytesWrapper::new(&seekable);
        let mut decoder = Decoder::new(wrapper).unwrap();
        let mut output = Vec::with_capacity(INPUT.len());

        loop {
            let n = decoder.decompress(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(&INPUT.as_bytes(), &output);
    }

    fn test_cycle_stand_alone_seek_table(
        frame_size_policy: Option<FrameSizePolicy>,
        format: Format,
    ) {
        let mut seekable = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        let mut in_progress = 0;
        while in_progress < INPUT.len() {
            let progress = encoder
                .compress(&INPUT.as_bytes()[in_progress..], &mut buf)
                .unwrap();
            seekable.extend(&buf[..progress.out_progress()]);
            in_progress += progress.in_progress();
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.out_progress()]);
            if prog.data_left() == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_format_serializer(format);
        let mut seek_table = Vec::with_capacity(ser.encoded_len());
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            seek_table.extend(&buf[..n]);
        }

        assert_eq!(seek_table.len(), ser.encoded_len());

        let mut wrapper = BytesWrapper::new(&seek_table);
        let seek_table = SeekTable::from_seekable_format(&mut wrapper, format).unwrap();

        let wrapper = BytesWrapper::new(&seekable);
        let mut decoder = DecodeOptions::new(wrapper)
            .seek_table(seek_table)
            .into_decoder()
            .unwrap();
        let mut output = Vec::with_capacity(INPUT.len());

        loop {
            let n = decoder.decompress(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(&INPUT.as_bytes(), &output);
    }

    fn test_patch_cycle(frame_size_policy: Option<FrameSizePolicy>) {
        let old = INPUT;
        let new = alloc::format!("{INPUT}\nThe End");
        let mut patch = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        // Create a binary patch
        let mut in_progress = 0;
        while in_progress < new.len() {
            let progress = encoder
                .compress_with_prefix(
                    &new.as_bytes()[in_progress..],
                    &mut buf,
                    Some(old.as_bytes()),
                )
                .unwrap();
            patch.extend(&buf[..progress.out_progress()]);
            in_progress += progress.in_progress();
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            patch.extend(&buf[..prog.out_progress()]);
            if prog.data_left() == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            patch.extend(&buf[..n]);
        }

        let wrapper = BytesWrapper::new(&patch);
        let mut decoder = Decoder::new(wrapper).unwrap();
        let mut output: Vec<u8> = Vec::with_capacity(new.len());

        loop {
            let n = decoder
                .decompress_with_prefix(&mut buf, Some(old.as_bytes()))
                .unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(new.as_bytes(), &output);
    }

    #[cfg(feature = "std")]
    fn test_cycle_std(frame_size_policy: Option<FrameSizePolicy>) {
        use std::io::{Cursor, copy};

        let mut input = Cursor::new(INPUT);
        let mut seekable = Cursor::new(vec![]);
        let mut opts = EncodeOptions::new();
        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }

        let mut encoder = opts.into_encoder(&mut seekable).unwrap();
        copy(&mut input, &mut encoder).unwrap();

        let n = encoder.finish().unwrap();
        assert_eq!(n, seekable.position());

        let mut decoder = Decoder::new(seekable).unwrap();
        let mut output = Cursor::new(vec![]);
        copy(&mut decoder, &mut output).unwrap();

        assert_eq!(INPUT.as_bytes(), output.get_ref());
    }

    #[test]
    fn cycle() {
        test_cycle(None);
    }

    #[test]
    fn patch_cycle() {
        test_patch_cycle(None);
    }

    #[test]
    fn cycle_stand_alone_seek_table_head() {
        test_cycle_stand_alone_seek_table(None, Format::Head);
    }

    #[test]
    fn cycle_stand_alone_seek_table_foot() {
        test_cycle_stand_alone_seek_table(None, Format::Foot);
    }

    #[test]
    #[cfg(feature = "std")]
    fn cycle_std() {
        test_cycle_std(None);
    }

    // What this version writes with this libzstd for two checksummed frames. When it fails
    // because the bytes changed, bump `VERSION`, unless only the libzstd did; then update both.
    #[test]
    #[cfg(feature = "std")]
    fn version_pins_output() {
        use std::io::Write;

        #[rustfmt::skip]
        const EXPECTED: [u8; 89] = [
            0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x68, 0x7d, 0x00, 0x00, 0x48, 0x7a, 0x65,
            0x65, 0x6b, 0x73, 0x74, 0x64, 0x20, 0x7a, 0x01, 0x00, 0x78, 0xba, 0x47,
            0xb1, 0xc8, 0x76, 0x69, 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x68, 0x7d, 0x00,
            0x00, 0x48, 0x73, 0x74, 0x64, 0x20, 0x7a, 0x65, 0x65, 0x6b, 0x73, 0x01,
            0x00, 0x70, 0xba, 0x47, 0x2f, 0xa3, 0xe3, 0x50, 0x5e, 0x2a, 0x4d, 0x18,
            0x19, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
            0x1c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0xb1, 0xea, 0x92, 0x8f,
        ];

        let mut written = vec![];
        let mut encoder = EncodeOptions::new()
            .checksum_flag(true)
            .compression_level(19)
            .frame_size_policy(FrameSizePolicy::Uncompressed(100))
            .into_encoder(&mut written)
            .unwrap();
        encoder.write_all(&b"zeekstd ".repeat(24)).unwrap();
        encoder.finish().unwrap();

        assert_eq!(
            (VERSION, zstd_safe::version_string(), written.as_slice()),
            ("7.0.0", "1.5.7", EXPECTED.as_slice())
        );
    }

    proptest! {
        #[test]
        fn cycle_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        fn cycle_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_cycle(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }

        #[test]
        #[cfg(feature = "std")]
        fn cycle_custom_compressed_frame_size_std(frame_size in 1..1024u32) {
            test_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        #[cfg(feature = "std")]
        fn cycle_custom_decompressed_frame_size_std(frame_size in 1..1024u32) {
            test_cycle_std(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }

        #[test]
        fn cycle_stand_alone_seek_table_foot_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_cycle_stand_alone_seek_table(Some(FrameSizePolicy::Compressed(frame_size)), Format::Head);
        }

        #[test]
        fn cycle_stand_alone_seek_table_foot_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_cycle_stand_alone_seek_table(Some(FrameSizePolicy::Uncompressed(frame_size)), Format::Foot);
        }

        #[test]
        fn patch_cycle_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_patch_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        fn patch_cycle_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_patch_cycle(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }
    }
}
