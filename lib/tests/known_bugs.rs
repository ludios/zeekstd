// Model-output: Claude Fable 5.1
//! Reproductions of the library findings in `ai-code-reviews/known_unfixed_bugs.md`.
//!
//! Each test asserts the behaviour the finding asks for. A test that is `#[ignore]`d still fails
//! at HEAD: run `cargo test -p zeekstd --test known_bugs -- --ignored` to see which findings are
//! still open, and drop the attribute once a fix makes its test pass. The tests without the
//! attribute guard findings that are only reachable on other targets, or that were fixed.
#![cfg(feature = "std")]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use zeekstd::{
    BytesWrapper, DecodeOptions, Decoder, EncodeOptions, Encoder, FrameSizePolicy, SeekTable,
    seek_table::Format,
};
use zstd_safe::{InBuffer, OutBuffer};

const SKIPPABLE_MAGIC: u32 = 0x184D_2A5E;
const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;
/// Skippable frame header: magic plus frame size.
const SKIPPABLE_HEADER_SIZE: usize = 8;
/// Seek table integrity field: frame count, descriptor, magic.
const INTEGRITY_SIZE: usize = 9;

/// Records, per thread, the largest single allocation requested since the last `reset`.
struct PeakAlloc;

thread_local! {
    static PEAK_REQUEST: Cell<usize> = const { Cell::new(0) };
}

impl PeakAlloc {
    fn reset() {
        PEAK_REQUEST.with(|p| p.set(0));
    }

    /// The largest allocation requested on this thread since the last `reset`, in bytes.
    fn peak() -> usize {
        PEAK_REQUEST.with(Cell::get)
    }
}

// Safety: forwards every call to `System`; the bookkeeping never allocates.
unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PEAK_REQUEST.with(|p| p.set(p.get().max(layout.size())));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: PeakAlloc = PeakAlloc;

/// A `Read + Seek` source that hands out at most `chunk` bytes per read.
struct Chunked<'a> {
    inner: Cursor<&'a [u8]>,
    chunk: usize,
}

impl<'a> Chunked<'a> {
    fn new(bytes: &'a [u8], chunk: usize) -> Self {
        Self {
            inner: Cursor::new(bytes),
            chunk,
        }
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(self.chunk);
        self.inner.read(&mut buf[..len])
    }
}

impl Seek for Chunked<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Serializes a seek table whose only frame has the sizes `(c_size, d_size)` in `format`.
fn one_frame_table(c_size: u32, d_size: u32, format: Format) -> Vec<u8> {
    let mut st = SeekTable::new();
    st.log_frame(c_size, d_size).unwrap();
    let mut ser = st.into_format_serializer(format);
    let mut buf = vec![0; ser.encoded_len()];
    assert_eq!(ser.write_into(&mut buf), buf.len());
    buf
}

/// A `Foot` seek table frame declaring `num_frames` frames but carrying no entries. With
/// `num_frames == 0` this is the valid empty archive the reference implementation produces.
fn foot_table_without_entries(num_frames: u32) -> Vec<u8> {
    let mut bytes = SKIPPABLE_MAGIC.to_le_bytes().to_vec();
    bytes.extend((INTEGRITY_SIZE as u32).to_le_bytes());
    bytes.extend(num_frames.to_le_bytes());
    bytes.push(0);
    bytes.extend(SEEKABLE_MAGIC.to_le_bytes());
    assert_eq!(bytes.len(), SKIPPABLE_HEADER_SIZE + INTEGRITY_SIZE);
    bytes
}

/// Compresses `input` into one seekable archive per element, checksums on, and returns the
/// archive bytes.
fn seekable(frames: &[&[u8]]) -> Vec<u8> {
    let mut encoder = EncodeOptions::new()
        .checksum_flag(true)
        .into_encoder(Vec::new())
        .unwrap();
    for frame in frames {
        encoder.write_all(frame).unwrap();
        encoder.end_frame().unwrap();
    }
    encoder.finish().unwrap();
    // `finish` consumed the encoder together with its writer, so compress again into a writer we
    // keep; the output is deterministic
    let mut out = Vec::new();
    let mut encoder = EncodeOptions::new()
        .checksum_flag(true)
        .into_encoder(&mut out)
        .unwrap();
    for frame in frames {
        encoder.write_all(frame).unwrap();
        encoder.end_frame().unwrap();
    }
    encoder.finish().unwrap();
    out
}

/// Decompresses everything from `decoder` in `buf_len`-byte steps.
fn read_all<S: zeekstd::Seekable>(
    decoder: &mut Decoder<'_, S>,
    buf_len: usize,
) -> zeekstd::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0; buf_len];
    loop {
        let n = decoder.decompress(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend(&buf[..n]);
    }
}

/// Builds a legacy (spec 0.1.0) archive with the reference compressor: one frame of `content`,
/// plus a seek table whose entries carry a checksum. Returns the archive and the byte offset of
/// the checksum field of its only entry.
fn legacy_archive_with_table_checksum(content: &[u8]) -> (Vec<u8>, usize) {
    let mut cstream = zstd_safe::seekable::SeekableCStream::create();
    // A frame size of 0 selects the reference's maximum, 1 GiB
    cstream.init(3, true, 0).unwrap();
    let mut out = vec![0; 1024 + content.len() * 2];
    let mut out_buf = OutBuffer::around(&mut out);
    let mut in_buf = InBuffer::around(content);
    while in_buf.pos() < content.len() {
        cstream.compress_stream(&mut out_buf, &mut in_buf).unwrap();
    }
    while cstream.end_stream(&mut out_buf).unwrap() != 0 {}
    let len = out_buf.pos();
    out.truncate(len);
    // Entry layout: c_size, d_size, checksum; the table is one entry plus the integrity field
    let checksum_at = len - INTEGRITY_SIZE - 4;
    (out, checksum_at)
}

/// Finding 3: `from_reader` must not turn unread buffer bytes into entries.
#[test]
#[ignore = "known unfixed: from_reader parses the whole buffer regardless of how much was read"]
fn from_reader_survives_one_byte_reads() {
    let table = one_frame_table(123, 456, Format::Head);
    let st = SeekTable::from_reader(Chunked::new(&table, 1)).unwrap();
    assert_eq!(st.frame_size_comp(0).unwrap(), 123);
    assert_eq!(st.frame_size_decomp(0).unwrap(), 456);
}

/// Finding 3: a truncated detached table must be rejected, not read as zeros.
#[test]
#[ignore = "known unfixed: from_reader accepts a truncated Head table"]
fn from_reader_rejects_truncated_table() {
    let table = one_frame_table(123, 456, Format::Head);
    for len in SKIPPABLE_HEADER_SIZE + INTEGRITY_SIZE..table.len() {
        assert!(
            SeekTable::from_reader(Cursor::new(&table[..len])).is_err(),
            "table truncated to {len} bytes was accepted"
        );
    }
}

/// Finding 7: a table header claiming many frames must not be trusted with a large allocation
/// before the source is known to hold the table.
#[test]
fn forged_frame_count_does_not_allocate_before_validation() {
    let forged = foot_table_without_entries(10_000_000);
    PeakAlloc::reset();
    let result = SeekTable::from_seekable(&mut BytesWrapper::new(&forged));
    let peak = PeakAlloc::peak();
    assert!(result.is_err());
    assert!(
        peak < 1 << 20,
        "a 17-byte source made the parser request a {peak}-byte allocation"
    );
}

/// Finding 10: `from_seekable_format` must cope with sources that return few bytes per read.
fn short_reads_parse_correctly(format: Format) {
    let table = one_frame_table(123, 456, format);
    for chunk in [1, 4, 8, 9, 16] {
        let st = SeekTable::from_seekable_format(&mut Chunked::new(&table, chunk), format)
            .unwrap_or_else(|err| panic!("{chunk}-byte reads failed: {err}"));
        assert_eq!(st.frame_size_comp(0).unwrap(), 123);
        assert_eq!(st.frame_size_decomp(0).unwrap(), 456);
    }
}

#[test]
#[ignore = "known unfixed: header loop overwrites the buffer start and Head slices buf[17..read] with read < 17"]
fn short_reads_parse_head_table() {
    short_reads_parse_correctly(Format::Head);
}

#[test]
#[ignore = "known unfixed: header loop overwrites the buffer start on reads shorter than 8 bytes"]
fn short_reads_parse_foot_table() {
    short_reads_parse_correctly(Format::Foot);
}

/// Finding 11: a legacy table checksum that the reference decoder rejects must not be silently
/// ignored. `seekable_format.md` documents ignoring them as policy, so this test also records the
/// interoperability gap that policy creates.
#[test]
#[ignore = "known unfixed by policy: legacy seek table checksums are skipped (seekable_format.md 0.1.1)"]
fn corrupted_legacy_table_checksum_is_rejected() {
    let (mut archive, checksum_at) = legacy_archive_with_table_checksum(b"hello storage");
    archive[checksum_at] ^= 0xFF;

    let mut reference = zstd_safe::seekable::Seekable::create();
    reference.init_buff(&archive).unwrap();
    let mut out = [0u8; 64];
    assert!(
        reference.decompress(&mut out[..], 0).is_err(),
        "the reference decoder should reject the corrupted table checksum"
    );

    let mut decoder = Decoder::new(BytesWrapper::new(&archive)).unwrap();
    assert!(read_all(&mut decoder, 64).is_err());
}

/// Finding 12: an archive with zero frames is valid and decodes to nothing.
#[test]
#[ignore = "known unfixed: frame_index_at computes num_frames - 1 for an empty table"]
fn zero_frame_archive_decodes_to_nothing() {
    let archive = foot_table_without_entries(0);
    let st = SeekTable::from_seekable(&mut BytesWrapper::new(&archive)).unwrap();
    assert_eq!(st.num_frames(), 0);
    let mut decoder = Decoder::new(BytesWrapper::new(&archive)).unwrap();
    assert_eq!(read_all(&mut decoder, 64).unwrap(), b"");
}

/// Finding 12: frame lookups on an empty table must not underflow.
#[test]
#[ignore = "known unfixed: frame_index_decomp underflows on an empty table"]
fn zero_frame_table_lookups_do_not_panic() {
    let st = SeekTable::new();
    assert_eq!(st.frame_index_decomp(0), 0);
    assert_eq!(st.frame_index_comp(0), 0);
}

/// Finding 14: a skippable header whose size field is near `u32::MAX` must fail cleanly. On
/// 64-bit targets the addition cannot overflow, so this only bites on 32-bit targets, where it is
/// unverified; the test is here so that a 32-bit CI job would catch it.
#[test]
fn oversized_skippable_header_is_rejected() {
    let mut table = one_frame_table(1, 1, Format::Foot);
    table[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(SeekTable::from_seekable(&mut BytesWrapper::new(&table)).is_err());
}

/// Finding 15: `Write::flush` must push data that zstd still holds through to the writer.
#[test]
#[ignore = "known unfixed: Encoder::flush never asks zstd to flush its own buffers"]
fn flush_pushes_accepted_input_to_the_writer() {
    let mut out = Vec::new();
    let mut encoder = Encoder::new(&mut out).unwrap();
    encoder.write_all(b"hello").unwrap();
    encoder.flush().unwrap();
    drop(encoder);
    assert!(!out.is_empty(), "nothing reached the writer after flush");
}

/// Finding 18: after zstd reports corruption, further reads without a reset must keep failing
/// rather than hand out bytes decoded from an undefined context state.
#[test]
#[ignore = "known unfixed: the decoder neither poisons nor resets its context after a zstd error"]
fn decoder_keeps_failing_after_a_zstd_error() {
    let content = b"hello storage, this is the content of the archive".repeat(20);
    let mut archive = seekable(&[&content, &content]);
    // The block header of the first frame lives right after its 6-byte frame header
    archive[6] ^= 0xFF;
    let mut decoder = Decoder::new(BytesWrapper::new(&archive)).unwrap();
    let mut buf = vec![0; 4096];
    let first = decoder.decompress(&mut buf);
    assert!(first.is_err(), "corrupted block header was not detected");
    for attempt in 0..8 {
        let result = decoder.decompress(&mut buf);
        assert!(
            result.is_err(),
            "call {attempt} after the error returned {result:?} instead of an error"
        );
    }
}

/// Finding 19: the serializer must return zero for an empty destination instead of indexing it.
fn empty_buffer_writes_nothing(format: Format) {
    let mut ser = SeekTable::new().into_format_serializer(format);
    let mut head = [0u8; 12];
    assert_eq!(ser.write_into(&mut head), 12);
    assert_eq!(ser.write_into(&mut []), 0);
    let mut rest = [0u8; 16];
    assert_eq!(ser.write_into(&mut rest), ser.encoded_len() - 12);
}

#[test]
#[ignore = "known unfixed: the descriptor byte write indexes buf[0] of an empty slice"]
fn serializer_accepts_empty_buffer_foot() {
    empty_buffer_writes_nothing(Format::Foot);
}

#[test]
#[ignore = "known unfixed: the descriptor byte write indexes buf[0] of an empty slice"]
fn serializer_accepts_empty_buffer_head() {
    empty_buffer_writes_nothing(Format::Head);
}

/// Decodes `archive` through `table` from decompressed offset `offset`.
fn read_with_table(archive: &[u8], table: SeekTable, offset: u64) -> zeekstd::Result<Vec<u8>> {
    let mut decoder = DecodeOptions::new(BytesWrapper::new(archive))
        .seek_table(table)
        .offset(offset)
        .into_decoder()?;
    read_all(&mut decoder, 64)
}

/// Finding 2, regression: a table that declares one byte less than the frame holds is rejected
/// instead of silently truncating the output.
#[test]
fn declared_size_too_small_is_rejected() {
    let archive = seekable(&[b"hello storage"]);
    let st = SeekTable::from_seekable(&mut BytesWrapper::new(&archive)).unwrap();
    let mut forged = SeekTable::new();
    forged
        .log_frame(st.frame_size_comp(0).unwrap() as u32, 12)
        .unwrap();
    assert!(read_with_table(&archive, forged, 0).is_err());
}

/// Finding 8, regression: a table that declares one byte more than the frame holds is rejected
/// instead of spinning at the end of the source.
#[test]
fn declared_size_too_large_is_rejected() {
    let archive = seekable(&[b"hello storage"]);
    let st = SeekTable::from_seekable(&mut BytesWrapper::new(&archive)).unwrap();
    let mut forged = SeekTable::new();
    forged
        .log_frame(st.frame_size_comp(0).unwrap() as u32, 14)
        .unwrap();
    assert!(read_with_table(&archive, forged, 0).is_err());
}

/// Finding 2, regression: frames whose declared decompressed sizes are shifted are rejected, both
/// on a full read and on a seek that the shifted table sends into the wrong frame.
#[test]
fn misaligned_frame_sizes_are_rejected() {
    let archive = seekable(&[b"abc", b"XYZ"]);
    let st = SeekTable::from_seekable(&mut BytesWrapper::new(&archive)).unwrap();
    let mut forged = SeekTable::new();
    forged
        .log_frame(st.frame_size_comp(0).unwrap() as u32, 2)
        .unwrap();
    forged
        .log_frame(st.frame_size_comp(1).unwrap() as u32, 4)
        .unwrap();
    assert!(read_with_table(&archive, forged.clone(), 0).is_err());
    assert!(read_with_table(&archive, forged, 2).is_err());
}

/// Finding 2, follow-up: a seek table whose compressed sizes point a seek at the wrong place must
/// yield an error rather than data from another frame.
#[test]
fn seek_with_wrong_compressed_sizes_fails() {
    let archive = seekable(&[b"abc", b"XYZ"]);
    let st = SeekTable::from_seekable(&mut BytesWrapper::new(&archive)).unwrap();
    let mut forged = SeekTable::new();
    forged
        .log_frame(st.frame_size_comp(0).unwrap() as u32 - 1, 3)
        .unwrap();
    forged
        .log_frame(st.frame_size_comp(1).unwrap() as u32 + 1, 3)
        .unwrap();
    let mut decoder = DecodeOptions::new(BytesWrapper::new(&archive))
        .seek_table(forged)
        .lower_frame(1)
        .into_decoder()
        .unwrap();
    let result = read_all(&mut decoder, 64);
    assert!(
        !matches!(&result, Ok(out) if out != b"XYZ"),
        "seek returned {result:?}, neither the right frame nor an error"
    );
    assert!(result.is_err());
}

/// Finding 13, regression: both zero frame-size policies are rejected at construction.
#[test]
fn zero_frame_size_policies_are_rejected() {
    for policy in [
        FrameSizePolicy::Compressed(0),
        FrameSizePolicy::Uncompressed(0),
    ] {
        let err = EncodeOptions::new()
            .frame_size_policy(policy)
            .into_raw_encoder()
            .err()
            .expect("zero frame size accepted");
        assert!(err.is_invalid_frame_size_policy());
    }
}
