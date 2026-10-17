// Model-output: Claude Opus 5.5
//! Property tests of the public API.
//!
//! Archives are built from random input by random sequences of encoder calls, with output
//! buffers small enough to cut frame endings short. Every archive must decode back to its input
//! from any position, through any source, with the reference implementation too, and damage must
//! never pass for content.
#![cfg(feature = "std")]

use std::{
    cell::RefCell,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    ops::Range,
    rc::Rc,
};

use proptest::{prelude::*, sample::Index};
use zeekstd::{
    BytesWrapper, DecodeOptions, Decoder, EncodeOptions, EpilogueProgress, FrameSizePolicy,
    RawEncoder, SEEKABLE_MAX_FRAME_SIZE, SeekTable, seek_table::Format,
};
use zstd_safe::{DCtx, InBuffer, OutBuffer};

/// Input of up to some KiB, in pieces that zstd stores raw, compresses, or run-length encodes,
/// so that one frame can hold blocks of every type.
fn content() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        prop::collection::vec(any::<u8>(), 0..2000),
        prop::collection::vec(0..4u8, 0..4000),
        (any::<u8>(), 0..4000usize).prop_map(|(byte, len)| vec![byte; len]),
    ];
    prop::collection::vec(piece, 0..4).prop_map(|pieces| pieces.concat())
}

/// Frame sizes that give some KiB of input several frames, often many.
fn frame_size_policy() -> impl Strategy<Value = FrameSizePolicy> {
    let size = |max: u32| prop_oneof![1..64u32, 1..max];
    prop_oneof![
        size(2000).prop_map(FrameSizePolicy::Uncompressed),
        size(600).prop_map(FrameSizePolicy::Compressed),
    ]
}

/// A `RawEncoder` call, with the size of the output buffer it gets.
#[derive(Clone, Debug)]
enum Step {
    /// Compresses the next `len` bytes of input, calling again until they are consumed.
    Compress { len: usize, out: usize },
    /// Flushes, calling again until nothing is left to flush unless `once`.
    Flush { out: usize, once: bool },
    /// Ends the frame, calling again until it is ended unless `once`. An ending left pending is
    /// for whichever call comes next to finish.
    EndFrame { out: usize, once: bool },
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let epilogue = || (1..32usize, any::<bool>());
    let step = prop_oneof![
        6 => (0..3000usize, 1..256usize).prop_map(|(len, out)| Step::Compress { len, out }),
        1 => epilogue().prop_map(|(out, once)| Step::Flush { out, once }),
        1 => epilogue().prop_map(|(out, once)| Step::EndFrame { out, once }),
    ];
    prop::collection::vec(step, 0..16)
}

/// A seekable archive and what it was made from.
#[derive(Debug)]
struct Archive {
    input: Vec<u8>,
    /// What every frame references, if anything.
    prefix: Option<Vec<u8>>,
    policy: FrameSizePolicy,
    checksum: bool,
    /// The frames, without a seek table.
    frames: Vec<u8>,
    seek_table: SeekTable,
    /// For each frame, whether the frame size policy ended it, rather than `end_frame`.
    ended_by_policy: Vec<bool>,
}

impl Archive {
    /// The frames followed by their seek table in `Foot` format.
    fn with_seek_table(&self) -> Vec<u8> {
        [&self.frames[..], &serialize(&self.seek_table, Format::Foot)].concat()
    }

    /// The compressed bytes of frame `index`.
    fn frame(&self, index: u32) -> &[u8] {
        let start = self.seek_table.frame_start_comp(index).unwrap() as usize;
        let end = self.seek_table.frame_end_comp(index).unwrap() as usize;
        &self.frames[start..end]
    }

    /// The input that frame `index` holds.
    fn frame_content(&self, index: u32) -> &[u8] {
        let start = self.seek_table.frame_start_decomp(index).unwrap() as usize;
        let end = self.seek_table.frame_end_decomp(index).unwrap() as usize;
        &self.input[start..end]
    }
}

/// A `RawEncoder` compressing `input` into `frames`, every frame referencing `prefix`.
struct Session<'a> {
    encoder: RawEncoder<'a>,
    input: &'a [u8],
    /// How much of `input` the encoder consumed.
    pos: usize,
    prefix: Option<&'a [u8]>,
    frames: Vec<u8>,
}

impl<'a> Session<'a> {
    /// Compresses the input up to `end` with `out`-byte buffers.
    fn compress(&mut self, end: usize, out: usize) {
        let mut buf = vec![0; out];
        while self.pos < end {
            let input = &self.input[self.pos..end];
            let progress = self
                .encoder
                .compress_with_prefix(input, &mut buf, self.prefix)
                .unwrap();
            assert!(
                progress.in_progress() + progress.out_progress() > 0,
                "compress stalled"
            );
            self.frames.extend(&buf[..progress.out_progress()]);
            self.pos += progress.in_progress();
        }
    }

    /// Calls `epilogue`, `RawEncoder::flush` or `RawEncoder::end_frame`, with `out`-byte buffers,
    /// once or until it reports that no data is left.
    fn epilogue(
        &mut self,
        epilogue: fn(&mut RawEncoder<'a>, &mut [u8]) -> zeekstd::Result<EpilogueProgress>,
        out: usize,
        once: bool,
    ) {
        let mut buf = vec![0; out];
        loop {
            let progress = epilogue(&mut self.encoder, &mut buf).unwrap();
            self.frames.extend(&buf[..progress.out_progress()]);
            if once || progress.data_left() == 0 {
                return;
            }
        }
    }

    /// Compresses what is left of the input and ends the last frame. Returns the frames and
    /// their seek table.
    fn finish(mut self) -> (Vec<u8>, SeekTable) {
        self.compress(self.input.len(), 64);
        self.epilogue(RawEncoder::end_frame, 64, false);
        (self.frames, self.encoder.into_seek_table())
    }
}

/// Feeds `input` to a `RawEncoder` through `steps`, then finishes the session. Every frame
/// references `prefix`.
fn encode(
    input: Vec<u8>,
    prefix: Option<Vec<u8>>,
    policy: FrameSizePolicy,
    checksum: bool,
    steps: &[Step],
) -> Archive {
    let encoder = EncodeOptions::new()
        .frame_size_policy(policy.clone())
        .checksum_flag(checksum)
        .into_raw_encoder()
        .unwrap();
    let mut session = Session {
        encoder,
        input: &input,
        pos: 0,
        prefix: prefix.as_deref(),
        frames: vec![],
    };
    // The frames that were open when an `end_frame` started. That may have finished an ending
    // the policy started, but no other frame can have been ended by anything but the policy.
    let mut ended_explicitly = vec![];

    for step in steps {
        match *step {
            Step::Compress { len, out } => {
                session.compress(input.len().min(session.pos + len), out);
            }
            Step::Flush { out, once } => session.epilogue(RawEncoder::flush, out, once),
            Step::EndFrame { out, once } => {
                ended_explicitly.push(session.encoder.seek_table().num_frames());
                session.epilogue(RawEncoder::end_frame, out, once);
            }
        }
    }
    let (frames, seek_table) = session.finish();
    // The last `end_frame` ended the last frame
    let num_frames = seek_table.num_frames();
    ended_explicitly.push(num_frames - 1);

    Archive {
        ended_by_policy: (0..num_frames)
            .map(|i| !ended_explicitly.contains(&i))
            .collect(),
        input,
        prefix,
        policy,
        checksum,
        frames,
        seek_table,
    }
}

/// Archives of `content()` with checksums as `checksum` picks them, and with frames that
/// reference the prefix `prefix` picks, if any. The input of those repeats the prefix, so that
/// zstd finds matches in it.
fn archive_with(
    checksum: impl Strategy<Value = bool>,
    prefix: impl Strategy<Value = Option<Vec<u8>>>,
) -> impl Strategy<Value = Archive> {
    (content(), prefix, frame_size_policy(), checksum, steps()).prop_map(
        |(content, prefix, policy, checksum, steps)| {
            let input = match &prefix {
                Some(prefix) => [&content[..], prefix].concat(),
                None => content,
            };
            encode(input, prefix, policy, checksum, &steps)
        },
    )
}

/// Archives with or without checksums, one in four with a prefix.
fn archive() -> impl Strategy<Value = Archive> {
    archive_with(any::<bool>(), sometimes_a_prefix())
}

fn sometimes_a_prefix() -> impl Strategy<Value = Option<Vec<u8>>> {
    prop::option::weighted(0.25, content())
}

/// `seek_table` serialized in `format`.
fn serialize(seek_table: &SeekTable, format: Format) -> Vec<u8> {
    let mut ser = seek_table.clone().into_format_serializer(format);
    let mut bytes = vec![0; ser.encoded_len()];
    assert_eq!(ser.write_into(&mut bytes), bytes.len());
    bytes
}

/// Everything zstd decodes from `bytes`, which may end inside a frame. The first frame
/// references `prefix`.
fn zstd_stream_decode(bytes: &[u8], prefix: Option<&[u8]>) -> Vec<u8> {
    let mut dctx = DCtx::create();
    if let Some(prefix) = prefix {
        dctx.ref_prefix(prefix).unwrap();
    }
    let mut decoded = vec![];
    let mut buf = vec![0; 64 * 1024];
    let mut input = InBuffer::around(bytes);
    loop {
        let mut output = OutBuffer::around(&mut buf[..]);
        let in_before = input.pos();
        dctx.decompress_stream(&mut output, &mut input).unwrap();
        let produced = output.pos();
        decoded.extend(&buf[..produced]);
        if produced == 0 && input.pos() == in_before {
            return decoded;
        }
    }
}

/// A `Read + Seek` source that returns at most `chunk` bytes per read.
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

/// Read sizes from a byte at a time to more than the decoder's input buffer holds.
fn chunk() -> impl Strategy<Value = usize> {
    prop_oneof![1..64usize, 1..200_000usize]
}

/// Decompresses from `decoder` in `buf_len`-byte steps until it reports the end, referencing
/// `prefix` at every frame. Panics if the decoder produces more than its seek table holds, so
/// that one that never reports the end cannot hang the test.
fn decode_all<'a, S: zeekstd::Seekable>(
    decoder: &mut Decoder<'a, S>,
    buf_len: usize,
    prefix: Option<&'a [u8]>,
) -> zeekstd::Result<Vec<u8>> {
    let mut output = vec![];
    let mut buf = vec![0; buf_len];
    loop {
        let n = decoder.decompress_with_prefix(&mut buf, prefix)?;
        if n == 0 {
            return Ok(output);
        }
        output.extend(&buf[..n]);
        assert!(output.len() as u64 <= decoder.seek_table().size_decomp());
    }
}

/// Where the decoder under test gets its seek table.
#[derive(Clone, Debug)]
enum TableSource {
    /// Parsed by the decoder from the end of the archive.
    Archive,
    /// Parsed from a separate serialization in `format`, read `chunk` bytes at a time.
    Detached { format: Format, chunk: usize },
}

fn table_source() -> impl Strategy<Value = TableSource> {
    prop_oneof![
        Just(TableSource::Archive),
        (prop_oneof![Just(Format::Head), Just(Format::Foot)], chunk())
            .prop_map(|(format, chunk)| TableSource::Detached { format, chunk }),
    ]
}

/// What `DecodeOptions` set the decoder up with. Positions and frames pick from up to one past
/// the valid range, so that an option is out of range now and then.
#[derive(Clone, Debug)]
struct Start {
    offset: Option<Index>,
    lower_frame: Option<Index>,
    offset_limit: Option<Index>,
    upper_frame: Option<Index>,
}

fn start() -> impl Strategy<Value = Start> {
    let option = || prop::option::weighted(0.2, any::<Index>());
    (option(), option(), option(), option()).prop_map(
        |(offset, lower_frame, offset_limit, upper_frame)| Start {
            offset,
            lower_frame,
            offset_limit,
            upper_frame,
        },
    )
}

impl Start {
    /// Sets these options on `opts` for a decoder over the frames of `st`. Returns `opts` with
    /// the position and limit they give the decoder, `None` if an option is out of range. A frame
    /// overrides a position.
    fn apply<'a, S>(
        &self,
        mut opts: DecodeOptions<'a, S>,
        st: &SeekTable,
    ) -> (DecodeOptions<'a, S>, Option<(u64, u64)>) {
        let size = st.size_decomp();
        let num_frames = u64::from(st.num_frames());
        let in_range = |pos: u64| (pos <= size).then_some(pos);
        let mut offset = Some(0);
        if let Some(index) = self.offset {
            let pos = pick(index, size);
            opts = opts.offset(pos);
            offset = in_range(pos);
        }
        if let Some(index) = self.lower_frame {
            let frame = pick(index, num_frames) as u32;
            opts = opts.lower_frame(frame);
            offset = st.frame_start_decomp(frame).ok();
        }
        let mut limit = Some(size);
        if let Some(index) = self.offset_limit {
            let pos = pick(index, size);
            opts = opts.offset_limit(pos);
            limit = in_range(pos);
        }
        if let Some(index) = self.upper_frame {
            let frame = pick(index, num_frames) as u32;
            opts = opts.upper_frame(frame);
            limit = st.frame_end_decomp(frame).ok();
        }
        (opts, offset.zip(limit))
    }
}

/// A seek on a `Decoder`, by a distance picked from up to one past the end.
#[derive(Clone, Copy, Debug)]
enum SeekCall {
    Start(Index),
    Current { distance: Index, backwards: bool },
    End(Index),
}

fn seek_call() -> impl Strategy<Value = SeekCall> {
    prop_oneof![
        any::<Index>().prop_map(SeekCall::Start),
        (any::<Index>(), any::<bool>()).prop_map(|(distance, backwards)| SeekCall::Current {
            distance,
            backwards
        }),
        any::<Index>().prop_map(SeekCall::End),
    ]
}

impl SeekCall {
    /// This seek from `offset` among `size` bytes. Returns it with the position it leads to,
    /// `None` for one that has to fail.
    fn resolve(self, offset: u64, size: u64) -> (SeekFrom, Option<u64>) {
        let in_range = |pos: u64| (pos <= size).then_some(pos);
        match self {
            Self::Start(index) => {
                let pos = pick(index, size);
                (SeekFrom::Start(pos), in_range(pos))
            }
            Self::Current {
                distance,
                backwards,
            } => {
                let distance = pick(distance, size);
                if backwards {
                    let pos = offset.checked_sub(distance);
                    (SeekFrom::Current(-(distance as i64)), pos)
                } else {
                    (
                        SeekFrom::Current(distance as i64),
                        in_range(offset + distance),
                    )
                }
            }
            Self::End(distance) => {
                let distance = pick(distance, size);
                (
                    SeekFrom::End(-(distance as i64)),
                    size.checked_sub(distance),
                )
            }
        }
    }
}

/// A call on a `Decoder`. Positions and frames pick from up to one past the valid range.
#[derive(Clone, Debug)]
enum Call {
    Decompress(usize),
    SetOffset(Index),
    SetOffsetLimit(Index),
    SetLowerFrame(Index),
    SetUpperFrame(Index),
    Seek(SeekCall),
    Reset,
}

fn calls() -> impl Strategy<Value = Vec<Call>> {
    let call = prop_oneof![
        8 => (1..400usize).prop_map(Call::Decompress),
        2 => any::<Index>().prop_map(Call::SetOffset),
        2 => any::<Index>().prop_map(Call::SetOffsetLimit),
        1 => any::<Index>().prop_map(Call::SetLowerFrame),
        1 => any::<Index>().prop_map(Call::SetUpperFrame),
        3 => seek_call().prop_map(Call::Seek),
        1 => Just(Call::Reset),
    ];
    prop::collection::vec(call, 0..40)
}

/// `index` mapped to 0 up to one past `end`.
fn pick(index: Index, end: u64) -> u64 {
    index.index(end as usize + 2) as u64
}

/// Checks a decoder over `archive`, whose source returns `chunk` bytes per read, against a
/// model: the position and limit it is set up with, then moved by `calls`. Each decompression
/// must return the input from the position up to the limit, as much as fits.
fn check_decoder(
    archive: &Archive,
    tables: &TableSource,
    chunk: usize,
    start: &Start,
    calls: &[Call],
) -> Result<(), TestCaseError> {
    let (input, st) = (&archive.input, &archive.seek_table);
    let size = input.len() as u64;
    let num_frames = u64::from(st.num_frames());
    let prefix = archive.prefix.as_deref();

    let whole = archive.with_seek_table();
    let opts = match tables {
        TableSource::Archive => DecodeOptions::new(Chunked::new(&whole, chunk)),
        TableSource::Detached {
            format,
            chunk: table_chunk,
        } => {
            let bytes = serialize(st, *format);
            let parsed =
                SeekTable::from_seekable_format(&mut Chunked::new(&bytes, *table_chunk), *format)
                    .unwrap();
            prop_assert_eq!(&parsed, st);
            DecodeOptions::new(Chunked::new(&archive.frames, chunk)).seek_table(parsed)
        }
    };
    let (opts, set_up) = start.apply(opts, st);
    let Some((mut offset, mut limit)) = set_up else {
        prop_assert!(opts.into_decoder().is_err());
        return Ok(());
    };
    let mut decoder = opts.into_decoder().unwrap();

    for call in calls {
        match *call {
            Call::Decompress(len) => {
                let mut buf = vec![0; len];
                let n = decoder.decompress_with_prefix(&mut buf, prefix).unwrap();
                let wanted = limit.saturating_sub(offset).min(len as u64) as usize;
                prop_assert_eq!(n, wanted, "offset {}, limit {}", offset, limit);
                let at = offset as usize;
                prop_assert!(buf[..n] == input[at..at + n], "wrong bytes at {}", at);
                offset += n as u64;
            }
            Call::SetOffset(index) | Call::SetOffsetLimit(index) => {
                let pos = pick(index, size);
                let (result, model) = match call {
                    Call::SetOffset(_) => (decoder.set_offset(pos), &mut offset),
                    _ => (decoder.set_offset_limit(pos), &mut limit),
                };
                if pos <= size {
                    result.unwrap();
                    *model = pos;
                } else {
                    prop_assert!(result.unwrap_err().is_offset_out_of_range());
                }
            }
            Call::SetLowerFrame(index) | Call::SetUpperFrame(index) => {
                let frame = pick(index, num_frames) as u32;
                let (result, model, wanted) = match call {
                    Call::SetLowerFrame(_) => (
                        decoder.set_lower_frame(frame),
                        &mut offset,
                        st.frame_start_decomp(frame),
                    ),
                    _ => (
                        decoder.set_upper_frame(frame),
                        &mut limit,
                        st.frame_end_decomp(frame),
                    ),
                };
                if let Ok(pos) = wanted {
                    prop_assert_eq!(result.unwrap(), pos);
                    *model = pos;
                } else {
                    prop_assert!(result.unwrap_err().is_frame_index_too_large());
                }
            }
            Call::Seek(seek) => {
                let (pos, target) = seek.resolve(offset, size);
                let result = decoder.seek(pos);
                if let Some(target) = target {
                    prop_assert_eq!(result.unwrap(), target);
                    offset = target;
                } else {
                    prop_assert!(result.is_err());
                }
            }
            Call::Reset => {
                decoder.reset();
                prop_assert_eq!(decoder.read_compressed(), 0);
                offset = 0;
                limit = size;
            }
        }
        prop_assert_eq!(decoder.offset(), offset);
        prop_assert_eq!(decoder.offset_limit(), limit);
    }
    Ok(())
}

/// Reads `archive` with the reference decoder, `len` bytes from each position `at` picks from
/// `input`, which the archive holds.
fn check_reference_reads(
    archive: &[u8],
    input: &[u8],
    reads: &[(Index, usize)],
) -> Result<(), TestCaseError> {
    let mut reference = zstd_safe::seekable::Seekable::create();
    reference.init_buff(archive).unwrap();
    for (at, len) in reads {
        let start = at.index(input.len() + 1);
        let end = input.len().min(start + len);
        let mut buf = vec![0; end - start];
        let mut done = 0;
        while done < buf.len() {
            let n = reference
                .decompress(&mut buf[done..], (start + done) as u64)
                .unwrap();
            prop_assert!(n > 0, "the reference stalled at {}", start + done);
            done += n;
        }
        prop_assert!(
            buf == input[start..end],
            "the reference read {}..{} differently",
            start,
            end
        );
    }
    Ok(())
}

fn reads() -> impl Strategy<Value = Vec<(Index, usize)>> {
    prop::collection::vec((any::<Index>(), 0..3000usize), 0..8)
}

/// A writer that the test can read while an `Encoder` owns it, taking at most `chunk` bytes per
/// call.
#[derive(Clone)]
struct SharedWriter {
    bytes: Rc<RefCell<Vec<u8>>>,
    chunk: usize,
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(self.chunk);
        self.bytes.borrow_mut().extend(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A call on an `Encoder`.
#[derive(Clone, Debug)]
enum EncoderCall {
    /// Writes the next `len` bytes of input.
    Write(usize),
    Flush,
    EndFrame,
}

fn encoder_calls() -> impl Strategy<Value = Vec<EncoderCall>> {
    let call = prop_oneof![
        4 => (0..3000usize).prop_map(EncoderCall::Write),
        1 => Just(EncoderCall::Flush),
        1 => Just(EncoderCall::EndFrame),
    ];
    prop::collection::vec(call, 0..16)
}

/// Feeds `input` to an `Encoder` through `calls` and finishes it, into a writer that takes
/// `chunk` bytes per call. Checks that a flush delivers all input written before it, that
/// `end_frame` logs one frame, and that the encoder counts what reached the writer. Returns the
/// archive.
fn encode_with_writer(
    input: &[u8],
    policy: FrameSizePolicy,
    checksum: bool,
    calls: &[EncoderCall],
    chunk: usize,
) -> Result<Vec<u8>, TestCaseError> {
    let writer = SharedWriter {
        bytes: Rc::default(),
        chunk,
    };
    let mut encoder = EncodeOptions::new()
        .frame_size_policy(policy)
        .checksum_flag(checksum)
        .into_encoder(writer.clone())
        .unwrap();
    let mut pos = 0;
    for call in calls {
        match *call {
            EncoderCall::Write(len) => {
                let end = input.len().min(pos + len);
                encoder.write_all(&input[pos..end]).unwrap();
                pos = end;
            }
            EncoderCall::Flush => {
                encoder.flush().unwrap();
                let flushed = zstd_stream_decode(&writer.bytes.borrow(), None);
                prop_assert!(flushed == input[..pos], "flush after {} bytes", pos);
            }
            EncoderCall::EndFrame => {
                let num_frames = encoder.seek_table().num_frames();
                encoder.end_frame().unwrap();
                prop_assert_eq!(encoder.seek_table().num_frames(), num_frames + 1);
            }
        }
        prop_assert_eq!(
            encoder.written_compressed(),
            writer.bytes.borrow().len() as u64
        );
    }
    encoder.write_all(&input[pos..]).unwrap();
    let total = encoder.finish().unwrap();
    let archive = writer.bytes.take();
    prop_assert_eq!(total, archive.len() as u64);
    Ok(archive)
}

/// Damage done to stored bytes.
#[derive(Clone, Debug)]
enum Damage {
    /// XORs the byte `at` picks with `mask`, which is never zero.
    Flip { at: Index, mask: u8 },
    /// Cuts the bytes off at the length `at` picks, losing at least the last one.
    Truncate { at: Index },
}

impl Damage {
    /// Damages `bytes` at a position picked from `region`.
    fn apply(&self, bytes: &mut Vec<u8>, region: Range<usize>) {
        let position = |at: &Index| region.start + at.index(region.len());
        match self {
            Self::Flip { at, mask } => bytes[position(at)] ^= mask,
            Self::Truncate { at } => bytes.truncate(position(at)),
        }
    }
}

fn damage() -> impl Strategy<Value = Damage> {
    prop_oneof![
        4 => (any::<Index>(), 1..=255u8).prop_map(|(at, mask)| Damage::Flip { at, mask }),
        1 => any::<Index>().prop_map(|at| Damage::Truncate { at }),
    ]
}

/// A change to the seek table entry of the frame `frame` picks: `delta` added to its compressed
/// size if `compressed`, else to its decompressed size.
type EntryChange = (Index, i64, bool);

fn entry_changes() -> impl Strategy<Value = Vec<EntryChange>> {
    let delta = prop_oneof![-3..=3i64, -5000..=5000i64];
    prop::collection::vec((any::<Index>(), delta, any::<bool>()), 1..4)
}

/// The seek table of `archive` with `changes` made to its entries.
fn forge(archive: &Archive, changes: &[EntryChange]) -> SeekTable {
    let st = &archive.seek_table;
    let mut sizes: Vec<(u32, u32)> = (0..st.num_frames())
        .map(|i| {
            let c_size = st.frame_size_comp(i).unwrap();
            let d_size = st.frame_size_decomp(i).unwrap();
            (c_size as u32, d_size as u32)
        })
        .collect();
    for (frame, delta, compressed) in changes {
        let num_frames = sizes.len();
        let entry = &mut sizes[frame.index(num_frames)];
        let size = if *compressed {
            &mut entry.0
        } else {
            &mut entry.1
        };
        *size = size.saturating_add_signed(*delta as i32);
    }
    seek_table_of(&sizes)
}

/// Checks that a decoder that reads the frames of `archive` through `forged`, from `offset` on,
/// either fails or returns what is really there. The decoder verifies each frame it decodes
/// against `forged`, but not that the frame it seeks to is the one `forged` means: an entry
/// before it may have moved where frames start, onto another frame. So it must have decoded the
/// frames from the one that really starts where `forged` says its frame does, each as large as
/// `forged` says, and return their content from as far into the first as `offset` lies by
/// `forged`.
fn check_forged_read(
    archive: &Archive,
    forged: SeekTable,
    offset: u64,
) -> Result<(), TestCaseError> {
    let st = &archive.seek_table;
    let frame = forged.frame_index_decomp(offset);
    let c_start = forged.frame_start_comp(frame).unwrap();
    let true_frame = (0..st.num_frames()).find(|&i| st.frame_start_comp(i).unwrap() == c_start);
    let into_frame = offset - forged.frame_start_decomp(frame).unwrap();
    let len = (forged.size_decomp() - offset) as usize;
    let num_frames = forged.num_frames();
    let forged_sizes: Vec<u64> = (frame..num_frames)
        .map(|i| forged.frame_size_decomp(i).unwrap())
        .collect();

    let result = DecodeOptions::new(BytesWrapper::new(&archive.frames))
        .seek_table(forged)
        .offset(offset)
        .into_decoder()
        .and_then(|mut decoder| decode_all(&mut decoder, 100, archive.prefix.as_deref()));
    let Ok(decoded) = result else {
        return Ok(());
    };
    // Nothing is wanted from the end on, so nothing gets decoded either
    if len == 0 {
        prop_assert!(decoded.is_empty());
        return Ok(());
    }
    let Some(true_frame) = true_frame else {
        return Err(TestCaseError::fail(format!(
            "{} bytes from {} accepted, though no frame starts at {}",
            decoded.len(),
            offset,
            c_start
        )));
    };
    let true_sizes: Vec<u64> = (true_frame..)
        .take(forged_sizes.len())
        .map(|i| st.frame_size_decomp(i).unwrap_or(u64::MAX))
        .collect();
    prop_assert_eq!(
        &true_sizes,
        &forged_sizes,
        "frames from {} decoded as frames from {}",
        true_frame,
        frame
    );
    let start = (st.frame_start_decomp(true_frame).unwrap() + into_frame) as usize;
    prop_assert!(
        decoded == archive.input[start..start + len],
        "{} bytes from {} differ",
        len,
        offset
    );
    Ok(())
}

/// Frame sizes as the format stores them, small and empty ones included.
fn frame_sizes() -> impl Strategy<Value = Vec<(u32, u32)>> {
    let size = || prop_oneof![0..4u32, 0..100_000u32, any::<u32>()];
    prop::collection::vec((size(), size()), 0..300)
}

/// A seek table of frames with `sizes`, compressed size first.
fn seek_table_of(sizes: &[(u32, u32)]) -> SeekTable {
    let mut st = SeekTable::new();
    for &(c_size, d_size) in sizes {
        st.log_frame(c_size, d_size).unwrap();
    }
    st
}

/// Where frames of `sizes` start, followed by where the last one ends.
fn bounds(sizes: impl Iterator<Item = u32>) -> Vec<u64> {
    let mut bounds = vec![0];
    for size in sizes {
        bounds.push(bounds.last().unwrap() + u64::from(size));
    }
    bounds
}

/// Checks `lookup`, a frame lookup by position, against `bounds` of the frames: at and just
/// before every bound, and at `positions` taken modulo two past the end. The frame found must be
/// the last that starts at or before the position, or the last frame for one past the end.
fn check_frame_lookup(
    lookup: impl Fn(u64) -> u32,
    bounds: &[u64],
    positions: &[u64],
) -> Result<(), TestCaseError> {
    let (starts, end) = (&bounds[..bounds.len() - 1], bounds[bounds.len() - 1]);
    let near_bounds = bounds.iter().flat_map(|&pos| [pos.saturating_sub(1), pos]);
    for pos in near_bounds.chain(positions.iter().map(|pos| pos % (end + 2))) {
        let frame = if pos >= end {
            starts.len().saturating_sub(1)
        } else {
            starts.partition_point(|&start| start <= pos) - 1
        };
        prop_assert_eq!(lookup(pos), frame as u32, "at {}", pos);
    }
    Ok(())
}

/// Write sizes for a serializer, used in turn, zero included but not only zeros.
fn write_sizes() -> impl Strategy<Value = Vec<usize>> {
    (1..40usize, prop::collection::vec(0..40usize, 0..8))
        .prop_map(|(first, rest)| [vec![first], rest].concat())
}

/// Serializes `st` in `format` through buffers of `sizes` in turn, twice with a reset in
/// between. Checks that it writes what one large buffer gets, then nothing.
fn check_chunked_serialization(
    st: &SeekTable,
    format: Format,
    sizes: &[usize],
) -> Result<(), TestCaseError> {
    let whole = serialize(st, format);
    let mut ser = st.clone().into_format_serializer(format);
    prop_assert_eq!(ser.encoded_len(), whole.len());
    for _ in 0..2 {
        let mut written: Vec<u8> = vec![];
        let mut buf = [0; 40];
        for &size in sizes.iter().cycle() {
            if written.len() >= whole.len() && size > 0 {
                prop_assert_eq!(ser.write_into(&mut buf[..size]), 0);
                break;
            }
            let n = ser.write_into(&mut buf[..size]);
            prop_assert!(n <= size);
            written.extend(&buf[..n]);
        }
        prop_assert!(written == whole);
        ser.reset();
    }
    Ok(())
}

/// The descriptor byte of a seek table serialized in `format`, in `bytes` of the table alone.
fn descriptor_at(format: Format, bytes: &[u8]) -> usize {
    match format {
        // Skippable header, then the frame count
        Format::Head => 12,
        // The descriptor comes before the 4-byte magic number
        Format::Foot => bytes.len() - 5,
    }
}

fn format() -> impl Strategy<Value = Format> {
    prop_oneof![Just(Format::Head), Just(Format::Foot)]
}

proptest! {
    /// The frames are zstd frames of what the seek table says, with checksums if asked for, and
    /// as large as the frame size policy wants them.
    #[test]
    fn raw_encoder_writes_the_frames_its_seek_table_lists(archive in archive()) {
        let st = &archive.seek_table;
        prop_assert_eq!(st.size_comp(), archive.frames.len() as u64);
        prop_assert_eq!(st.size_decomp(), archive.input.len() as u64);
        prop_assert_eq!(archive.ended_by_policy.len(), st.num_frames() as usize);

        for i in 0..st.num_frames() {
            let frame = archive.frame(i);
            prop_assert_eq!(zstd_safe::find_frame_compressed_size(frame).unwrap(), frame.len());
            // The Content_Checksum_flag of the Frame_Header_Descriptor
            prop_assert_eq!(frame[4] & 0x4 != 0, archive.checksum);
            let decoded = zstd_stream_decode(frame, archive.prefix.as_deref());
            prop_assert!(decoded == archive.frame_content(i), "frame {}", i);

            let (c_size, d_size) = (frame.len(), archive.frame_content(i).len());
            prop_assert!(d_size <= SEEKABLE_MAX_FRAME_SIZE);
            match archive.policy {
                FrameSizePolicy::Uncompressed(size) => {
                    let size = size as usize;
                    prop_assert!(d_size <= size);
                    if archive.ended_by_policy[i as usize] {
                        prop_assert_eq!(d_size, size, "frame {}", i);
                    }
                }
                FrameSizePolicy::Compressed(size) => {
                    if archive.ended_by_policy[i as usize] {
                        prop_assert!(c_size >= size as usize, "frame {}", i);
                    }
                }
            }
        }
    }

    #[test]
    fn archives_decode_with_the_reference_implementation(
        archive in archive_with(any::<bool>(), Just(None)),
        reads in reads(),
    ) {
        let whole = archive.with_seek_table();
        prop_assert!(zstd::decode_all(&whole[..]).unwrap() == archive.input);
        check_reference_reads(&whole, &archive.input, &reads)?;
    }

    #[test]
    fn decoder_behaves_like_a_cursor_over_the_input(
        archive in archive(),
        tables in table_source(),
        chunk in chunk(),
        start in start(),
        calls in calls(),
    ) {
        check_decoder(&archive, &tables, chunk, &start, &calls)?;
    }

    #[test]
    fn encoder_archives_decode_everywhere(
        input in content(),
        policy in frame_size_policy(),
        checksum in any::<bool>(),
        calls in encoder_calls(),
        chunk in 1..70_000usize,
        reads in reads(),
    ) {
        let archive = encode_with_writer(&input, policy, checksum, &calls, chunk)?;
        let mut decoder = Decoder::new(BytesWrapper::new(&archive)).unwrap();
        prop_assert!(decode_all(&mut decoder, 1000, None).unwrap() == input);
        prop_assert!(zstd::decode_all(&archive[..]).unwrap() == input);
        check_reference_reads(&archive, &input, &reads)?;
    }

    /// A damaged archive with checksums fails to decode or decodes to its input. Damage to the
    /// frames is noticed from wherever a read starts, damage to the seek table by whole reads.
    #[test]
    fn damage_never_passes_for_content(
        archive in archive_with(Just(true), sometimes_a_prefix()),
        damage in damage(),
        to_seek_table in any::<bool>(),
        from in any::<Index>(),
        chunk in chunk(),
        buf_len in 1..5000usize,
    ) {
        let mut bytes = archive.with_seek_table();
        // The seek table is the smaller part, but gets damaged as often as the frames
        let frames_end = archive.frames.len();
        let region = if to_seek_table { frames_end..bytes.len() } else { 0..frames_end };
        damage.apply(&mut bytes, region);
        // A wrong decompressed size in the seek table shifts where the later frames start, which
        // a read from one of them cannot notice, and a cut loses the seek table
        let frames_only = !to_seek_table && matches!(damage, Damage::Flip { .. });
        let offset = if frames_only { from.index(archive.input.len() + 1) } else { 0 };
        let prefix = archive.prefix.as_deref();
        let result = DecodeOptions::new(Chunked::new(&bytes, chunk))
            .offset(offset as u64)
            .into_decoder()
            .and_then(|mut decoder| decode_all(&mut decoder, buf_len, prefix));
        if let Ok(decoded) = result {
            prop_assert!(decoded == archive.input[offset..], "{:?} accepted", damage);
        }
    }

    #[test]
    fn forged_seek_tables_never_pass_for_content(
        archive in archive(),
        changes in entry_changes(),
        from in any::<Index>(),
    ) {
        let forged = forge(&archive, &changes);
        let offset = from.index(forged.size_decomp() as usize + 1) as u64;
        check_forged_read(&archive, forged.clone(), offset)?;
        check_forged_read(&archive, forged, 0)?;
    }

    /// Bytes that are no archive, or frames that are no zstd frames, fail without a panic.
    #[test]
    fn garbage_is_rejected_without_panicking(
        bytes in content(),
        d_sizes in prop::collection::vec(0..5000u32, 0..8),
        cuts in prop::collection::vec(any::<Index>(), 0..8),
        buf_len in 1..5000usize,
    ) {
        for format in [Format::Head, Format::Foot] {
            let _ = SeekTable::from_seekable_format(&mut BytesWrapper::new(&bytes), format);
        }
        let _ = SeekTable::from_reader(&bytes[..]);
        if let Ok(mut decoder) = Decoder::new(BytesWrapper::new(&bytes)) {
            let _ = decode_all(&mut decoder, buf_len, None);
        }

        // The bytes as frames, split where `cuts` pick
        let mut cuts: Vec<usize> = cuts.iter().map(|cut| cut.index(bytes.len() + 1)).collect();
        cuts.push(bytes.len());
        cuts.sort_unstable();
        let mut sizes = vec![];
        let mut start = 0;
        for (cut, d_size) in cuts.iter().zip(d_sizes.iter().chain(std::iter::repeat(&0))) {
            sizes.push(((cut - start) as u32, *d_size));
            start = *cut;
        }
        let mut decoder = DecodeOptions::new(BytesWrapper::new(&bytes))
            .seek_table(seek_table_of(&sizes))
            .into_decoder()
            .unwrap();
        let _ = decode_all(&mut decoder, buf_len, None);
    }

    #[test]
    fn seek_table_lookups_follow_the_frame_sizes(
        sizes in frame_sizes(),
        positions in prop::collection::vec(any::<u64>(), 0..20),
    ) {
        let st = seek_table_of(&sizes);
        let num_frames = sizes.len() as u32;
        prop_assert_eq!(st.num_frames(), num_frames);
        let c_bounds = bounds(sizes.iter().map(|&(c_size, _)| c_size));
        let d_bounds = bounds(sizes.iter().map(|&(_, d_size)| d_size));
        prop_assert_eq!(st.size_comp(), c_bounds[sizes.len()]);
        prop_assert_eq!(st.size_decomp(), d_bounds[sizes.len()]);
        let max = |size: fn(&(u32, u32)) -> u32| {
            u64::from(sizes.iter().map(size).max().unwrap_or(0))
        };
        prop_assert_eq!(st.max_frame_size_comp(), max(|&(c_size, _)| c_size));
        prop_assert_eq!(st.max_frame_size_decomp(), max(|&(_, d_size)| d_size));

        for (i, &(c_size, d_size)) in (0..).zip(&sizes) {
            let at = i as usize;
            prop_assert_eq!(st.frame_start_comp(i).unwrap(), c_bounds[at]);
            prop_assert_eq!(st.frame_end_comp(i).unwrap(), c_bounds[at + 1]);
            prop_assert_eq!(st.frame_size_comp(i).unwrap(), u64::from(c_size));
            prop_assert_eq!(st.frame_start_decomp(i).unwrap(), d_bounds[at]);
            prop_assert_eq!(st.frame_end_decomp(i).unwrap(), d_bounds[at + 1]);
            prop_assert_eq!(st.frame_size_decomp(i).unwrap(), u64::from(d_size));
        }
        prop_assert!(st.frame_start_comp(num_frames).unwrap_err().is_frame_index_too_large());
        prop_assert!(st.frame_end_decomp(num_frames).unwrap_err().is_frame_index_too_large());
        prop_assert!(st.frame_size_comp(num_frames).unwrap_err().is_frame_index_too_large());

        check_frame_lookup(|pos| st.frame_index_comp(pos), &c_bounds, &positions)?;
        check_frame_lookup(|pos| st.frame_index_decomp(pos), &d_bounds, &positions)?;
    }

    /// Serialization does not depend on the buffer sizes, and parsing gets back the table from
    /// sources that return few bytes per read and hold other data next to the table.
    #[test]
    fn seek_tables_round_trip(
        sizes in frame_sizes(),
        write_sizes in write_sizes(),
        chunk in 1..40usize,
        other in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let st = seek_table_of(&sizes);
        for format in [Format::Head, Format::Foot] {
            check_chunked_serialization(&st, format, &write_sizes)?;
            let bytes = serialize(&st, format);
            let parse = |bytes: &[u8]| {
                SeekTable::from_seekable_format(&mut Chunked::new(bytes, chunk), format)
            };
            prop_assert_eq!(&parse(&bytes).unwrap(), &st);
            // A head table comes before the frames, a foot table after them
            let beside = match format {
                Format::Head => [&bytes[..], &other].concat(),
                Format::Foot => [&other[..], &bytes].concat(),
            };
            prop_assert_eq!(&parse(&beside).unwrap(), &st);
        }

        let head = [&serialize(&st, Format::Head)[..], &other].concat();
        let mut reader = Chunked::new(&head, chunk);
        prop_assert_eq!(&SeekTable::from_reader(&mut reader).unwrap(), &st);
        prop_assert_eq!(reader.inner.position() as usize, head.len() - other.len());
    }

    #[test]
    fn seek_tables_agree_with_the_reference_implementation(
        sizes in frame_sizes(),
        checksums in prop::option::of(prop::collection::vec(any::<u32>(), 300)),
    ) {
        let st = seek_table_of(&sizes);
        let ours = serialize(&st, Format::Foot);
        let mut reference = zstd_safe::seekable::Seekable::create();
        reference.init_buff(&ours).unwrap();
        prop_assert_eq!(reference.num_frames(), st.num_frames());
        for i in 0..st.num_frames() {
            let theirs = (
                reference.frame_compressed_offset(i).unwrap(),
                reference.frame_decompressed_offset(i).unwrap(),
                reference.frame_compressed_size(i).unwrap() as u64,
                reference.frame_decompressed_size(i).unwrap() as u64,
            );
            let ours = (
                st.frame_start_comp(i).unwrap(),
                st.frame_start_decomp(i).unwrap(),
                st.frame_size_comp(i).unwrap(),
                st.frame_size_decomp(i).unwrap(),
            );
            prop_assert_eq!(theirs, ours, "frame {}", i);
        }

        // The reference writes legacy entries with checksums if asked to
        let mut log = zstd_safe::seekable::FrameLog::create(checksums.is_some());
        for (i, &(c_size, d_size)) in sizes.iter().enumerate() {
            let checksum = checksums.as_ref().map(|sums| sums[i]);
            log.log_frame(c_size, d_size, checksum).unwrap();
        }
        // Room for the skippable header, the integrity field, and entries with checksums
        let mut theirs = vec![0; 8 + 9 + sizes.len() * 12];
        let mut out = OutBuffer::around(&mut theirs[..]);
        prop_assert_eq!(log.write_seek_table(&mut out).unwrap(), 0);
        let written = out.pos();
        theirs.truncate(written);
        let parsed = SeekTable::from_seekable(&mut BytesWrapper::new(&theirs)).unwrap();
        prop_assert_eq!(&parsed, &st);
    }

    /// A damaged seek table is rejected or parses to a table that serializes to the same bytes,
    /// up to the descriptor bits the format leaves unused. Legacy tables, whose checksums the
    /// serializer does not write, are left out.
    #[test]
    fn damaged_seek_tables_are_rejected_or_read_as_written(
        sizes in prop::collection::vec((any::<u32>(), any::<u32>()), 0..20),
        format in format(),
        damage in damage(),
    ) {
        let mut bytes = serialize(&seek_table_of(&sizes), format);
        let len = bytes.len();
        damage.apply(&mut bytes, 0..len);
        let parsed = SeekTable::from_seekable_format(&mut BytesWrapper::new(&bytes), format);
        if let Ok(parsed) = parsed {
            let descriptor = descriptor_at(format, &bytes);
            if bytes[descriptor] & 0x80 == 0 {
                bytes[descriptor] &= !0x03;
                prop_assert!(serialize(&parsed, format) == bytes, "{:?} accepted", damage);
            }
        }
    }
}
