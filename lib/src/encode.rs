// Model-output: Claude Fable 5.1
// Model-output: Claude Opus 5
#[cfg(feature = "std")]
use alloc::vec::Vec;
use zstd_safe::{
    CCtx, CParameter, CompressionLevel, InBuffer, OutBuffer, ResetDirective,
    zstd_sys::ZSTD_EndDirective,
};

#[cfg(feature = "std")]
use crate::seek_table::Format;
use crate::{Error, SEEKABLE_MAX_FRAME_SIZE, SeekTable, error::Result};

// Constant value always can be casted
const MAX_FRAME_SIZE: u32 = SEEKABLE_MAX_FRAME_SIZE as u32;

/// A policy that controls when new frames are started automatically.
///
/// The uncompressed frame size will never get greater than [`SEEKABLE_MAX_FRAME_SIZE`],
/// independent of the frame size policy in use, i.e. a new frame will **always** be started if
/// the uncompressed frame size reaches [`SEEKABLE_MAX_FRAME_SIZE`].
///
/// In all cases, the frame size must be greater than 0.
#[derive(Debug, Clone)]
pub enum FrameSizePolicy {
    /// Starts a new frame when the compressed size of the current frame exceeds the specified
    /// size.
    ///
    /// This will not accurately limit the compressed frame size, but start a new frame if
    /// the compressed frame size is equal to or exceeds the configured value.
    Compressed(u32),
    /// Starts a new frame when the uncompressed data of the current frame reaches the specified
    /// size.
    Uncompressed(u32),
}

impl Default for FrameSizePolicy {
    /// The default policy starts a new frame when the uncompressed data of the current frame
    /// reaches 2MiB.
    fn default() -> Self {
        Self::Uncompressed(0x200_000)
    }
}

/// The progress of a compression step.
#[derive(Debug)]
pub struct CompressionProgress {
    in_progress: usize,
    out_progress: usize,
}

impl CompressionProgress {
    fn new(in_progress: usize, out_progress: usize) -> Self {
        Self {
            in_progress,
            out_progress,
        }
    }

    /// The input progress, i.e. the number of bytes that were consumed from the input buffer.
    pub fn in_progress(&self) -> usize {
        self.in_progress
    }

    /// The output progress, i.e. the number of bytes that were written to the output buffer.
    pub fn out_progress(&self) -> usize {
        self.out_progress
    }
}

/// The progress of writing the frame epilogue.
#[derive(Debug)]
pub struct EpilogueProgress {
    out_progress: usize,
    data_left: usize,
}

impl EpilogueProgress {
    fn new(out_progress: usize, data_left: usize) -> Self {
        Self {
            out_progress,
            data_left,
        }
    }

    /// The output progress, i.e. the number of bytes that were written to the output buffer.
    pub fn out_progress(&self) -> usize {
        self.out_progress
    }

    /// A minimal estimation of the bytes left to flush. The epilogue is entirely written if this
    /// value is zero.
    pub fn data_left(&self) -> usize {
        self.data_left
    }
}

/// Options that configure how data is compressed.
///
/// # Examples
///
/// Supports builder like chaining.
///
/// ```
/// use zeekstd::{EncodeOptions, FrameSizePolicy};
///
/// let encoder = EncodeOptions::new()
///     .checksum_flag(false)
///     .compression_level(5)
///     .frame_size_policy(FrameSizePolicy::Uncompressed(8192))
///     .into_raw_encoder()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct EncodeOptions<'a> {
    cctx: CCtx<'a>,
    frame_policy: FrameSizePolicy,
    checksum_flag: bool,
    compression_level: CompressionLevel,
}

impl Default for EncodeOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EncodeOptions<'a> {
    /// Creates a set of options with default values.
    ///
    /// # Panics
    ///
    /// If allocation of [`CCtx`] fails.
    pub fn new() -> Self {
        Self::with_cctx(CCtx::create())
    }

    /// Tries to create new options with default values.
    ///
    /// Returns `None` if allocation of [`CCtx`] fails.
    pub fn try_new() -> Option<Self> {
        let cctx = CCtx::try_create()?;
        Some(Self::with_cctx(cctx))
    }

    /// Create options with the given compression context.
    pub fn with_cctx(cctx: CCtx<'a>) -> Self {
        Self {
            cctx,
            frame_policy: FrameSizePolicy::default(),
            checksum_flag: false,
            compression_level: CompressionLevel::default(),
        }
    }

    /// Sets a [`CCtx`].
    pub fn cctx(mut self, cctx: CCtx<'a>) -> Self {
        self.cctx = cctx;
        self
    }

    /// Sets a [`FrameSizePolicy`].
    pub fn frame_size_policy(mut self, policy: FrameSizePolicy) -> Self {
        self.frame_policy = policy;
        self
    }

    /// Whether to write 32 bit checksums at the end of frames.
    pub fn checksum_flag(mut self, flag: bool) -> Self {
        self.checksum_flag = flag;
        self
    }

    /// Sets the compression level used by zstd.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Creates a [`RawEncoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder cannot be created.
    pub fn into_raw_encoder(self) -> Result<RawEncoder<'a>> {
        RawEncoder::with_opts(self)
    }

    /// Creates an [`Encoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the encoder cannot be created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::EncodeOptions;
    ///
    /// let output = File::create("data.zst").unwrap();
    /// let encoder = EncodeOptions::new()
    ///     .checksum_flag(true)
    ///     .into_encoder(output)
    ///     .unwrap();
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn into_encoder<W>(self, writer: W) -> Result<Encoder<'a, W>> {
        Encoder::with_opts(writer, self)
    }
}

/// A reusable, seekable encoder.
///
/// Performs low level in-memory seekable compression for streams of data. The `RawEncoder` starts
/// new frames automatically at 2MiB of uncompressed data by default. See [`EncodeOptions`] to
/// change this and other compression parameters.
///
/// # Examples
///
/// Creates seekable compressed files using a `RawEncoder`. See the [`Encoder`], for a more
/// approachable interface.
///
/// ```
/// use zeekstd::RawEncoder;
///
/// let mut encoder = RawEncoder::new()?;
/// // We just assume that all data fits into `buf`. Real-world applications should allocate more
/// // memory when needed.
/// let mut buf = [0u8; 64];
/// let mut in_progress = 0;
/// let mut out_progress = 0;
/// let input = b"Hello, World!";
///
/// // Compress input data...
/// while in_progress < input.len() {
///     let prog = encoder.compress(&input[in_progress..], &mut buf[out_progress..])?;
///     in_progress += prog.in_progress();
///     out_progress += prog.out_progress();
/// }
///
/// // Write the frame epilogue...
/// // This is done automatically during compression according to the configured frame size policy,
/// // however, you need to end the last frame manually
/// loop {
///     let prog = encoder.end_frame(&mut buf[out_progress..])?;
///     out_progress += prog.out_progress();
///     if prog.data_left() == 0 {
///         break;
///     }
/// }
///
/// // Finally, append the seek table...
/// let mut seek_table_serializer = encoder.into_seek_table().into_serializer();
/// loop {
///     let n = seek_table_serializer.write_into(&mut buf[out_progress..]);
///     if n == 0 {
///         break;
///     }
/// #   out_progress += n;
/// }
///
/// # use zeekstd::{BytesWrapper, Decoder};
/// # let mut decoder = Decoder::new(BytesWrapper::new(&buf[..out_progress]))?;
/// # let mut buf = [0u8; 16];
/// # let n = decoder.decompress(&mut buf)?;
/// # assert_eq!(input, &buf[..n]);
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct RawEncoder<'a> {
    cctx: CCtx<'a>,
    frame_policy: FrameSizePolicy,
    /// Whether a frame ending was started but could not be written completely yet. Zstd has to
    /// finish it before anything else may happen to the frame.
    frame_ending: bool,
    frame_c_size: u32,
    frame_d_size: u32,
    seek_table: SeekTable,
}

impl<'a> RawEncoder<'a> {
    /// Creates a new `RawEncoder` with the given [`EncodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder could not be created.
    pub fn with_opts(mut opts: EncodeOptions<'a>) -> Result<Self> {
        if let FrameSizePolicy::Uncompressed(0) | FrameSizePolicy::Compressed(0) = opts.frame_policy
        {
            return Err(Error::invalid_frame_size_policy());
        }

        opts.cctx
            .set_parameter(CParameter::CompressionLevel(opts.compression_level))?;
        opts.cctx
            .set_parameter(CParameter::ChecksumFlag(opts.checksum_flag))?;

        Ok(Self {
            cctx: opts.cctx,
            frame_policy: opts.frame_policy,
            frame_ending: false,
            frame_c_size: 0,
            frame_d_size: 0,
            seek_table: SeekTable::new(),
        })
    }

    /// Performs a streaming compression step from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. The returned [`CompressionProgress`]
    /// indicates how many bytes were consumed from `input` and written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more compressed data, and then present again remaining input data.
    ///
    /// If a `prefix` is passed, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a prefix involves building tables, which is a CPU consuming
    /// operation, with non-negligible impact on latency. This should be avoided for small frame
    /// sizes. If there is a need to use the same prefix multiple times without long distance mode,
    /// consider loading a dictionary into the compression context instead.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress_with_prefix<'b: 'a>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<CompressionProgress> {
        if self.is_frame_complete() {
            let mut out_progress = 0;
            while out_progress < output.len() {
                let progress = self.end_frame(&mut output[out_progress..])?;
                out_progress += progress.out_progress;
                if progress.data_left == 0 {
                    break;
                }
            }

            Ok(CompressionProgress::new(0, out_progress))
        } else {
            let limit = input.len().min(self.remaining_frame_size());
            let mut in_buf = InBuffer::around(&input[..limit]);
            let mut out_buf = OutBuffer::around(output);
            // Reference prefix at the beginning of a frame
            // TODO: chain when stable
            if let Some(pref) = prefix {
                if self.frame_d_size == 0 {
                    self.cctx.ref_prefix(pref)?;
                }
            }

            while in_buf.pos() < limit && out_buf.pos() < out_buf.capacity() {
                self.cctx.compress_stream2(
                    &mut out_buf,
                    &mut in_buf,
                    ZSTD_EndDirective::ZSTD_e_continue,
                )?;
            }

            // Casting should always be fine
            self.frame_c_size += out_buf.pos() as u32;
            self.frame_d_size += in_buf.pos() as u32;

            Ok(CompressionProgress::new(in_buf.pos(), out_buf.pos()))
        }
    }
}

impl RawEncoder<'_> {
    /// Creates a new `RawEncoder` with default parameters.
    ///
    /// This is equivalent to calling `EncodeOptions::new().into_raw_encoder()`.
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder cannot be created.
    pub fn new() -> Result<Self> {
        Self::with_opts(EncodeOptions::new())
    }

    /// Performs a streaming compression step from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. The returned [`CompressionProgress`]
    /// indicates how many bytes were consumed from `input` and written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more compressed data, and then present again remaining input data.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::RawEncoder;
    ///
    /// let mut encoder = RawEncoder::new()?;
    /// let input = b"Hello, World!";
    /// let mut output: Vec<u8> = vec![];
    /// let mut in_progress = 0;
    /// let mut buf = [0u8; 4];
    ///
    /// while in_progress < input.len() {
    ///     let prog = encoder.compress(&input[in_progress..], &mut buf)?;
    ///     output.extend(&buf[..prog.out_progress()]);
    ///     in_progress += prog.in_progress();
    /// }
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<CompressionProgress> {
        self.compress_with_prefix(input, output, None)
    }

    /// Ends the current frame and adds it to the seek table.
    ///
    /// Call this repetitively to write the frame epilogue to `output`. The Encoder terminates
    /// frames during compression automatically according to the configured [`FrameSizePolicy`].
    /// Additionally this function can be used to end frames manually at any time during
    /// compression, however, you always need to end the last frame manually.
    ///
    /// The returned [`EpilogueProgress`] indicates how many bytes were written to `output` and
    /// provides a minimal estimation of how many bytes are left to flush. Should be called until
    /// no more bytes are left to flush.
    ///
    /// # Errors
    ///
    /// Fails if the frame epilogue cannot be written or the frame limit is reached.
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::RawEncoder;
    ///
    /// let mut encoder = RawEncoder::new()?;
    /// let mut output: Vec<u8> = vec![];
    /// let mut in_progress = 0;
    /// let mut buf = [0u8; 128];
    ///
    /// // Compress input data...
    ///
    /// loop {
    ///     let prog = encoder.end_frame(&mut buf)?;
    ///     output.extend(&buf[..prog.out_progress()]);
    ///     if prog.data_left() == 0 {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn end_frame(&mut self, output: &mut [u8]) -> Result<EpilogueProgress> {
        let mut empty_buf = InBuffer::around(&[]);
        let mut out_buf = OutBuffer::around(output);

        loop {
            let prev_out_pos = out_buf.pos();
            let n = self.cctx.compress_stream2(
                &mut out_buf,
                &mut empty_buf,
                ZSTD_EndDirective::ZSTD_e_end,
            )?;

            // Casting should always be fine
            self.frame_c_size += (out_buf.pos() - prev_out_pos) as u32;

            // Check first if writing the frame epilogue finished before checking whether the out
            // buffer is full. Changing the order leads to frames not beeing logged when the frame
            // epilogue fits exactly in the buffer.
            if n == 0 {
                break;
            }

            if out_buf.pos() == out_buf.capacity() {
                // Indicate that more buffer space is required
                self.frame_ending = true;
                return Ok(EpilogueProgress::new(out_buf.pos(), n));
            }
        }

        self.seek_table
            .log_frame(self.frame_c_size, self.frame_d_size)?;
        self.reset_frame();

        // If we get here the frame is complete
        Ok(EpilogueProgress::new(out_buf.pos(), 0))
    }

    /// Flushes the data that is buffered inside the compression context into `output` without
    /// ending the frame.
    ///
    /// Call this repetitively until [`EpilogueProgress::data_left`] is zero. Everything consumed
    /// before the call is then in `output` or in an earlier output. A flush closes a block, which
    /// costs a little compression ratio, so it is meant for callers that need what they have
    /// written so far to reach the output now.
    ///
    /// Writes nothing for a frame that consumed no input. A frame ending left pending by
    /// [`Self::end_frame`] running out of output space is finished instead, which logs the frame
    /// in the seek table and starts a new one.
    ///
    /// # Errors
    ///
    /// If flushing fails.
    pub fn flush(&mut self, output: &mut [u8]) -> Result<EpilogueProgress> {
        // A frame ending that is under way has to be finished: zstd would otherwise leave the
        // frame unterminated, and the seek table would never learn about it.
        if self.frame_ending {
            return self.end_frame(output);
        }

        // Nothing was fed into this frame, so nothing is buffered: leave the compression session
        // untouched, so that a prefix can still be referenced for the frame about to start.
        if self.frame_d_size == 0 {
            return Ok(EpilogueProgress::new(0, 0));
        }

        let mut empty_buf = InBuffer::around(&[]);
        let mut out_buf = OutBuffer::around(output);

        loop {
            let n = self.cctx.compress_stream2(
                &mut out_buf,
                &mut empty_buf,
                ZSTD_EndDirective::ZSTD_e_flush,
            )?;

            if n == 0 || out_buf.pos() == out_buf.capacity() {
                // Casting should always be fine
                self.frame_c_size += out_buf.pos() as u32;
                return Ok(EpilogueProgress::new(out_buf.pos(), n));
            }
        }
    }

    /// Returns a reference to the internal [`SeekTable`].
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::RawEncoder;
    ///
    /// let mut encoder = RawEncoder::new()?;
    /// let seek_table = encoder.seek_table();
    ///
    /// assert_eq!(seek_table.num_frames(), 0);
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
    }

    /// Consumes this raw encoder and returns the internal [`SeekTable`].
    pub fn into_seek_table(self) -> SeekTable {
        self.seek_table
    }

    /// Resets the current frame.
    ///
    /// This will discard any compression progress for the current frame and resets the
    /// compression session.
    #[allow(clippy::missing_panics_doc)]
    pub fn reset_frame(&mut self) {
        self.frame_ending = false;
        self.frame_c_size = 0;
        self.frame_d_size = 0;
        self.cctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
    }

    /// Resets the internal [`SeekTable`].
    ///
    /// Note that this does not reset the current frame, in most cases this function should be
    /// called together with `reset_frame()`.
    ///
    /// # Example
    ///
    /// ```
    /// # use zeekstd::RawEncoder;
    /// # let mut encoder = RawEncoder::new()?;
    /// encoder.reset_frame();
    /// encoder.reset_seek_table();
    /// assert_eq!(encoder.seek_table().num_frames(), 0);
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn reset_seek_table(&mut self) {
        self.seek_table = SeekTable::new();
    }

    fn remaining_frame_size(&self) -> usize {
        let n = match self.frame_policy {
            FrameSizePolicy::Compressed(_) => MAX_FRAME_SIZE - self.frame_d_size,
            FrameSizePolicy::Uncompressed(limit) => MAX_FRAME_SIZE.min(limit) - self.frame_d_size,
        };

        n.try_into().expect("Remaining frame size fits in usize")
    }

    fn is_frame_complete(&self) -> bool {
        match self.frame_policy {
            FrameSizePolicy::Compressed(size) => {
                size <= self.frame_c_size || MAX_FRAME_SIZE <= self.frame_d_size
            }
            FrameSizePolicy::Uncompressed(limit) => MAX_FRAME_SIZE.min(limit) <= self.frame_d_size,
        }
    }
}

/// A single-use seekable encoder.
///
/// The `Encoder` starts new frames automatically at 2MiB of uncompressed data by default. See
/// [`EncodeOptions`] to change this and other compression parameters.
///
/// # Examples
///
/// Creates a seekable compressed file using an `Encoder`.
///
/// ```no_run
/// use std::{fs::File, io};
/// use zeekstd::Encoder;
///
/// let mut input = File::open("foo")?;
/// let output = File::create("foo.zst")?;
/// let mut encoder = Encoder::new(output)?;
/// io::copy(&mut input, &mut encoder)?;
/// // End the last frame and write the seek table to the output
/// encoder.finish()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub struct Encoder<'a, W> {
    raw: RawEncoder<'a>,
    /// Compressed bytes on their way to the writer: `out_buf[out_buf_written..out_buf_pos]` still
    /// has to be written, `out_buf[out_buf_pos..]` is free.
    out_buf: Vec<u8>,
    out_buf_written: usize,
    out_buf_pos: usize,
    writer: W,
    written_compressed: u64,
}

#[cfg(feature = "std")]
impl<'a, W> Encoder<'a, W> {
    /// Creates a new `Encoder` with default parameters.
    ///
    /// This is equivalent to calling `EncodeOptions::new().into_encoder(writer)`.
    ///
    /// # Errors
    ///
    /// Fails if the encoder could not be created.
    pub fn new(writer: W) -> Result<Self> {
        Self::with_opts(writer, EncodeOptions::new())
    }

    /// Creates a new `Encoder` with the given [`EncodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the encoder could not be created.
    pub fn with_opts(writer: W, opts: EncodeOptions<'a>) -> Result<Self> {
        Ok(Self {
            raw: opts.into_raw_encoder()?,
            out_buf: alloc::vec![0; CCtx::out_size()],
            out_buf_written: 0,
            out_buf_pos: 0,
            writer,
            written_compressed: 0,
        })
    }
}

#[cfg(feature = "std")]
impl<W> Encoder<'_, W> {
    /// Returns a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.raw.seek_table
    }

    /// The total number of compressed bytes that have been written to the internal writer.
    pub fn written_compressed(&self) -> u64 {
        self.written_compressed
    }

    /// Converts this encoder into the internal [`SeekTable`].
    pub fn into_seek_table(self) -> SeekTable {
        self.raw.into_seek_table()
    }
}

#[cfg(feature = "std")]
impl<'a, W: std::io::Write> Encoder<'a, W> {
    /// Consumes and compresses input data from `buf`.
    ///
    /// Call this repetitively to consume input data. Compressed data gets written to the internal
    /// writer. Returns the number of bytes consumed from `buf`.
    ///
    /// If a `prefix` is provided, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a prefix involves building tables, which is a CPU consuming
    /// operation, with non-negligible impact on latency. This should be avoided for small frame
    /// sizes. If there is a need to use the same prefix multiple times without long distance mode,
    /// consider loading a dictionary into the compression context instead.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress_with_prefix<'b: 'a>(
        &mut self,
        buf: &[u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<usize> {
        let mut input_progress = 0;

        while input_progress < buf.len() {
            // Consumed input cannot be handed back, so no write error may follow it within one
            // call: make room before compressing, and once some input went in, leave the error
            // for the next call to report.
            match self.flush_out_buf(false) {
                Ok(()) => {}
                Err(err) if input_progress == 0 => return Err(err),
                Err(_) => break,
            }

            let progress = self.raw.compress_with_prefix(
                &buf[input_progress..],
                &mut self.out_buf[self.out_buf_pos..],
                prefix,
            )?;

            if progress.in_progress == 0 && progress.out_progress == 0 {
                break;
            }

            self.out_buf_pos += progress.out_progress;
            input_progress += progress.in_progress;
        }

        Ok(input_progress)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> Encoder<'_, W> {
    /// Consumes and compresses input data from `buf`.
    ///
    /// Call this repetitively to consume input data. Compressed data gets written to the internal
    /// writer. Returns the number of bytes consumed from `buf`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::Encoder;
    ///
    /// let output = File::create("data.zst")?;
    /// let mut encoder = Encoder::new(output)?;
    ///
    /// encoder.compress(b"Hello, World!")?;
    /// # Ok::<(), zeekstd::Error>(())
    ///
    /// ```
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress(&mut self, buf: &[u8]) -> Result<usize> {
        self.compress_with_prefix(buf, None)
    }

    /// Ends the current frame.
    ///
    /// Call this to write the frame epilogue to the internal writer. Returns the number of bytes
    /// written.
    ///
    /// # Errors
    ///
    /// Fails if the frame epilogue cannot be written or the frame limit is reached.
    pub fn end_frame(&mut self) -> Result<usize> {
        let mut progress = 0;

        loop {
            self.flush_out_buf(false)?;
            let prog = self.raw.end_frame(&mut self.out_buf[self.out_buf_pos..])?;
            self.out_buf_pos += prog.out_progress;
            progress += prog.out_progress;

            if prog.data_left == 0 {
                return Ok(progress);
            }
        }
    }

    /// Ends the current frame and writes the seek table.
    ///
    /// Call this to write the seek table in `Foot` format to the internal writer. Returns the
    /// total number of bytes, i.e. all compressed data plus the size of the seek table,
    /// written by this `Encoder`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::Encoder;
    ///
    /// let output = File::create("data.zst")?;
    /// let mut encoder = Encoder::new(output)?;
    ///
    /// encoder.compress(b"Hello")?;
    /// encoder.finish()?;
    /// # Ok::<(), zeekstd::Error>(())
    ///
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if the frame cannot be finished or writing the seek table fails.
    pub fn finish(self) -> Result<u64> {
        self.finish_format(Format::Foot)
    }

    /// Ends the current frame and writes the seek table in the given format.
    ///
    /// Returns the total number of bytes, i.e. all compressed data plus the size of the seek table,
    /// written by this `Encoder`.
    ///
    /// # Errors
    ///
    /// Fails if the frame cannot be finished or writing the seek table fails.
    pub fn finish_format(mut self, format: Format) -> Result<u64> {
        self.end_frame()?;
        self.flush_out_buf(true)?;
        // Nothing can be retried from here on, `self` is consumed, so plain `write_all` will do
        let mut ser = self.raw.into_seek_table().into_format_serializer(format);

        loop {
            let n = ser.write_into(&mut self.out_buf);
            if n == 0 {
                break;
            }

            self.writer.write_all(&self.out_buf[..n])?;
            self.written_compressed += n as u64;
        }

        self.writer.flush()?;

        Ok(self.written_compressed)
    }

    /// Writes the buffered compressed bytes to the writer, if the buffer is full or `force` is
    /// true.
    ///
    /// Bytes the writer accepts leave the buffer at once, so when a write fails partway, only the
    /// bytes still owed remain: calling this again resumes there and never resends a prefix.
    fn flush_out_buf(&mut self, force: bool) -> Result<()> {
        if self.out_buf_pos < self.out_buf.len() && !force {
            return Ok(());
        }

        while self.out_buf_written < self.out_buf_pos {
            let pending = &self.out_buf[self.out_buf_written..self.out_buf_pos];
            match self.writer.write(pending) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    )
                    .into());
                }
                Ok(n) => {
                    assert!(
                        n <= pending.len(),
                        "writer accepted more bytes than it was given"
                    );
                    self.out_buf_written += n;
                    self.written_compressed += n as u64;
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err.into()),
            }
        }

        self.out_buf_written = 0;
        self.out_buf_pos = 0;

        Ok(())
    }

    /// Moves everything the compression context still holds for the current frame into the
    /// output buffer, writing the buffer out whenever it fills up.
    fn drain_cctx(&mut self) -> Result<()> {
        loop {
            self.flush_out_buf(false)?;
            let prog = self.raw.flush(&mut self.out_buf[self.out_buf_pos..])?;
            self.out_buf_pos += prog.out_progress;

            if prog.data_left == 0 {
                return Ok(());
            }
        }
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> std::io::Write for Encoder<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(self.compress(buf)?)
    }

    /// Delivers everything written so far to the writer and flushes it. This does not end the
    /// current frame, unless a frame ending was already under way because an earlier call failed
    /// partway, in which case that ending is completed first.
    fn flush(&mut self) -> std::io::Result<()> {
        self.drain_cctx()?;
        self.flush_out_buf(true)?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::tests::INPUT;
    #[cfg(feature = "std")]
    use crate::{BytesWrapper, Decoder};

    use super::*;

    #[test]
    fn raw_encoder_reset() {
        let mut encoder = RawEncoder::new().unwrap();
        let mut buf = vec![0; 1024];
        encoder.compress(b"Hello", &mut buf).unwrap();
        encoder.end_frame(&mut buf).unwrap();
        assert_eq!(encoder.seek_table().num_frames(), 1);
        let first_st = encoder.seek_table().clone();

        // Build up some frame progress to reset it later
        encoder.compress(b"Bye", &mut [0; 128]).unwrap();

        encoder.reset_frame();
        encoder.reset_seek_table();
        assert_eq!(encoder.seek_table().num_frames(), 0);

        encoder.compress(b"Hello", &mut buf).unwrap();
        encoder.end_frame(&mut buf).unwrap();
        assert_eq!(encoder.seek_table().num_frames(), 1);

        debug_assert_eq!(&first_st, encoder.seek_table());
    }

    #[test]
    fn raw_encoder_forbids_uncompressed_frame_size_0() {
        assert!(
            EncodeOptions::new()
                .frame_size_policy(FrameSizePolicy::Uncompressed(0))
                .into_raw_encoder()
                .err()
                .unwrap()
                .is_invalid_frame_size_policy()
        );
    }

    #[test]
    fn raw_encoder_forbids_compressed_frame_size_0() {
        assert!(
            EncodeOptions::new()
                .frame_size_policy(FrameSizePolicy::Compressed(0))
                .into_raw_encoder()
                .err()
                .unwrap()
                .is_invalid_frame_size_policy()
        );
    }

    #[test]
    fn checksum() {
        let mut seekable = vec![];
        let mut encoder = EncodeOptions::new()
            .checksum_flag(true)
            .frame_size_policy(FrameSizePolicy::Uncompressed(INPUT.len() as u32 / 3))
            .into_raw_encoder()
            .unwrap();

        let mut buf = vec![0; INPUT.len()];

        let mut in_progress = 0;
        while in_progress < INPUT.len() {
            let progress = encoder
                .compress(&INPUT.as_bytes()[in_progress..], &mut buf)
                .unwrap();
            seekable.extend(&buf[..progress.out_progress]);
            in_progress += progress.in_progress;
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.out_progress]);
            if prog.data_left == 0 {
                break;
            }
        }

        let num_frames = encoder.seek_table().num_frames();
        let st = encoder.into_seek_table();
        for i in 0..num_frames {
            let start_pos = st.frame_start_comp(i).unwrap();
            // Get the Frame_Header_Descriptor field
            let descriptor: u8 = seekable[start_pos as usize + 4];
            // Check that the Content_Checksum_flag is set
            assert!(descriptor & 0x4 > 0);
        }
    }

    /// A flush must deliver what was written before it, and must not end the frame.
    #[test]
    #[cfg(feature = "std")]
    fn flush_delivers_input_without_ending_the_frame() {
        use std::io::Write;

        let mut out = Vec::new();
        let mut encoder = Encoder::new(&mut out).unwrap();
        encoder.flush().unwrap();
        assert_eq!(encoder.written_compressed(), 0, "nothing to flush yet");

        encoder.write_all(INPUT.as_bytes()).unwrap();
        encoder.flush().unwrap();
        let flushed = encoder.written_compressed();
        assert!(flushed > 0, "the flushed input did not reach the writer");

        encoder.write_all(INPUT.as_bytes()).unwrap();
        let total = encoder.finish().unwrap();
        assert!(total > flushed);
        assert_eq!(out.len() as u64, total);

        let seek_table =
            crate::SeekTable::from_seekable(&mut crate::BytesWrapper::new(&out)).unwrap();
        assert_eq!(seek_table.num_frames(), 1);
        let mut decoder = crate::Decoder::new(crate::BytesWrapper::new(&out)).unwrap();
        let mut restored = vec![0; INPUT.len() * 2 + 1];
        let mut n = 0;
        loop {
            let progress = decoder.decompress(&mut restored[n..]).unwrap();
            if progress == 0 {
                break;
            }
            n += progress;
        }
        assert_eq!(&restored[..n], INPUT.repeat(2).as_bytes());
    }

    /// 200 KiB of xorshift noise: incompressible, so an encoder's output buffer fills up and gets
    /// written out in the middle of compression.
    #[cfg(feature = "std")]
    fn noise() -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        (0..200 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// A frame ending that an output buffer cut short must be finished by a following flush, not
    /// bypassed: the frame would otherwise stay unlogged and merge with the next one.
    #[test]
    #[cfg(feature = "std")]
    fn flush_finishes_a_pending_frame_ending() {
        let input = noise();
        let mut encoder = RawEncoder::new().unwrap();
        let mut archive = vec![];
        let mut buf = vec![0; 128 * 1024];

        let mut consumed = 0;
        while consumed < input.len() {
            let progress = encoder.compress(&input[consumed..], &mut buf).unwrap();
            archive.extend(&buf[..progress.out_progress()]);
            consumed += progress.in_progress();
        }

        // Start the frame ending in a buffer too small to hold it
        let mut tiny = [0u8; 4];
        let progress = encoder.end_frame(&mut tiny).unwrap();
        archive.extend(&tiny[..progress.out_progress()]);
        assert!(
            progress.data_left() > 0,
            "the ending should still be pending"
        );

        loop {
            let progress = encoder.flush(&mut buf).unwrap();
            archive.extend(&buf[..progress.out_progress()]);
            if progress.data_left() == 0 {
                break;
            }
        }
        assert_eq!(
            encoder.seek_table().num_frames(),
            1,
            "the frame was not logged"
        );

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            archive.extend(&buf[..n]);
        }

        let mut decoder = Decoder::new(BytesWrapper::new(&archive)).unwrap();
        let mut restored = vec![0; input.len()];
        let mut pos = 0;
        loop {
            let n = decoder.decompress(&mut restored[pos..]).unwrap();
            if n == 0 {
                break;
            }
            pos += n;
        }
        assert_eq!(restored[..pos], input[..]);
    }

    /// Flushing a frame that consumed nothing must leave the compression session untouched, so
    /// that a prefix can still be referenced afterwards.
    #[test]
    #[cfg(feature = "std")]
    fn flush_of_an_idle_frame_keeps_a_prefix_usable() {
        use std::io::Write;

        let mut out = vec![];
        let mut encoder = Encoder::new(&mut out).unwrap();
        encoder.flush().unwrap();
        encoder
            .compress_with_prefix(INPUT.as_bytes(), Some(INPUT.as_bytes()))
            .expect("referencing a prefix after an idle flush");
        encoder.end_frame().unwrap();
        encoder.flush().unwrap();
        encoder
            .compress_with_prefix(INPUT.as_bytes(), Some(INPUT.as_bytes()))
            .expect("referencing a prefix after a flush between frames");
    }

    /// Round trips through writers that fail partway, retrying like a caller that still holds its
    /// data would.
    #[cfg(feature = "std")]
    mod io_errors {
        use std::{
            io::{self, ErrorKind, Write},
            ops::Range,
        };

        use super::*;

        /// A writer that accepts at most `chunk` bytes per call and fails, with `kind`, on every
        /// call whose index (counting from zero) lies in `failing_calls`.
        struct FlakyWriter {
            written: Vec<u8>,
            chunk: usize,
            calls: usize,
            failing_calls: Range<usize>,
            kind: ErrorKind,
        }

        impl Write for FlakyWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let call = self.calls;
                self.calls += 1;
                if self.failing_calls.contains(&call) {
                    return Err(io::Error::from(self.kind));
                }
                let n = buf.len().min(self.chunk);
                self.written.extend(&buf[..n]);
                Ok(n)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        /// Feeds `input` to `encoder` in 10 KiB slices, retrying a slice whenever the encoder
        /// reports an IO error, and returns how many errors it saw.
        fn compress_with_retries(
            encoder: &mut Encoder<'_, &mut FlakyWriter>,
            input: &[u8],
        ) -> usize {
            let mut errors = 0;
            let mut pos = 0;
            while pos < input.len() {
                let end = input.len().min(pos + 10 * 1024);
                match encoder.compress(&input[pos..end]) {
                    Ok(n) => pos += n,
                    Err(err) => {
                        assert!(err.is_io());
                        errors += 1;
                    }
                }
            }
            errors
        }

        /// Flushes `encoder`, retrying on errors of `kind`, and returns how many errors it saw.
        fn flush_with_retries(
            encoder: &mut Encoder<'_, &mut FlakyWriter>,
            kind: ErrorKind,
        ) -> usize {
            let mut errors = 0;
            while let Err(err) = encoder.flush() {
                assert_eq!(err.kind(), kind);
                errors += 1;
            }
            errors
        }

        fn decompress_all(seekable: &[u8]) -> Vec<u8> {
            let mut decoder = Decoder::new(BytesWrapper::new(seekable)).unwrap();
            let mut output = vec![];
            let mut buf = vec![0; 64 * 1024];
            loop {
                let n = decoder.decompress(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                output.extend(&buf[..n]);
            }
            output
        }

        /// Compresses `noise()` through a writer whose calls in `failing_calls` fail with `kind`,
        /// retrying as a caller would, and checks that the archive decodes back to the input.
        /// Returns how many errors reached the caller and how many write calls the writer saw, or
        /// `None` when the failure hit `finish`, which consumes the encoder and so cannot be
        /// retried.
        fn round_trip(failing_calls: Range<usize>, kind: ErrorKind) -> Option<(usize, usize)> {
            let input = noise();
            let mut writer = FlakyWriter {
                written: vec![],
                chunk: 30_000,
                calls: 0,
                failing_calls,
                kind,
            };
            let mut encoder = Encoder::new(&mut writer).unwrap();
            let mut errors = compress_with_retries(&mut encoder, &input);
            errors += flush_with_retries(&mut encoder, kind);
            match encoder.finish() {
                Err(err) => {
                    assert!(err.is_io());
                    None
                }
                Ok(total) => {
                    assert_eq!(total, writer.written.len() as u64);
                    assert_eq!(decompress_all(&writer.written), input);
                    Some((errors, writer.calls))
                }
            }
        }

        /// Compresses `noise()` through a writer whose calls in `failing_calls` fail with
        /// `WouldBlock`, flushes once all input is in, and decodes the archive again. Frames end
        /// every 40 KiB, so a failure can interrupt an automatic frame ending, which the flush has
        /// to finish rather than bypass. Returns the decoded bytes and how many write calls the
        /// writer saw, or `None` when the error landed in `finish`, which cannot be retried.
        fn round_trip_with_flush(failing_calls: Range<usize>) -> Option<(Vec<u8>, usize)> {
            let input = noise();
            let mut writer = FlakyWriter {
                written: vec![],
                chunk: 30_000,
                calls: 0,
                failing_calls,
                kind: ErrorKind::WouldBlock,
            };
            let mut encoder = EncodeOptions::new()
                .frame_size_policy(FrameSizePolicy::Uncompressed(40_000))
                .into_encoder(&mut writer)
                .unwrap();
            compress_with_retries(&mut encoder, &input);
            flush_with_retries(&mut encoder, ErrorKind::WouldBlock);
            match encoder.finish() {
                Err(err) => {
                    assert!(err.is_io());
                    None
                }
                Ok(total) => {
                    assert_eq!(total, writer.written.len() as u64);
                    Some((decompress_all(&writer.written), writer.calls))
                }
            }
        }

        #[test]
        fn write_errors_around_frame_endings_never_corrupt_the_archive() {
            let input = noise();
            let (_, calls) = round_trip_with_flush(0..0).unwrap();
            for fail_at in 0..calls {
                if let Some((output, _)) = round_trip_with_flush(fail_at..fail_at + 1) {
                    assert_eq!(
                        output, input,
                        "wrong output after write call {fail_at} failed"
                    );
                }
            }
        }

        #[test]
        fn write_errors_never_corrupt_the_archive() {
            let (_, calls) = round_trip(0..0, ErrorKind::WouldBlock).unwrap();
            for fail_at in 0..calls {
                if let Some((errors, _)) = round_trip(fail_at..fail_at + 2, ErrorKind::WouldBlock) {
                    // Two failures in a row: whatever the first one interrupted, the second hits
                    // a fresh call and must reach the caller
                    assert!(
                        errors >= 1,
                        "no error reported for write calls {fail_at} and {}",
                        fail_at + 1
                    );
                }
            }
        }

        #[test]
        fn interrupted_writes_are_retried_internally() {
            let (_, calls) = round_trip(0..0, ErrorKind::Interrupted).unwrap();
            for fail_at in 0..calls {
                let (errors, _) = round_trip(fail_at..fail_at + 2, ErrorKind::Interrupted).unwrap();
                assert_eq!(errors, 0, "interruption of write call {fail_at} leaked");
            }
        }
    }
}
