// Model-output: Claude Fable 5.1
// Model-output: Claude Opus 5
// Model-output: Claude Opus 5.5
use alloc::vec;
use alloc::vec::Vec;
use zstd_safe::{DCtx, ErrorCode, InBuffer, OutBuffer, ResetDirective};

use crate::{
    Error,
    error::Result,
    seek_table::SeekTable,
    seekable::{OffsetFrom, Seekable},
};

/// Options that configure how data is decompressed.
pub struct DecodeOptions<'a, S> {
    dctx: DCtx<'a>,
    src: S,
    seek_table: Option<SeekTable>,
    lower_frame: Option<u32>,
    offset: Option<u64>,
    upper_frame: Option<u32>,
    offset_limit: Option<u64>,
}

impl<'a, S> DecodeOptions<'a, S> {
    /// Creates a set of decoding options with default initial values. `src` contains the
    /// compressed data.
    ///
    /// # Panics
    ///
    /// If allocation of [`DCtx`] fails.
    pub fn new(src: S) -> Self {
        Self::with_dctx(src, DCtx::create())
    }

    /// Tries to create new options.
    ///
    /// Returns `None` if allocation of [`DCtx`] fails.
    pub fn try_new(src: S) -> Option<Self> {
        let dctx = DCtx::try_create()?;
        Some(Self::with_dctx(src, dctx))
    }

    /// Creates options with the given decompression context.
    pub fn with_dctx(src: S, dctx: DCtx<'a>) -> Self {
        Self {
            dctx,
            src,
            seek_table: None,
            lower_frame: None,
            offset: None,
            upper_frame: None,
            offset_limit: None,
        }
    }

    /// Sets a [`DCtx`].
    pub fn dctx(mut self, dctx: DCtx<'a>) -> Self {
        self.dctx = dctx;
        self
    }

    /// Sets the [`SeekTable`] for this options.
    ///
    /// If a seek table is set, it will be used directly during decompression instead of reading
    /// the seek table from the seekable `src`.
    pub fn seek_table(mut self, seek_table: SeekTable) -> Self {
        self.seek_table = Some(seek_table);
        self
    }

    /// Sets the frame where decompression starts.
    ///
    /// Overrides the offset set with [`Self::offset`] if both are specified.
    pub fn lower_frame(mut self, index: u32) -> Self {
        self.lower_frame = Some(index);
        self
    }

    /// Sets the last frame that is included in decompression.
    ///
    /// Overrides the offset limit set with [`Self::offset_limit`] if both are specified.
    pub fn upper_frame(mut self, index: u32) -> Self {
        self.upper_frame = Some(index);
        self
    }

    /// Sets the decompression offset.
    ///
    /// The offset is the position in the decompressed data of the seekable source from which
    /// decompression starts.
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets a limit for the decompression offset.
    ///
    /// The limit is the position in the decompressed data of the seekable source at which
    /// decompresion stops.
    pub fn offset_limit(mut self, limit: u64) -> Self {
        self.offset_limit = Some(limit);
        self
    }
}

impl<'a, S: Seekable> DecodeOptions<'a, S> {
    /// Builds a [`Decoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the decoder could not created.
    pub fn into_decoder(self) -> Result<Decoder<'a, S>> {
        Decoder::with_opts(self)
    }
}

/// Decompresses data from a seekable source.
///
/// A decoder reads compressed data from a seekable source. By default, it decompresses
/// everything, from the first to the last frame. This can be changed via [`DecodeOptions`] or by
/// setting the offset after initialization.
pub struct Decoder<'a, S> {
    dctx: DCtx<'a>,
    seek_table: SeekTable,
    src: S,
    /// Index of the frame the decompression context is in, or about to enter.
    frame_idx: u32,
    /// Whether the decompression context sits between frames, i.e. the last frame it saw was
    /// consumed completely, trailer included.
    frame_done: bool,
    decomp_pos: u64,
    offset: u64,
    offset_limit: u64,
    in_buf: Vec<u8>,
    in_buf_pos: usize,
    in_buf_limit: usize,
    out_buf: Vec<u8>,
    read_compressed: u64,
    /// The error that left the decompression context out of step with this decoder. Every
    /// decompression returns it again until the context is reset.
    failure: Option<Failure>,
}

/// A decompression error after which the context's state no longer matches the decoder's.
#[derive(Clone, Copy)]
enum Failure {
    Zstd(ErrorCode),
    FrameSizeMismatch,
}

impl From<Failure> for Error {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Zstd(code) => code.into(),
            Failure::FrameSizeMismatch => Error::frame_size_mismatch(),
        }
    }
}

/// Stores `failure` in `slot`, the decoder's `failure` field. Returns it as an error.
fn record(slot: &mut Option<Failure>, failure: Failure) -> Error {
    *slot = Some(failure);
    failure.into()
}

/// Whether a decompression context that sits at decompressed position `pos` has to go on without
/// room for output, to consume the frame ending at `frame_end` (`None` past the last frame): the
/// trailer of the frame it is in, once that produced its last byte, or a whole empty frame, if it
/// lies before `limit`, where the read ends. `frame_done` tells whether the context is between
/// frames. An empty frame at the limit is left alone, like every frame past it.
fn frame_pending(frame_done: bool, frame_end: Option<u64>, pos: u64, limit: u64) -> bool {
    frame_end == Some(pos) && (!frame_done || pos < limit)
}

impl<'a, S: Seekable> Decoder<'a, S> {
    /// Creates a new `Decoder` with default parameters and `src` as source.
    ///
    /// This is equivalent to calling `DecodeOptions::new(src).into_decoder()`.
    ///
    /// # Errors
    ///
    /// Fails if the decoder could not be created.
    pub fn new(src: S) -> Result<Self> {
        Self::with_opts(DecodeOptions::new(src))
    }

    /// Creates a new `Decoder` with the given [`DecodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the decoder cannot be created.
    pub fn with_opts(mut opts: DecodeOptions<'a, S>) -> Result<Self> {
        let seek_table = opts
            .seek_table
            .map_or_else(|| SeekTable::from_seekable(&mut opts.src), Ok)?;

        let offset = if let Some(index) = opts.lower_frame {
            seek_table.frame_start_decomp(index)?
        } else {
            opts.offset.unwrap_or(0)
        };

        Self::check_offset(offset, &seek_table)?;

        let offset_limit = if let Some(index) = opts.upper_frame {
            seek_table.frame_end_decomp(index)?
        } else {
            opts.offset_limit
                .unwrap_or_else(|| seek_table.size_decomp())
        };

        Self::check_offset(offset_limit, &seek_table)?;

        Ok(Self {
            dctx: opts.dctx,
            seek_table,
            src: opts.src,
            frame_idx: 0,
            frame_done: true,
            decomp_pos: 0,
            offset,
            offset_limit,
            in_buf: vec![0; DCtx::in_size()],
            in_buf_pos: 0,
            in_buf_limit: 0,
            out_buf: vec![0; DCtx::out_size()],
            read_compressed: 0,
            failure: None,
        })
    }

    /// Reads from the source into the input buffer once that is used up. Fails if the read fails
    /// or returns nothing, leaving the buffer used up, so that the next call reads again.
    fn fill_in_buf(&mut self) -> Result<()> {
        if self.in_buf_pos == self.in_buf_limit {
            self.in_buf_limit = match self.src.read(&mut self.in_buf)? {
                0 => return Err(Error::unexpected_eof()),
                n => n,
            };
            self.in_buf_pos = 0;
        }
        Ok(())
    }

    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`. Decompression is finished when no more bytes are written to `buf`.
    ///
    /// Every frame that gets decompressed to its end is verified, i.e. its checksum if it has
    /// one, and its decompressed size against the seek table. An offset limit inside a frame
    /// skips the verification of that frame.
    ///
    /// If a `prefix` is passed, it will be referenced at the beginning of every frame.
    /// Referencing a raw content prefix has almost no CPU nor memory cost.
    ///
    /// # Errors
    ///
    /// If decompression fails, the source ends inside a frame, a frame disagrees with its seek
    /// table entry, or any parameter is invalid. After a failed decompression or disagreeing
    /// frame, every call returns the same error until [`Self::reset`] or a [`Self::set_offset`]
    /// that cannot continue from the current position. A failed read from the source is retried
    /// by the next call instead.
    #[allow(clippy::missing_panics_doc)]
    pub fn decompress_with_prefix<'b: 'a>(
        &mut self,
        buf: &mut [u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<usize> {
        if let Some(failure) = self.failure {
            return Err(failure.into());
        }
        // An empty archive has nothing to read or produce
        if self.seek_table.num_frames() == 0 {
            return Ok(0);
        }

        if self.read_compressed == 0 {
            self.frame_idx = self.seek_table.frame_index_decomp(self.offset);
            let start_pos = self.seek_table.frame_start_comp(self.frame_idx)?;
            self.src.set_offset(OffsetFrom::Start(start_pos))?;
            self.decomp_pos = self.seek_table.frame_start_decomp(self.frame_idx)?;
            // Reference prefix at the beginning of decompression
            if let Some(pref) = prefix {
                self.dctx.ref_prefix(pref)?;
            }
            // Trigger reading from src
            self.in_buf_pos = 0;
            self.in_buf_limit = 0;
        }

        let mut output_progress = 0;
        // Decompressed end of the frame the context is in, `None` past the last frame
        let mut frame_end = self.seek_table.frame_end_decomp(self.frame_idx).ok();
        loop {
            // The output window below ends at the current frame's declared end at the latest, so
            // the context never gets past it
            assert!(frame_end.is_none_or(|end| self.decomp_pos <= end));
            // Stop once no more output is wanted, unless a frame still has to be consumed here
            let output_wanted = self.offset < self.offset_limit && output_progress < buf.len();
            let pending = frame_pending(
                self.frame_done,
                frame_end,
                self.decomp_pos,
                self.offset_limit,
            );
            if !output_wanted && !pending {
                break;
            }

            if let Err(err) = self.fill_in_buf() {
                // Bytes already placed in `buf` must be reported, so a failed or empty read is
                // left for the next call, which retries it and reports its error
                if output_progress > 0 {
                    break;
                }
                return Err(err);
            }

            let mut in_buffer = InBuffer::around(&self.in_buf[self.in_buf_pos..self.in_buf_limit]);
            // A frame gets no room beyond its declared end: one that holds more stalls there
            let frame_stop = frame_end.unwrap_or(u64::MAX);
            let mut out_buffer = if self.decomp_pos < self.offset {
                // Dummy decompression until we get to offset
                let limit = (self.offset.min(frame_stop) - self.decomp_pos)
                    .min(self.out_buf.len() as u64) as usize;
                OutBuffer::around(&mut self.out_buf[..limit])
            } else {
                // Bytes we still need to decompress, capped at usize::MAX
                let remaining: usize = self
                    .offset_limit
                    .min(frame_stop)
                    .saturating_sub(self.decomp_pos)
                    .try_into()
                    .unwrap_or(usize::MAX);
                let limit = buf.len().min(output_progress.saturating_add(remaining));
                OutBuffer::around(&mut buf[output_progress..limit])
            };

            let in_len = self.in_buf_limit - self.in_buf_pos;
            while in_buffer.pos() < in_len {
                let pos = self.decomp_pos + out_buffer.pos() as u64;
                if out_buffer.pos() == out_buffer.capacity()
                    && !frame_pending(self.frame_done, frame_end, pos, self.offset_limit)
                {
                    break;
                }

                let (in_before, out_before) = (in_buffer.pos(), out_buffer.pos());
                let n = self
                    .dctx
                    .decompress_stream(&mut out_buffer, &mut in_buffer)
                    .map_err(|code| record(&mut self.failure, Failure::Zstd(code)))?;
                // Given input and room for output, zstd always makes progress. The only calls
                // made without room are at the declared end of a frame, so a stall means the
                // frame holds more data than its seek table entry says.
                if in_buffer.pos() == in_before && out_buffer.pos() == out_before {
                    return Err(record(&mut self.failure, Failure::FrameSizeMismatch));
                }

                // Frame end
                self.frame_done = n == 0;
                if self.frame_done {
                    let end = self.decomp_pos + out_buffer.pos() as u64;
                    if frame_end != Some(end) {
                        return Err(record(&mut self.failure, Failure::FrameSizeMismatch));
                    }
                    self.frame_idx += 1;
                    frame_end = self.seek_table.frame_end_decomp(self.frame_idx).ok();
                    // TODO: chain when stable
                    if let Some(pref) = prefix {
                        self.dctx
                            .reset(ResetDirective::SessionOnly)
                            .expect("Resetting session never fails");
                        self.dctx
                            .ref_prefix(pref)
                            .map_err(|code| record(&mut self.failure, Failure::Zstd(code)))?;
                    }
                }
            }
            // Every pass runs the context at least once, and that either advances or fails above
            assert!(in_buffer.pos() > 0 || out_buffer.pos() > 0);

            self.decomp_pos += out_buffer.pos() as u64;
            self.in_buf_pos += in_buffer.pos();
            self.read_compressed += in_buffer.pos() as u64;

            // Only add progress if we actually wrote something to buf
            if self.decomp_pos > self.offset {
                self.offset += out_buffer.pos() as u64;
                output_progress += out_buffer.pos();
            }
        }

        Ok(output_progress)
    }
}

impl<S: Seekable> Decoder<'_, S> {
    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`. Decompression is finished when no more bytes are written to `buf`.
    ///
    /// # Errors
    ///
    /// If decompression fails or any parameter is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use zeekstd::{BytesWrapper, RawEncoder};
    /// # let mut encoder = RawEncoder::new()?;
    /// # let mut seekable = [0u8; 128];
    /// # let prog = encoder.compress(b"Hello, World!", &mut seekable)?;
    /// # let end_prog = encoder.end_frame(&mut seekable[prog.out_progress()..])?;
    /// # let mut ser = encoder.into_seek_table().into_serializer();
    /// # let mut n = prog.out_progress() + end_prog.out_progress();
    /// # n += ser.write_into(&mut seekable[n..]);
    /// # let seekable = BytesWrapper::new(&seekable[..n]);
    /// use zeekstd::Decoder;
    ///
    /// let mut decoder = Decoder::new(seekable)?;
    /// // Make sure `buf` is big enough to hold all decompressed data
    /// let mut buf = [0u8; 128];
    /// let mut progress = 0;
    ///
    /// // Decompress in a loop until no more bytes are written to `buf`
    /// loop {
    ///     let n = decoder.decompress(&mut buf[progress..])?;
    ///     if n == 0 {
    ///         break;
    ///     }
    ///     progress += n;
    /// }
    ///
    /// # assert_eq!(b"Hello, World!", &buf[..progress]);
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn decompress(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decompress_with_prefix(buf, None)
    }

    /// Resets the current decompresion status.
    ///
    /// This resets the internal decompression context as well as decompression offset and limit.
    /// The next decompression operation after this function will start from the beginning of the
    /// seekable source.
    ///
    /// # Examples
    ///
    /// ```
    /// # use zeekstd::{BytesWrapper, RawEncoder};
    /// # let mut encoder = RawEncoder::new()?;
    /// # let mut seekable = [0u8; 128];
    /// # let prog = encoder.compress(b"Hello, World!", &mut seekable)?;
    /// # let end_prog = encoder.end_frame(&mut seekable[prog.out_progress()..])?;
    /// # let mut ser = encoder.into_seek_table().into_serializer();
    /// # let mut n = prog.out_progress() + end_prog.out_progress();
    /// # n += ser.write_into(&mut seekable[n..]);
    /// # let seekable = BytesWrapper::new(&seekable[..n]);
    /// use zeekstd::Decoder;
    ///
    /// let mut decoder = Decoder::new(seekable)?;
    /// decoder.reset();
    ///
    /// assert_eq!(decoder.read_compressed(), 0);
    /// assert_eq!(decoder.offset(), 0);
    /// assert_eq!(decoder.offset_limit(), decoder.seek_table().size_decomp());
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn reset(&mut self) {
        self.reset_dctx();
        self.offset = 0;
        self.offset_limit = self.seek_table().size_decomp();
    }

    fn reset_dctx(&mut self) {
        self.read_compressed = 0;
        self.frame_done = true;
        self.failure = None;
        self.dctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
    }

    /// Sets the decompression offset to the beginning of the frame at `index`.
    ///
    /// This has the same effect as calling [`Self::set_offset`] with the decompressed start
    /// position of the frame at `index`.
    ///
    /// # Errors
    ///
    /// When the the passed frame index is out of range.
    pub fn set_lower_frame(&mut self, index: u32) -> Result<u64> {
        let offset = self.seek_table.frame_start_decomp(index)?;
        self.set_offset(offset)?;

        Ok(offset)
    }

    /// Sets the limit for the decompression offset to the end of the frame at `index`.
    ///
    /// This has the same effect as calling [`Self::set_offset_limit`] with the decompressed end
    /// position of the frame at `index`. The current decompression state will not be reset, it is
    /// possible to change the upper frame in the middle of a decompression operation.
    ///
    /// # Errors
    ///
    /// When the the passed frame index is out of range.
    pub fn set_upper_frame(&mut self, index: u32) -> Result<u64> {
        let offset = self.seek_table.frame_end_decomp(index)?;
        self.set_offset_limit(offset)?;

        Ok(offset)
    }

    /// Sets the decompression offset.
    ///
    /// The offset is the position in the _decompressed_ data of the seekable source from which
    /// decompression starts. If possible, the decoder will continue decompression from the current
    /// internal state.
    ///
    /// **Note**: If the passed offset is not the beginning of a frame, the decoder will perform a
    /// dummy decompression from the beginning of the frame up to the offset position.
    ///
    /// # Errors
    ///
    /// When the passed offset is out of range.
    pub fn set_offset(&mut self, offset: u64) -> Result<()> {
        Self::check_offset(offset, self.seek_table())?;
        let current_frame = self.seek_table().frame_index_decomp(self.offset);
        let target_frame = self.seek_table().frame_index_decomp(offset);

        // Only reset if we cannot continue from previous decompression
        if current_frame != target_frame || offset < self.offset {
            self.reset_dctx();
        }
        self.offset = offset;

        Ok(())
    }

    /// Sets a limit for the decompression offset.
    ///
    /// The limit is the position in the _decompressed_ data of the seekable source at which
    /// decompression stops. This does not reset the current decompression state, the limit can be
    /// changed in the middle of a decompression operation without interrupting the ongoing
    /// operation. It is possible to set a limit that is lower than the current decompression
    /// offset, however, it will lead to any decompression operation making no progress, i.e.
    /// it will produce zero decompressed bytes.
    ///
    /// **Note**: The decoder will immediately stop decompression at the specified limit. The
    /// frame checksum of the last decompressed frame will not be verified, if the limit isn't at
    /// the end of a frame.
    ///
    /// # Errors
    ///
    /// When the passed limit is out of range.
    pub fn set_offset_limit(&mut self, limit: u64) -> Result<()> {
        Self::check_offset(limit, self.seek_table())?;
        self.offset_limit = limit;

        Ok(())
    }

    fn check_offset(offset: u64, seek_table: &SeekTable) -> Result<()> {
        if offset > seek_table.size_decomp() {
            Err(Error::offset_out_of_range())
        } else {
            Ok(())
        }
    }

    /// Gets the total number of compressed bytes read since the last reset.
    pub fn read_compressed(&self) -> u64 {
        self.read_compressed
    }

    /// Gets a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
    }

    /// Gets the current offset of this decoder.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Gets the offset limit of this decoder.
    pub fn offset_limit(&self) -> u64 {
        self.offset_limit
    }
}

/// Allows to read decompressed data from a `Decoder`.
///
/// # Examples
///
/// ```no_run
/// use std::{fs::File, io};
/// use zeekstd::Decoder;
///
/// let seekable = File::open("seekable.zst")?;
/// let mut output = File::create("output")?;
/// let mut decoder = Decoder::new(seekable)?;
/// io::copy(&mut decoder, &mut output)?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
///
/// Similar to regular decompression, this supports frame limits.
///
/// ```no_run
/// # use std::{fs::File, io};
/// # use zeekstd::Decoder;
/// # let seekable = File::open("seekable.zst")?;
/// # let mut decoder = Decoder::new(seekable)?;
/// decoder.set_lower_frame(2)?;
/// decoder.set_upper_frame(3)?;
/// io::copy(&mut decoder, &mut io::stdout())?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
///
/// And also arbitrary byte offsets.
///
/// ```no_run
/// # use std::{fs::File, io};
/// # use zeekstd::Decoder;
/// # let seekable = File::open("seekable.zst")?;
/// # let mut decoder = Decoder::new(seekable)?;
/// decoder.set_offset(123)?;
/// decoder.set_offset_limit(456)?;
/// io::copy(&mut decoder, &mut io::stdout())?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<S: Seekable> std::io::Read for Decoder<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.decompress(buf)?)
    }
}

/// Allows to set the offset of a `Decoder` via seeking.
///
/// # Examples
///
/// ```
/// # use zeekstd::{BytesWrapper, RawEncoder};
/// # let mut encoder = RawEncoder::new()?;
/// # let mut seekable = [0u8; 128];
/// # let prog = encoder.compress(b"Hello, World!", &mut seekable)?;
/// # let end_prog = encoder.end_frame(&mut seekable[prog.out_progress()..])?;
/// # let mut ser = encoder.into_seek_table().into_serializer();
/// # let mut n = prog.out_progress() + end_prog.out_progress();
/// # n += ser.write_into(&mut seekable[n..]);
/// # let seekable = BytesWrapper::new(&seekable[..n]);
/// use std::io::{Seek, SeekFrom};
/// use zeekstd::Decoder;
///
/// let mut decoder = Decoder::new(seekable)?;
/// decoder.seek(SeekFrom::Start(7))?;
///
/// assert_eq!(decoder.offset(), 7);
///
/// # let mut buf = [0u8; 128];
/// # let n = decoder.decompress(&mut buf)?;
/// # assert_eq!(b"World!", &buf[..n]);
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<S: Seekable> std::io::Seek for Decoder<'_, S> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::{self, SeekFrom};

        match pos {
            SeekFrom::Start(offset) => {
                self.set_offset(offset).map_err(io::Error::other)?;
                Ok(offset)
            }
            SeekFrom::End(n) => {
                if n > 0 {
                    return Err(io::Error::other(Error::offset_out_of_range()));
                }

                let offset = self
                    .seek_table()
                    .size_decomp()
                    .checked_add_signed(n)
                    .ok_or(io::Error::other(Error::offset_out_of_range()))?;
                self.set_offset(offset).map_err(io::Error::other)?;

                Ok(offset)
            }
            SeekFrom::Current(n) => {
                let offset = self
                    .offset
                    .checked_add_signed(n)
                    .ok_or(io::Error::other(Error::offset_out_of_range()))?;
                self.set_offset(offset).map_err(io::Error::other)?;

                Ok(offset)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::{
        BytesWrapper, EncodeOptions, FrameSizePolicy, SEEK_TABLE_INTEGRITY_SIZE,
        seek_table::Format, tests::INPUT,
    };

    use super::*;

    /// Pseudo-random bytes that zstd stores in raw blocks, so flipping one of them can only be
    /// noticed by the frame checksum.
    fn noise(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 56) as u8
            })
            .collect()
    }

    /// Compresses `input` into a complete seekable (frames followed by a `Foot` seek table),
    /// checking that the encoder's progress reports add up to what it wrote.
    fn encode(input: &[u8], frame_size_policy: Option<FrameSizePolicy>, checksum: bool) -> Vec<u8> {
        let mut seekable = vec![];
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(frame_size_policy.unwrap_or_default())
            .checksum_flag(checksum)
            .into_raw_encoder()
            .unwrap();

        let mut buf = vec![0; input.len().max(64)];

        let mut in_progress = 0;
        let mut out_progress = 0;
        while in_progress < input.len() {
            let progress = encoder.compress(&input[in_progress..], &mut buf).unwrap();
            seekable.extend(&buf[..progress.out_progress()]);
            in_progress += progress.in_progress();
            out_progress += progress.out_progress();
        }
        assert_eq!(in_progress, input.len());

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.out_progress()]);
            out_progress += prog.out_progress();
            if prog.data_left() == 0 {
                break;
            }
        }
        assert_eq!(out_progress, seekable.len());

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            seekable.extend(&buf[..n]);
        }
        assert_eq!(out_progress + ser.encoded_len(), seekable.len());

        seekable
    }

    fn new_seekable(frame_size_policy: Option<FrameSizePolicy>) -> Vec<u8> {
        encode(INPUT.as_bytes(), frame_size_policy, false)
    }

    /// Serves at most `chunk` bytes per read, so that a frame trailer lands in a later read
    /// than the data it protects.
    struct ChunkedBytes<'a> {
        inner: BytesWrapper<'a>,
        chunk: usize,
    }

    impl Seekable for ChunkedBytes<'_> {
        fn set_offset(&mut self, offset: OffsetFrom) -> Result<u64> {
            self.inner.set_offset(offset)
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let len = buf.len().min(self.chunk);
            self.inner.read(&mut buf[..len])
        }

        fn seek_table_integrity(
            &mut self,
            format: Format,
        ) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]> {
            self.inner.seek_table_integrity(format)
        }
    }

    /// A decoder over `seekable` whose data reads return at most `chunk` bytes. The seek table
    /// is parsed from the plain bytes, as the table parser does not cope with short reads yet.
    fn chunked_decoder(seekable: &[u8], chunk: usize) -> Decoder<'static, ChunkedBytes<'_>> {
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(seekable)).unwrap();
        let src = ChunkedBytes {
            inner: BytesWrapper::new(seekable),
            chunk,
        };
        DecodeOptions::new(src)
            .seek_table(st)
            .into_decoder()
            .unwrap()
    }

    /// Decompresses everything the decoder is set up to produce, asking for at most `chunk`
    /// bytes per call.
    fn decode_all<S: Seekable>(decoder: &mut Decoder<'_, S>, chunk: usize) -> Result<Vec<u8>> {
        let mut output = vec![];
        let mut buf = vec![0; chunk];
        loop {
            let n = decoder.decompress(&mut buf)?;
            if n == 0 {
                return Ok(output);
            }
            output.extend_from_slice(&buf[..n]);
        }
    }

    fn assert_checksum_error(result: Result<Vec<u8>>, context: &str) {
        match result {
            Ok(output) => panic!(
                "corruption went unnoticed ({context}): got {} bytes",
                output.len()
            ),
            Err(err) => assert!(
                err.is_zstd() && err.to_string().contains("checksum"),
                "expected a checksum error ({context}), got: {err}"
            ),
        }
    }

    #[test]
    fn small_reads_restore_everything() {
        let input = noise(2500);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        assert_eq!(st.num_frames(), 3);

        for chunk in [1, 3, 1000] {
            let mut decoder = chunked_decoder(&seekable, chunk);
            assert_eq!(decode_all(&mut decoder, 4096).unwrap(), input);
            // Every frame, including its trailer, has been consumed
            assert_eq!(decoder.read_compressed(), st.size_comp());
        }
    }

    #[test]
    fn checksum_verified_when_trailer_arrives_in_a_later_read() {
        let input = noise(3000);
        let mut seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        // Flip a payload byte of the last frame
        let last = st.num_frames() - 1;
        let payload = st.frame_start_comp(last).unwrap() as usize + 20;
        seekable[payload] ^= 0xFF;

        for chunk in [1, 3] {
            let mut decoder = chunked_decoder(&seekable, chunk);
            assert_checksum_error(
                decode_all(&mut decoder, 4096),
                &alloc::format!("{chunk}-byte reads"),
            );
        }
    }

    #[test]
    fn checksum_verified_when_limit_is_at_an_inner_frame_end() {
        let input = noise(3000);
        let mut seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        // Flip a payload byte of the middle frame
        let payload = st.frame_start_comp(1).unwrap() as usize + 20;
        seekable[payload] ^= 0xFF;

        let mut decoder = chunked_decoder(&seekable, 1);
        decoder.set_upper_frame(1).unwrap();
        assert_checksum_error(decode_all(&mut decoder, 4096), "upper frame 1");
    }

    #[test]
    fn checksum_verified_when_trailer_starts_at_input_buffer_boundary() {
        // Frame header (6 bytes) and raw block header (3 bytes) plus the payload fill the
        // decoder's input buffer exactly, leaving the checksum for the next read.
        let input = noise(DCtx::in_size() - 9);
        let mut seekable = encode(&input, None, true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        assert_eq!(st.num_frames(), 1);
        assert_eq!(
            st.frame_size_comp(0).unwrap(),
            DCtx::in_size() as u64 + 4,
            "test setup: the checksum must start at the input buffer boundary"
        );
        seekable[100] ^= 0xFF;

        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();
        // A buffer large enough to take the whole frame content in one call, like the CLI uses
        assert_checksum_error(
            decode_all(&mut decoder, input.len() + 1),
            "input buffer boundary",
        );
    }

    #[test]
    fn truncated_source_is_rejected() {
        let input = noise(2500);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        let data_len = st.size_comp() as usize;

        // Cut off the last checksum only, then part of the last frame's content
        for cut in [4, 100] {
            let src = BytesWrapper::new(&seekable[..data_len - cut]);
            let mut decoder = DecodeOptions::new(src)
                .seek_table(st.clone())
                .into_decoder()
                .unwrap();
            let result = decode_all(&mut decoder, 4096);
            assert!(
                result.as_ref().is_err_and(Error::is_unexpected_eof),
                "source cut by {cut} bytes: {:?}",
                result.as_ref().map(Vec::len)
            );
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn truncated_source_reads_as_unexpected_eof() {
        let input = noise(2500);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        let data_len = st.size_comp() as usize;

        // Cut off the last checksum, so the source ends inside the last frame
        let src = BytesWrapper::new(&seekable[..data_len - 4]);
        let mut decoder = DecodeOptions::new(src)
            .seek_table(st)
            .into_decoder()
            .unwrap();

        let err = std::io::copy(&mut decoder, &mut std::io::sink()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        let inner = err
            .into_inner()
            .expect("the zeekstd error is kept as source");
        assert!(
            inner
                .downcast_ref::<Error>()
                .is_some_and(Error::is_unexpected_eof)
        );
    }

    #[test]
    fn source_that_ends_at_the_last_frame_is_accepted() {
        // Without checksums the last frame's final input byte is part of its last block, and the
        // detached seek table leaves nothing behind it. zstd keeps that byte unconsumed until all
        // buffered output is flushed, so the tiny output buffer never makes the decoder read at
        // EOF while output is still owed.
        let input = noise(2500);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), false);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        let data = &seekable[..st.size_comp() as usize];
        let mut decoder = DecodeOptions::new(BytesWrapper::new(data))
            .seek_table(st)
            .into_decoder()
            .unwrap();
        assert_eq!(decode_all(&mut decoder, 7).unwrap(), input);
    }

    #[test]
    fn seek_table_that_disagrees_with_frame_is_rejected() {
        let input = noise(1500);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        assert_eq!(st.num_frames(), 2);

        let sizes = |i: u32| {
            (
                st.frame_size_comp(i).unwrap() as u32,
                st.frame_size_decomp(i).unwrap() as u32,
            )
        };
        let (c_size_0, d_size_0) = sizes(0);

        // Declare the first frame one byte shorter, then one byte longer, than it is
        for wrong_d_size_0 in [d_size_0 - 1, d_size_0 + 1] {
            let mut wrong = SeekTable::new();
            wrong.log_frame(c_size_0, wrong_d_size_0).unwrap();
            for i in 1..st.num_frames() {
                let (c_size, d_size) = sizes(i);
                wrong.log_frame(c_size, d_size).unwrap();
            }
            let mut decoder = DecodeOptions::new(BytesWrapper::new(&seekable))
                .seek_table(wrong)
                .into_decoder()
                .unwrap();
            let result = decode_all(&mut decoder, 4096);
            assert!(
                result.as_ref().is_err_and(Error::is_frame_size_mismatch),
                "first frame declared as {wrong_d_size_0} instead of {d_size_0} bytes: {:?}",
                result.as_ref().map(Vec::len)
            );
        }
    }

    #[test]
    fn frame_declared_shorter_than_the_frames_after_it_is_rejected() {
        let input = noise(2050);
        let seekable = encode(&input, Some(FrameSizePolicy::Uncompressed(1000)), true);
        let st = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
        assert_eq!(st.num_frames(), 3);

        // Frame 1 declared 100 bytes short, more than the 50 of frame 2, so that the declared
        // end of the archive falls inside frame 1
        let mut wrong = SeekTable::new();
        for i in 0..st.num_frames() {
            let c_size = st.frame_size_comp(i).unwrap() as u32;
            let d_size = st.frame_size_decomp(i).unwrap() as u32;
            wrong
                .log_frame(c_size, if i == 1 { d_size - 100 } else { d_size })
                .unwrap();
        }
        let mut decoder = DecodeOptions::new(BytesWrapper::new(&seekable))
            .seek_table(wrong)
            .into_decoder()
            .unwrap();
        let result = decode_all(&mut decoder, 4096);
        assert!(
            result.as_ref().is_err_and(Error::is_frame_size_mismatch),
            "{:?}",
            result.as_ref().map(Vec::len)
        );
    }

    /// Compresses each of `pieces` into a frame of its own, checksums on, an empty piece into an
    /// empty frame. Returns the frames, without a seek table, and their seek table.
    fn frames(pieces: &[&[u8]]) -> (Vec<u8>, SeekTable) {
        let mut encoder = EncodeOptions::new()
            .checksum_flag(true)
            .into_raw_encoder()
            .unwrap();
        let mut archive = vec![];
        let mut buf = vec![0; 4096];
        for piece in pieces {
            let mut pos = 0;
            while pos < piece.len() {
                let prog = encoder.compress(&piece[pos..], &mut buf).unwrap();
                archive.extend(&buf[..prog.out_progress()]);
                pos += prog.in_progress();
            }
            loop {
                let prog = encoder.end_frame(&mut buf).unwrap();
                archive.extend(&buf[..prog.out_progress()]);
                if prog.data_left() == 0 {
                    break;
                }
            }
        }
        (archive, encoder.into_seek_table())
    }

    /// A decoder over `src` with `st` as its seek table.
    fn decoder_with<'a>(src: &'a [u8], st: &SeekTable) -> Decoder<'static, BytesWrapper<'a>> {
        DecodeOptions::new(BytesWrapper::new(src))
            .seek_table(st.clone())
            .into_decoder()
            .unwrap()
    }

    #[test]
    fn upper_frame_does_not_enter_a_following_empty_frame() {
        let data = noise(1000);
        let (archive, st) = frames(&[&data, b""]);
        assert_eq!(st.frame_size_decomp(1).unwrap(), 0);

        // A source holding only frame 0, as a range fetch of just the frame asked for: the read
        // must end with frame 0 and not reach into the empty frame 1 past it
        let frame0_end = st.frame_end_comp(0).unwrap();
        let mut decoder = decoder_with(&archive[..frame0_end as usize], &st);
        decoder.set_upper_frame(0).unwrap();
        assert_eq!(decode_all(&mut decoder, 4096).unwrap(), data);
        assert_eq!(decoder.read_compressed(), frame0_end);
    }

    #[test]
    fn empty_frame_inside_the_range_is_consumed_and_verified() {
        let data = noise(2000);
        let (mut archive, st) = frames(&[&data[..1000], b"", &data[1000..]]);
        assert_eq!(st.num_frames(), 3);

        // Whether or not the output buffer fills up right at the empty frame, a whole read
        // passes through it and ends with every frame consumed
        for chunk in [1000, 4096] {
            let mut decoder = decoder_with(&archive, &st);
            assert_eq!(decode_all(&mut decoder, chunk).unwrap(), data);
            assert_eq!(decoder.read_compressed(), st.size_comp());
        }

        // The empty frame's checksum is checked like any other
        archive[st.frame_end_comp(1).unwrap() as usize - 1] ^= 1;
        let mut decoder = decoder_with(&archive, &st);
        assert_checksum_error(
            decode_all(&mut decoder, 4096),
            "empty frame inside the range",
        );
    }

    #[test]
    fn source_ending_after_reported_bytes_fails_on_the_next_call() {
        let data = noise(2000);
        let (archive, st) = frames(&[&data[..1000], &data[1000..]]);
        let frame0_end = st.frame_end_comp(0).unwrap() as usize;

        // The source ends right after frame 0, or inside frame 1
        for cut in [frame0_end, frame0_end + 10] {
            let mut decoder = decoder_with(&archive[..cut], &st);
            let mut buf = vec![0; 4096];
            // Frame 0 fits the buffer, so its bytes, and what the source holds of frame 1, are
            // reported before the source's end is
            let n = decoder.decompress(&mut buf).unwrap();
            assert!(n >= 1000, "{n}");
            assert_eq!(buf[..n], data[..n]);
            let result = decoder.decompress(&mut buf);
            assert!(
                result.as_ref().is_err_and(Error::is_unexpected_eof),
                "{result:?}"
            );
        }
    }

    #[test]
    fn options() {
        let seekable = new_seekable(None);
        let mut seekable = BytesWrapper::new(&seekable);
        let st = SeekTable::from_seekable(&mut seekable).unwrap();

        let oks = [
            DecodeOptions::new(seekable.clone()),
            DecodeOptions::new(seekable.clone()).lower_frame(st.num_frames() - 1),
            DecodeOptions::new(seekable.clone()).upper_frame(st.num_frames() - 1),
            DecodeOptions::new(seekable.clone()).offset(st.size_decomp()),
            DecodeOptions::new(seekable.clone()).offset_limit(st.size_decomp()),
            DecodeOptions::new(BytesWrapper::new(&[0, 128])).seek_table(st.clone()),
        ];

        let errs = [
            DecodeOptions::new(BytesWrapper::new(&[0, 128])),
            DecodeOptions::new(seekable.clone()).lower_frame(st.num_frames()),
            DecodeOptions::new(seekable.clone()).upper_frame(st.num_frames()),
            DecodeOptions::new(seekable.clone()).offset(st.size_decomp() + 1),
            DecodeOptions::new(seekable.clone()).offset_limit(st.size_decomp() + 1),
        ];

        for opts in oks {
            assert!(opts.into_decoder().is_ok());
        }

        for opts in errs {
            assert!(opts.into_decoder().is_err());
        }
    }

    #[test]
    fn decompress_and_reset() {
        let seekable = new_seekable(None);
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();

        assert_eq!(n, output.len());
        assert_eq!(INPUT.as_bytes(), output);

        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, 0);

        decoder.reset();
        let n = decoder.decompress(&mut output).unwrap();

        assert_eq!(n, output.len());
        assert_eq!(INPUT.as_bytes(), output);
    }

    #[test]
    fn decompress_until_upper_frame() {
        let frame_size = INPUT.len() / 7;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        // Decompress until frame 5 (inclusive)
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(5).unwrap();

        let len = frame_size * 6;
        let mut output = vec![0; len];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, len);
        assert_eq!(&INPUT.as_bytes()[..n], &output);
    }

    #[test]
    fn decompress_last_frames() {
        let frame_size = INPUT.len() / 9;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        // Decompress the last 4 frames, of 9 or 10 depending on whether 9 divides the input
        let last = decoder.seek_table().num_frames() - 1;
        decoder.set_lower_frame(last - 3).unwrap();
        decoder.set_upper_frame(last).unwrap();

        let len = INPUT.len() - frame_size * (last - 3) as usize;
        let mut output = vec![0; len];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, len);
        assert_eq!(&INPUT.as_bytes()[INPUT.len() - n..], &output);
    }

    #[test]
    fn upper_frame_greater_than_lower_frame() {
        let frame_size = INPUT.len() / 13;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        // Lower frame greater than upper frame, expect zero bytes read
        decoder.set_lower_frame(9).unwrap();
        decoder.set_upper_frame(8).unwrap();
        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(0, n);
    }

    #[test]
    fn reset_decompression() {
        let seekable = new_seekable(None);
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        // Dummy decompression so we can reset something
        decoder.decompress(&mut [0; 128]).unwrap();
        decoder.reset();
        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, INPUT.len());
        assert_eq!(INPUT.as_bytes(), output);
    }

    #[test]
    fn decompress_everything_after_partly_decompression() {
        let frame_size = INPUT.len() / 32;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        decoder.set_lower_frame(23).unwrap();
        decoder.set_upper_frame(29).unwrap();

        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, frame_size * 30 - frame_size * 23);
        assert_eq!(
            INPUT.as_bytes()[frame_size * 23..frame_size * 30],
            output[..n]
        );

        // Decompress all frames
        decoder.set_lower_frame(0).unwrap();
        decoder
            .set_upper_frame(decoder.seek_table().num_frames() - 1)
            .unwrap();
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, INPUT.len());
        assert_eq!(INPUT.as_bytes(), output);
    }

    #[test]
    fn set_frame_boundaries() {
        let seekable = new_seekable(None);
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();
        let num_frames = decoder.seek_table().num_frames();

        assert!(decoder.set_lower_frame(num_frames - 1).is_ok());
        assert!(decoder.set_upper_frame(num_frames - 1).is_ok());

        // Frame index out of range
        assert!(
            decoder
                .set_lower_frame(num_frames)
                .unwrap_err()
                .is_frame_index_too_large()
        );
        assert!(
            decoder
                .set_upper_frame(num_frames)
                .unwrap_err()
                .is_frame_index_too_large()
        );
    }

    #[test]
    fn set_offset_boundaries() {
        let seekable = new_seekable(None);
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        let mut offset = decoder.seek_table().size_decomp();
        assert!(decoder.set_offset(offset).is_ok());
        assert!(decoder.set_offset_limit(offset).is_ok());

        offset += 1;
        assert!(
            decoder
                .set_offset(offset)
                .unwrap_err()
                .is_offset_out_of_range()
        );
        assert!(
            decoder
                .set_offset_limit(offset)
                .unwrap_err()
                .is_offset_out_of_range()
        );
    }

    #[test]
    fn decompress_within_offset_boundaries() {
        let frame_size = INPUT.len() / 34;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        let offset = INPUT.len() / 3;
        let offset_limit = 2 * offset;
        decoder.set_offset(offset as u64).unwrap();
        decoder.set_offset_limit(offset_limit as u64).unwrap();

        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, offset_limit - offset);
        assert_eq!(INPUT.as_bytes()[offset..offset_limit], output[..n]);

        // Limit stays unchanged
        decoder.set_offset(3).unwrap();
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, offset_limit - 3);
        assert_eq!(INPUT.as_bytes()[3..offset_limit], output[..n]);

        // Reset unsets offset and limit
        decoder.reset();
        assert_eq!(decoder.offset(), 0);
        assert_eq!(decoder.offset_limit(), decoder.seek_table().size_decomp());
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, INPUT.len());
        assert_eq!(INPUT.as_bytes(), output);
    }

    #[cfg(feature = "std")]
    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn seek_decoder() {
        use std::io::{Seek, SeekFrom};

        let frame_size = INPUT.len() / 52;
        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(frame_size as u32)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();

        // Set the offset limit to make sure it isn't changed by seeking
        let seek_pos = frame_size * 13;
        let end = frame_size * 51;
        decoder.set_offset_limit(end as u64).unwrap();

        // Seek from start
        decoder.seek(SeekFrom::Start(seek_pos as u64)).unwrap();
        assert_eq!(decoder.offset(), seek_pos as u64);
        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_ne!(decoder.read_compressed(), 0);
        assert_eq!(n, end - seek_pos);
        assert_eq!(INPUT.as_bytes()[seek_pos..end], output[..n]);
        // Reading moves offset accordingly
        assert_eq!(decoder.offset(), end as u64);

        // Seek from end (needs to be more than one frame)
        let seek_pos = -((2 * frame_size) as i64);
        let start = (INPUT.len() as i64 + seek_pos) as usize;
        assert_ne!(decoder.read_compressed(), 0);
        decoder.seek(SeekFrom::End(seek_pos)).unwrap();
        assert_eq!(
            decoder.offset(),
            (INPUT.len() as u64).wrapping_add_signed(seek_pos)
        );
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - start);
        assert_eq!(INPUT.as_bytes()[start..end], output[..n]);

        // Positive seek from current
        decoder.seek(SeekFrom::Start(69)).unwrap();
        decoder.seek(SeekFrom::Current(10)).unwrap();
        assert_eq!(decoder.offset(), 79);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - 79);
        assert_eq!(INPUT.as_bytes()[79..end], output[..n]);

        // Negative seek from current
        decoder.seek(SeekFrom::Start(69)).unwrap();
        decoder.seek(SeekFrom::Current(-10)).unwrap();
        assert_eq!(decoder.offset(), 59);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - 59);
        assert_eq!(INPUT.as_bytes()[59..end], output[..n]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn set_offset_within_frame_continues_decompression() {
        use std::io::Read;

        let seekable = new_seekable(Some(FrameSizePolicy::Uncompressed(100)));
        let mut decoder = Decoder::new(BytesWrapper::new(&seekable)).unwrap();
        assert_eq!(decoder.read_compressed(), 0);

        decoder.set_offset(10).unwrap();
        decoder.read_exact(&mut [0; 10]).unwrap();
        assert_ne!(decoder.read_compressed(), 0);

        // No reset when frame doesn't change and offset > current offset
        decoder.set_offset(30).unwrap();
        assert_eq!(decoder.offset(), 30);
        assert_ne!(decoder.read_compressed(), 0);
        let mut output = vec![0; INPUT.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, INPUT.len() - 30);
        assert_eq!(INPUT.as_bytes()[30..], output[..n]);

        // Reset when offset is in another frame
        decoder.set_offset(101).unwrap();
        assert_eq!(decoder.offset(), 101);
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, INPUT.len() - 101);
        assert_eq!(INPUT.as_bytes()[101..], output[..n]);
    }

    /// Round trips through sources that fail partway, retrying like a caller that keeps what it
    /// already received would.
    #[cfg(feature = "std")]
    mod io_errors {
        use std::{
            io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom},
            ops::Range,
        };

        use super::*;

        /// A source that returns at most `chunk` bytes per read and fails, with `kind`, on every
        /// read whose index (counting from zero) lies in `failing_reads`.
        struct FlakySource<'a> {
            inner: Cursor<&'a [u8]>,
            chunk: usize,
            reads: usize,
            failing_reads: Range<usize>,
            kind: ErrorKind,
        }

        impl Read for FlakySource<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let read = self.reads;
                self.reads += 1;
                if self.failing_reads.contains(&read) {
                    return Err(io::Error::from(self.kind));
                }
                let n = buf.len().min(self.chunk);
                io::Read::read(&mut self.inner, &mut buf[..n])
            }
        }

        impl Seek for FlakySource<'_> {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.inner.seek(pos)
            }
        }

        /// Decompresses `seekable` through a source whose reads in `failing_reads` fail with
        /// `kind`, retrying as a caller would. Returns the output, how many errors reached the
        /// caller, and how many reads the source saw.
        fn decompress_with_retries(
            seekable: &[u8],
            seek_table: &SeekTable,
            failing_reads: Range<usize>,
            kind: ErrorKind,
        ) -> (Vec<u8>, usize, usize) {
            let mut src = FlakySource {
                inner: Cursor::new(seekable),
                chunk: 64,
                reads: 0,
                failing_reads,
                kind,
            };
            let mut decoder = DecodeOptions::new(&mut src)
                .seek_table(seek_table.clone())
                .into_decoder()
                .unwrap();
            let mut output = vec![];
            let mut buf = vec![0; INPUT.len()];
            let mut errors = 0;
            loop {
                match decoder.decompress(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => output.extend(&buf[..n]),
                    Err(err) => {
                        assert!(err.is_io());
                        errors += 1;
                    }
                }
            }
            drop(decoder);
            (output, errors, src.reads)
        }

        #[test]
        fn read_errors_never_lose_output() {
            let seekable =
                new_seekable(Some(FrameSizePolicy::Uncompressed(INPUT.len() as u32 / 7)));
            let seek_table = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
            let (_, _, reads) =
                decompress_with_retries(&seekable, &seek_table, 0..0, ErrorKind::TimedOut);
            for fail_at in 0..reads {
                let (output, errors, _) = decompress_with_retries(
                    &seekable,
                    &seek_table,
                    fail_at..fail_at + 2,
                    ErrorKind::TimedOut,
                );
                // Two failures in a row: whatever the first one interrupted, the second hits a
                // fresh call and must reach the caller
                assert!(
                    errors >= 1,
                    "no error reported for reads {fail_at} and {}",
                    fail_at + 1
                );
                assert_eq!(
                    output,
                    INPUT.as_bytes(),
                    "wrong output after reads {fail_at} and {} failed",
                    fail_at + 1
                );
            }
        }

        #[test]
        fn interrupted_reads_are_retried_internally() {
            let seekable =
                new_seekable(Some(FrameSizePolicy::Uncompressed(INPUT.len() as u32 / 7)));
            let seek_table = SeekTable::from_seekable(&mut BytesWrapper::new(&seekable)).unwrap();
            let (_, _, reads) =
                decompress_with_retries(&seekable, &seek_table, 0..0, ErrorKind::Interrupted);
            for fail_at in 0..reads {
                let (output, errors, _) = decompress_with_retries(
                    &seekable,
                    &seek_table,
                    fail_at..fail_at + 2,
                    ErrorKind::Interrupted,
                );
                assert_eq!(errors, 0, "interruption of read {fail_at} leaked");
                assert_eq!(output, INPUT.as_bytes());
            }
        }
    }
}
