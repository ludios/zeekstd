// Model-output: Claude Fable 5.1
// Model-output: Claude Opus 5.5
//! Sources and loops shared by the test suites.
#![allow(dead_code)]

use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    ops::Range,
};

use zeekstd::{Decoder, SeekTable, seek_table::Format};

/// A `Read + Seek` source that returns at most `chunk` bytes per read, and only bytes of its
/// window if it has one, like a source that fetched just those: a read elsewhere fails.
pub struct Chunked<'a> {
    pub inner: Cursor<&'a [u8]>,
    chunk: usize,
    window: Option<Range<u64>>,
}

impl<'a> Chunked<'a> {
    pub fn new(bytes: &'a [u8], chunk: usize) -> Self {
        Self {
            inner: Cursor::new(bytes),
            chunk,
            window: None,
        }
    }

    /// Limits reads to the bytes in `window`.
    pub fn within(mut self, window: Range<u64>) -> Self {
        self.window = Some(window);
        self
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len = buf.len().min(self.chunk);
        if let Some(window) = &self.window {
            let pos = self.inner.position();
            if !window.contains(&pos) {
                let message = format!("read at {pos}, outside the window {window:?}");
                return Err(io::Error::other(message));
            }
            len = len.min((window.end - pos) as usize);
        }
        self.inner.read(&mut buf[..len])
    }
}

impl Seek for Chunked<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// `seek_table` serialized in `format`.
pub fn serialize(seek_table: &SeekTable, format: Format) -> Vec<u8> {
    let mut ser = seek_table.clone().into_format_serializer(format);
    let mut bytes = vec![0; ser.encoded_len()];
    assert_eq!(ser.write_into(&mut bytes), bytes.len());
    bytes
}

/// Decompresses from `decoder` in `buf_len`-byte steps until it reports the end, referencing
/// `prefix` at every frame. Panics if the decoder produces more than its seek table holds, so
/// that one that never reports the end cannot hang the test.
pub fn decode_all<'a, S: zeekstd::Seekable>(
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
