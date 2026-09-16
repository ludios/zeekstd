//! Library-level interop probes. Each case writes `<name>.zst` and `<name>.expected` into OUT.
//! Foot-format archives are additionally verified with Meta's reference seekable decoder
//! (zstd's contrib/seekable_format, via zstd-safe's `seekable` feature) and with zeekstd's Decoder.
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
};
use zeekstd::{BytesWrapper, DecodeOptions, Decoder, EncodeOptions, Encoder, FrameSizePolicy, RawEncoder, seek_table::Format};
use zstd_safe::{CCtx, CParameter, DCtx, DParameter};

const S: &str = "/tmp/claude-1000/-home-at-code-rust-zeekstd/47699d34-aff7-43ab-b601-f33bcfba8014/scratchpad";

fn data(name: &str) -> Vec<u8> { fs::read(format!("{S}/data/{name}")).unwrap() }
fn out_path(name: &str, ext: &str) -> String { format!("{S}/out/lib_{name}.{ext}") }

/// Deterministic chunk sizes without pulling in a crate.
struct Lcg(u64);
impl Lcg { fn next(&mut self, max: usize) -> usize { self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); ((self.0 >> 33) as usize % max) + 1 } }

fn verify_reference(name: &str, archive: &[u8], expected: &[u8]) -> Result<String, String> {
    let e = |c| zstd_safe::get_error_name(c).to_string();
    let mut s = zstd_safe::seekable::Seekable::create();
    s.init_buff(archive).map_err(|c| format!("ref init_buff: {}", e(c)))?;
    let n = s.num_frames();
    let (mut csum, mut dsum) = (0u64, 0u64);
    for i in 0..n {
        csum += s.frame_compressed_size(i).map_err(|c| e(c))? as u64;
        dsum += s.frame_decompressed_size(i).map_err(|c| e(c))? as u64;
    }
    if dsum != expected.len() as u64 { return Err(format!("ref table dsum {dsum} != {}", expected.len())); }
    let table_len = 8 + 9 + 8 * n as u64; // skippable header + integrity + entries
    if csum + table_len != archive.len() as u64 { return Err(format!("ref table csum {csum} + table {table_len} != archive {}", archive.len())); }
    // full read through the reference decoder, in 100 KiB steps
    let mut out = vec![0u8; expected.len()];
    let mut pos = 0usize;
    while pos < out.len() {
        let end = (pos + 100 * 1024).min(out.len());
        let got = s.decompress(&mut out[pos..end], pos as u64).map_err(|c| format!("ref decompress @{pos}: {}", e(c)))?;
        if got == 0 { return Err(format!("ref decompress returned 0 at {pos}")); }
        pos += got;
    }
    if out != expected { return Err("ref full output differs".into()); }
    // random access across the first frame boundary and at the tail
    if n >= 2 && !expected.is_empty() {
        let b = s.frame_decompressed_offset(1).map_err(|_| "ref frame offset".to_string())? as usize;
        let from = b.saturating_sub(37); let to = (b + 41).min(expected.len());
        let mut buf = vec![0u8; to - from];
        let got = s.decompress(&mut buf[..], from as u64).map_err(|c| format!("ref range: {}", e(c)))?;
        if &buf[..got] != &expected[from..from + got] || got != to - from { return Err(format!("ref range [{from},{to}) differs")); }
    }
    Ok(format!("ref ok: {n} frames"))
}

fn verify_zeekstd(archive: &[u8], expected: &[u8], prefix: Option<&[u8]>) -> Result<(), String> {
    let mut dctx = DCtx::create();
    if let Some(p) = prefix { dctx.set_parameter(DParameter::WindowLogMax(p.len().ilog2() + 1)).unwrap(); }
    let mut dec = DecodeOptions::with_dctx(BytesWrapper::new(archive), dctx).into_decoder().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = dec.decompress_with_prefix(&mut buf, prefix).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        out.extend_from_slice(&buf[..n]);
    }
    if out != expected { return Err(format!("zeekstd Decoder output differs ({} vs {})", out.len(), expected.len())); }
    Ok(())
}

fn finish_case(name: &str, archive: Vec<u8>, expected: &[u8], foot: bool, prefix: Option<&[u8]>) {
    fs::write(out_path(name, "zst"), &archive).unwrap();
    fs::write(out_path(name, "expected"), expected).unwrap();
    let r = if foot && prefix.is_none() { verify_reference(name, &archive, expected) } else { Ok("ref skipped".into()) };
    let z = verify_zeekstd(&archive, expected, prefix);
    let z = if foot { z } else { Ok(()) };
    println!("{:<24} {:>10} B  {}  {}", name, archive.len(), r.map_or_else(|e| format!("REF-FAIL {e}"), |m| m), z.map_or_else(|e| format!("ZK-FAIL {e}"), |_| "zk ok".into()));
}

fn raw_to_vec<'a>(mut enc: RawEncoder<'a>, input: &[u8], in_chunk: usize, out_buf_len: usize, table_buf_len: usize, prefix: Option<&'a [u8]>) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut out = vec![0u8; out_buf_len];
    let mut pos = 0;
    while pos < input.len() {
        let end = (pos + in_chunk).min(input.len());
        let p = enc.compress_with_prefix(&input[pos..end], &mut out, prefix).unwrap();
        archive.extend_from_slice(&out[..p.out_progress()]);
        pos += p.in_progress();
    }
    loop {
        let p = enc.end_frame(&mut out).unwrap();
        archive.extend_from_slice(&out[..p.out_progress()]);
        if p.data_left() == 0 { break; }
    }
    let mut ser = enc.into_seek_table().into_serializer();
    let mut tb = vec![0u8; table_buf_len];
    loop {
        let n = ser.write_into(&mut tb);
        if n == 0 { break; }
        archive.extend_from_slice(&tb[..n]);
    }
    archive
}

fn main() {
    let mixed = data("mixed10m");
    let text6m = data("text6m_exact");
    let rnd1m = data("rnd1m");

    // A. Encoder defaults: library default has checksums OFF
    {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf).unwrap();
        io::copy(&mut &mixed[..], &mut enc).unwrap();
        enc.finish().unwrap();
        finish_case("default_nochecksum", buf, &mixed, true, None);
    }
    // B. Head-format table appended after the data (finish_format(Head))
    {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf).unwrap();
        io::copy(&mut &mixed[..], &mut enc).unwrap();
        enc.finish_format(Format::Head).unwrap();
        finish_case("head_appended", buf, &mixed, false, None);
    }
    // C. RawEncoder, 1000-byte frames, checksums, 7-byte output buffer, 13-byte input chunks, 3-byte table buffer
    {
        let input = &text6m[..100 * 1024];
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(1000)).into_raw_encoder().unwrap();
        finish_case("raw_tinybuf", raw_to_vec(enc, input, 13, 7, 3, None), input, true, None);
    }
    // C2. same but 1-byte output buffer and 1-byte table buffer (worst case for the epilogue/table splitting)
    {
        let input = &text6m[..20 * 1024];
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(777)).into_raw_encoder().unwrap();
        finish_case("raw_1bytebuf", raw_to_vec(enc, input, 5, 1, 1, None), input, true, None);
    }
    // D. Compressed-size policy via RawEncoder
    {
        let mut input = rnd1m.clone(); input.extend_from_slice(&text6m[..2 * 1024 * 1024]);
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Compressed(4096)).into_raw_encoder().unwrap();
        finish_case("raw_cpol4096", raw_to_vec(enc, &input, 4096, 4096, 64, None), &input, true, None);
    }
    // E. Manual frames incl. empty frames: end_frame() before any data, twice in a row, then finish()
    {
        let mut buf = Vec::new();
        let mut enc = EncodeOptions::new().checksum_flag(true).into_encoder(&mut buf).unwrap();
        enc.end_frame().unwrap();            // empty first frame
        enc.write_all(b"hello").unwrap();
        enc.end_frame().unwrap();
        enc.end_frame().unwrap();            // another empty frame
        let mut lcg = Lcg(7);
        let mut pos = 5;
        while pos < mixed.len() { let n = lcg.next(100_000).min(mixed.len() - pos); enc.write_all(&mixed[pos..pos + n]).unwrap(); pos += n; }
        enc.end_frame().unwrap();
        enc.finish().unwrap();               // finish() ends the (now empty) current frame again
        let mut expected = b"hello".to_vec(); expected.extend_from_slice(&mixed[5..]);
        finish_case("manual_empty_frames", buf, &expected, true, None);
    }
    // F. Encoder over BufWriter<File>, 64 KiB frames, level 9, odd chunk sizes, flush() mid-stream
    {
        let path = out_path("bufwriter_l9", "zst");
        let file = File::create(&path).unwrap();
        let mut enc = EncodeOptions::new().checksum_flag(true).compression_level(9).frame_size_policy(FrameSizePolicy::Uncompressed(65536)).into_encoder(BufWriter::new(file)).unwrap();
        let mut lcg = Lcg(99);
        let mut pos = 0;
        while pos < mixed.len() { let n = lcg.next(50_000).min(mixed.len() - pos); enc.write_all(&mixed[pos..pos + n]).unwrap(); pos += n; if pos % 3 == 0 { enc.flush().unwrap(); } }
        enc.finish().unwrap();
        let archive = fs::read(&path).unwrap();
        finish_case("bufwriter_l9", archive, &mixed, true, None);
    }
    // G. 1-byte frames: 100K frames at level 3, 1K frames at level 19
    {
        let input = &text6m[..100 * 1024];
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(1)).into_raw_encoder().unwrap();
        finish_case("frames1b_100k_l3", raw_to_vec(enc, input, 4096, 65536, 65536, None), input, true, None);
        let input = &text6m[..1024];
        let enc = EncodeOptions::new().checksum_flag(true).compression_level(19).frame_size_policy(FrameSizePolicy::Uncompressed(1)).into_raw_encoder().unwrap();
        finish_case("frames1b_1k_l19", raw_to_vec(enc, input, 4096, 65536, 65536, None), input, true, None);
    }
    // H. Prefix (patch) via the library, 1 MiB frames -> 3 frames, window log like the CLI
    {
        let pfx = data("pfx3m"); let input = data("pfx3m_modified");
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::WindowLog(pfx.len().ilog2() + 1)).unwrap();
        cctx.set_parameter(CParameter::EnableLongDistanceMatching(true)).unwrap();
        let enc = EncodeOptions::with_cctx(cctx).checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(1 << 20)).into_raw_encoder().unwrap();
        let archive = raw_to_vec(enc, &input, 65536, 65536, 65536, Some(&pfx));
        finish_case("prefix_3frames", archive, &input, true, Some(&pfx));
    }
    // I. Empty input through Encoder
    {
        let mut buf = Vec::new();
        let enc = EncodeOptions::new().checksum_flag(true).into_encoder(&mut buf).unwrap();
        enc.finish().unwrap();
        finish_case("empty", buf, b"", true, None);
    }
    // J. Frame size exactly equal to input, and input = frame size + 1 (boundary), 64 KiB frames
    {
        let input = &rnd1m[..65536];
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(65536)).into_raw_encoder().unwrap();
        finish_case("exact_frame", raw_to_vec(enc, input, 65536, 65536, 65536, None), input, true, None);
        let input = &rnd1m[..65537];
        let enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(65536)).into_raw_encoder().unwrap();
        finish_case("exact_frame_plus1", raw_to_vec(enc, input, 65536, 65536, 65536, None), input, true, None);
    }
    // K. Decoder-side note: also write a plain single-frame archive from Encoder with 1 GiB policy over 10 MiB (single frame)
    {
        let mut buf = Vec::new();
        let mut enc = EncodeOptions::new().checksum_flag(true).frame_size_policy(FrameSizePolicy::Uncompressed(1 << 30)).into_encoder(&mut buf).unwrap();
        io::copy(&mut &mixed[..], &mut enc).unwrap();
        enc.finish().unwrap();
        finish_case("single_frame_10m", buf, &mixed, true, None);
    }
}
