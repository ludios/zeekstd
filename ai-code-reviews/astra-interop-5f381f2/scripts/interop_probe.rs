use std::{env, fs::{self, File}, io::{self, Read, Write, Seek, SeekFrom}};
use zeekstd::{EncodeOptions, FrameSizePolicy, seek_table::Format};
use zstd_safe::{CCtx, CParameter};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ze<T>(r: std::result::Result<T, usize>) -> Result<T> {
    r.map_err(|e| format!("zstd: {}", zstd_safe::get_error_name(e)).into())
}
fn main() {
    if let Err(e) = run() { eprintln!("ERROR: {e}"); std::process::exit(1); }
}
fn run() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    if a[1] == "version" { println!("libzstd {}", zstd_safe::version_string()); return Ok(()); }
    if a[1] == "scan" {
        let data = fs::read(&a[2])?;
        let mut offset = 0;
        while offset < data.len() {
            let n = ze(zstd_safe::find_frame_compressed_size(&data[offset..]))?;
            println!("{} {} {:02x}{:02x}{:02x}{:02x}", offset, n, data[offset],data[offset+1],data[offset+2],data[offset+3]);
            offset += n;
        }
        return Ok(());
    }
    if a[1] == "oracle" { return oracle(&a[2], &a[3]); }
    let get = |key: &str, def: &str| -> String {
        a[4..].iter().find_map(|s| s.strip_prefix(&format!("{key}=")).map(str::to_owned)).unwrap_or(def.to_owned())
    };
    let raw = get("api", "writer") == "raw";
    let head = get("format", "foot") == "head";
    let separate = get("separate", "0") == "1";
    let format = if head { Format::Head } else { Format::Foot };
    let frame: u32 = get("frame", "2097152").parse()?;
    let input_chunk: usize = get("in", "131072").parse()?;
    let output_chunk: usize = get("out", "131591").parse()?;
    let flush_every: usize = get("flush", "0").parse()?;
    let end_every: usize = get("end", "0").parse()?;
    let end_flush = get("end_flush", "0") == "1";
    let prefix = get("prefix", "");
    let prefix = if prefix.is_empty() { None } else { Some(fs::read(prefix)?) };
    let dictionary = get("dict", "");
    let mut cctx = CCtx::create();
    if !dictionary.is_empty() { ze(cctx.load_dictionary(&fs::read(dictionary)?))?; }
    let window: u32 = get("window", "0").parse()?;
    if window != 0 { ze(cctx.set_parameter(CParameter::WindowLog(window)))?; }
    if get("ldm", "0") == "1" { ze(cctx.set_parameter(CParameter::EnableLongDistanceMatching(true)))?; }
    if get("content", "1") == "0" { ze(cctx.set_parameter(CParameter::ContentSizeFlag(false)))?; }
    let workers: u32 = get("workers", "0").parse()?;
    if workers != 0 { ze(cctx.set_parameter(CParameter::NbWorkers(workers)))?; }
    if get("pledge", "0") == "1" { ze(cctx.set_pledged_src_size(Some(fs::metadata(&a[2])?.len())))?; }
    let opts = EncodeOptions::with_cctx(cctx)
        .compression_level(get("level", "3").parse()?)
        .checksum_flag(get("checksum", "0") == "1")
        .frame_size_policy(if get("policy", "u") == "u" { FrameSizePolicy::Uncompressed(frame) } else { FrameSizePolicy::Compressed(frame) });
    let mut src = File::open(&a[2])?;
    let mut dst = File::create(&a[3])?;
    let mut ib = vec![0; input_chunk];
    let mut calls = 0;
    if raw {
        let mut enc = opts.into_raw_encoder()?;
        let mut ob = vec![0; output_chunk];
        // Exercise documented no-op calls too.
        let p = enc.compress(&[], &mut [])?;
        assert_eq!(p.in_progress() + p.out_progress(), 0);
        loop {
            let n = src.read(&mut ib)?;
            if n == 0 { break; }
            let mut pos = 0;
            while pos < n {
                let p = enc.compress_with_prefix(&ib[pos..n], &mut ob, prefix.as_deref())?;
                dst.write_all(&ob[..p.out_progress()])?;
                pos += p.in_progress();
            }
            calls += 1;
            if flush_every != 0 && calls % flush_every == 0 {
                loop { let p = enc.flush(&mut ob)?; dst.write_all(&ob[..p.out_progress()])?; if p.data_left() == 0 { break; } }
            }
            if end_every != 0 && calls % end_every == 0 {
                let p = enc.end_frame(&mut ob)?;
                dst.write_all(&ob[..p.out_progress()])?;
                if p.data_left() != 0 {
                    loop { let p = if end_flush { enc.flush(&mut ob)? } else { enc.end_frame(&mut ob)? }; dst.write_all(&ob[..p.out_progress()])?; if p.data_left() == 0 { break; } }
                }
            }
        }
        loop { let p = enc.end_frame(&mut ob)?; dst.write_all(&ob[..p.out_progress()])?; if p.data_left() == 0 { break; } }
        let mut ser = enc.into_seek_table().into_format_serializer(format);
        let mut side;
        let target: &mut dyn Write = if separate { side = File::create(format!("{}.table", a[3]))?; &mut side } else { &mut dst };
        loop { let n = ser.write_into(&mut ob); if n == 0 { break; } target.write_all(&ob[..n])?; }
    } else {
        let short: usize = get("short", "18446744073709551615").parse()?;
        struct Short<'a>(&'a mut File, usize);
        impl Write for Short<'_> {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> { self.0.write(&b[..b.len().min(self.1)]) }
            fn flush(&mut self) -> io::Result<()> { self.0.flush() }
        }
        let mut enc = opts.into_encoder(Short(&mut dst, short))?;
        loop {
            let n = src.read(&mut ib)?;
            if n == 0 { break; }
            let mut pos = 0;
            while pos < n { pos += enc.compress_with_prefix(&ib[pos..n], prefix.as_deref())?; }
            calls += 1;
            if flush_every != 0 && calls % flush_every == 0 { enc.flush()?; }
            if end_every != 0 && calls % end_every == 0 { enc.end_frame()?; }
        }
        if separate {
            enc.end_frame()?;
            enc.flush()?;
            let mut ser = enc.into_seek_table().into_format_serializer(format);
            io::copy(&mut ser, &mut File::create(format!("{}.table", a[3]))?)?;
        } else { enc.finish_format(format)?; }
    }
    Ok(())
}

fn oracle(archive: &str, original: &str) -> Result<()> {
    let data = fs::read(archive)?;
    let mut dec = zstd_safe::seekable::Seekable::create();
    ze(dec.init_buff(&data))?;
    let mut co = 0u64;
    let mut ds = 0u64;
    let mut max_d = 0;
    let mut checksum_frames = 0;
    let mut offsets = vec![0];
    for i in 0..dec.num_frames() {
        let c = ze(dec.frame_compressed_size(i))? as u64;
        let d = ze(dec.frame_decompressed_size(i))? as u64;
        assert_eq!(dec.frame_compressed_offset(i).unwrap(), co);
        assert_eq!(dec.frame_decompressed_offset(i).unwrap(), ds);
        assert_eq!(ze(zstd_safe::find_frame_compressed_size(&data[co as usize..]))? as u64, c, "index disagrees with actual frame boundary");
        let f = &data[co as usize..(co+c) as usize];
        assert_eq!(&f[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        if f[4] & 4 != 0 { checksum_frames += 1; }
        if let Some(content) = zstd_safe::get_frame_content_size(f).map_err(|e| format!("{e:?}"))? { assert_eq!(content, d); }
        co += c; ds += d; max_d = max_d.max(d);
        if offsets.len() < 20 || i + 2 >= dec.num_frames() { offsets.push(ds); }
    }
    let table = &data[co as usize..];
    assert_eq!(&table[..4], &[0x5e, 0x2a, 0x4d, 0x18]);
    let size = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
    assert_eq!(size + 8, table.len());
    assert_eq!(size, dec.num_frames() as usize * 8 + 9);
    assert_eq!(table[table.len()-5], 0);
    assert_eq!(ds, fs::metadata(original)?.len(), "indexed uncompressed total");
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut ob = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < ds {
        let n = (ds-offset).min(ob.len() as u64) as usize;
        let got = ze(dec.decompress(&mut ob[..n], offset))?;
        assert_eq!(got, n);
        out.write_all(&ob[..n])?;
        offset += n as u64;
    }
    out.flush()?;
    let mut src = File::open(original)?;
    let mut queries = 0;
    // Out-of-order queries, frame crossings, and 32-bit offset crossings.
    offsets.extend([ds/2, ds/3, ds.saturating_sub(1), 0xffff_ffff, 0x1_0000_0000]);
    offsets.reverse();
    for off in offsets {
        for start in [off.saturating_sub(13), off] {
            if start >= ds { continue; }
            let n = (ds-start).min(257) as usize;
            let mut expected = vec![0; n];
            src.seek(SeekFrom::Start(start))?; src.read_exact(&mut expected)?;
            let got = ze(dec.decompress(&mut ob[..n], start))?;
            assert_eq!(got, n); assert_eq!(&ob[..n], &expected);
            queries += 1;
        }
    }
    eprintln!("REFERENCE_OK frames={} compressed_data={} decompressed={} max_frame={} checksum_frames={} random_queries={}", dec.num_frames(), co, ds, max_d, checksum_frames, queries);
    Ok(())
}
