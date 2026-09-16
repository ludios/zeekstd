// Model-output: Claude Fable 5.1
//! Reproductions of the CLI findings in `known_unfixed_bugs.md`.
//!
//! Each test asserts the behaviour the finding asks for. A test that is `#[ignore]`d still fails
//! at HEAD: run `cargo test -p zeekstd_cli -- --ignored known_bugs` to see which findings are
//! still open, and drop the attribute once a fix makes its test pass.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

/// Archive content without a newline, so that a line-buffered stdout holds all of it until exit.
const CONTENT: &[u8] = b"hello storage";

/// Path of the CLI binary under test.
const ZEEKSTD: &str = env!("CARGO_BIN_EXE_zeekstd");

/// A `Foot` seek table frame with zero frames: the archive the reference implementation writes
/// for empty input.
const ZERO_FRAME_ARCHIVE: [u8; 17] = [
    0x5E, 0x2A, 0x4D, 0x18, // skippable magic
    9, 0, 0, 0, // frame size
    0, 0, 0, 0, // number of frames
    0, // descriptor
    0xB1, 0xEA, 0x92, 0x8F, // seekable magic
];

/// Writes `content` to `dir/name` and returns the path.
fn file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

/// Compresses `content` with the CLI into `dir/input.zst` and returns the archive path.
fn archive(dir: &Path, content: &[u8]) -> PathBuf {
    let input = file(dir, "input", content);
    let out = dir.join("input.zst");
    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--output-file")
        .arg(&out)
        .assert()
        .success();
    out
}

/// Finding 4: an output path that names the input must not truncate the input.
#[test]
#[ignore = "known unfixed: the output is created, truncating the input, before the input is read"]
fn compress_onto_itself_keeps_the_source() {
    let dir = TempDir::new().unwrap();
    let input = file(dir.path(), "input", CONTENT);
    let run = cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--output-file")
        .arg(&input)
        .arg("--force")
        .arg("--quiet")
        .assert();
    assert_eq!(fs::read(&input).unwrap(), CONTENT);
    run.failure();
}

/// Finding 4: a hard link of the input is the input.
#[test]
#[ignore = "known unfixed: outputs are not checked for aliasing the input"]
fn compress_onto_hard_link_keeps_the_source() {
    let dir = TempDir::new().unwrap();
    let input = file(dir.path(), "input", CONTENT);
    let link = dir.path().join("link");
    fs::hard_link(&input, &link).unwrap();
    let run = cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--output-file")
        .arg(&link)
        .arg("--force")
        .arg("--quiet")
        .assert();
    assert_eq!(fs::read(&input).unwrap(), CONTENT);
    run.failure();
}

/// Finding 4: decompressing an archive onto itself must not truncate the archive.
#[test]
#[ignore = "known unfixed: the output is created before the archive is opened"]
fn decompress_onto_itself_keeps_the_archive() {
    let dir = TempDir::new().unwrap();
    let archive = archive(dir.path(), CONTENT);
    let before = fs::read(&archive).unwrap();
    let run = cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(&archive)
        .arg("--output-file")
        .arg(&archive)
        .arg("--force")
        .arg("--quiet")
        .assert();
    assert_eq!(fs::read(&archive).unwrap(), before);
    run.failure();
}

/// Finding 5: a decompression that fails must leave the previous output untouched.
#[test]
#[ignore = "known unfixed: the output is created before the input is opened"]
fn failed_decompression_keeps_the_previous_output() {
    let dir = TempDir::new().unwrap();
    let backup = file(dir.path(), "backup", b"previous restore");
    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(dir.path().join("missing.zst"))
        .arg("--output-file")
        .arg(&backup)
        .arg("--force")
        .arg("--quiet")
        .assert()
        .failure();
    assert_eq!(fs::read(&backup).unwrap(), b"previous restore");
}

/// Finding 5: declining to overwrite the data file cancels the operation, so the seek table file
/// that was approved first must survive as well.
#[test]
#[ignore = "known unfixed: the seek table file is truncated before the data file prompt"]
fn cancelled_compression_keeps_the_existing_seek_table() {
    let dir = TempDir::new().unwrap();
    let input = file(dir.path(), "input", CONTENT);
    let out = file(dir.path(), "out.zst", b"old archive");
    let table = file(dir.path(), "table", b"old table");
    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--output-file")
        .arg(&out)
        .arg("--seek-table-file")
        .arg(&table)
        .write_stdin("y\nn\n")
        .assert()
        .failure();
    assert_eq!(fs::read(&table).unwrap(), b"old table");
    assert_eq!(fs::read(&out).unwrap(), b"old archive");
}

/// Finding 5: a missing prefix file must be noticed before any output is created.
#[test]
#[ignore = "known unfixed: outputs are created before the prefix is loaded"]
fn missing_prefix_does_not_create_outputs() {
    let dir = TempDir::new().unwrap();
    let input = file(dir.path(), "input", CONTENT);
    let out = dir.path().join("out.zst");
    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--patch-from")
        .arg(dir.path().join("missing"))
        .arg("--output-file")
        .arg(&out)
        .assert()
        .failure();
    assert!(!out.exists(), "an output was created for a failed run");
}

/// Finding 6: a stdout that accepts nothing must make decompression fail.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "known unfixed: decompression never flushes stdout, and the exit-time flush error is lost"]
fn decompress_to_full_device_fails() {
    let dir = TempDir::new().unwrap();
    let archive = archive(dir.path(), CONTENT);
    let status = Command::new(ZEEKSTD)
        .arg("decompress")
        .arg(&archive)
        .arg("--stdout")
        .stdout(File::create("/dev/full").unwrap())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "exit status {status} although nothing could be written"
    );
}

/// Finding 12: a valid zero-frame archive lists without panicking.
#[test]
#[ignore = "known unfixed: the summary asks for frame num_frames - 1 of an empty table"]
fn list_zero_frame_archive() {
    let dir = TempDir::new().unwrap();
    let archive = file(dir.path(), "zero.zst", &ZERO_FRAME_ARCHIVE);
    cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg(&archive)
        .assert()
        .success();
}

/// Finding 12: a valid zero-frame archive decompresses to nothing.
#[test]
#[ignore = "known unfixed: frame lookup underflows on an empty table"]
fn decompress_zero_frame_archive() {
    let dir = TempDir::new().unwrap();
    let archive = file(dir.path(), "zero.zst", &ZERO_FRAME_ARCHIVE);
    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(&archive)
        .arg("--stdout")
        .assert()
        .success()
        .stdout(b"".as_slice());
}

/// Waits until process `pid` blocks on a pipe, for at most five seconds. The CLI reads its input
/// only after the prefix has been loaded, and its stdin is the only pipe it ever waits on, so this
/// marks the point where the prefix is in use, however it is stored. The wait channel is named
/// `anon_pipe_read`, `pipe_wait_readable` or `pipe_read` depending on the kernel.
#[cfg(target_os = "linux")]
fn wait_until_blocked_on_stdin(pid: u32) {
    let wchan = format!("/proc/{pid}/wchan");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match fs::read_to_string(&wchan) {
            Ok(wait) if wait.contains("pipe") => return,
            Ok(_) => thread::sleep(Duration::from_millis(20)),
            Err(err) => panic!("process {pid} went away before reading stdin: {err}"),
        }
    }
    panic!("process {pid} did not start reading stdin within five seconds");
}

/// Finding 16: truncating a prefix file after the CLI has loaded it must not kill the process.
/// The prefix is above the 1 MiB threshold at which the CLI memory-maps prefixes by default.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "known unfixed: mapped prefix files are not protected against concurrent truncation"]
fn truncating_a_mapped_prefix_does_not_crash() {
    use std::os::unix::process::ExitStatusExt;

    let dir = TempDir::new().unwrap();
    let prefix = file(dir.path(), "prefix", &vec![0xAB; 2 << 20]);
    let mut child = Command::new(ZEEKSTD)
        .arg("compress")
        .arg("--patch-from")
        .arg(&prefix)
        .arg("--stdout")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_until_blocked_on_stdin(child.id());
    OpenOptions::new()
        .write(true)
        .open(&prefix)
        .unwrap()
        .set_len(0)
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // The child may already be gone, which closes the pipe
    let _ = stdin.write_all(&vec![0xAB; 1 << 16]);
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.signal().is_none(),
        "the CLI was killed by signal {:?}",
        output.status.signal()
    );
}

/// Finding 17: a prefix shorter than 512 bytes is valid content and must not fail compression.
#[test]
#[ignore = "known unfixed: the window log is derived from the prefix length and falls below zstd's minimum"]
fn small_prefix_round_trips() {
    let dir = TempDir::new().unwrap();
    let prefix = file(dir.path(), "prefix", &[b'x'; 100]);
    let input = file(dir.path(), "input", CONTENT);
    let out = dir.path().join("out.zst");
    let restored = dir.path().join("restored");
    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(&input)
        .arg("--patch-from")
        .arg(&prefix)
        .arg("--output-file")
        .arg(&out)
        .assert()
        .success();
    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(&out)
        .arg("--patch-apply")
        .arg(&prefix)
        .arg("--output-file")
        .arg(&restored)
        .assert()
        .success();
    assert_eq!(fs::read(&restored).unwrap(), CONTENT);
}

/// Finding 20: an out-of-range frame count must produce a clean error, not a panic.
#[test]
#[ignore = "known unfixed: from_frame + num_frames is added without overflow checking"]
fn list_frame_range_overflow_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let archive = archive(dir.path(), CONTENT);
    let output = cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg(&archive)
        .arg("--from-frame")
        .arg("2")
        .arg("--num-frames")
        .arg("4294967295")
        .assert()
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "the CLI panicked: {stderr}");
}

/// Nit: `--to-frame` advertises the special value `last` but only accepts `end`.
#[test]
#[ignore = "known unfixed: --to-frame help says 'last', the parser accepts 'end'"]
fn to_frame_accepts_last_as_advertised() {
    let dir = TempDir::new().unwrap();
    let archive = archive(dir.path(), CONTENT);
    cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg(&archive)
        .arg("--to-frame")
        .arg("last")
        .assert()
        .success();
}
