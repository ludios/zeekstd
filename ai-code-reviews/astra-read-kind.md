# Summary by Claude Fable 5.1

Design question put to Codex CLI (gpt-6-astra, reasoning effort xhigh) on 2026-09-16, while fixing astra finding 8 (decoder spins on EOF): should `Decoder`'s `std::io::Read` impl surface the new `UnexpectedEof` error as `io::ErrorKind::UnexpectedEof` instead of `Other`?

Codex's answer: **yes**, map that one error to `UnexpectedEof` and keep the wrapped `zeekstd::Error` as its source. It checked std's adapters (`read_exact`, `read_to_end`, `io::copy`, `BufReader`, `take`) and found none treat that kind as a clean end of stream, and it checked how `zstd`, `flate2`, `xz2`, `bzip2` and `ruzstd` report truncated input (all but `ruzstd` use `UnexpectedEof`). It advises against widening the change to pass `Kind::IO` kinds through or to map zstd corruption to `InvalidData` in the same step. zeekstd-68's `From<zeekstd::Error> for io::Error` is where the arm belongs.

Codex's full answer follows below, verbatim.

---

**Yes — map the new error to `std::io::ErrorKind::UnexpectedEof`.** The decoder cannot produce the data promised by the seek table because compressed input ended. That fits [std’s definition](https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.UnexpectedEof), and lets callers recognize truncation without parsing a message.

Use `io::Error::new(io::ErrorKind::UnexpectedEof, err)` when `err.is_unexpected_eof()`; retain `io::Error::other(err)` otherwise. Keeping the original `zeekstd::Error` preserves its message and allows downcasting.

The standard adapters do not treat this kind as successful EOF:

| API | Behavior |
| --- | --- |
| `read_exact` | Propagates either `UnexpectedEof` or `Other` from `read`; also synthesizes `UnexpectedEof` if `Ok(0)` arrives before its buffer is full. Retries `Interrupted`. [Source](https://doc.rust-lang.org/std/io/trait.Read.html#method.read_exact) |
| `read_to_end`, `io::copy` | Return either error; neither swallows or retries `UnexpectedEof`/`Other`. Both retry `Interrupted`; clean EOF is `Ok(0)`. [Read](https://doc.rust-lang.org/std/io/trait.Read.html#method.read_to_end), [copy source](/home/at/.rustup/toolchains/nightly-2026-08-29-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/io/copy.rs:45) |
| `BufReader::read` | Returns buffered bytes or propagates the underlying error unchanged; no special retry for either kind, or for `Interrupted` in this method. Its `read_exact`/`read_to_end` retain their usual retry behavior. [Source](/home/at/.rustup/toolchains/nightly-2026-08-29-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/io/buffered/bufreader.rs:351) |
| `take(n).read` | Propagates errors without retrying; once its limit reaches zero, returns `Ok(0)` without reading further. Thus it can leave later corruption undiscovered regardless of error kind. [Source](/home/at/.rustup/toolchains/nightly-2026-08-29-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/io/util.rs:235) |

Comparable implementations support this choice, although they are not unanimous:

| Decoder source inspected | Truncated-input behavior |
| --- | --- |
| `zstd` 0.13.3 | `stream::read::Decoder` reaches `raw::Decoder::finish`, which returns `UnexpectedEof` for an incomplete frame. Native zstd errors separately remain `Other`. [finish](/home/at/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zstd-0.13.3/src/stream/raw.rs:247), [native mapping](/home/at/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zstd-0.13.3/src/lib.rs:48) |
| `flate2` | Current upstream `zio::read` returns `UnexpectedEof` when input ends without stream completion and no output is produced; gzip header/footer reads also use it. Older implementations differ, so this is not a claim about every version. [zio](https://docs.rs/flate2/latest/src/flate2/zio.rs.html#124-171), [gzip helper](https://raw.githubusercontent.com/rust-lang/flate2-rs/main/src/gz/mod.rs) |
| `xz2` 0.1.7, binding to liblzma | Returns `UnexpectedEof` when decoding ends without `StreamEnd`; separately detects corruption as `InvalidData`. [Source](https://docs.rs/xz2/latest/src/xz2/bufread.rs.html#203-238) |
| `bzip2` 0.6.1 | Returns `UnexpectedEof` when input is exhausted, no progress occurs, and decompression is unfinished. [Source](https://docs.rs/bzip2/latest/src/bzip2/bufread.rs.html#177-221) |
| `ruzstd` | `StreamingDecoder::read` wraps `decode_blocks` failures, including truncated-input failures, as `Other`. [Source](https://docs.rs/ruzstd/latest/src/ruzstd/decoding/streaming_decoder.rs.html#118-156) |

The separate `liblzma` fork’s source could not be fetched; the verified liblzma comparison above is through `xz2`.

**Keep this fix minimal.** Consistency favors preserving `Kind::IO`’s original kind eventually, particularly `Interrupted` and `WouldBlock`, but that is an independent behavior change. Exposing `Interrupted` enables automatic retries, so decoder progress and partial-output handling need checking first. Recognized zstd corruption errors would reasonably map to `InvalidData`; blanket-mapping `Kind::Zstd` would misclassify parameter and allocation failures. Neither widening is necessary to classify this new error correctly; `zstd` itself demonstrates the narrower policy.

**Pitfall:** callers that interpret every `UnexpectedEof` as clean termination can hide truncation. `read_exact` already conflates insufficient application-level bytes with an underlying decoder’s premature EOF at the kind level; inspect the retained error payload when that distinction matters. Successfully filling a `read_exact` buffer also does not validate the unread remainder of an archive. These limitations do not justify reporting a known truncation as `Other`.
