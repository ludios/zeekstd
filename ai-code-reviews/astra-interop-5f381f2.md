# Summary by Claude Opus 5

Independent empirical check run on 2026-09-16 with Codex CLI (gpt-6-astra, reasoning effort xhigh)
against commit 5f381f2. The full report is [astra-interop-5f381f2/report.md](astra-interop-5f381f2/report.md);
the harness, CSVs and structured logs are next to it. The question put to Codex was the user's own,
verbatim: assuming non-hostile input, is zeekstd good enough to store data, and will standard zstd
tools decompress everything it writes?

**Independence was enforced, not assumed.** Codex worked from a `git archive` extract of 5f381f2 in
a scratch directory with `ai-code-reviews/`, `CLAUDE.md` and `AGENTS.md` removed and no git history,
so neither the earlier reports nor the commit messages that summarize them were reachable. It was
told not to read the live checkout and not to chase the review that `lib/tests/known_bugs.rs` cites.
The exact brief is [astra-interop-5f381f2/prompt.md](astra-interop-5f381f2/prompt.md). It designed
its own matrix; I gave it no test plan beyond pointing at the reference seekable decoder as an
optional second oracle.

**Verdict: yes for ordinary archives.** 777 writer attempts, 2,098 SHA-256 comparisons. All 750
ordinary-window self-contained archives were recovered byte for byte by plain `zstd -dc`, including
two files over 4 GiB. 726 passed an independent check through Meta's reference seekable decoder,
with 17,768 random-read comparisons against the original bytes. Codex found no malformed frame and
no incorrect seek-table entry in any of the 774 non-colliding archives.

**The four qualifications**, none of which is a bad archive:

- **Patch and dictionary archives are not self-contained.** They need the base, and multi-frame
  patches fail under `zstd --patch-from` after the first frame. `zstd -D BASE` recovers them.
- **A base over 32 MiB cannot be passed to `-D` at all**, and a large window needs `--memory=`.
  Codex executed a per-frame recovery for a 129 MiB base and got the exact hash back.
- **`Head` and detached tables are not natively reference-seekable.** Sequential `zstd -dc` still
  recovers every byte; only third-party random access needs the table converted to `Foot`.
- **Two forced-path collisions destroy data.** `compress -f X -o X` exits 0 and leaves an empty
  archive where the original was.

**My spot-checks.** I re-derived the counts from `results/archives.csv`: 750 matches, 26 failures,
1 rejected write, and every one of the 26 is a dependency, window-limit or collision case named in
the report. I reproduced both path collisions at current HEAD with the freshly built CLI: a 4,096
byte file became a 38-byte archive decompressing to nothing, exit 0. I reproduced the multi-frame
`--patch-from` control with no zeekstd involved at all, and this is worth recording because my first
attempt was a bad control: patches of *random* data against a random base decode fine concatenated,
since the second frame never actually references the base. With base-derived data the stock-zstd
concatenation fails at exactly the second frame with `Data corruption detected` while `-D` recovers
everything, which is what Codex reported. Its diagnosis holds: that failure is a zstd CLI
limitation, not a zeekstd defect.

Codex reached these conclusions independently of the earlier interop work in
[interop-2026-09-16.md](interop-2026-09-16.md), and where the two overlap they agree, including the
32 MiB `-D` ceiling and the library's checksums being off by default.

The 21 GB of generated corpora and archives were left in the session scratchpad; `scripts/run_all.sh`
regenerates them and needs roughly 25 GiB of working disk.
