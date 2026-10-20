# Phase 6: figures, docs, polish

The tool was finished in Phase 5. Phase 6 is the part that makes it legible to someone who did not build it: two
figures drawn from the tool's own output, a documentation trail, and a last pass over the rough edges.

## The figures

Both live in [`docs/figures/`](figures/) and are embedded at the top of the README. Neither is a mock-up — the
numbers and the behaviour they show are the tool's.

### `growth.svg` — why one character matters

A log-scale line of **measured** backtracking steps against input length, for an exponential regex (`^(a+)+$`)
and a linear one (`^a+$`), on the failing input `"aaa…a!"`. The exponential line roughly doubles with every
character and passes half a billion steps at 26 characters; the linear line is a flat crawl near the bottom.
This is the whole thesis of the project in one picture: the danger is not in how the regex looks, it is in how
the work grows.

It is generated, not hand-drawn: [`script/gen_figures.py`](../script/gen_figures.py) runs
`redos-proof match` at `n = 1..26` for both patterns and plots the step counts it reports. Re-run it after
`cargo build --release` and the figure reflects the current model exactly. Zero dependencies (Python stdlib),
matching the rest of the project; the SVG sits on a self-contained light card so it reads on either GitHub
theme.

### `pipeline.svg` — the honest split

The architecture in one row: the **static model** (blue) parses the regex, builds a step-counted NFA, and finds
the ambiguity and an attack string; then the **real engine** (orange) runs that attack on Node, Python or Ruby
at growing lengths, and the verdict comes from the measured timings. The footer carries the case that makes the
split worth having — `(a+)+$` is proven exponential on Node and CPython but *not reproduced* on memoizing Ruby
3.2+ — and a real line of `scan` output.

This one is hand-authored (it shows structure, not data), but every claim on it is something the tool actually
does and the other phase docs back up.

## The documentation trail

Each phase has a standalone document, and the README links all six:

| Doc | What it covers |
|---|---|
| [phase-1.md](phase-1.md) | the backtracking model, differential-tested against real engines, and the engine bugs that fell out |
| [phase-2.md](phase-2.md) | finding exponential and polynomial ambiguity, and the attack string for each |
| [phase-3.md](phase-3.md) | proving a finding by running it on the real engine, verdict from wall-clock growth |
| [phase-4.md](phase-4.md) | scanning real source trees; CLI, SARIF, pre-commit hook, GitHub Action |
| [phase-5.md](phase-5.md) | measuring recall and precision against a corpus that cannot lie |
| phase-6.md | this: figures and polish |

The README itself is the entry point: the two figures, a worked `scan`, a `files` scan, the `bench` summary,
the differential-testing table, and the engine bugs — enough to understand what the tool does and trust the
numbers without reading the source.

## The polish pass

- **`--help` and `--version`.** The CLI now answers `redos-proof --help` (and `-h`, `help`) on stdout with exit
  0, and `--version` prints the crate version. An unknown command still prints usage to stderr with exit 2.
- **Crate metadata.** `Cargo.toml` carries the description, repository, license, keywords and categories a
  published crate needs; the only dependency remains `serde_json`, and only as a dev-dependency for a test — the
  tool itself ships with **zero runtime dependencies**, including the hand-written SARIF writer.
- **Clean docs build.** `cargo doc --no-deps` runs in CI with `-D warnings`, so the rustdoc stays warning-free.
- **No stray edges.** No `TODO`/`FIXME`/`unimplemented!` anywhere in `src/` or `tests/`; `cargo fmt --check` and
  `cargo clippy --all-targets -- -D warnings` are green and enforced in CI on every push.

## What this is, and what it is not

redos-proof is a complete, honest ReDoS detector for JavaScript, TypeScript, Python and Ruby: it suspects
statically and confirms empirically, it tells you which engine a pattern is dangerous on, and it never reports a
finding it cannot back with a measurement. It is **not** the last word in static analysis — `recheck` finds
cases this model does not (see [phase-5.md](phase-5.md)), and "nothing found" is never a proof of safety. The
contribution is the discipline: a number you can reproduce on your own machine behind every claim.
