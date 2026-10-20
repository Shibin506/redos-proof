# Phase 5: measurement

Phases 1–4 build the tool. Phase 5 asks the only question that matters for a detector: **how good is it?** Two
numbers decide that — how many real vulnerable regexes it catches (recall), and how often it cries wolf on safe
ones (precision). This phase measures both, against a corpus that cannot lie, and runs the tool on real
repositories.

## The honest corpus

A ReDoS test set is usually a list of CVE ids. That is a problem: you end up trusting the label. A pattern
tagged "CVE-XXXX, exponential" might be polynomial, might be fixed, might never have been exploitable on the
engine you care about. If the corpus is wrong, every score computed from it is wrong.

So this corpus carries no label it did not earn. It is two files:

- [`corpus/vulnerable.txt`](../corpus/vulnerable.txt) — patterns that **actually blow up on a real engine**.
  Every one was run on Node (or CPython) with its worst-case input before it went in the file; the ones that
  did not slow down were thrown out, regardless of what any advisory called them. The attack strings come from
  classic ReDoS literature and the OWASP catalogue, but the "vulnerable" verdict is measured here, not quoted.
- [`corpus/safe.txt`](../corpus/safe.txt) — real-world linear regexes: email checks, ISO dates, semver, hex
  colours, phone numbers, base64, kebab-case. These must never be flagged. They are the false-positive trap,
  and they include patterns a shape-only linter gets wrong (`[a-z]+(-[a-z]+)*` has a `+` inside a `*`, but the
  required `-` makes it unambiguous and safe).

Each line is `dialect <TAB> flags <TAB> pattern <TAB> note`. Two engines (Node, CPython) are represented;
Ruby is left out of the pass/fail set on purpose — see "The split that Ruby makes visible" below.

## Running the measurement

`redos-proof bench` runs the whole corpus through the detector and, for each flagged pattern, through the real
engine:

```
$ cargo run --release -- bench
ok    vuln  flagged  javascript  /(a+)+$/  [engine: reproduced]
ok    vuln  flagged  javascript  /(x+x+)+y/  [engine: reproduced]
...
ok    safe  clean    javascript  /^[a-z0-9_]+@[a-z]+\.[a-z]+$/
ok    safe  clean    javascript  /[a-z]+(-[a-z]+)*/
...

--- corpus summary ---
vulnerable: 18/18 flagged by the model   (recall 100%)
            18/18 reproduced on the real engine
safe:       0/16 wrongly flagged   (precision 100%)

all 34 corpus entries behaved as expected
```

On this corpus the static model catches every vulnerable pattern (recall 100%) and flags none of the safe
ones (precision 100%), and — the point of the whole project — the real engine reproduces every blow-up the
model claimed. `--no-prove` runs the model alone (no subprocess), which is what the regression test uses.

**This is a regression test, not a one-off number.** [`tests/corpus.rs`](../tests/corpus.rs) reads the same two
files on every `cargo test` and fails the build if a committed vulnerable pattern stops being flagged or a safe
one starts being flagged. The corpus and the detector are versioned together, so the score cannot silently rot.

## The split that Ruby makes visible

The reason the "vulnerable" column is proved per engine, and not taken from a label, shows up the moment you
change engines. `(a+)+$` is a textbook exponential regex. On Node and CPython it blows up. On Ruby 3.2+ it does
**not** — Ruby memoizes its backtracking and finishes instantly:

```
$ cargo run --release -- scan --dialect ruby '(a+)+$'
VULNERABLE (backtracking model): EXPONENTIAL (one extra character can double the work)
  ...
  real engine (Ruby): NOT reproduced
  note: the pattern is exponential for a plain backtracking engine, but Ruby did not slow down.
```

A corpus that labelled `(a+)+$` "exponential, always" would score the tool as wrong on Ruby. The honest answer
is that the pattern is dangerous *on a plain backtracking engine* and safe *on a memoizing one*, and the tool
reports exactly that. That is why Ruby entries are kept out of the pass/fail corpus: their honest expected
outcome is "flagged by the model, not reproduced by the engine", which is a correct result, not a miss.

## On real repositories

The corpus is built to be caught. The harder test is live code the tool has never seen. Three popular,
actively-maintained npm libraries, scanned at a pinned commit (model only, no engine):

| Repository | Commit | Files | Regexes | Flagged | Not analysable |
|---|---|---:|---:|---:|---:|
| [chalk/chalk](https://github.com/chalk/chalk) | `47fc05a` | 14 | 6 | 0 | 0 |
| [sindresorhus/slugify](https://github.com/sindresorhus/slugify) | `3b17b2e` | 4 | 6 | 0 | 0 |
| [validatorjs/validator.js](https://github.com/validatorjs/validator.js) | `9ff3424` | 130 | 756 | 0 | 8 |

Zero findings — and that is the right answer. These libraries are audited and their historical ReDoS
advisories are long since patched, so a scanner that reported vulnerabilities here would be producing false
positives. The number that matters is the one in the last two columns: **768 real-world regexes, zero false
positives**, with 8 honestly reported as using a feature the model does not yet handle rather than guessed at.
That precision on live code is what separates a proof-backed detector from a shape-matching linter that would
light up on `validator.js`'s 756 patterns.

(Reproduce with `redos-proof files <path>`; the repository dogfoods the same scan on itself in
[`.github/workflows/redos-scan.yml`](../.github/workflows/redos-scan.yml).)

## How it compares to other tools

ReDoS detection is a crowded field. An honest placement of this tool among the others:

| Tool | Approach | Proves on a real engine? | Cross-engine aware? |
|---|---|---|---|
| `safe-regex` (npm) | star-height heuristic on the shape | no | no |
| eslint ReDoS plugins | AST pattern rules | no | no |
| `recheck` / `redos` (npm) | automaton + fuzzing, attack-string synthesis | partial (its own VM) | no |
| `regexploit` (Doyensec) | computes attack strings from the structure | no | no |
| **redos-proof** | backtracking model + **timed run on the real engine** | **yes** | **yes** |

`recheck` is the most capable analyzer here — its hybrid automaton/fuzzing engine finds cases this tool's
static model does not. This tool is not trying to beat it at static analysis. Its one distinctive claim is the
**honest split**: a static model proposes, and the *actual* Node/Python/Ruby binary on your machine confirms or
refuses, so a finding is never "this looks dangerous" but "this took 1.2 seconds on your engine, and here is the
input". That is also what lets it tell you `(a+)+$` is exploitable on Node but not on Ruby 3.2+ — a distinction
a shape-only tool cannot make, because the difference is not in the shape, it is in the engine.

## Limits of the measurement

- The corpus is small and hand-built; 100% recall on 18 patterns is not 100% recall in general. It is a
  regression floor — these must keep working — not a claim of completeness.
- Recall is measured only where the model and a backtracking engine agree. The real recall question ("what
  vulnerable regexes does the static model miss?") is bounded by Phase 2's limits (it reports one finding per
  regex, and misses some separator-specific polynomial cases), not re-measured here.
- The real-repo scan is model-only and at a single commit each; it shows precision on live code, not a
  longitudinal study.
