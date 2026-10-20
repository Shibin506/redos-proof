# Phase 3: proving a finding on the real engine

Phase 2 confirms a finding against the model — an exact copy of how the engine backtracks. Phase 3 goes one
step further and runs the attack on the **actual** Node, Python or Ruby, timing the match as the input grows.
The verdict shown to the user is read from those real wall-clock times, so the proof is the engine choking on
its own, not the model's opinion of it.

```
$ redos-proof scan '(a+)+$'
VULNERABLE (backtracking model): EXPONENTIAL (one extra character can double the work)
  prefix   "aa"
  pump     "a"
  suffix   "!"
  example attack input (pump x20): "aaaaaaaaaaaaaaaaaaaaaa!"
  real engine (Node): PROVEN EXPONENTIAL
        13 chars       0.4 ms
        17 chars       4.6 ms
        21 chars      72.2 ms
        25 chars    1225.5 ms
        29 chars  timed out (still running after 2.5 s)
```

Four extra characters take Node from 4.6 ms to timing out — that is the exponential, measured.

## How it runs

For each finding, the prover builds the attack (`prefix` + `pump` repeated + `suffix`) at a schedule of sizes
and runs each one as a **fresh process** on the real engine, timing the single match. A catastrophic match
cannot be interrupted from inside a single-threaded engine, so each process is killed from the outside when it
runs past a 2.5-second deadline; a kill at a short input length is itself the proof. The timeout is enforced
in Rust (spawn, poll, kill), so it needs no external `timeout` command and works the same on Linux and macOS.

The verdict is read from the measured times the same way the model's growth is read, but on wall-clock time: a
time-out at a short input, or time that multiplies as the input grows a little, is exponential; time that
grows like a power of the length is polynomial; anything flat is "not reproduced".

## The honest results this surfaces

Running on the real engine, not the model, turns up two kinds of model-versus-reality gaps, and the tool
reports what the engine actually does.

**The same pattern differs across engines.** `(a+)+$` is exponential for a plain backtracking engine, and
Node and Python choke on it. **Ruby 3.3 does not** — Ruby 3.2 added memoized matching that defeats most of
these patterns, so the same attack runs in well under a millisecond even at 50,000 characters:

```
$ redos-proof scan --dialect ruby '(a+)+$'
  real engine (Ruby): NOT reproduced
  note: the pattern is exponential for a plain backtracking engine, but Ruby did not slow down.
        Ruby defeats many of these patterns (Ruby 3.2+ memoizes); the same regex would still be
        dangerous on an engine that does not.
```

This is the sort of thing a tool that only reasons about the pattern's shape gets wrong. `scan` exits
non-zero only when the real engine reproduces the blow-up, so it does not raise a false alarm on Ruby code
that is actually safe — while still warning that the pattern is dangerous if the code is ported.

**The measured degree can differ from the model's.** The model counts backtracking steps, so it calls
`\d+\d+!` quadratic. On CPython the wall-clock grows faster — about cubic — because each backtracking step
carries its own overhead that itself scales. The tool reports the degree it measured on the real engine, not
the model's step-count degree, because that is what the user's program will actually experience.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | No finding, or the model found one but the real engine did not reproduce it (safe on *your* engine; a warning is still printed) |
| 1 | The real engine reproduced the blow-up — a present danger — or the engine is not installed, so the model's verdict is trusted |

## Tests

- `src/prove.rs`: the classifier is unit-tested on synthetic timings (deterministic, no engine needed), and
  the kill-on-timeout path is tested with a hanging process.
- `tests/proof.rs` (gated on the engine being installed): Node and Python prove the exponential and polynomial
  patterns; Ruby reports the memoized patterns as not reproduced; one test pins the headline result that
  `(a+)+$` is exponential in Node but not in Ruby.

## Known limits

- The prover runs the single engine for the pattern's dialect (Node for JavaScript, CPython for Python, Ruby
  for Ruby). It does not cross-run a JavaScript pattern on Python.
- Timing is wall-clock and varies between machines; the verdict is derived from growth, not absolute times, so
  it is robust, but the printed milliseconds are illustrative.
- A pattern that is genuinely exponential but needs a very large input to show it (a small growth factor) may
  not time out within the schedule; the model's verdict still stands and is shown.
- Ruby's memoization has limits (it is disabled by backreferences and bounded by memory); "not reproduced" is
  specific to the pattern and the Ruby version tested, not a promise about all Ruby.
