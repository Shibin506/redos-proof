# Phase 2: finding the vulnerable patterns, and proving each one

Phase 1 built a faithful model of how JavaScript, Python and Ruby backtrack. Phase 2 uses it to **find**
regular expressions that can be made to do super-linear work, and to **prove** each finding by constructing
the input that triggers it and measuring the blow-up.

## The honest split

Like a credential scanner that only reports a leak it can verify, the detector separates suspicion from
proof:

1. **Static analysis** looks at the pattern's automaton and *suspects* a vulnerable loop. From it, it builds
   a candidate attack: a `prefix` to reach the loop, a `pump` string the loop can match more than one way,
   and a `suffix` that forces the match to fail so the engine backtracks.
2. **Measurement** then runs that attack through the Phase 1 simulator at growing pump counts and counts the
   steps. A finding is reported only when the work really does explode.

So every reported finding comes with its proof attached: the attack string, and the measured step counts.
Nothing is reported on the strength of the pattern's shape alone.

```
$ redos-proof scan '(a+)+$'
VULNERABLE: EXPONENTIAL (one extra character can double the work)
  prefix   "aa"
  pump     "a"
  suffix   "!"
  proof: measured steps as the pump repeats (prefix + pump*n + suffix):
    n=12   139242 steps
    n=14   557032 steps
    n=16   2228198 steps
    n=18   8912868 steps
    n=20   20000001 steps
    (the simulator gave up: the work is already astronomical)
  example attack input (pump x20): "aaaaaaaaaaaaaaaaaaaaaa!"
```

`scan` exits non-zero on a vulnerable pattern, so it can gate a CI check or a pre-commit hook.

## How exponential blow-up is found

Exponential backtracking (`(a+)+`, `(a*)*`, `(a|a)*`) comes from a loop whose body can match the same text in
more than one way: with n repetitions, the number of ways is 2^n, and a failing suffix makes the engine try
them all.

The detector finds this with the classic **product-automaton** test, run over the full ε-NFA (so ambiguity
hidden in the loop structure — not just in reading different characters — is caught; `(a*)*` is ambiguous
through its nesting, and both copies read the same `a`). It pairs the automaton with itself and looks for a
strongly connected component that contains:

- a **diagonal** state `(q, q)` — both copies in the same place;
- an **off-diagonal** state `(p1, p2)` with `p1 != p2` — the two copies have diverged;
- at least one step that **reads a character** — so the pump is not empty.

Such a component means one pass of the loop reaches `q` again two different ways. The pump string is read off
the cycle, and the loop lives inside the component. Strongly connected components are found with Tarjan's
algorithm, run iteratively so it handles large product graphs.

## How polynomial blow-up is found

Quadratic (or worse) backtracking (`\d+\d+`, `.*.*=.*`) comes from two loops in a row that overlap: the first
can give back characters that the second then takes, so the engine re-splits the run at every position. The
detector looks for two character positions that each repeat on themselves, where the first can reach the
second and they share a character. The degree is read from the measured growth curve (a log-log fit of steps
against length).

## Why atomic groups and possessive quantifiers come out safe

`(?>a+)+` and `a++` are not vulnerable, because the atomic group and the possessive quantifier never give
characters back. This falls out for free: the measurement step runs the real Phase 1 simulator, which models
those constructs exactly, so a candidate that cannot actually blow up is measured as linear and dropped. The
analysis never has to special-case them.

## What "confirmed" rests on

The guarantee is empirical, not just a matter of the model agreeing with itself. The test suite takes every
finding the detector reports and runs its attack string through **real Node**, checking that the time grows
the way the finding claims — exponential attacks time out or explode, polynomial attacks slow down
quadratically. A finding that does not blow up in the real engine is a false positive and fails the build.

- `reported_exponentials_really_blow_up_in_node` / `reported_polynomials_really_slow_down_in_node`: the
  curated patterns, checked against Node.
- `no_false_positives_against_node`: hundreds of random regexes (thousands with `REDOS_FUZZ_LONG=1`); every
  one the detector flags must actually blow up in Node. The tool never cries wolf.

The checks never use an absolute time threshold (constant factors differ between patterns). They use growth:
adding more pump makes a true exponential's time explode while a safe pattern stays flat.

Every rule was mutation-tested: disabling the measurement gate, forcing the polynomial degree to zero, and
removing the read-step edge from the product automaton each make a test fail.

## What the detector found while it was being built

Running the random fuzzer turned up real catastrophic patterns by accident, for example
`((?:[ab]+.)+(?:\d[a-z]*)+)*`, which takes Node **8.7 seconds on a 41-character input** and times out a little
beyond that. Each was confirmed against the real engine before the detector's verdict was trusted.

## Known limits

- **Not a safety proof.** "No catastrophic backtracking found" means none was confirmed, not that the pattern
  is safe. Patterns too large to analyse (more than a couple of thousand automaton states) are reported as
  not analysed.
- **Backreferences and other unmodelled features** (from Phase 1) make a pattern unanalysable; it is reported
  as such, never guessed at.
- The detector reports the single most severe finding per pattern, not every vulnerable loop.
- Phase 3 will add timing against real Node, Python and Ruby to the report itself (not only the test suite),
  so the proof shown to the user is a real-engine measurement, not only the model's step count.
