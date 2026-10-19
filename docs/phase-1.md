# Phase 1: an exact model of backtracking, checked against the real engines

## What it is

Before a tool can predict that a regex explodes, it needs to run regexes the way backtracking engines do and
count the work. Phase 1 builds that:

1. **Parser** (`src/parser.rs`): JavaScript, Python and Ruby syntax into one tree (`src/ast.rs`). Where the
   languages differ, each follows its engine (table below).
2. **Automaton** (`src/nfa.rs`): states with *ordered* choices. A backtracking engine tries the first branch
   of a choice and only comes back to the second when everything after the first fails; that order decides
   how much work it does. `a*` is `Split(loop, exit)`, `a*?` is `Split(exit, loop)`.
3. **Simulator** (`src/matcher.rs`): runs the automaton exactly as a backtracking engine does, leftmost start
   first, and counts every state visited. That count is the work that explodes in a ReDoS, measured exactly
   instead of timed.

## The dialect rules the engines taught us

Most of these were not in the first version of the model. The differential test found each one, and each was
confirmed by running the engine directly before the model was changed.

| Rule | JavaScript | Python | Ruby |
|---|---|---|---|
| `^` / `$` | whole input (lines with `m`) | whole input; `$` also before a final `\n` | always lines; `^` never at the very end after a final `\n` |
| `.` | not `\n \r U+2028 U+2029` | not `\n` | not `\n` (`m` flag: everything) |
| `\w` / `\d` | ASCII | Unicode (`\d` is every decimal digit, e.g. `٣`) | ASCII |
| `\s` | Unicode | Unicode (plus `\x1c`-`\x1f`) | ASCII |
| `\b` word characters | ASCII | Unicode | Unicode (though Ruby's `\w` is ASCII; taken from `\b` itself, as it differs slightly from `[[:word:]]`) |
| Python's `\B` on an empty input | | never matches | |
| An empty loop iteration (`(?:\|\w)*`) | fails; the engine tries the next branch | ends the loop | ends the loop |
| ... in a required iteration (`(?:x\|(?<=\A)){2}`) | no check | no check | ends the loop (counts as done), unless Onigmo unrolled the loop |
| `x{2}?` | lazy `{2}` | lazy `{2}` | "optionally two x" |
| `x{2}+` | (error) | possessive | "one or more pairs" |
| Possessive `(?:a\|ab){2}+` | (none) | every iteration atomic: fails on `abac` | (not possessive) |
| Case folding of the Kelvin sign `\u212A` | not with `k` (unless `u`) | with `k` | with `k` |

Character classes and case folding are generated, not written: `script/gen_tables.sh` asks each engine about
every one of the 1.1 million code points, and `script/gen_folds.py` asks which characters it treats as the
same letter (2,978 pairs per engine). The tables are what the engines do, not what their documents say.

## How it is checked

`tests/engines.rs` generates random patterns from a grammar (groups, alternation, every quantifier with lazy
and possessive forms, anchors, word boundaries, lookaround, atomic groups, flags) and random inputs (ASCII plus
`é`, a no-break space, `٣` and the Kelvin sign), runs them through the model and through the installed Node,
Python and Ruby, and requires the same leftmost match every time. It also requires that every pattern the
engine accepts, the parser accepts.

Final results, on the finished model (seeds 7, 11 and 13):

| Engine | Matches compared | Explained | Unexplained |
|---|---:|---:|---:|
| Node 22.22 (V8) | 600,000 | none needed | 0 |
| Python 3.11.15 | 599,998 | none needed | 0 |
| Ruby 3.3.6 | 599,961 | 55 proven case by case, 1 by category | 0 |

Matches not compared are ones where the engine itself failed (a crash, or Ruby's 1-second timeout on a real
ReDoS; see below).

**Every rule was mutation-tested**: each of the 14 dialect rules above (and the simulator's choice order) was
broken on purpose, and each break made a test fail. The first round found one rule no test covered (JavaScript's
Unicode `\s`), because the inputs were ASCII-only; the non-ASCII inputs were added for that.

## Where Ruby and the model differ, and why

A Ruby disagreement is only accepted when a second run proves its cause; any other disagreement fails the build.
The one exception (6) is counted and reported separately.

1. **Captures in the empty-iteration check (a Ruby design choice).** Onigmo counts a loop iteration that
   matched nothing but changed a capture group as progress. The model does not track captures. Proof: Ruby
   agrees with the model once every `(...)` is made `(?:...)`. Pinned by `the_known_ruby_difference_is_still_real`.
2. **`.` with `m` (a Ruby bug).** `"a a_"[/\B.+/m]` is `nil`, but `"a a_"[/\B[\s\S]+/]` is `"_"`. The two
   patterns match exactly the same characters. Proof: Ruby agrees with the model after `.` is rewritten as `[\s\S]`.
   Pinned by `the_ruby_dot_bug_is_still_there`.
3. **Automatic possessive loops ignore case folding (a Ruby bug).** `"!\u212A" =~ /\W+k/i` is `nil`, although the
   Kelvin sign is both a `\W` and a `k` under `i`; `/\W+(?:k|\u212A)/i` matches, and Python matches both. Proof:
   Ruby agrees with the model once `k` and `s` are spelled out with their folding partners. Pinned by
   `the_ruby_fold_possessive_bug_is_still_there`.
4. **Short counted loops are unrolled (an Onigmo implementation detail).** Onigmo checks for empty iterations
   even in the required part of `x{2}`, but only when it compiles the loop as a loop; short loops become copies
   with no check, and which one it picks depends on the size of its compiled code. The model has both forms
   (`CompileOptions::ruby_required_iteration_check`). Proof: Ruby agrees with the other form.
5. **Ruby's search skips a match it can find (a Ruby bug, general).** Told to match exactly where the model's
   match starts (`\G`), Ruby finds the model's match there, though its normal left-to-right search reported none
   or a later one. A leftmost search may never do that. This proof catches any such case, whatever its cause.
6. **The Kelvin sign and the long s under `i` (a Ruby inconsistency; by category).** `/\Ak?\z/i` matches the
   Kelvin sign `\u212A`, and `/k*a/i` and `/ka/i` match `"\u212Aa"` from its start, but `/k?a/i` skips the
   `\u212A`. Disagreements where Ruby uses `i` and the model's match covers one of these two characters are put
   down to this without a per-case proof (1 case in 600,000). Pinned by `rubys_special_folding_is_still_inconsistent`.

## Engine bugs found

| Engine | Minimal case | What happens |
|---|---|---|
| Ruby 3.3.6 | `/((?=(.)))+/.match("a")` | `RegexpError: failed to allocate memory`. With no memory limit Ruby keeps allocating until the system kills it: one character of input. |
| Ruby 3.3.6 | `"a a_"[/\B.+/m]` | `nil` instead of `"_"` (see 2 above) |
| Ruby 3.3.6 | `"!\u212A" =~ /\W+k/i` | `nil` instead of `0` (see 3 above) |
| Ruby 3.3.6 | `"\u212Aa"[/k?a/i]` | `"a"`, though `/\Ak?\z/i` matches `\u212A` and `/k*a/i` gives `"\u212Aa"` (see 6 above) |
| CPython 3.11.15 | `re.search(r"(?:(x)y\|){2}+", "xy")` | `SystemError: The span of capturing group is wrong, please report a bug for the re module`. Without the possessive `+` it matches `"xy"`. |

These have not been reported upstream yet, and a newer release may already have fixed some of them. Each is a
one-line reproduction, ready to file.

The random patterns also produced real ReDoS by accident: `(?:(?:|.?){2})+n` takes 3.8 s in Python and 1.1 s in
Node on a 10-character input. The harness gives Ruby a 1-second limit per match (`Regexp.timeout`) and a memory
cap, and reports these instead of waiting.

## The step counter

```
$ redos-proof steps '^(a+)+$' '' a '!'
       n            steps    ratio
       1               11
       2               28     2.55
       4              130     4.64
       8             2170    16.69
      16           557050   256.71      twice the input: 2^8 times the work
$ redos-proof steps --dialect python '^(\w+\s?)*$' '' 'ab ' '!'
      16          3014664   256.35
      32       2000000001   663.42  (step limit)
$ redos-proof steps '^a+$' '' a '!'
    4096            24578     2.00      linear
```

## Known limits

- **Not modelled** (reported as such, never guessed): backreferences (`\1`, `\k<n>`), Unicode properties
  (`\p{L}`), Ruby's `\G` and conditionals, Python's `\N{...}`.
- **Captures are not tracked**, so the model gives the overall match, not group contents (and differs from
  Ruby in the case above).
- **Multi-character case folding** is not modelled: Ruby's `/ß/i` matches `"ss"`.
- **JavaScript without `u`** works on UTF-16 code units; the model works on code points. They differ only for
  characters outside the Basic Multilingual Plane (emoji, for example).
- **Lookbehind**: the model gets the same answer as the engines, but not the same step count (JavaScript reads
  lookbehind backwards; the model tries each start).
- The engines' own optimizations (first-character prefilters, Ruby's memoization) are not modelled: the step
  count is what a plain backtracking engine does. Phase 3 measures the real engines.
