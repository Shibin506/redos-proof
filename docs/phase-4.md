# Phase 4: scanning real source code

Phases 1-3 work on one regex at a time. Phase 4 turns the tool on a codebase: it pulls the regexes out of
source files, runs the detector on each, and reports the vulnerable ones with their location — ready for CI, a
pre-commit hook, or GitHub code scanning.

```
$ redos-proof files src val.py
src/app.js:1:12  EXPONENTIAL  /(a+)+$/
    attack: "aaaaaaaaaaaaaaaaaaaaaa!"
val.py:2:17  EXPONENTIAL  /(.*,)*$/
    attack: ",,,,,,,,,,,,,,,,,,,,!"

scanned 2 files, 3 regexes: 2 vulnerable
```

`files` takes files or directories, walks the tree (skipping `node_modules`, `.git`, `target`, `venv` and the
like), and exits non-zero when it finds something — so it gates a CI job or a commit. Add `--prove` to run each
finding on the real engine (Phase 3) and fail only on the ones the engine actually reproduces; add `--sarif`
to emit a SARIF 2.1.0 report for GitHub code scanning.

## Pulling regexes out of code

The extractors are **hand-written character scanners, not regexes**, so the tool that hunts ReDoS can never be
ReDoS'd by the code it scans. They find the common ways a regex is written:

| Language | Extracted |
|---|---|
| JavaScript / TypeScript (`.js .jsx .ts .tsx .mjs .cjs`) | `/pattern/flags` literals and `new RegExp("pattern", "flags")` |
| Python (`.py .pyi`) | `re.compile(...)` and `re.search/match/sub/...` with a string first argument (raw `r"..."` or plain) |
| Ruby (`.rb`) | `/pattern/flags` and `%r{...}` literals, and `Regexp.new("pattern")` |

Two things make this more than a grep:

- **Division is not a regex.** `a / b / c` in JavaScript is not two regex literals. The scanner uses the
  standard heuristic — what the previous meaningful token was — so `x / 2` is division but `return /re/` and
  `= /re/` are regexes. A `/` inside a character class (`/[/]/`) is handled too.
- **String escapes are resolved to what the engine sees.** `new RegExp("\\d+")` is the pattern `\d+`, not
  `\\d+`; a Python raw string `r"\d+"` is `\d+` and a plain string `"\\d+"` is also `\d+`. The scanner decodes
  each language's string escapes so the pattern handed to the detector is exactly the one the engine compiles.

Strings and comments are never mined, and non-literal arguments (`re.compile("a" + var)`) and member access
(`x.re.compile(...)`) are skipped.

## Output

- **Human** (default): `file:line:col`, the kind of blow-up, the regex, and an example attack input. With
  `--prove`, the real-engine verdict and worst timing.
- **SARIF** (`--sarif`): a SARIF 2.1.0 document, hand-written so the tool stays dependency-free. Exponential
  findings are `error`, polynomial are `warning`. Upload it with `github/codeql-action/upload-sarif` and the
  findings show up inline on the pull request.

## Running it on a project

A git pre-commit hook (`hooks/pre-commit`, and a `.pre-commit-hooks.yaml` for the pre-commit framework) blocks
a commit that adds a vulnerable regex to a changed `.js/.ts/.py/.rb` file. A composite GitHub Action
(`.github/actions/redos-proof`) and an example workflow (`.github/workflows/redos-scan.yml`) build the tool,
scan the repository, and upload the SARIF to code scanning.

## Tests

- `src/source.rs`: extraction unit tests — regex literals vs division, the `RegExp`/`Regexp.new`/`%r`
  constructors, raw and escaped strings, and that strings and comments are not mined.
- `tests/scanning.rs`: end-to-end scans of throwaway source trees — a mixed JS/Python/Ruby tree with the right
  hits, skipped `node_modules` and safe patterns, severity ordering, and correct line and column.
- The SARIF output is validated as JSON in the manual checks; an empty tree produces a valid empty report.

## Known limits

- Extraction is heuristic, not a full parser. It errs toward **missing** a regex rather than inventing one: a
  regex built by string concatenation, or passed through a variable, is not followed. Template literals with
  `${...}` interpolation are skipped.
- Flags are read from regex literals and from `new RegExp(pattern, flags)`, but not from Python's `flags=`
  argument or inline `(?i)` beyond what the pattern itself carries — so a pattern's analysis uses the flags on
  the literal.
- The detector's own limits carry over (Phase 2): it reports the single most severe finding per regex, and
  some polynomial cases whose loop needs a specific separator character are missed. "Nothing found" is not a
  proof of safety.
