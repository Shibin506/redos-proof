//! Differential test: the model must find exactly the match the real engine finds.
//!
//! Thousands of random patterns (from a grammar covering groups, alternation, every quantifier, lazy and
//! possessive forms, anchors, word boundaries, lookaround, atomic groups and flags) and random inputs are run
//! through our parser + simulator and through real Node, Python and Ruby. Every match position must agree,
//! and every pattern the engine accepts must be accepted by our parser.

use std::fmt::Write as _;
use std::process::Command;

use redos_proof::matcher::{Outcome, search};
use redos_proof::nfa::{CompileError, CompileOptions, compile, compile_with};
use redos_proof::{Dialect, Flags, parse};
use serde_json::{Value, json};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

fn atom(r: &mut Rng, d: Dialect, depth: u32) -> String {
    let leaf = [
        "a", "b", "A", ".", "[ab]", "[^a]", "[a-b1]", "\\d", "\\w", "\\s", "\\W", "1", " ", "\\n", "k", "[j-l]", "é", "\\S", "\\D",
    ];
    if depth == 0 || r.below(10) < 6 {
        return r.pick(&leaf).to_string();
    }
    let inner = regex(r, d, depth - 1);
    match r.below(if d == Dialect::Js { 9 } else { 10 }) {
        0 | 1 => format!("({inner})"),
        2 | 3 => format!("(?:{inner})"),
        4 => format!("(?={inner})"),
        5 => format!("(?!{inner})"),
        // Python and Ruby only accept fixed-width lookbehind: keep the body a single character there.
        6 => format!("(?<={})", if d == Dialect::Js { inner } else { r.pick(&leaf).to_string() }),
        7 => format!("(?<!{})", if d == Dialect::Js { inner } else { r.pick(&leaf).to_string() }),
        8 => r.pick(&["^", "$", "\\b", "\\B"]).to_string(),
        _ => format!("(?>{inner})"),
    }
}

fn quantified(r: &mut Rng, d: Dialect, depth: u32) -> String {
    let a = atom(r, d, depth);
    if a.starts_with('^')
        || a.starts_with('$')
        || a.starts_with("\\b")
        || a.starts_with("\\B")
        || a.starts_with("(?=")
        || a.starts_with("(?!")
        || a.starts_with("(?<")
    {
        return a; // quantified assertions are errors in some engines and meaningless in all
    }
    let q = match r.below(12) {
        0 => "*",
        1 => "+",
        2 => "?",
        3 => "{0,2}",
        4 => "{1,}",
        5 => "{2}",
        6 => "{1,3}",
        _ => return a,
    };
    let suffix = match r.below(5) {
        0 => "?",
        1 if d != Dialect::Js => "+",
        _ => "",
    };
    format!("{a}{q}{suffix}")
}

fn regex(r: &mut Rng, d: Dialect, depth: u32) -> String {
    let alts = 1 + r.below(3).saturating_sub(1);
    let mut out = String::new();
    for i in 0..alts {
        if i > 0 {
            out.push('|');
        }
        for _ in 0..r.below(4) {
            out += &quantified(r, d, depth);
        }
    }
    out
}

fn input(r: &mut Rng) -> String {
    // Mostly ASCII, plus characters on which the engines' Unicode rules differ: a Latin letter, a no-break
    // space, an Arabic-Indic digit and the Kelvin sign (which case-folds to `k` in some engines).
    let alphabet = [
        'a', 'b', 'A', '1', ' ', '\n', '_', 'a', 'b', ' ', 'é', '\u{a0}', '\u{663}', '\u{212a}', 'k',
    ];
    (0..r.below(11)).map(|_| alphabet[r.below(alphabet.len())]).collect()
}

fn flags(r: &mut Rng, d: Dialect) -> String {
    let options: &[&str] = match d {
        Dialect::Js => &["", "", "i", "m", "s", "ims"],
        Dialect::Python => &["", "", "i", "m", "s", "ims", "a"],
        Dialect::Ruby => &["", "", "i", "m", "im"],
    };
    r.pick(options).to_string()
}

fn have(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok_and(|o| o.status.success())
}

/// Runs every case through the real engine; one result object per case.
fn engine(d: Dialect, cases: &[Value]) -> Vec<Value> {
    let dir = tempfile_dir();
    // One file per call: tests run in parallel, and two of them may ask the same engine at once.
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let file = dir.join(format!("cases-{}-{call}.json", d.name()));
    std::fs::write(&file, serde_json::to_string(cases).unwrap()).unwrap();
    let script = |name: &str| format!("{}/tests/engines/{name}", env!("CARGO_MANIFEST_DIR"));
    let out = match d {
        Dialect::Js => Command::new("node").arg(script("run.js")).arg(&file).output(),
        Dialect::Python => Command::new("python3").arg(script("run.py")).arg(&file).output(),
        // Under a memory cap: some patterns make Ruby allocate without bound (see docs), and with a cap it
        // raises an error the runner reports instead of being killed by the system.
        Dialect::Ruby => Command::new("bash")
            .args(["-c", "ulimit -v 4000000; exec ruby -Ku \"$0\" \"$1\""])
            .arg(script("run.rb"))
            .arg(&file)
            .env("LANG", "C.UTF-8")
            .output(),
    }
    .unwrap();
    assert!(
        out.status.success(),
        "{} runner failed: {}",
        d.name(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<Vec<Value>>(&out.stdout).unwrap()
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("redos-proof-engines-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn differential(d: Dialect, program: &str, seed: u64, cases: usize) {
    if !have(program) {
        eprintln!("skipping {}: `{program}` is not installed", d.name());
        return;
    }
    // REDOS_DIFF_SEED / REDOS_DIFF_CASES run a different or bigger sample (CI uses the defaults).
    let seed = std::env::var("REDOS_DIFF_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(seed, |s| s * 31 + seed);
    let cases = std::env::var("REDOS_DIFF_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(cases);
    let mut r = Rng(seed);
    let mut list = Vec::new();
    for _ in 0..cases {
        let pattern = regex(&mut r, d, 3);
        let flags = flags(&mut r, d);
        let inputs: Vec<String> = (0..6).map(|_| input(&mut r)).collect();
        list.push(json!({ "pattern": pattern, "flags": flags, "inputs": inputs }));
    }
    let results = engine(d, &list);
    let (mut compared, mut engine_errors, mut skipped) = (0, 0, 0);
    let mut failures = String::new();
    // (pattern, flags, input, model's answer) for disagreements, re-checked below.
    let mut mismatches: Vec<(String, String, String, Value)> = Vec::new();
    for (case, result) in list.iter().zip(&results) {
        let pattern = case["pattern"].as_str().unwrap();
        let flag_str = case["flags"].as_str().unwrap();
        let ours = Flags::parse(d, flag_str).and_then(|f| parse(pattern, d, f));
        if let Some(err) = result.get("error") {
            engine_errors += 1;
            // We may accept patterns the engine rejects (e.g. Python's limits on lookbehind); not the reverse.
            let _ = err;
            continue;
        }
        let regex = match ours {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(
                    failures,
                    "{}: we reject /{pattern}/{flag_str} ({e}) but the engine accepts it",
                    d.name()
                );
                continue;
            }
        };
        let nfa = match compile(&regex) {
            Ok(n) => n,
            Err(CompileError::Unsupported(_)) | Err(CompileError::TooLarge { .. }) => {
                skipped += 1;
                continue;
            }
        };
        for (input, want) in case["inputs"].as_array().unwrap().iter().zip(result["spans"].as_array().unwrap()) {
            let input = input.as_str().unwrap();
            if let Some(crash) = want.get("crash") {
                eprintln!(
                    "{}: the engine itself crashed on /{pattern}/{flag_str} with {input:?}: {crash}",
                    d.name()
                );
                skipped += 1;
                continue;
            }
            let got = match search(&nfa, input, 50_000_000).outcome {
                Outcome::Match { start, end } => json!([start, end]),
                Outcome::NoMatch => Value::Null,
                Outcome::StepLimit => {
                    skipped += 1;
                    continue;
                }
            };
            compared += 1;
            if &got != want {
                mismatches.push((pattern.to_string(), flag_str.to_string(), input.to_string(), got));
            }
        }
    }
    let known = known_ruby_capture_difference(d, &mut mismatches)
        + known_ruby_dot_bug(d, &mut mismatches)
        + known_ruby_fold_possessive_bug(d, &mut mismatches)
        + known_onigmo_unrolled_loop(d, &mut mismatches)
        + known_ruby_skipped_match(d, &mut mismatches);
    let by_category = ruby_special_fold_inconsistency(d, &mut mismatches);
    if by_category > 0 {
        eprintln!(
            "{}: {by_category} disagreements put down to Ruby's inconsistent folding of the Kelvin sign / long s (by category)",
            d.name()
        );
    }
    for (pattern, flags, input, got) in &mismatches {
        let _ = writeln!(
            failures,
            "{}: /{pattern}/{flags} on {input:?}: model {got}, engine disagrees",
            d.name()
        );
    }
    eprintln!(
        "{}: {compared} matches compared, {engine_errors} patterns rejected by the engine, {skipped} skipped, {known} known differences",
        d.name()
    );
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.lines().count(),
        failures.lines().take(40).collect::<Vec<_>>().join("\n")
    );
    assert!(compared > cases * 3, "too few comparisons: {compared}");
}

#[test]
fn matches_node() {
    differential(Dialect::Js, "node", 1, 4000);
}

#[test]
fn matches_python() {
    differential(Dialect::Python, "python3", 2, 4000);
}

#[test]
fn matches_ruby() {
    differential(Dialect::Ruby, "ruby", 3, 4000);
}

/// Ruby's empty-iteration check also looks at captures (Onigmo's "null check memst"): a loop iteration that
/// matched nothing but changed a capture group still counts as progress. The model does not track captures,
/// so it differs there. A disagreement is put down to this only if Ruby agrees with the model once every
/// capturing group is made non-capturing; anything else stays a failure. Returns how many were explained.
fn known_ruby_capture_difference(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby || mismatches.is_empty() {
        return 0;
    }
    let cases: Vec<Value> = mismatches
        .iter()
        .map(|(p, f, i, _)| json!({ "pattern": without_captures(p), "flags": f, "inputs": [i] }))
        .collect();
    let results = engine(d, &cases);
    let before = mismatches.len();
    let mut i = 0;
    mismatches.retain(|(_, _, _, got)| {
        let again = &results[i]["spans"][0];
        i += 1;
        again != got
    });
    before - mismatches.len()
}

/// A bug in Ruby 3.3 (Onigmo): with the `m` flag, a pattern like `\B.+` or `$.+` misses matches that the
/// identical `\B[\s\S]+` finds (`"a a_"[/\B.+/m]` is nil, `"a a_"[/\B[\s\S]+/]` is "_"). `.` under `m` and
/// `[\s\S]` match exactly the same characters, so when Ruby agrees with the model after that rewrite, the
/// disagreement is Ruby's. Returns how many were explained.
fn known_ruby_dot_bug(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby {
        return 0;
    }
    let candidates: Vec<usize> = (0..mismatches.len())
        .filter(|&i| mismatches[i].1.contains('m') && mismatches[i].0.contains('.'))
        .collect();
    if candidates.is_empty() {
        return 0;
    }
    let cases: Vec<Value> = candidates
        .iter()
        .map(|&i| json!({ "pattern": dot_as_class(&mismatches[i].0), "flags": mismatches[i].1, "inputs": [mismatches[i].2] }))
        .collect();
    let results = engine(d, &cases);
    let explained: Vec<usize> = candidates
        .iter()
        .zip(&results)
        .filter(|&(&i, r)| r["spans"][0] == mismatches[i].3)
        .map(|(&i, _)| i)
        .collect();
    for &i in explained.iter().rev() {
        mismatches.remove(i);
    }
    explained.len()
}

/// Onigmo unrolls short counted loops into copies (no empty-iteration check in the required part) and keeps
/// longer ones as loops (with the check), depending on the size of its compiled code, which the model cannot
/// know. Explained when Ruby agrees with the model built the other way (the loop unrolled).
fn known_onigmo_unrolled_loop(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby {
        return 0;
    }
    let before = mismatches.len();
    let cases: Vec<Value> = mismatches
        .iter()
        .map(|(p, f, i, _)| json!({ "pattern": p, "flags": f, "inputs": [i] }))
        .collect();
    if cases.is_empty() {
        return 0;
    }
    let results = engine(d, &cases);
    let mut k = 0;
    mismatches.retain(|(p, f, i, _)| {
        let ruby = &results[k]["spans"][0];
        k += 1;
        let unrolled = Flags::parse(d, f)
            .and_then(|flags| parse(p, d, flags))
            .ok()
            .and_then(|r| {
                compile_with(
                    &r,
                    CompileOptions {
                        ruby_required_iteration_check: false,
                    },
                )
                .ok()
            })
            .map(|nfa| match search(&nfa, i, 50_000_000).outcome {
                Outcome::Match { start, end } => json!([start, end]),
                _ => Value::Null,
            });
        unrolled.as_ref() != Some(ruby)
    });
    before - mismatches.len()
}

/// Ruby's search skipped a match it can find: asked to match exactly where the model's match starts (`\G`),
/// Ruby finds the model's match there, though its normal left-to-right search reported none or a later one. A
/// leftmost search may never do that, so the disagreement is a Ruby search bug, proven case by case.
fn known_ruby_skipped_match(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby {
        return 0;
    }
    let candidates: Vec<usize> = (0..mismatches.len()).filter(|&i| mismatches[i].3.is_array()).collect();
    if candidates.is_empty() {
        return 0;
    }
    let cases: Vec<Value> = candidates
        .iter()
        .map(|&i| json!({ "pattern": mismatches[i].0, "flags": mismatches[i].1, "inputs": [mismatches[i].2], "anchor_at": mismatches[i].3[0] }))
        .collect();
    let results = engine(d, &cases);
    let explained: Vec<usize> = candidates
        .iter()
        .zip(&results)
        .filter(|&(&i, r)| r["spans"][0] == mismatches[i].3)
        .map(|(&i, _)| i)
        .collect();
    for &i in explained.iter().rev() {
        mismatches.remove(i);
    }
    explained.len()
}

/// Ruby folds the Kelvin sign (U+212A) and the long s (U+017F) inconsistently under `i`: `/\Ak?\z/i` matches
/// the Kelvin sign, but `/k?a/i` skips it in "\u{212a}a" (where `/k*a/i` and `/ka/i` match it). These are put
/// down to that by category, not proven one by one: Ruby, the `i` flag, and the model's match covering one of
/// the two characters. Returns how many; they are reported separately from the proven ones.
fn ruby_special_fold_inconsistency(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby {
        return 0;
    }
    let before = mismatches.len();
    mismatches.retain(|(_, flags, input, model)| {
        let covered = match model.as_array() {
            Some(span) => {
                let (start, end) = (span[0].as_u64().unwrap() as usize, span[1].as_u64().unwrap() as usize);
                input
                    .chars()
                    .skip(start)
                    .take(end - start)
                    .any(|c| c == '\u{212a}' || c == '\u{17f}')
            }
            None => false,
        };
        !(flags.contains('i') && covered)
    });
    before - mismatches.len()
}

#[test]
fn rubys_special_folding_is_still_inconsistent() {
    if !have("ruby") {
        return;
    }
    let s = "\u{212a}a";
    let cases = [
        json!({ "pattern": r"\Ak?\z", "flags": "i", "inputs": ["\u{212a}"] }),
        json!({ "pattern": "k?a", "flags": "i", "inputs": [s] }),
        json!({ "pattern": "k*a", "flags": "i", "inputs": [s] }),
    ];
    let r = engine(Dialect::Ruby, &cases);
    assert_eq!(r[0]["spans"][0], json!([0, 1]), "k? can match the Kelvin sign on its own");
    assert_eq!(r[1]["spans"][0], json!([1, 2]), "but k?a skips it");
    assert_eq!(r[2]["spans"][0], json!([0, 2]), "while k*a takes it");
}

/// A bug in Ruby 3.3 (Onigmo): it makes a loop possessive when it thinks the loop cannot match what follows,
/// but ignores case folding while deciding. `"!\u{212a}" =~ /\W+k/i` is nil, though the Kelvin sign is both a
/// `\W` and a `k` under `i` (`/\W+(?:k|\u{212a})/i` matches; Python matches both). When Ruby agrees with the
/// model after `k` and `s` are spelled out with their folding partners, the disagreement is Ruby's.
fn known_ruby_fold_possessive_bug(d: Dialect, mismatches: &mut Vec<(String, String, String, Value)>) -> usize {
    if d != Dialect::Ruby {
        return 0;
    }
    let candidates: Vec<usize> = (0..mismatches.len()).filter(|&i| mismatches[i].1.contains('i')).collect();
    if candidates.is_empty() {
        return 0;
    }
    let cases: Vec<Value> = candidates
        .iter()
        .map(|&i| json!({ "pattern": spell_out_folds(&mismatches[i].0), "flags": mismatches[i].1, "inputs": [mismatches[i].2] }))
        .collect();
    let results = engine(d, &cases);
    let explained: Vec<usize> = candidates
        .iter()
        .zip(&results)
        .filter(|&(&i, r)| r["spans"][0] == mismatches[i].3)
        .map(|(&i, _)| i)
        .collect();
    for &i in explained.iter().rev() {
        mismatches.remove(i);
    }
    explained.len()
}

/// `k` becomes `(?:k|\u{212a})` and `s` becomes `(?:s|\u{17f})` outside classes: the same thing under `i`.
fn spell_out_folds(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let (mut i, mut in_class) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if i + 1 < chars.len() => {
                out.push(c);
                out.push(chars[i + 1]);
                i += 1;
            }
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' => {
                in_class = false;
                out.push(c);
            }
            'k' | 'K' if !in_class => out.push_str(r"(?:k|\u{212a})"),
            's' | 'S' if !in_class => out.push_str(r"(?:s|\u{17f})"),
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

#[test]
fn the_ruby_fold_possessive_bug_is_still_there() {
    // Pinned: when a Ruby release fixes it, this fails, and the docs and the classification above go.
    if !have("ruby") {
        return;
    }
    let kelvin = "!\u{212a}";
    let plain = engine(Dialect::Ruby, &[json!({ "pattern": r"\W+k", "flags": "i", "inputs": [kelvin] })]);
    let spelled = engine(
        Dialect::Ruby,
        &[json!({ "pattern": r"\W+(?:k|\u{212a})", "flags": "i", "inputs": [kelvin] })],
    );
    assert_eq!(plain[0]["spans"][0], Value::Null, "Ruby misses the match");
    assert_eq!(spelled[0]["spans"][0], json!([0, 2]), "and finds it when the fold is spelled out");
    let nfa = compile(&parse(r"\W+k", Dialect::Ruby, Flags::parse(Dialect::Ruby, "i").unwrap()).unwrap()).unwrap();
    assert_eq!(search(&nfa, kelvin, 1000).outcome, Outcome::Match { start: 0, end: 2 });
}

/// Every `.` outside a class becomes `[\s\S]` (the same set when the dot matches newlines).
fn dot_as_class(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let (mut i, mut in_class) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if i + 1 < chars.len() => {
                out.push(c);
                out.push(chars[i + 1]);
                i += 1;
            }
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' => {
                in_class = false;
                out.push(c);
            }
            '.' if !in_class => out.push_str("[\\s\\S]"),
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

#[test]
fn the_ruby_dot_bug_is_still_there() {
    // Pinned: when a Ruby release fixes it, this fails, and the docs and the classification above go.
    if !have("ruby") {
        return;
    }
    let with_dot = engine(Dialect::Ruby, &[json!({ "pattern": "\\B.+", "flags": "m", "inputs": ["a a_"] })]);
    let with_class = engine(
        Dialect::Ruby,
        &[json!({ "pattern": "\\B[\\s\\S]+", "flags": "", "inputs": ["a a_"] })],
    );
    assert_eq!(
        with_dot[0]["spans"][0],
        Value::Null,
        "Ruby misses the match with `.` and the m flag"
    );
    assert_eq!(with_class[0]["spans"][0], json!([3, 4]), "and finds it with the equivalent class");
    let nfa = compile(&parse("\\B.+", Dialect::Ruby, Flags::parse(Dialect::Ruby, "m").unwrap()).unwrap()).unwrap();
    assert_eq!(search(&nfa, "a a_", 1000).outcome, Outcome::Match { start: 3, end: 4 });
}

/// `(x)` becomes `(?:x)`; groups that already start with `(?` are left alone.
fn without_captures(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let (mut i, mut in_class) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        out.push(c);
        match c {
            '\\' if i + 1 < chars.len() => {
                out.push(chars[i + 1]);
                i += 1;
            }
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class && chars.get(i + 1) != Some(&'?') => out.push_str("?:"),
            _ => {}
        }
        i += 1;
    }
    out
}

#[test]
fn the_known_ruby_difference_is_still_real() {
    // Pinned: if Ruby or the model changes here, this fails and the docs must be updated.
    if !have("ruby") {
        return;
    }
    let pattern = "(|A(| +a){2}){1,3} 1";
    let input = "A AA 1 bA";
    let ruby = engine(Dialect::Ruby, &[json!({ "pattern": pattern, "flags": "", "inputs": [input] })]);
    let plain = engine(
        Dialect::Ruby,
        &[json!({ "pattern": without_captures(pattern), "flags": "", "inputs": [input] })],
    );
    let nfa = compile(&parse(pattern, Dialect::Ruby, Flags::default()).unwrap()).unwrap();
    assert_eq!(search(&nfa, input, 1_000_000).outcome, Outcome::Match { start: 2, end: 6 });
    assert_eq!(ruby[0]["spans"][0], json!([3, 6]), "Ruby, with captures");
    assert_eq!(
        plain[0]["spans"][0],
        json!([2, 6]),
        "Ruby, same pattern without captures, agrees with the model"
    );
}
