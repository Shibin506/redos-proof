//! Phase 2 detection: curated patterns, and the honesty guarantee that every reported finding really does
//! make the *real* engine do super-linear work (not just the model).
//!
//! The honesty checks never use an absolute time threshold (constant factors vary between patterns). They
//! use growth: adding more pump makes a true exponential's time explode (or time out), while a safe pattern
//! stays flat. A finding that does not grow in the real engine is a false positive and fails the test.

use std::process::Command;

use redos_proof::analysis::{Blowup, Finding, analyze};
use redos_proof::nfa::compile;
use redos_proof::{Dialect, Flags, parse};

fn find(pattern: &str, dialect: Dialect) -> Option<Finding> {
    let regex = parse(pattern, dialect, Flags::default()).ok()?;
    let nfa = compile(&regex).ok()?;
    analyze(&nfa).ok()?.into_iter().next()
}

fn verdict(pattern: &str, dialect: Dialect) -> Option<Blowup> {
    find(pattern, dialect).map(|f| f.blowup)
}

#[test]
fn known_vulnerable_patterns_are_detected() {
    // Classic and real-world ReDoS shapes. Each must be reported as exponential.
    let exponential = [
        "(a+)+$",
        "(a*)*c",
        "(a|a)*c",
        "([a-z]+)*$",
        "(x+x+)+y",
        "(\\d+)*$",
        "^(\\w+\\s?)*$",
        "^(.*,)*$",
        "(([a-z])+.)+[A-Z]([a-z])+$",
    ];
    for p in exponential {
        assert_eq!(verdict(p, Dialect::Js), Some(Blowup::Exponential), "{p} should be exponential");
    }
}

#[test]
fn known_polynomial_patterns_are_detected() {
    for p in ["\\d+\\d+!", ".*.*=.*", "\\s*\\s*$"] {
        match verdict(p, Dialect::Js) {
            Some(Blowup::Polynomial { degree }) => assert!(degree >= 2, "{p}: degree {degree}"),
            other => panic!("{p}: expected polynomial, got {other:?}"),
        }
    }
}

#[test]
fn safe_patterns_are_not_flagged() {
    // Linear patterns, and ones made safe by atomic groups or possessive quantifiers.
    let safe_js = [
        "a+",
        "a*b",
        "abc",
        "(abc)+d",
        "[a-z]+@[a-z]+",
        "a{2,5}b",
        "(a|b|c)*x",
        "\\w+",
        "^\\d{4}-\\d{2}$",
        "(a|ab)*c",
        "a.*b.*c!",
    ];
    for p in safe_js {
        assert_eq!(verdict(p, Dialect::Js), None, "{p} should be safe");
    }
    let safe_py = ["(?>a+)+$", "a++b", "(?>[a-z]+)*$", "(?:a+)++$"];
    for p in safe_py {
        assert_eq!(verdict(p, Dialect::Python), None, "{p} should be safe (atomic/possessive)");
    }
}

#[test]
fn the_attack_string_is_well_formed() {
    let f = find("(a+)+$", Dialect::Js).unwrap();
    assert_eq!(f.pump, vec!['a' as u32]);
    assert!(f.input(5).starts_with("aaaaa"));
    // The step count the detector recorded really grows.
    assert!(f.growth.hit_cap || f.growth.samples.last().unwrap().1 > f.growth.samples[0].1 * 50);
}

// ---------------------------------------------------------------------------------------------------
// The honesty guarantee: a reported finding blows up on the real engine.

fn have(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok_and(|o| o.status.success())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum NodeTime {
    Ms(f64),
    TimedOut,
}

/// How long Node took to run `pattern` against `input`, or `TimedOut`. A fresh process each time, and
/// `timeout` kills Node if the match runs too long (exit code 124).
fn node_time(pattern: &str, input: &str, timeout_secs: &str) -> NodeTime {
    let script = "const r=new RegExp(process.argv[1]);const s=process.argv[2];const t=process.hrtime.bigint();r.test(s);console.log(Number(process.hrtime.bigint()-t)/1e6);";
    let out = Command::new("timeout")
        .args([timeout_secs, "node", "-e", script, pattern, input])
        .output()
        .unwrap();
    if out.status.code() == Some(124) {
        return NodeTime::TimedOut;
    }
    NodeTime::Ms(String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0.0))
}

/// Confirms a claimed exponential really blows up in Node. Two inputs twelve pumps apart: a true exponential
/// either times out or grows by a large factor; a safe pattern stays flat. Returns `Err(reason)` if the
/// finding does not blow up (a false positive).
fn node_confirms_exponential(pattern: &str, f: &Finding) -> Result<(), String> {
    let (lo, hi) = pick_pump_counts(f, 36, 48);
    let a_lo = f.input(lo);
    let a_hi = f.input(hi);
    match (node_time(pattern, &a_lo, "4"), node_time(pattern, &a_hi, "4")) {
        (_, NodeTime::TimedOut) | (NodeTime::TimedOut, _) => Ok(()),
        (NodeTime::Ms(t0), NodeTime::Ms(t1)) => {
            if t1 > t0 * 8.0 && t1 > 5.0 {
                Ok(())
            } else {
                Err(format!(
                    "Node time barely grew: {t0:.2}ms (n={lo}) -> {t1:.2}ms (n={hi}); attack {:?}",
                    f.input(lo)
                ))
            }
        }
    }
}

/// Two pump counts `(lo, hi)`, shrunk together if the attack would be too long for Node.
fn pick_pump_counts(f: &Finding, mut lo: usize, mut hi: usize) -> (usize, usize) {
    while f.input(hi).len() > 4000 && lo > 8 {
        lo -= 6;
        hi -= 6;
    }
    (lo, hi)
}

#[test]
fn reported_exponentials_really_blow_up_in_node() {
    if !have("node") {
        return;
    }
    for p in [
        "(a+)+$",
        "(a*)*c",
        "([a-z]+)*$",
        "(x+x+)+y",
        "^(.*,)*$",
        "(\\d+)*$",
        "(([a-z])+.)+[A-Z]([a-z])+$",
    ] {
        let f = find(p, Dialect::Js).unwrap();
        node_confirms_exponential(p, &f).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
}

#[test]
fn reported_polynomials_really_slow_down_in_node() {
    if !have("node") {
        return;
    }
    for p in [".*.*=.*", "\\d+\\d+!", "\\s*\\s*$"] {
        let f = find(p, Dialect::Js).unwrap();
        // Double the length; a quadratic grows ~4x, well above a linear 2x.
        let (t0, t1) = (node_time(p, &f.input(1500), "4"), node_time(p, &f.input(3000), "4"));
        let grew = matches!(t1, NodeTime::TimedOut) || matches!((t0, t1), (NodeTime::Ms(a), NodeTime::Ms(b)) if b > a * 2.5 && b > 5.0);
        assert!(grew, "{p}: expected quadratic slow-down in Node, got {t0:?} -> {t1:?}");
    }
}

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
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

/// Random regexes weighted toward loops and groups, where ReDoS lives.
fn random_regex(r: &mut Rng, depth: u32) -> String {
    let leaf = ["a", "b", "[a-z]", "[ab]", "\\d", "\\w", ".", "x"];
    if depth == 0 || r.below(10) < 4 {
        return format!("{}{}", r.pick(&leaf), r.pick(&["", "", "+", "*", "?"]));
    }
    let inner = (0..1 + r.below(2)).map(|_| random_regex(r, depth - 1)).collect::<String>();
    match r.below(6) {
        0 | 1 => format!("({inner}){}", r.pick(&["*", "+", "*", "+"])),
        2 => format!("(?:{inner}){}", r.pick(&["*", "+"])),
        3 => format!("({inner}|{}){}", random_regex(r, depth - 1), r.pick(&["*", "+"])),
        _ => inner,
    }
}

#[test]
fn no_false_positives_against_node() {
    // For many random regexes, every finding the detector reports must actually blow up (or slow down) in
    // Node. This is the core guarantee: the tool never cries wolf.
    if !have("node") {
        return;
    }
    let mut r = Rng(0xD15EA5E);
    let cases = if std::env::var("REDOS_FUZZ_LONG").is_ok() { 3000 } else { 150 };
    let (mut flagged, mut checked) = (0, 0);
    for _ in 0..cases {
        let pattern = random_regex(&mut r, 3);
        let Some(f) = find(&pattern, Dialect::Js) else { continue };
        flagged += 1;
        match f.blowup {
            Blowup::Exponential => {
                if f.input(48).len() > 6000 {
                    continue;
                }
                checked += 1;
                node_confirms_exponential(&pattern, &f).unwrap_or_else(|e| panic!("FALSE POSITIVE (exponential) /{pattern}/: {e}"));
            }
            Blowup::Polynomial { degree } => {
                if f.input(3000).len() > 8000 {
                    continue;
                }
                checked += 1;
                let (t0, t1) = (node_time(&pattern, &f.input(1500), "4"), node_time(&pattern, &f.input(3000), "4"));
                let grew =
                    matches!(t1, NodeTime::TimedOut) || matches!((t0, t1), (NodeTime::Ms(a), NodeTime::Ms(b)) if b > a * 2.2 && b > 3.0);
                assert!(
                    grew,
                    "FALSE POSITIVE (polynomial degree {degree}) /{pattern}/: Node timing barely grew ({t0:?} -> {t1:?})"
                );
            }
        }
    }
    eprintln!("random: {flagged} patterns flagged, {checked} confirmed against Node (of {cases})");
    assert!(flagged > 0, "the fuzzer never flagged anything — generator too tame");
}
