//! Phase 3: the detector's findings, proven on the real engines.
//!
//! Each test runs a finding's attack through the actual Node, Python or Ruby and checks the real-engine
//! verdict. These are gated on the engine being installed. The deterministic classifier logic is unit-tested
//! in `src/prove.rs`.

use redos_proof::analysis::{Finding, analyze};
use redos_proof::nfa::compile;
use redos_proof::prove::{Engine, Verdict, prove};
use redos_proof::{Dialect, Flags, parse};

fn finding(pattern: &str, dialect: Dialect) -> Finding {
    let nfa = compile(&parse(pattern, dialect, Flags::default()).unwrap()).unwrap();
    analyze(&nfa)
        .unwrap()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{pattern}: no finding"))
}

fn real_verdict(pattern: &str, dialect: Dialect) -> Option<Verdict> {
    let f = finding(pattern, dialect);
    let proof = prove(pattern, dialect, Flags::default(), &f);
    proof.verdict
}

#[test]
fn node_proves_exponential_patterns() {
    if !Engine::Node.available() {
        return;
    }
    for p in ["(a+)+$", "(a*)*c", "([a-z]+)*$", "(x+x+)+y"] {
        assert_eq!(
            real_verdict(p, Dialect::Js),
            Some(Verdict::Exponential),
            "{p} should be proven exponential in Node"
        );
    }
}

#[test]
fn node_proves_polynomial_patterns() {
    if !Engine::Node.available() {
        return;
    }
    for p in [".*.*=.*", "\\s*\\s*$"] {
        match real_verdict(p, Dialect::Js) {
            Some(Verdict::Polynomial { degree }) => assert!(degree >= 2, "{p}: degree {degree}"),
            other => panic!("{p}: expected polynomial, got {other:?}"),
        }
    }
}

#[test]
fn python_proves_its_findings() {
    if !Engine::Python.available() {
        return;
    }
    assert_eq!(real_verdict("(a+)+$", Dialect::Python), Some(Verdict::Exponential));
    assert!(matches!(
        real_verdict("\\d+\\d+!", Dialect::Python),
        Some(Verdict::Polynomial { .. })
    ));
}

#[test]
fn ruby_memoization_is_surfaced_honestly() {
    // Ruby 3.2+ memoizes and defeats the classic ReDoS patterns. The prover must report this honestly:
    // the model finds the pattern exponential, but real Ruby does not reproduce it. If a future Ruby drops
    // the optimization, this test fails and the docs must be revisited.
    if !Engine::Ruby.available() {
        return;
    }
    assert_eq!(
        real_verdict("(a+)+$", Dialect::Ruby),
        Some(Verdict::NotReproduced),
        "Ruby 3.3 memoizes (a+)+$"
    );
}

#[test]
fn the_same_pattern_differs_across_engines() {
    // The headline honesty result: one pattern, exponential in the model and in Node, mitigated by Ruby.
    if !Engine::Node.available() || !Engine::Ruby.available() {
        return;
    }
    assert_eq!(real_verdict("(a+)+$", Dialect::Js), Some(Verdict::Exponential), "Node blows up");
    assert_eq!(real_verdict("(a+)+$", Dialect::Ruby), Some(Verdict::NotReproduced), "Ruby does not");
}

#[test]
fn an_uninstalled_engine_is_reported_not_crashed() {
    // When the engine is missing, the proof is marked unavailable rather than panicking.
    let f = finding("(a+)+$", Dialect::Js);
    let proof = prove("(a+)+$", Dialect::Js, Flags::default(), &f);
    if Engine::Node.available() {
        assert!(proof.available && proof.verdict.is_some());
    } else {
        assert!(!proof.available && proof.measurements.is_empty() && proof.verdict.is_none());
    }
}
