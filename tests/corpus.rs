//! Phase 5: the committed corpus is a regression test.
//!
//! Every pattern in `corpus/vulnerable.txt` must still be flagged by the model, and every pattern in
//! `corpus/safe.txt` must still be left alone. This runs the model only (no subprocess), so it is fast and
//! deterministic; the real-engine side is covered by `tests/proof.rs` and by `redos-proof bench`.

use std::path::PathBuf;

use redos_proof::bench::{Summary, parse_corpus, run};

fn corpus(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn every_vulnerable_pattern_is_still_flagged() {
    let entries = parse_corpus(&corpus("vulnerable.txt"), true);
    assert!(entries.len() >= 15, "corpus shrank unexpectedly: {} entries", entries.len());
    let mut missed = Vec::new();
    for e in &entries {
        let o = run(e, false);
        if o.unanalysable {
            missed.push(format!("{} (unanalysable)", e.pattern));
        } else if !o.detected {
            missed.push(format!("{} (not flagged)", e.pattern));
        }
    }
    assert!(missed.is_empty(), "known-vulnerable patterns the model missed: {missed:?}");
}

#[test]
fn no_safe_pattern_is_flagged() {
    let entries = parse_corpus(&corpus("safe.txt"), false);
    assert!(entries.len() >= 10, "safe corpus shrank unexpectedly: {} entries", entries.len());
    let mut false_positives = Vec::new();
    for e in &entries {
        if run(e, false).detected {
            false_positives.push(e.pattern.clone());
        }
    }
    assert!(false_positives.is_empty(), "safe patterns wrongly flagged: {false_positives:?}");
}

#[test]
fn summary_is_perfect_recall_and_precision_on_the_model() {
    let mut entries = parse_corpus(&corpus("vulnerable.txt"), true);
    entries.extend(parse_corpus(&corpus("safe.txt"), false));
    let outcomes: Vec<_> = entries.iter().map(|e| run(e, false)).collect();
    let s = Summary::of(&outcomes);
    assert_eq!(s.detected, s.vulnerable_total, "recall below 100%");
    assert_eq!(s.false_positives, 0, "model produced a false positive");
    assert!((s.recall() - 1.0).abs() < 1e-9);
    assert!((s.precision() - 1.0).abs() < 1e-9);
}
