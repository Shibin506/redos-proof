//! Phase 5: run the detector over a corpus and measure how well it does.
//!
//! The corpus is two plain-text files, [`parse_corpus`] reads them:
//!
//! - `vulnerable.txt` — patterns that provably blow up on a real engine. Every one was confirmed by
//!   actually running it (see `docs/phase-5.md`); the expectation is that the model flags it **and**, when
//!   the engine is installed, the engine reproduces the blow-up.
//! - `safe.txt` — real-world linear regexes (emails, dates, semver, …). The expectation is that the model
//!   flags **nothing**: these guard against false positives.
//!
//! Each line is tab-separated: `dialect <TAB> flags <TAB> pattern <TAB> note`. The flags field may be empty.
//! Lines that are blank or start with `#` are ignored. No pattern is labelled from a CVE id we cannot
//! check; the label is earned by measurement.

use crate::analysis::analyze;
use crate::ast::Dialect;
use crate::nfa::compile;
use crate::parser::{Flags, parse};
use crate::prove::{Verdict, prove};

/// One corpus entry and what we expect of it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub dialect: Dialect,
    pub flags: String,
    pub pattern: String,
    pub note: String,
    /// `true` for `vulnerable.txt`, `false` for `safe.txt`.
    pub expect_vulnerable: bool,
}

/// Parses one corpus file. `expect_vulnerable` is set on every entry it yields.
pub fn parse_corpus(text: &str, expect_vulnerable: bool) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 {
            continue;
        }
        let Some(dialect) = Dialect::parse_name(fields[0].trim()) else {
            continue;
        };
        out.push(Entry {
            dialect,
            flags: fields[1].trim().to_string(),
            pattern: fields[2].to_string(),
            note: fields.get(3).map(|s| s.trim().to_string()).unwrap_or_default(),
            expect_vulnerable,
        });
    }
    out
}

/// What the engine said, when it was run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Engine was not installed, so the blow-up could not be run.
    Unavailable,
    /// Engine ran and reproduced the blow-up (exponential or polynomial).
    Reproduced,
    /// Engine ran and did *not* slow down (e.g. a memoizing engine like Ruby 3.2+).
    NotReproduced,
}

/// The outcome of running one entry through the detector (and optionally the engine).
#[derive(Debug, Clone)]
pub struct Outcome {
    pub entry: Entry,
    /// The static model flagged the pattern as vulnerable.
    pub detected: bool,
    /// The real-engine result, if proving was requested and the pattern was flagged.
    pub engine: Option<Engine>,
    /// A pattern the parser/compiler could not model (counted, not a pass or a fail).
    pub unanalysable: bool,
}

impl Outcome {
    /// A correct result: safe entries must not be flagged; vulnerable entries must be flagged (and, if the
    /// engine ran, reproduced).
    pub fn is_correct(&self) -> bool {
        if self.entry.expect_vulnerable {
            self.detected && !matches!(self.engine, Some(Engine::NotReproduced))
        } else {
            !self.detected
        }
    }
}

/// Runs one entry: parse → compile → analyse, and, when `prove_on_engine`, run the attack on the real engine.
pub fn run(entry: &Entry, prove_on_engine: bool) -> Outcome {
    let mk = || {
        let flags = Flags::parse(entry.dialect, &entry.flags).ok()?;
        let regex = parse(&entry.pattern, entry.dialect, flags).ok()?;
        compile(&regex).ok().map(|nfa| (nfa, flags))
    };
    let Some((nfa, flags)) = mk() else {
        return Outcome {
            entry: entry.clone(),
            detected: false,
            engine: None,
            unanalysable: true,
        };
    };
    let Ok(findings) = analyze(&nfa) else {
        return Outcome {
            entry: entry.clone(),
            detected: false,
            engine: None,
            unanalysable: true,
        };
    };
    let finding = findings.into_iter().next();
    let detected = finding.is_some();
    let engine = match (prove_on_engine, &finding) {
        (true, Some(f)) => {
            let proof = prove(&entry.pattern, entry.dialect, flags, f);
            Some(if !proof.available {
                Engine::Unavailable
            } else if matches!(proof.verdict, Some(Verdict::Exponential | Verdict::Polynomial { .. })) {
                Engine::Reproduced
            } else {
                Engine::NotReproduced
            })
        }
        _ => None,
    };
    Outcome {
        entry: entry.clone(),
        detected,
        engine,
        unanalysable: false,
    }
}

/// Totals over a run of the whole corpus.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub vulnerable_total: usize,
    pub detected: usize,
    pub reproduced: usize,
    pub engine_unavailable: usize,
    pub safe_total: usize,
    pub false_positives: usize,
    pub unanalysable: usize,
}

impl Summary {
    pub fn of(outcomes: &[Outcome]) -> Summary {
        let mut s = Summary::default();
        for o in outcomes {
            if o.unanalysable {
                s.unanalysable += 1;
            }
            if o.entry.expect_vulnerable {
                s.vulnerable_total += 1;
                if o.detected {
                    s.detected += 1;
                }
                match o.engine {
                    Some(Engine::Reproduced) => s.reproduced += 1,
                    Some(Engine::Unavailable) => s.engine_unavailable += 1,
                    _ => {}
                }
            } else {
                s.safe_total += 1;
                if o.detected {
                    s.false_positives += 1;
                }
            }
        }
        s
    }

    /// Fraction of known-vulnerable patterns the model flags, in `[0, 1]`.
    pub fn recall(&self) -> f64 {
        if self.vulnerable_total == 0 {
            1.0
        } else {
            self.detected as f64 / self.vulnerable_total as f64
        }
    }

    /// Fraction of flagged patterns that really are vulnerable, in `[0, 1]`.
    pub fn precision(&self) -> f64 {
        let flagged = self.detected + self.false_positives;
        if flagged == 0 { 1.0 } else { self.detected as f64 / flagged as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tabbed_lines_and_skips_comments() {
        let text = "# header\njs\t\t(a+)+$\tnote here\npython\ti\t(\\d+)+$\t\n\n";
        let entries = parse_corpus(text, true);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].dialect, Dialect::Js);
        assert_eq!(entries[0].flags, "");
        assert_eq!(entries[0].pattern, "(a+)+$");
        assert_eq!(entries[0].note, "note here");
        assert!(entries[0].expect_vulnerable);
        assert_eq!(entries[1].dialect, Dialect::Python);
        assert_eq!(entries[1].flags, "i");
    }

    #[test]
    fn model_flags_a_vulnerable_entry_and_not_a_safe_one() {
        let vuln = Entry {
            dialect: Dialect::Js,
            flags: String::new(),
            pattern: "(a+)+$".to_string(),
            note: String::new(),
            expect_vulnerable: true,
        };
        let safe = Entry {
            dialect: Dialect::Js,
            flags: String::new(),
            pattern: "^[a-z0-9_]+$".to_string(),
            note: String::new(),
            expect_vulnerable: false,
        };
        // Model only (no engine): both should be "correct".
        assert!(run(&vuln, false).detected);
        assert!(!run(&safe, false).detected);
        assert!(run(&vuln, false).is_correct());
        assert!(run(&safe, false).is_correct());
    }
}
