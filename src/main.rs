//! The `redos-proof` command line.
//!
//!   redos-proof match [--dialect js|python|ruby] [--flags im] <pattern> <input>
//!       where the leftmost match is, and how many steps a backtracking engine takes to find it
//!   redos-proof steps [--dialect ...] [--flags ...] <pattern> <prefix> <pump> <suffix> [max-n]
//!       how the work grows as `pump` is repeated: prefix + pump×n + suffix, for n = 1, 2, 4, 8...
//!   redos-proof scan [--dialect ...] [--flags ...] <pattern>
//!       report whether the pattern is vulnerable to catastrophic backtracking, with the proof

use std::process::ExitCode;

use redos_proof::analysis::{Blowup, analyze};
use redos_proof::matcher::{Outcome, search};
use redos_proof::nfa::compile;
use redos_proof::prove::{Timing, Verdict, prove};
use redos_proof::{Dialect, Flags, parse};

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut dialect = Dialect::Js;
    let mut flags = String::new();
    while let Some(i) = args.iter().position(|a| a == "--dialect" || a == "--flags") {
        let Some(v) = args.get(i + 1).cloned() else {
            eprintln!("{} needs a value", args[i]);
            return ExitCode::from(2);
        };
        if args[i] == "--dialect" {
            match Dialect::parse_name(&v) {
                Some(d) => dialect = d,
                None => {
                    eprintln!("unknown dialect {v:?} (js, python, ruby)");
                    return ExitCode::from(2);
                }
            }
        } else {
            flags = v;
        }
        args.drain(i..i + 2);
    }
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => return usage(),
    };
    let nfa = |pattern: &str| {
        let f = Flags::parse(dialect, &flags).map_err(|e| e.to_string())?;
        let regex = parse(pattern, dialect, f).map_err(|e| format!("parse error {e}"))?;
        compile(&regex).map_err(|e| e.to_string())
    };
    match (cmd, rest) {
        ("match", [pattern, input]) => {
            let nfa = match nfa(pattern) {
                Ok(n) => n,
                Err(e) => return fail(&e),
            };
            let run = search(&nfa, input, u64::MAX);
            match run.outcome {
                Outcome::Match { start, end } => {
                    let text: String = input.chars().skip(start).take(end - start).collect();
                    println!("match {start}..{end} {text:?} after {} steps", run.steps);
                }
                Outcome::NoMatch => println!("no match after {} steps", run.steps),
                Outcome::StepLimit => unreachable!(),
            }
            ExitCode::SUCCESS
        }
        ("steps", [pattern, prefix, pump, suffix, max @ ..]) => {
            let nfa = match nfa(pattern) {
                Ok(n) => n,
                Err(e) => return fail(&e),
            };
            let max_n: usize = max.first().and_then(|m| m.parse().ok()).unwrap_or(1 << 12);
            println!("{:>8} {:>16} {:>8}", "n", "steps", "ratio");
            let mut last: Option<u64> = None;
            let mut n = 1;
            while n <= max_n {
                let input = format!("{prefix}{}{suffix}", pump.repeat(n));
                let run = search(&nfa, &input, 2_000_000_000);
                let ratio = last.map(|l| format!("{:.2}", run.steps as f64 / l as f64)).unwrap_or_default();
                let note = if run.outcome == Outcome::StepLimit { "  (step limit)" } else { "" };
                println!("{n:>8} {:>16} {ratio:>8}{note}", run.steps);
                if run.outcome == Outcome::StepLimit {
                    break;
                }
                last = Some(run.steps);
                n *= 2;
            }
            ExitCode::SUCCESS
        }
        ("scan", [pattern]) => {
            let nfa = match nfa(pattern) {
                Ok(n) => n,
                Err(e) => return fail(&e),
            };
            match analyze(&nfa) {
                Err(e) => {
                    println!("not analysed: {e:?}");
                    ExitCode::SUCCESS
                }
                Ok(findings) if findings.is_empty() => {
                    println!("no catastrophic backtracking found (not a guarantee of safety; see the limits in the docs)");
                    ExitCode::SUCCESS
                }
                Ok(findings) => {
                    let f = &findings[0];
                    let kind = match f.blowup {
                        Blowup::Exponential => "EXPONENTIAL (one extra character can double the work)".to_string(),
                        Blowup::Polynomial { degree } => format!("POLYNOMIAL degree {degree} (work grows like length^{degree})"),
                    };
                    println!("VULNERABLE (backtracking model): {kind}");
                    let show = |label: &str, v: &[u32]| {
                        let s: String = v.iter().filter_map(|&c| char::from_u32(c)).collect();
                        println!("  {label:8} {s:?}");
                    };
                    show("prefix", &f.prefix);
                    show("pump", &f.pump);
                    show("suffix", &f.suffix);
                    println!("  example attack input (pump x20): {:?}", f.input(20));

                    // Phase 3: run the attack on the real engine and show the wall-clock proof.
                    let parsed = Flags::parse(dialect, &flags).unwrap_or_default();
                    let proof = prove(pattern, dialect, parsed, f);
                    if !proof.available {
                        println!(
                            "  real engine ({}): not installed, cannot run the attack; trusting the model",
                            proof.engine.name()
                        );
                        return ExitCode::FAILURE;
                    }
                    let label = match proof.verdict {
                        Some(Verdict::Exponential) => "PROVEN EXPONENTIAL".to_string(),
                        Some(Verdict::Polynomial { degree }) => format!("PROVEN POLYNOMIAL (degree {degree})"),
                        Some(Verdict::NotReproduced) | None => "NOT reproduced".to_string(),
                    };
                    println!("  real engine ({}): {label}", proof.engine.name());
                    for m in &proof.measurements {
                        match m.timing {
                            Timing::Millis(t) => println!("    {:>6} chars  {t:>8.1} ms", m.len),
                            Timing::TimedOut => println!("    {:>6} chars  timed out (still running after 2.5 s)", m.len),
                        }
                    }
                    match proof.verdict {
                        Some(Verdict::NotReproduced) | None => {
                            println!(
                                "  note: the pattern is exponential for a plain backtracking engine, but {} did not slow down.",
                                proof.engine.name()
                            );
                            println!(
                                "        {} defeats many of these patterns (Ruby 3.2+ memoizes); the same regex would still be dangerous on an engine that does not.",
                                proof.engine.name()
                            );
                            // Not reproduced on this engine: exit 0, but the warning above stands.
                            ExitCode::SUCCESS
                        }
                        // Proven on the real engine: non-zero so the command can gate CI or a pre-commit hook.
                        _ => ExitCode::FAILURE,
                    }
                }
            }
        }
        _ => usage(),
    }
}

fn fail(e: &str) -> ExitCode {
    eprintln!("{e}");
    ExitCode::FAILURE
}

fn usage() -> ExitCode {
    eprintln!("usage: redos-proof match [--dialect js|python|ruby] [--flags F] <pattern> <input>");
    eprintln!("       redos-proof steps [--dialect ...] [--flags F] <pattern> <prefix> <pump> <suffix> [max-n]");
    eprintln!("       redos-proof scan  [--dialect ...] [--flags F] <pattern>");
    ExitCode::from(2)
}
