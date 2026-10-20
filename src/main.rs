//! The `redos-proof` command line.
//!
//!   redos-proof match [--dialect js|python|ruby] [--flags im] <pattern> <input>
//!       where the leftmost match is, and how many steps a backtracking engine takes to find it
//!   redos-proof steps [--dialect ...] [--flags ...] <pattern> <prefix> <pump> <suffix> [max-n]
//!       how the work grows as `pump` is repeated: prefix + pump×n + suffix, for n = 1, 2, 4, 8...
//!   redos-proof scan [--dialect ...] [--flags ...] <pattern>
//!       report whether the pattern is vulnerable to catastrophic backtracking, with the proof
//!   redos-proof files [--prove] [--sarif] <path>...
//!       scan source files or directories for vulnerable regexes (JavaScript, TypeScript, Python, Ruby)
//!   redos-proof bench [--no-prove] [corpus-dir]
//!       run the detector over the corpus (corpus/vulnerable.txt, corpus/safe.txt) and report recall/precision

use std::process::ExitCode;

use std::path::PathBuf;

use redos_proof::analysis::{Blowup, analyze};
use redos_proof::matcher::{Outcome, search};
use redos_proof::nfa::compile;
use redos_proof::prove::{Timing, Verdict, prove};
use redos_proof::scan::{Report, scan_paths};
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
        ("files", rest) if !rest.is_empty() => files_command(rest),
        ("bench", rest) => bench_command(rest),
        _ => usage(),
    }
}

/// `bench [--no-prove] [dir]` — run the detector over the corpus and report recall/precision.
fn bench_command(args: &[String]) -> ExitCode {
    use redos_proof::bench::{Engine, Summary, parse_corpus, run};

    let mut prove_on_engine = true;
    let mut dir = PathBuf::from("corpus");
    for a in args {
        match a.as_str() {
            "--no-prove" => prove_on_engine = false,
            other if other.starts_with("--") => {
                eprintln!("unknown option {other}");
                return ExitCode::from(2);
            }
            path => dir = PathBuf::from(path),
        }
    }

    let read = |name: &str| std::fs::read_to_string(dir.join(name));
    let (Ok(vuln_text), Ok(safe_text)) = (read("vulnerable.txt"), read("safe.txt")) else {
        eprintln!("cannot read {}/vulnerable.txt and {}/safe.txt", dir.display(), dir.display());
        return ExitCode::from(2);
    };

    let mut entries = parse_corpus(&vuln_text, true);
    entries.extend(parse_corpus(&safe_text, false));
    let outcomes: Vec<_> = entries.iter().map(|e| run(e, prove_on_engine)).collect();

    for o in &outcomes {
        let status = if o.is_correct() { "ok  " } else { "FAIL" };
        let engine = match o.engine {
            Some(Engine::Reproduced) => "  [engine: reproduced]",
            Some(Engine::NotReproduced) => "  [engine: not reproduced]",
            Some(Engine::Unavailable) => "  [engine: not installed]",
            None => "",
        };
        let flag = if o.detected { "flagged" } else { "clean  " };
        let want = if o.entry.expect_vulnerable { "vuln" } else { "safe" };
        println!(
            "{status}  {want}  {flag}  {}  /{}/{}{engine}",
            o.entry.dialect.name(),
            o.entry.pattern,
            o.entry.flags,
        );
    }

    let s = Summary::of(&outcomes);
    println!("\n--- corpus summary ---");
    println!(
        "vulnerable: {}/{} flagged by the model   (recall {:.0}%)",
        s.detected,
        s.vulnerable_total,
        s.recall() * 100.0
    );
    if prove_on_engine {
        println!(
            "            {}/{} reproduced on the real engine{}",
            s.reproduced,
            s.vulnerable_total,
            if s.engine_unavailable > 0 {
                format!(" ({} skipped: engine not installed)", s.engine_unavailable)
            } else {
                String::new()
            }
        );
    }
    println!(
        "safe:       {}/{} wrongly flagged   (precision {:.0}%)",
        s.false_positives,
        s.safe_total,
        s.precision() * 100.0
    );
    if s.unanalysable > 0 {
        println!("{} entr(y/ies) could not be modelled", s.unanalysable);
    }

    let failures = outcomes.iter().filter(|o| !o.is_correct()).count();
    if failures == 0 {
        println!("\nall {} corpus entries behaved as expected", outcomes.len());
        ExitCode::SUCCESS
    } else {
        println!("\n{failures} corpus entr(y/ies) did not behave as expected");
        ExitCode::FAILURE
    }
}

fn files_command(args: &[String]) -> ExitCode {
    let mut prove = false;
    let mut sarif = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for a in args {
        match a.as_str() {
            "--prove" => prove = true,
            "--sarif" => sarif = true,
            other if other.starts_with("--") => {
                eprintln!("unknown option {other}");
                return ExitCode::from(2);
            }
            path => paths.push(PathBuf::from(path)),
        }
    }
    if paths.is_empty() {
        return usage();
    }
    // 2 MiB cap skips generated and minified files.
    let report = scan_paths(&paths, prove, 2 << 20);
    if sarif {
        print!("{}", sarif_report(&report));
    } else {
        print_report(&report, prove);
    }
    // Exit non-zero if anything was found (gating a CI check or pre-commit hook). With --prove, only count
    // findings the real engine reproduced.
    let dangerous = report.hits.iter().filter(|h| !prove || h.is_confirmed_on_engine()).count();
    if dangerous > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

fn print_report(report: &Report, proved: bool) {
    use redos_proof::prove::{Timing, Verdict};
    for h in &report.hits {
        let kind = match h.finding.blowup {
            Blowup::Exponential => "EXPONENTIAL".to_string(),
            Blowup::Polynomial { degree } => format!("POLYNOMIAL(^{degree})"),
        };
        println!(
            "{}:{}:{}  {kind}  /{}/{}",
            h.file.display(),
            h.literal.line,
            h.literal.col,
            h.literal.pattern,
            h.literal.flags
        );
        println!("    attack: {:?}", h.finding.input(20));
        if let Some(proof) = &h.proof {
            if !proof.available {
                println!("    real engine ({}): not installed", proof.engine.name());
            } else {
                let label = match proof.verdict {
                    Some(Verdict::Exponential) => "PROVEN EXPONENTIAL",
                    Some(Verdict::Polynomial { .. }) => "PROVEN POLYNOMIAL",
                    _ => "not reproduced on this engine",
                };
                let worst = proof.measurements.iter().rev().find_map(|m| match m.timing {
                    Timing::TimedOut => Some("timed out".to_string()),
                    Timing::Millis(t) if t > 1.0 => Some(format!("{t:.0} ms")),
                    _ => None,
                });
                match worst {
                    Some(w) => println!(
                        "    real engine ({}): {label} ({w} at {} chars)",
                        proof.engine.name(),
                        proof.measurements.last().map(|m| m.len).unwrap_or(0)
                    ),
                    None => println!("    real engine ({}): {label}", proof.engine.name()),
                }
            }
        }
    }
    let confirmed = report.hits.iter().filter(|h| !proved || h.is_confirmed_on_engine()).count();
    println!(
        "\nscanned {} files, {} regexes: {} vulnerable{}{}",
        report.files_scanned,
        report.regexes_scanned,
        confirmed,
        if proved && confirmed != report.hits.len() {
            format!(" (of {} flagged by the model)", report.hits.len())
        } else {
            String::new()
        },
        if report.unanalysable > 0 {
            format!(", {} not analysable", report.unanalysable)
        } else {
            String::new()
        },
    );
}

/// A minimal SARIF 2.1.0 document, for GitHub code scanning. Hand-written to keep the tool dependency-free.
fn sarif_report(report: &Report) -> String {
    let mut results = String::new();
    for (i, h) in report.hits.iter().enumerate() {
        if i > 0 {
            results.push(',');
        }
        let kind = match h.finding.blowup {
            Blowup::Exponential => "exponential".to_string(),
            Blowup::Polynomial { degree } => format!("polynomial (degree {degree})"),
        };
        let msg = format!(
            "Regex vulnerable to {kind} backtracking (ReDoS). Attack input: {}",
            truncate(&h.finding.input(20), 80)
        );
        let level = if matches!(h.finding.blowup, Blowup::Exponential) {
            "error"
        } else {
            "warning"
        };
        results.push_str("{\"ruleId\":\"redos\",\"level\":");
        results.push_str(&json_string(level));
        results.push_str(",\"message\":{\"text\":");
        results.push_str(&json_string(&msg));
        results.push_str("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        results.push_str(&json_string(&h.file.display().to_string()));
        results.push_str("},\"region\":{\"startLine\":");
        results.push_str(&h.literal.line.max(1).to_string());
        results.push_str(",\"startColumn\":");
        results.push_str(&h.literal.col.max(1).to_string());
        results.push_str("}}}]}");
    }
    let header = "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
\"runs\":[{\"tool\":{\"driver\":{\"name\":\"redos-proof\",\
\"informationUri\":\"https://github.com/Shibin506/redos-proof\",\
\"rules\":[{\"id\":\"redos\",\"name\":\"ReDoS\",\
\"shortDescription\":{\"text\":\"Regular expression vulnerable to catastrophic backtracking\"}}]}},\"results\":[";
    format!("{header}{results}]}}]}}\n")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(n).collect::<String>())
    }
}

/// JSON-encodes a string (the only JSON escaping the SARIF writer needs).
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn fail(e: &str) -> ExitCode {
    eprintln!("{e}");
    ExitCode::FAILURE
}

fn usage() -> ExitCode {
    eprintln!("usage: redos-proof match [--dialect js|python|ruby] [--flags F] <pattern> <input>");
    eprintln!("       redos-proof steps [--dialect ...] [--flags F] <pattern> <prefix> <pump> <suffix> [max-n]");
    eprintln!("       redos-proof scan  [--dialect ...] [--flags F] <pattern>");
    eprintln!("       redos-proof files [--prove] [--sarif] <path>...");
    eprintln!("       redos-proof bench [--no-prove] [corpus-dir]");
    ExitCode::from(2)
}
