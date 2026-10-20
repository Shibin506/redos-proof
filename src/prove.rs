//! Phase 3: prove a finding on the real engine.
//!
//! Phase 2 confirms a finding against the model (an exact copy of how the engine backtracks). Phase 3 goes
//! one step further and runs the attack on the *actual* Node, Python or Ruby, timing the match as the input
//! grows. The verdict is read from those real wall-clock times, so the proof shown to the user is the engine
//! choking on its own, not the model's opinion of it.
//!
//! A catastrophic match cannot be interrupted from inside a single-threaded engine, so each run is a fresh
//! process killed from outside when it runs too long. A kill at a short input length is itself the proof.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::analysis::{Blowup, Finding};
use crate::ast::Dialect;
use crate::parser::Flags;

/// A real regex engine to run the attack on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Node,
    Python,
    Ruby,
}

impl Engine {
    pub fn for_dialect(d: Dialect) -> Engine {
        match d {
            Dialect::Js => Engine::Node,
            Dialect::Python => Engine::Python,
            Dialect::Ruby => Engine::Ruby,
        }
    }

    pub fn program(self) -> &'static str {
        match self {
            Engine::Node => "node",
            Engine::Python => "python3",
            Engine::Ruby => "ruby",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Engine::Node => "Node",
            Engine::Python => "Python",
            Engine::Ruby => "Ruby",
        }
    }

    /// Whether the engine is installed.
    pub fn available(self) -> bool {
        Command::new(self.program())
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }
}

/// How long one real match took.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Timing {
    Millis(f64),
    /// Killed after the per-run deadline: the match was still running.
    TimedOut,
}

#[derive(Debug, Clone, Copy)]
pub struct Measurement {
    /// Number of pump repetitions in the input.
    pub pump: usize,
    /// Length of the input in characters.
    pub len: usize,
    pub timing: Timing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Time multiplies as the input grows a little: catastrophic.
    Exponential,
    /// Time grows like `length^degree`.
    Polynomial { degree: u32 },
    /// The real engine did not slow down: the finding was not reproduced here.
    NotReproduced,
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub engine: Engine,
    /// `false` if the engine is not installed (then `measurements` is empty and `verdict` is `None`).
    pub available: bool,
    pub measurements: Vec<Measurement>,
    pub verdict: Option<Verdict>,
}

/// The per-run time budget. A real catastrophic match blows past this; a safe one finishes in well under it.
const DEADLINE: Duration = Duration::from_millis(2500);

/// Runs `finding`'s attack on the real engine for `dialect`, timing the match as the input grows, and reads
/// the verdict from the measured times.
pub fn prove(pattern: &str, dialect: Dialect, flags: Flags, finding: &Finding) -> Proof {
    let engine = Engine::for_dialect(dialect);
    if !engine.available() {
        return Proof {
            engine,
            available: false,
            measurements: Vec::new(),
            verdict: None,
        };
    }
    let flag_str = flag_string(dialect, flags);
    let schedule: Vec<usize> = match finding.blowup {
        // Exponential: raise the pump a little at a time; the time should explode.
        Blowup::Exponential => vec![10, 14, 18, 22, 26, 30, 34, 38, 42],
        // Polynomial: raise the length a lot; the time should grow like a power of it.
        Blowup::Polynomial { .. } => vec![200, 400, 800, 1600, 3200, 6400],
    };
    let mut measurements = Vec::new();
    for pump in schedule {
        let input = finding.input(pump);
        if input.len() > 200_000 {
            break;
        }
        let timing = time_match(engine, pattern, &flag_str, &input);
        measurements.push(Measurement {
            pump,
            len: input.chars().count(),
            timing,
        });
        if timing == Timing::TimedOut {
            break; // already proven to blow up; no need to go bigger
        }
    }
    let verdict = Some(classify(&measurements));
    Proof {
        engine,
        available: true,
        measurements,
        verdict,
    }
}

/// Times one match of `pattern` against `input` on the real engine, or `TimedOut` if it ran past the
/// deadline. A fresh process each time, killed from outside if it does not finish.
fn time_match(engine: Engine, pattern: &str, flags: &str, input: &str) -> Timing {
    let script = script_for(engine);
    let mut cmd = Command::new(engine.program());
    match engine {
        Engine::Node => cmd.args(["-e", script, "--", pattern, flags, input]),
        Engine::Python => cmd.args(["-c", script, pattern, flags, input]),
        Engine::Ruby => cmd.args(["-Ku", "-e", script, pattern, flags, input]).env("LANG", "C.UTF-8"),
    };
    match run_timed(&mut cmd, DEADLINE) {
        Some(stdout) => Timing::Millis(stdout.trim().parse().unwrap_or(0.0)),
        None => Timing::TimedOut,
    }
}

/// Spawns the command, waits up to `deadline`, and kills it if it does not finish. Returns its stdout, or
/// `None` if it was killed.
fn run_timed(cmd: &mut Command, deadline: Duration) -> Option<String> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let mut out = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut out);
                }
                return Some(out);
            }
            Ok(None) => {
                if start.elapsed() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return None,
        }
    }
}

/// Reads the verdict from the real measurements, the same way the model's growth is read but on wall-clock
/// time: a time-out at a short input, or time that multiplies as the input grows, is exponential; time that
/// grows like a power of the length is polynomial; anything flat is not reproduced.
fn classify(ms: &[Measurement]) -> Verdict {
    let timed_out_at = ms.iter().find(|m| m.timing == Timing::TimedOut);
    let points: Vec<(f64, f64, usize)> = ms
        .iter()
        .filter_map(|m| match m.timing {
            Timing::Millis(t) if t > 0.0 => Some((m.len as f64, t, m.pump)),
            _ => None,
        })
        .collect();

    // Exponential: the pump rises by a constant each step, so exponential time multiplies by a constant.
    // Look at the ratio between successive measurable points on the exponential schedule.
    let exp_like = {
        let on_exp_schedule = ms.first().is_some_and(|m| m.len < 100);
        if !on_exp_schedule {
            false
        } else if timed_out_at.is_some_and(|m| m.len < 120) {
            // Timed out while the input was still short: only catastrophic backtracking does that.
            true
        } else {
            let ratios: Vec<f64> = points.windows(2).map(|w| w[1].1 / w[0].1.max(0.0001)).collect();
            !ratios.is_empty()
                && ratios.iter().filter(|&&r| r > 1.6).count() >= ratios.len() * 2 / 3
                && points.last().map(|p| p.1).unwrap_or(0.0) > 20.0
        }
    };
    if exp_like {
        return Verdict::Exponential;
    }

    // Polynomial: fit log(time) against log(length) and round the slope.
    if let Some(degree) = polynomial_degree(&points, timed_out_at.is_some()) {
        return Verdict::Polynomial { degree };
    }
    Verdict::NotReproduced
}

fn polynomial_degree(points: &[(f64, f64, usize)], timed_out: bool) -> Option<u32> {
    let pts: Vec<(f64, f64)> = points.iter().filter(|p| p.1 > 0.5).map(|p| (p.0.ln(), p.1.ln())).collect();
    if pts.len() < 3 {
        // Not enough measurable points, but a time-out after real growth still means super-linear.
        return (timed_out && points.iter().any(|p| p.1 > 20.0)).then_some(2);
    }
    let tail = &pts[pts.len().saturating_sub(4)..];
    let k = tail.len() as f64;
    let sx: f64 = tail.iter().map(|p| p.0).sum();
    let sy: f64 = tail.iter().map(|p| p.1).sum();
    let sxx: f64 = tail.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = tail.iter().map(|p| p.0 * p.1).sum();
    let denom = k * sxx - sx * sx;
    if denom.abs() < 1e-9 {
        return None;
    }
    let slope = (k * sxy - sx * sy) / denom;
    (slope >= 1.6).then(|| slope.round().max(2.0) as u32)
}

/// The flags written the way the engine's own runner expects (letters for Node, re-flag letters for Python,
/// option letters for Ruby — the mapping lives in the scripts below).
fn flag_string(dialect: Dialect, flags: Flags) -> String {
    let mut s = String::new();
    if flags.ignore_case {
        s.push('i');
    }
    if flags.multiline {
        s.push('m');
    }
    if flags.dot_all {
        s.push('s');
    }
    if flags.extended {
        s.push('x');
    }
    if flags.unicode && dialect == Dialect::Js {
        s.push('u');
    }
    if flags.ascii && dialect == Dialect::Python {
        s.push('a');
    }
    s
}

/// The timing script for each engine. Reads pattern, flag string and input from argv, runs one search from
/// the start of the input (the attack is built to be worst-case there), and prints the elapsed milliseconds.
fn script_for(engine: Engine) -> &'static str {
    match engine {
        Engine::Node => {
            "const [p,f,s]=process.argv.slice(1);const r=new RegExp(p,f);const t=process.hrtime.bigint();r.test(s);console.log(Number(process.hrtime.bigint()-t)/1e6);"
        }
        Engine::Python => {
            "import re,sys,time\n\
             p,f,s=sys.argv[1],sys.argv[2],sys.argv[3]\n\
             F={'i':re.I,'m':re.M,'s':re.S,'x':re.X,'a':re.A}\n\
             r=re.compile(p,sum((F[c] for c in f),0))\n\
             t=time.perf_counter()\n\
             r.search(s)\n\
             print((time.perf_counter()-t)*1000)"
        }
        Engine::Ruby => {
            "p,f,s=ARGV\n\
             o=0; o|=Regexp::IGNORECASE if f.include?('i'); o|=Regexp::MULTILINE if f.include?('m'); o|=Regexp::EXTENDED if f.include?('x')\n\
             r=Regexp.new(p,o)\n\
             t=Process.clock_gettime(Process::CLOCK_MONOTONIC)\n\
             r.match(s)\n\
             puts((Process.clock_gettime(Process::CLOCK_MONOTONIC)-t)*1000)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pump: usize, len: usize, timing: Timing) -> Measurement {
        Measurement { pump, len, timing }
    }

    #[test]
    fn classify_reads_real_timings() {
        use Timing::{Millis, TimedOut};
        // Exponential schedule (short inputs), time multiplying then timing out.
        let exp = [
            m(10, 13, Millis(0.3)),
            m(14, 17, Millis(5.0)),
            m(18, 21, Millis(77.0)),
            m(22, 25, Millis(1157.0)),
            m(26, 29, TimedOut),
        ];
        assert_eq!(classify(&exp), Verdict::Exponential);
        // Timed out while the input was still short: catastrophic.
        assert_eq!(classify(&[m(10, 13, Millis(1.0)), m(14, 17, TimedOut)]), Verdict::Exponential);
        // Polynomial schedule (long inputs), time growing like length^2.
        let poly = [
            m(200, 201, Millis(3.0)),
            m(400, 401, Millis(13.0)),
            m(800, 801, Millis(52.0)),
            m(1600, 1601, Millis(205.0)),
        ];
        assert_eq!(classify(&poly), Verdict::Polynomial { degree: 2 });
        // Flat: not reproduced.
        let flat = [
            m(10, 13, Millis(0.0)),
            m(14, 17, Millis(0.0)),
            m(18, 21, Millis(0.0)),
            m(22, 25, Millis(0.0)),
        ];
        assert_eq!(classify(&flat), Verdict::NotReproduced);
    }

    #[test]
    fn run_timed_kills_a_hanging_process() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let out = run_timed(&mut cmd, Duration::from_millis(200));
        assert!(out.is_none(), "a process past the deadline is killed");
        assert!(start.elapsed() < Duration::from_secs(5), "and killed promptly, not waited out");
    }
}
