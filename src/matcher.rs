//! Runs an [`Nfa`] exactly the way a backtracking engine does, counting every step.
//!
//! The step count is the quantity that explodes in a ReDoS: a backtracking engine does about this many
//! steps of work. Counting them gives a deterministic measure (no timer noise), which the later phases use
//! to show how the work grows with the input.

use crate::ast::Assertion;
use crate::nfa::{Nfa, OnEmpty, State, StateId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The leftmost match, as `start..end` in characters (code points).
    Match {
        start: usize,
        end: usize,
    },
    NoMatch,
    /// Gave up after `max_steps`.
    StepLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub outcome: Outcome,
    /// States visited, over every start position tried.
    pub steps: u64,
}

/// Searches `input` like `re.search` / `RegExp.prototype.exec` / `String#match`: tries each start position
/// from the left and returns the first match the engine would find there.
pub fn search(nfa: &Nfa, input: &str, max_steps: u64) -> Run {
    let chars: Vec<u32> = input.chars().map(|c| c as u32).collect();
    search_chars(nfa, &chars, max_steps)
}

pub fn search_chars(nfa: &Nfa, input: &[u32], max_steps: u64) -> Run {
    let mut m = Machine {
        nfa,
        input,
        steps: 0,
        max_steps,
        loops: vec![usize::MAX; nfa.loops],
    };
    for start in 0..=input.len() {
        match m.run(nfa.start, start, None) {
            Ok(Some(end)) => {
                return Run {
                    outcome: Outcome::Match { start, end },
                    steps: m.steps,
                };
            }
            Ok(None) => {}
            Err(StepLimit) => {
                return Run {
                    outcome: Outcome::StepLimit,
                    steps: m.steps,
                };
            }
        }
    }
    Run {
        outcome: Outcome::NoMatch,
        steps: m.steps,
    }
}

/// Like [`search`] but only from position 0 (`re.match`, a sticky regex): the work for a single attempt.
pub fn match_at_start(nfa: &Nfa, input: &str, max_steps: u64) -> Run {
    let chars: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut m = Machine {
        nfa,
        input: &chars,
        steps: 0,
        max_steps,
        loops: vec![usize::MAX; nfa.loops],
    };
    let outcome = match m.run(nfa.start, 0, None) {
        Ok(Some(end)) => Outcome::Match { start: 0, end },
        Ok(None) => Outcome::NoMatch,
        Err(StepLimit) => Outcome::StepLimit,
    };
    Run { outcome, steps: m.steps }
}

struct StepLimit;

enum Frame {
    /// A choice to come back to.
    Try(StateId, usize),
    /// Undo a loop-position record when backtracking past it.
    Restore(usize, usize),
}

struct Machine<'a> {
    nfa: &'a Nfa,
    input: &'a [u32],
    steps: u64,
    max_steps: u64,
    /// Position at which each optional loop iteration started (`usize::MAX`: none).
    loops: Vec<usize>,
}

impl Machine<'_> {
    /// Runs from `state` at `pos` until a `Match` (returning the end position) or until every choice has
    /// failed. With `end`, a `Match` only counts at exactly that position (used for lookbehind).
    fn run(&mut self, state: StateId, pos: usize, end: Option<usize>) -> Result<Option<usize>, StepLimit> {
        let mut stack = vec![Frame::Try(state, pos)];
        while let Some(frame) = stack.pop() {
            let (mut s, mut p) = match frame {
                Frame::Restore(id, old) => {
                    self.loops[id] = old;
                    continue;
                }
                Frame::Try(s, p) => (s, p),
            };
            loop {
                self.steps += 1;
                if self.steps > self.max_steps {
                    return Err(StepLimit);
                }
                match &self.nfa.states[s] {
                    State::Char { set, next } => {
                        if p < self.input.len() && set.contains(self.input[p]) {
                            p += 1;
                            s = *next;
                        } else {
                            break;
                        }
                    }
                    State::Split { first, second } => {
                        stack.push(Frame::Try(*second, p));
                        s = *first;
                    }
                    State::Assert { kind, next } => {
                        if holds(kind, self.input, p) {
                            s = *next;
                        } else {
                            break;
                        }
                    }
                    State::Look {
                        start,
                        ahead,
                        negated,
                        next,
                    } => {
                        let (start, ahead, negated, next) = (*start, *ahead, *negated, *next);
                        let found = if ahead {
                            self.run(start, p, None)?.is_some()
                        } else {
                            // A lookbehind holds if some match of its body ends exactly here.
                            let mut found = false;
                            for from in (0..=p).rev() {
                                if self.run(start, from, Some(p))?.is_some() {
                                    found = true;
                                    break;
                                }
                            }
                            found
                        };
                        if found != negated {
                            s = next;
                        } else {
                            break;
                        }
                    }
                    State::Atomic { start, next } => {
                        let (start, next) = (*start, *next);
                        match self.run(start, p, None)? {
                            Some(e) => {
                                p = e;
                                s = next;
                            }
                            None => break,
                        }
                    }
                    State::LoopEnter { id, next } => {
                        stack.push(Frame::Restore(*id, self.loops[*id]));
                        self.loops[*id] = p;
                        s = *next;
                    }
                    State::LoopCheck { id, next, exit, on_empty } => {
                        s = match (self.loops[*id] == p, on_empty) {
                            (false, _) => *next,
                            (true, OnEmpty::Exit) => *exit, // an empty iteration ends the loop (Python, Ruby)
                            (true, OnEmpty::Fail) => break, // an empty iteration fails (JavaScript)
                        };
                    }
                    State::Match => {
                        if end.is_none_or(|e| e == p) {
                            return Ok(Some(p));
                        }
                        break;
                    }
                }
            }
        }
        Ok(None)
    }
}

fn holds(kind: &Assertion, input: &[u32], p: usize) -> bool {
    let len = input.len();
    match kind {
        Assertion::TextStart => p == 0,
        Assertion::TextEnd => p == len,
        Assertion::TextEndOrFinalNewline => p == len || (p + 1 == len && input[p] == 0x0A),
        Assertion::LineStart(t) => p == 0 || t.contains(input[p - 1]),
        Assertion::LineStartNotAtEnd => p == 0 || (p < len && input[p - 1] == 0x0A),
        Assertion::LineEnd(t) => p == len || t.contains(input[p]),
        Assertion::WordBoundary {
            negated: true,
            empty_input_fails: true,
            ..
        } if len == 0 => false,
        Assertion::WordBoundary { word, negated, .. } => {
            let before = p > 0 && word.contains(input[p - 1]);
            let after = p < len && word.contains(input[p]);
            (before != after) != *negated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Dialect;
    use crate::nfa::compile;
    use crate::parser::{Flags, parse};

    fn find(p: &str, d: Dialect, input: &str) -> Option<(usize, usize)> {
        let nfa = compile(&parse(p, d, Flags::default()).unwrap()).unwrap();
        match search(&nfa, input, 10_000_000).outcome {
            Outcome::Match { start, end } => Some((start, end)),
            Outcome::NoMatch => None,
            Outcome::StepLimit => panic!("step limit"),
        }
    }

    #[test]
    fn leftmost_then_by_priority() {
        assert_eq!(find("a+", Dialect::Js, "xaaa"), Some((1, 4)), "greedy takes all");
        assert_eq!(find("a+?", Dialect::Js, "xaaa"), Some((1, 2)), "lazy takes one");
        assert_eq!(
            find("a|ab", Dialect::Js, "ab"),
            Some((0, 1)),
            "first alternative wins, not the longest"
        );
        assert_eq!(
            find("(a|ab)c", Dialect::Js, "abc"),
            Some((0, 3)),
            "backtracks into the second alternative"
        );
        assert_eq!(find("b", Dialect::Js, "aaa"), None);
        assert_eq!(find("", Dialect::Js, ""), Some((0, 0)));
    }

    #[test]
    fn anchors_and_boundaries() {
        assert_eq!(find("a$", Dialect::Js, "a\n"), None);
        assert_eq!(
            find("a$", Dialect::Python, "a\n"),
            Some((0, 1)),
            "Python's $ matches before a final newline"
        );
        assert_eq!(find("^b", Dialect::Ruby, "a\nb"), Some((2, 3)), "Ruby's ^ is per line");
        assert_eq!(find("^b", Dialect::Js, "a\nb"), None);
        assert_eq!(find("\\bb", Dialect::Js, "ab b"), Some((3, 4)));
    }

    #[test]
    fn lookaround_and_atomic() {
        assert_eq!(find("a(?=b)", Dialect::Js, "acab"), Some((2, 3)));
        assert_eq!(find("a(?!b)", Dialect::Js, "abac"), Some((2, 3)));
        assert_eq!(find("(?<=b)a", Dialect::Js, "aba"), Some((2, 3)));
        assert_eq!(find("(?<!b)a", Dialect::Js, "baa"), Some((2, 3)));
        assert_eq!(find("(?>a+)a", Dialect::Python, "aaa"), None, "an atomic group does not give back");
        assert_eq!(find("a++a", Dialect::Python, "aaa"), None, "nor does a possessive quantifier");
        assert_eq!(
            find("(?>a|ab)c", Dialect::Ruby, "abc"),
            None,
            "the atomic group keeps its first choice"
        );
        assert_eq!(
            find("(?:a|ab){2}+c", Dialect::Python, "abac"),
            None,
            "Python: each possessive iteration is atomic"
        );
        assert_eq!(
            find("(?>(?:a|ab){2})c", Dialect::Python, "abac"),
            Some((0, 4)),
            "but a whole atomic group can backtrack inside"
        );
    }

    #[test]
    fn empty_iterations_end_the_loop() {
        assert_eq!(find("(a*)*b", Dialect::Js, "aab"), Some((0, 3)));
        assert_eq!(find("(a|)*b", Dialect::Js, "aab"), Some((0, 3)));
        assert_eq!(find("(?:a?)+?b", Dialect::Js, "ab"), Some((0, 2)));
        assert_eq!(
            find("(?:|\\w)*", Dialect::Js, "ab"),
            Some((0, 2)),
            "JavaScript fails an empty iteration and tries the next branch"
        );
        assert_eq!(find("(?:|\\w)*", Dialect::Python, "ab"), Some((0, 0)), "Python ends the loop there");
        assert_eq!(
            find("(?:\\w\\w\\d|(?<=\\A)){2}", Dialect::Ruby, "Aa1"),
            Some((0, 0)),
            "Ruby checks even required iterations"
        );
        assert_eq!(find("(?:\\w\\w\\d|(?<=\\A)){2}", Dialect::Python, "Aa1"), Some((0, 3)));
    }

    #[test]
    fn a_classic_redos_doubles_its_work_with_each_character() {
        let nfa = compile(&parse("^(a+)+$", Dialect::Js, Flags::default()).unwrap()).unwrap();
        let steps = |n: usize| search(&nfa, &format!("{}!", "a".repeat(n)), u64::MAX).steps;
        let (s10, s15, s20) = (steps(10), steps(15), steps(20));
        let ratio = (s20 as f64 / s15 as f64).powf(1.0 / 5.0);
        assert!(
            (1.9..2.1).contains(&ratio),
            "work should double per character: {s10} {s15} {s20}, ratio {ratio:.3}"
        );
        let safe = compile(&parse("^a+$", Dialect::Js, Flags::default()).unwrap()).unwrap();
        let linear = search(&safe, &format!("{}!", "a".repeat(20)), u64::MAX).steps;
        assert!(linear < 10 * 21, "a single a+ is linear: {linear} steps for 21 characters");
    }

    #[test]
    fn the_step_limit_stops_the_run() {
        let nfa = compile(&parse("^(a+)+$", Dialect::Js, Flags::default()).unwrap()).unwrap();
        let run = search(&nfa, &format!("{}!", "a".repeat(40)), 100_000);
        assert_eq!(run.outcome, Outcome::StepLimit);
        assert!(run.steps <= 100_001);
    }
}
