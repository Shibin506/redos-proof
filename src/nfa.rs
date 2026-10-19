//! The automaton a backtracking engine effectively runs: states with *ordered* choices.
//!
//! A backtracking engine tries the first branch of a choice, and only comes back to the second when the
//! first fails. That order is what decides how much work it does, so `Split` keeps it (`first` before
//! `second`): `a*` is `Split(loop, exit)`, `a*?` is `Split(exit, loop)`.

use std::fmt;

use crate::ast::{Assertion, Node, Regex};
use crate::charset::CharSet;

pub type StateId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Reads one character from `set`.
    Char {
        set: CharSet,
        next: StateId,
    },
    /// Tries `first`; if everything after it fails, comes back and tries `second`.
    Split {
        first: StateId,
        second: StateId,
    },
    Assert {
        kind: Assertion,
        next: StateId,
    },
    /// Runs the sub-automaton at `start` (which ends in its own `Match`) without consuming input.
    Look {
        start: StateId,
        ahead: bool,
        negated: bool,
        next: StateId,
    },
    /// Runs the sub-automaton at `start` once, keeps its first result, and never backtracks into it.
    Atomic {
        start: StateId,
        next: StateId,
    },
    /// Start of an optional loop iteration: remembers the position.
    LoopEnter {
        id: usize,
        next: StateId,
    },
    /// End of an optional loop iteration. If the iteration consumed nothing (how engines stop `(a*)*` from
    /// looping forever), JavaScript fails it, while Python and Ruby leave the loop and continue at `exit`.
    LoopCheck {
        id: usize,
        next: StateId,
        exit: StateId,
        on_empty: OnEmpty,
    },
    Match,
}

/// What an engine does when an optional loop iteration matched the empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnEmpty {
    /// The iteration fails, and the engine backtracks (ECMAScript's RepeatMatcher).
    Fail,
    /// The loop ends there and matching continues after it (CPython's `sre`, Onigmo).
    Exit,
}

#[derive(Debug, Clone)]
pub struct Nfa {
    pub states: Vec<State>,
    pub start: StateId,
    /// Number of loop ids used by `LoopEnter` / `LoopCheck`.
    pub loops: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// The pattern uses features the model cannot represent exactly (backreferences, `\p{...}`, ...).
    Unsupported(Vec<String>),
    /// Counted repeats like `(a{1000}){1000}` expand to more states than allowed.
    TooLarge { states: usize },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::Unsupported(what) => write!(f, "not modelled: {}", what.join(", ")),
            CompileError::TooLarge { states } => write!(f, "too large to model (more than {states} states)"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Above this many states (from expanding counted repeats) the pattern is reported as too large.
pub const MAX_STATES: usize = 100_000;

/// Choices the model cannot make from the pattern alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileOptions {
    /// Ruby (Onigmo) checks for empty iterations even in the required part of a counted loop, but only when
    /// it compiles the loop as a loop: short loops are unrolled into copies (decided by the size of Onigmo's
    /// compiled code), and copies have no check. `true` models a loop, `false` unrolled copies.
    pub ruby_required_iteration_check: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            ruby_required_iteration_check: true,
        }
    }
}

pub fn compile(regex: &Regex) -> Result<Nfa, CompileError> {
    compile_with(regex, CompileOptions::default())
}

pub fn compile_with(regex: &Regex, options: CompileOptions) -> Result<Nfa, CompileError> {
    let unsupported = regex.node.unsupported();
    if !unsupported.is_empty() {
        return Err(CompileError::Unsupported(unsupported));
    }
    let on_empty = if regex.dialect == crate::ast::Dialect::Js {
        OnEmpty::Fail
    } else {
        OnEmpty::Exit
    };
    let mut b = Builder {
        states: Vec::new(),
        loops: 0,
        on_empty,
        dialect: regex.dialect,
        options,
    };
    let done = b.push(State::Match);
    let start = b.node(&regex.node, done)?;
    Ok(Nfa {
        states: b.states,
        start,
        loops: b.loops,
    })
}

struct Builder {
    states: Vec<State>,
    loops: usize,
    on_empty: OnEmpty,
    dialect: crate::ast::Dialect,
    options: CompileOptions,
}

impl Builder {
    fn push(&mut self, s: State) -> StateId {
        self.states.push(s);
        self.states.len() - 1
    }

    fn check_size(&self) -> Result<(), CompileError> {
        if self.states.len() > MAX_STATES {
            return Err(CompileError::TooLarge { states: MAX_STATES });
        }
        Ok(())
    }

    /// Compiles `node` so that it continues to `next`; returns its entry state. Built back to front.
    fn node(&mut self, node: &Node, next: StateId) -> Result<StateId, CompileError> {
        self.check_size()?;
        Ok(match node {
            Node::Empty => next,
            Node::Set(set) => self.push(State::Char { set: set.clone(), next }),
            Node::Concat(items) => {
                let mut at = next;
                for item in items.iter().rev() {
                    at = self.node(item, at)?;
                }
                at
            }
            Node::Alt(alts) => {
                let mut at = self.node(alts.last().unwrap(), next)?;
                for alt in alts.iter().rev().skip(1) {
                    let first = self.node(alt, next)?;
                    at = self.push(State::Split { first, second: at });
                }
                at
            }
            Node::Group { node, .. } => self.node(node, next)?,
            Node::Assert(kind) => self.push(State::Assert { kind: kind.clone(), next }),
            Node::Look { node, ahead, negated } => {
                let start = self.sub(node)?;
                self.push(State::Look {
                    start,
                    ahead: *ahead,
                    negated: *negated,
                    next,
                })
            }
            Node::Atomic(inner) => {
                let start = self.sub(inner)?;
                self.push(State::Atomic { start, next })
            }
            Node::Repeat {
                node: inner,
                min,
                max,
                greedy,
                possessive,
            } => {
                if *possessive {
                    // CPython makes every iteration of a possessive loop atomic as well as the loop: it never
                    // re-enters iteration 1 to let iteration 2 match, so `(?:a|ab){2}+c` fails on "abac" where
                    // `(?>(?:a|ab){2})c` matches. That only shows when `min` is 2 or more. Ruby and Java make
                    // just the whole loop atomic.
                    let body = if self.dialect == crate::ast::Dialect::Python {
                        Node::Atomic(inner.clone())
                    } else {
                        (**inner).clone()
                    };
                    let plain = Node::Repeat {
                        node: Box::new(body),
                        min: *min,
                        max: *max,
                        greedy: true,
                        possessive: false,
                    };
                    let start = self.sub(&plain)?;
                    return Ok(self.push(State::Atomic { start, next }));
                }
                self.repeat(inner, *min, *max, *greedy, next)?
            }
            Node::Backref(_) | Node::Unsupported(_) => unreachable!("rejected before compiling"),
        })
    }

    /// A separate automaton for a lookaround or atomic group, ending in its own `Match`.
    fn sub(&mut self, node: &Node) -> Result<StateId, CompileError> {
        let done = self.push(State::Match);
        self.node(node, done)
    }

    fn repeat(&mut self, inner: &Node, min: u32, max: Option<u32>, greedy: bool, next: StateId) -> Result<StateId, CompileError> {
        let id = self.loops;
        self.loops += 1;
        // The optional part first (built back to front), then `min` mandatory copies in front of it.
        let mut at = match max {
            None => {
                // L: Split(enter -> body -> check -> L, next)
                let split = self.push(State::Split { first: next, second: next });
                let check = self.push(State::LoopCheck {
                    id,
                    next: split,
                    exit: next,
                    on_empty: self.on_empty,
                });
                let body = self.node(inner, check)?;
                let enter = self.push(State::LoopEnter { id, next: body });
                self.states[split] = if greedy {
                    State::Split {
                        first: enter,
                        second: next,
                    }
                } else {
                    State::Split {
                        first: next,
                        second: enter,
                    }
                };
                split
            }
            Some(max) => {
                let mut at = next;
                for _ in min..max {
                    let check = self.push(State::LoopCheck {
                        id,
                        next: at,
                        exit: next,
                        on_empty: self.on_empty,
                    });
                    let body = self.node(inner, check)?;
                    let enter = self.push(State::LoopEnter { id, next: body });
                    at = self.push(if greedy {
                        State::Split {
                            first: enter,
                            second: next,
                        }
                    } else {
                        State::Split {
                            first: next,
                            second: enter,
                        }
                    });
                    self.check_size()?;
                }
                at
            }
        };
        for _ in 0..min {
            if self.dialect == crate::ast::Dialect::Ruby && self.options.ruby_required_iteration_check {
                // Onigmo checks for empty iterations even below the minimum: once a required iteration of
                // `x{2}` matches nothing, the loop counts as done (`(?:\w\w\d|(?<=\A)){2}` matches "" in
                // "Aa1", where Python and JavaScript match "Aa1").
                let check = self.push(State::LoopCheck {
                    id,
                    next: at,
                    exit: next,
                    on_empty: OnEmpty::Exit,
                });
                let body = self.node(inner, check)?;
                at = self.push(State::LoopEnter { id, next: body });
            } else {
                at = self.node(inner, at)?;
            }
        }
        Ok(at)
    }
}

impl fmt::Display for Nfa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "start: {}", self.start)?;
        for (i, s) in self.states.iter().enumerate() {
            writeln!(f, "{i:4}: {s:?}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Dialect;
    use crate::parser::{Flags, parse};

    fn nfa(p: &str) -> Result<Nfa, CompileError> {
        compile(&parse(p, Dialect::Js, Flags::default()).unwrap())
    }

    #[test]
    fn greedy_and_lazy_loops_order_their_choices() {
        let greedy = nfa("a*").unwrap();
        let State::Split { first, .. } = &greedy.states[greedy.start] else {
            panic!("{greedy}")
        };
        assert!(
            matches!(greedy.states[*first], State::LoopEnter { .. }),
            "greedy: enter the loop first"
        );
        let lazy = nfa("a*?").unwrap();
        let State::Split { first, .. } = &lazy.states[lazy.start] else {
            panic!("{lazy}")
        };
        assert!(matches!(lazy.states[*first], State::Match), "lazy: leave first");
    }

    #[test]
    fn counted_repeats_expand_and_are_bounded() {
        let n = nfa("a{3,5}").unwrap();
        assert_eq!(n.states.iter().filter(|s| matches!(s, State::Char { .. })).count(), 5);
        assert!(matches!(nfa("(a{1000}){1000}"), Err(CompileError::TooLarge { .. })));
    }

    #[test]
    fn unmodelled_features_are_refused() {
        assert!(matches!(nfa("(a)\\1"), Err(CompileError::Unsupported(_))));
    }
}
