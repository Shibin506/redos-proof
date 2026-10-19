//! The parsed form of a regex. Dialect differences are resolved by the parser: a node means the same thing
//! whichever language the pattern came from (Ruby's `^` becomes `LineStart`, JavaScript's becomes `TextStart`).

use crate::charset::CharSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// ECMAScript (Node, browsers, Deno, Bun).
    Js,
    /// Python's `re` module.
    Python,
    /// Ruby (Onigmo).
    Ruby,
}

impl Dialect {
    pub fn name(self) -> &'static str {
        match self {
            Dialect::Js => "javascript",
            Dialect::Python => "python",
            Dialect::Ruby => "ruby",
        }
    }

    pub fn parse_name(s: &str) -> Option<Dialect> {
        match s {
            "js" | "javascript" | "node" | "ts" | "typescript" => Some(Dialect::Js),
            "py" | "python" => Some(Dialect::Python),
            "rb" | "ruby" => Some(Dialect::Ruby),
            _ => None,
        }
    }
}

/// Which characters end a line, for `^`/`$` in multi-line mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineTerminators {
    /// `\n`, `\r`, U+2028, U+2029 (JavaScript).
    Js,
    /// `\n` only (Python, Ruby).
    Newline,
}

impl LineTerminators {
    pub fn contains(self, c: u32) -> bool {
        match self {
            LineTerminators::Js => matches!(c, 0x0A | 0x0D | 0x2028 | 0x2029),
            LineTerminators::Newline => c == 0x0A,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Assertion {
    /// Start of the input.
    TextStart,
    /// End of the input.
    TextEnd,
    /// End of the input, or just before a final `\n` (Python's `$`, Ruby's `\Z`).
    TextEndOrFinalNewline,
    LineStart(LineTerminators),
    /// Ruby's `^`: start of a line, but never at the very end of the input (not after a final `\n`).
    LineStartNotAtEnd,
    LineEnd(LineTerminators),
    /// `\b` / `\B`, with the engine's own idea of a word character. Python's `\B` never matches an
    /// empty input (`empty_input_fails`), a documented quirk of `re` before Python 3.14.
    WordBoundary {
        word: CharSet,
        negated: bool,
        empty_input_fails: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Node {
    /// Matches the empty string.
    Empty,
    /// One character from the set (literals, classes, `.`, `\d`... all end up here, case folding applied).
    Set(CharSet),
    Concat(Vec<Node>),
    /// Alternatives, tried in order.
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        /// `a*+`: once the loop is done it never gives anything back.
        possessive: bool,
    },
    /// A group: capturing (numbered from 1), or index 0 for `(?:...)`.
    Group {
        node: Box<Node>,
        index: u32,
    },
    Assert(Assertion),
    /// Lookahead (`ahead`) or lookbehind; `negated` for `(?!...)` / `(?<!...)`.
    Look {
        node: Box<Node>,
        ahead: bool,
        negated: bool,
    },
    /// `(?>...)`: the group matches once, as the engine would on its first try, and is never re-entered.
    Atomic(Box<Node>),
    /// `\1`, `\k<name>`: the analysis cannot model these (they make the language non-regular).
    Backref(u32),
    /// A feature the analysis does not model (named in the message), kept so the rest still parses.
    Unsupported(String),
}

impl Node {
    /// Features that make the model inexact, with a description; empty if the model is exact.
    pub fn unsupported(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(&mut |n| match n {
            Node::Backref(i) => out.push(format!("backreference \\{i}")),
            Node::Unsupported(what) => out.push(what.clone()),
            _ => {}
        });
        out
    }

    pub fn walk(&self, f: &mut impl FnMut(&Node)) {
        f(self);
        match self {
            Node::Concat(v) | Node::Alt(v) => v.iter().for_each(|n| n.walk(f)),
            Node::Repeat { node, .. } | Node::Group { node, .. } | Node::Look { node, .. } | Node::Atomic(node) => node.walk(f),
            Node::Empty | Node::Set(_) | Node::Assert(_) | Node::Backref(_) | Node::Unsupported(_) => {}
        }
    }
}

/// A parsed regex.
#[derive(Debug, Clone)]
pub struct Regex {
    pub source: String,
    pub dialect: Dialect,
    pub node: Node,
    pub groups: u32,
}
