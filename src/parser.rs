//! Parses JavaScript, Python and Ruby regex syntax into [`Node`]s.
//!
//! Where the three disagree the parser follows each engine, and the differences are checked against the real
//! engines in `tests/engines.rs`. The ones that change what a pattern matches:
//!
//! | | JavaScript | Python | Ruby |
//! |---|---|---|---|
//! | `^` / `$` | whole input (lines with `m`) | whole input; `$` also before a final `\n` (lines with `m`) | always lines |
//! | `.` | not `\n \r U+2028 U+2029` (all with `s`) | not `\n` (all with `s`) | not `\n` (all with `m`) |
//! | `\w` `\d` | ASCII | Unicode | ASCII |
//! | `\s` | Unicode | Unicode (plus `\x1c`-`\x1f`) | ASCII |
//! | `x{,3}` | literal text | `x{0,3}` | `x{0,3}` |

use std::collections::HashMap;
use std::fmt;

use crate::ast::{Assertion, Dialect, LineTerminators, Node, Regex};
use crate::charset::CharSet;
use crate::{folds, tables};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Character offset in the pattern.
    pub pos: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at {}: {}", self.pos, self.message)
    }
}

impl std::error::Error for ParseError {}

/// The flags that change matching. Written the way each language writes them (`"im"`, `"s"`, `"x"`...).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub ignore_case: bool,
    /// `^`/`$` match at line boundaries (JavaScript and Python `m`; always on in Ruby).
    pub multiline: bool,
    /// `.` matches newlines too (JavaScript and Python `s`, Ruby `m`).
    pub dot_all: bool,
    /// Whitespace and `#` comments in the pattern are ignored (Python and Ruby `x`).
    pub extended: bool,
    /// JavaScript `u`/`v`: stricter syntax, `\u{...}` escapes.
    pub unicode: bool,
    /// Python `a`: `\w`, `\d`, `\s` and `\b` are ASCII-only.
    pub ascii: bool,
}

impl Flags {
    /// Reads a flag string in the dialect's own letters. Flags that do not change matching (`g`, `y`, `d`) are accepted.
    pub fn parse(dialect: Dialect, letters: &str) -> Result<Flags, ParseError> {
        let mut f = Flags::default();
        for c in letters.chars() {
            f.set(dialect, c, true).map_err(|message| ParseError { pos: 0, message })?;
        }
        Ok(f)
    }

    fn set(&mut self, dialect: Dialect, c: char, on: bool) -> Result<(), String> {
        match (dialect, c) {
            (_, 'i') => self.ignore_case = on,
            (Dialect::Js | Dialect::Python, 'm') => self.multiline = on,
            (Dialect::Js | Dialect::Python, 's') => self.dot_all = on,
            (Dialect::Ruby, 'm') => self.dot_all = on,
            (Dialect::Python | Dialect::Ruby, 'x') => self.extended = on,
            (Dialect::Js, 'u' | 'v') => self.unicode = on,
            (Dialect::Js, 'g' | 'y' | 'd') => {}
            (Dialect::Python, 'a') => self.ascii = on,
            (Dialect::Python, 'u' | 'L') => {}
            (Dialect::Ruby, 'o' | 'n' | 'e' | 's' | 'u') => {}
            _ => return Err(format!("unknown flag '{c}' for {}", dialect.name())),
        }
        Ok(())
    }
}

/// Parses `pattern` (the text between the slashes, or the string given to `re.compile`) in `dialect`.
pub fn parse(pattern: &str, dialect: Dialect, flags: Flags) -> Result<Regex, ParseError> {
    let mut p = Parser {
        chars: pattern.chars().collect(),
        pos: 0,
        dialect,
        flags,
        groups: 0,
        names: HashMap::new(),
        pending_named_backrefs: Vec::new(),
    };
    let node = p.alternation()?;
    if p.pos < p.chars.len() {
        return Err(p.error(if p.peek() == Some(')') {
            "unmatched ')'"
        } else {
            "unexpected character"
        }));
    }
    for (name, at) in std::mem::take(&mut p.pending_named_backrefs) {
        if !p.names.contains_key(&name) {
            return Err(ParseError {
                pos: at,
                message: format!("no group named '{name}'"),
            });
        }
    }
    Ok(Regex {
        source: pattern.to_string(),
        dialect,
        node,
        groups: p.groups,
    })
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    dialect: Dialect,
    flags: Flags,
    groups: u32,
    names: HashMap<String, u32>,
    pending_named_backrefs: Vec<(String, usize)>,
}

/// One item inside `[...]`: a single character (can start a range) or a whole class like `\d`.
enum ClassItem {
    Char(u32),
    Set(CharSet),
}

impl Parser {
    fn error(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            pos: self.pos,
            message: message.into(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_str(&mut self, s: &str) -> bool {
        let n = s.chars().count();
        if self.chars[self.pos..].iter().take(n).copied().eq(s.chars()) {
            self.pos += n;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Result<char, ParseError> {
        let c = self.peek().ok_or_else(|| self.error("unexpected end of pattern"))?;
        self.pos += 1;
        Ok(c)
    }

    /// In extended mode, skips whitespace and `#` comments between tokens.
    fn skip_extended(&mut self) {
        if !self.flags.extended {
            return;
        }
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => self.pos += 1,
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn alternation(&mut self) -> Result<Node, ParseError> {
        let mut alts = vec![self.concat()?];
        while self.eat('|') {
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap() } else { Node::Alt(alts) })
    }

    fn concat(&mut self) -> Result<Node, ParseError> {
        let mut items = Vec::new();
        loop {
            self.skip_extended();
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => {}
            }
            let Some(atom) = self.atom()? else {
                continue; // a flag change like `(?i)` or a comment: no node
            };
            let node = self.quantifier(atom)?;
            items.push(node);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap(),
            _ => Node::Concat(items),
        })
    }

    fn quantifier(&mut self, atom: Node) -> Result<Node, ParseError> {
        let mut node = atom;
        loop {
            self.skip_extended();
            let start = self.pos;
            let (min, max) = match self.peek() {
                Some('*') => {
                    self.pos += 1;
                    (0, None)
                }
                Some('+') => {
                    self.pos += 1;
                    (1, None)
                }
                Some('?') => {
                    self.pos += 1;
                    (0, Some(1))
                }
                Some('{') => match self.braces()? {
                    Some(b) => b,
                    None => return Ok(node), // not a quantifier: `{` is literal, parsed as the next atom
                },
                _ => return Ok(node),
            };
            if matches!(node, Node::Assert(_)) && self.dialect != Dialect::Ruby {
                // JavaScript (with `u`) and Python reject quantified anchors; Ruby accepts them.
                if self.dialect == Dialect::Python || self.flags.unicode {
                    return Err(ParseError {
                        pos: start,
                        message: "nothing to repeat".into(),
                    });
                }
            }
            if matches!(node, Node::Empty) && start == 0 {
                return Err(ParseError {
                    pos: start,
                    message: "nothing to repeat".into(),
                });
            }
            // Ruby (Onigmo) reads a `?` or `+` after `{n}` / `{n,m}` as a second quantifier, not as lazy or
            // possessive: `a{2}?` is "optionally two a's", `a{2}+` is "one or more pairs". Except that
            // `{n,m}?` with a range is lazy. Elsewhere `?` makes any quantifier lazy and `+` possessive.
            let ruby_brace = self.dialect == Dialect::Ruby && self.chars[start] == '{';
            let greedy = if ruby_brace && max == Some(min) { true } else { !self.eat('?') };
            let possessive = greedy && self.dialect != Dialect::Js && !ruby_brace && self.eat('+');
            if let Some(m) = max
                && m < min
            {
                return Err(ParseError {
                    pos: start,
                    message: "numbers out of order in {} quantifier".into(),
                });
            }
            if matches!(node, Node::Repeat { .. }) && self.dialect != Dialect::Ruby {
                // Only Ruby allows stacking quantifiers (`a**`). The `?` of a lazy `a*?` was consumed above.
                return Err(ParseError {
                    pos: start,
                    message: "multiple repeat".into(),
                });
            }
            node = Node::Repeat {
                node: Box::new(node),
                min,
                max,
                greedy,
                possessive,
            };
        }
    }

    /// `{n}`, `{n,}`, `{n,m}` and (Python, Ruby) `{,m}`. Returns `None`, consuming nothing, if this `{` is
    /// not a quantifier (it is then a literal `{`, except in JavaScript's `u` mode, where it is an error).
    fn braces(&mut self) -> Result<Option<(u32, Option<u32>)>, ParseError> {
        let start = self.pos;
        self.pos += 1;
        let num = |p: &mut Parser| -> Option<u32> {
            let s = p.pos;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.pos += 1;
            }
            (p.pos > s).then(|| p.chars[s..p.pos].iter().collect::<String>().parse().unwrap_or(u32::MAX))
        };
        let min = num(self);
        let result = if self.eat('}') {
            min.map(|m| (m, Some(m)))
        } else if self.eat(',') {
            let max = num(self);
            if self.eat('}') {
                match (min, max) {
                    (Some(a), b) => Some((a, b)),
                    (None, Some(b)) if self.dialect != Dialect::Js => Some((0, Some(b))),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        if result.is_none() {
            self.pos = start;
            if self.dialect == Dialect::Js && self.flags.unicode {
                return Err(self.error("incomplete quantifier"));
            }
        }
        Ok(result)
    }

    /// One atom, or `None` for something that produces no node (`(?i)`, `(?#...)`).
    fn atom(&mut self) -> Result<Option<Node>, ParseError> {
        let c = self.next()?;
        let node = match c {
            '.' => Node::Set(self.dot()),
            '^' => Node::Assert(match (self.dialect, self.flags.multiline) {
                // Ruby's `^` never matches at the very end of the input, even after a final newline.
                (Dialect::Ruby, _) => Assertion::LineStartNotAtEnd,
                (_, true) => Assertion::LineStart(self.terminators()),
                _ => Assertion::TextStart,
            }),
            '$' => Node::Assert(match (self.dialect, self.flags.multiline) {
                (Dialect::Ruby, _) | (_, true) => Assertion::LineEnd(self.terminators()),
                (Dialect::Python, false) => Assertion::TextEndOrFinalNewline,
                (Dialect::Js, false) => Assertion::TextEnd,
            }),
            '[' => Node::Set(self.class()?),
            '(' => return self.group(),
            '\\' => self.escape()?,
            '*' | '+' | '?' => {
                return Err(ParseError {
                    pos: self.pos - 1,
                    message: "nothing to repeat".into(),
                });
            }
            '{' if self.dialect == Dialect::Js && self.flags.unicode => return Err(self.error("lone '{' in u mode")),
            '}' | ']' if self.dialect == Dialect::Js && self.flags.unicode => return Err(self.error(format!("lone '{c}' in u mode"))),
            c => self.literal(c as u32),
        };
        Ok(Some(node))
    }

    fn terminators(&self) -> LineTerminators {
        if self.dialect == Dialect::Js {
            LineTerminators::Js
        } else {
            LineTerminators::Newline
        }
    }

    fn literal(&self, c: u32) -> Node {
        Node::Set(self.fold(CharSet::single(c)))
    }

    fn fold(&self, set: CharSet) -> CharSet {
        if !self.flags.ignore_case {
            return set;
        }
        set.case_fold(match self.dialect {
            Dialect::Js if self.flags.unicode => folds::FOLD_JS_UNICODE,
            Dialect::Js => folds::FOLD_JS_LEGACY,
            Dialect::Python => folds::FOLD_PY,
            Dialect::Ruby => folds::FOLD_RB,
        })
    }

    /// What `\b` counts as a word character. Ruby differs from its own `\w` here: `\w` is ASCII, but `\b`
    /// uses Unicode word characters (`"é" =~ /\b/` matches).
    fn boundary_word(&self) -> CharSet {
        match self.dialect {
            Dialect::Ruby => CharSet::from_ranges(tables::RB_BOUNDARY_WORD.iter().copied()),
            _ => self.word(),
        }
    }

    fn dot(&self) -> CharSet {
        if self.flags.dot_all {
            return CharSet::any();
        }
        match self.dialect {
            Dialect::Js => CharSet::from_ranges([(0x0A, 0x0A), (0x0D, 0x0D), (0x2028, 0x2029)]).negate(),
            Dialect::Python | Dialect::Ruby => CharSet::single(0x0A).negate(),
        }
    }

    fn word(&self) -> CharSet {
        match self.dialect {
            Dialect::Python if !self.flags.ascii => CharSet::from_ranges(tables::PY_WORD.iter().copied()),
            _ => CharSet::from_ranges([(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)]),
        }
    }

    fn digit(&self) -> CharSet {
        match self.dialect {
            Dialect::Python if !self.flags.ascii => CharSet::from_ranges(tables::PY_DIGIT.iter().copied()),
            _ => CharSet::range(0x30, 0x39),
        }
    }

    fn space(&self) -> CharSet {
        match self.dialect {
            Dialect::Python if !self.flags.ascii => CharSet::from_ranges(tables::PY_SPACE.iter().copied()),
            Dialect::Python => CharSet::from_ranges([(0x09, 0x0D), (0x20, 0x20)]),
            Dialect::Js => CharSet::from_ranges(tables::JS_SPACE.iter().copied()),
            Dialect::Ruby => CharSet::from_ranges([(0x09, 0x0D), (0x20, 0x20)]),
        }
    }

    /// `\d \D \w \W \s \S`, if `c` is one of them (shared by escapes inside and outside classes).
    fn class_escape(&self, c: char) -> Option<CharSet> {
        Some(match c {
            'd' => self.digit(),
            'D' => self.digit().negate(),
            'w' => self.word(),
            'W' => self.word().negate(),
            's' => self.space(),
            'S' => self.space().negate(),
            'h' if self.dialect == Dialect::Ruby => CharSet::from_ranges([(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)]),
            'H' if self.dialect == Dialect::Ruby => CharSet::from_ranges([(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)]).negate(),
            _ => return None,
        })
    }

    fn escape(&mut self) -> Result<Node, ParseError> {
        let at = self.pos - 1;
        let c = self.next().map_err(|_| ParseError {
            pos: at,
            message: "pattern ends with '\\'".into(),
        })?;
        if let Some(set) = self.class_escape(c) {
            // Case folding cannot change \d \w \s in these engines' ASCII forms; folding the Unicode ones is a no-op.
            return Ok(Node::Set(set));
        }
        Ok(match c {
            'b' => Node::Assert(Assertion::WordBoundary {
                word: self.boundary_word(),
                negated: false,
                empty_input_fails: false,
            }),
            'B' => Node::Assert(Assertion::WordBoundary {
                word: self.boundary_word(),
                negated: true,
                empty_input_fails: self.dialect == Dialect::Python,
            }),
            'A' if self.dialect != Dialect::Js => Node::Assert(Assertion::TextStart),
            'z' if self.dialect == Dialect::Ruby => Node::Assert(Assertion::TextEnd),
            'Z' if self.dialect == Dialect::Python => Node::Assert(Assertion::TextEnd),
            'Z' if self.dialect == Dialect::Ruby => Node::Assert(Assertion::TextEndOrFinalNewline),
            'G' if self.dialect == Dialect::Ruby => Node::Unsupported("\\G".into()),
            '1'..='9' => {
                // A backreference, if that many groups can exist; in JavaScript (without `u`) otherwise an octal escape.
                self.pos -= 1;
                let start = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
                let digits: String = self.chars[start..self.pos].iter().collect();
                let n: u32 = digits.parse().unwrap_or(u32::MAX);
                if self.dialect == Dialect::Python && digits.len() >= 3 && digits.chars().take(3).all(|d| d < '8') {
                    self.pos = start + 3;
                    return Ok(self.literal(u32::from_str_radix(&digits[..3], 8).unwrap()));
                }
                if self.dialect == Dialect::Js && !self.flags.unicode && n > self.count_groups() {
                    self.pos = start;
                    return Ok(self.legacy_octal());
                }
                Node::Backref(n)
            }
            'k' if self.peek() == Some('<') || (self.dialect == Dialect::Ruby && self.peek() == Some('\'')) => {
                let close = if self.next()? == '<' { '>' } else { '\'' };
                let start = self.pos;
                let name = self.name_until(close)?;
                if let Ok(n) = name.parse::<u32>() {
                    return Ok(Node::Backref(n));
                }
                self.pending_named_backrefs.push((name.clone(), start));
                Node::Backref(self.names.get(&name).copied().unwrap_or(0))
            }
            'p' | 'P' if self.dialect != Dialect::Python && (self.dialect == Dialect::Ruby || self.flags.unicode) => {
                let start = self.pos - 2;
                if self.eat('{') {
                    while self.peek().is_some_and(|c| c != '}') {
                        self.pos += 1;
                    }
                    self.eat('}');
                }
                Node::Unsupported(format!(
                    "Unicode property {}",
                    self.chars[start..self.pos].iter().collect::<String>()
                ))
            }
            _ => {
                let c = self.char_escape(c)?;
                self.literal(c)
            }
        })
    }

    /// The number of capturing groups in the whole pattern (JavaScript decides `\12` by it).
    fn count_groups(&self) -> u32 {
        let mut n = 0;
        let mut i = 0;
        let mut in_class = false;
        while i < self.chars.len() {
            match self.chars[i] {
                '\\' => i += 1,
                '[' => in_class = true,
                ']' => in_class = false,
                '(' if !in_class => {
                    let rest: String = self.chars[i + 1..].iter().take(3).collect();
                    if !rest.starts_with('?') || (rest.starts_with("?<") && !rest.starts_with("?<=") && !rest.starts_with("?<!")) {
                        n += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        n
    }

    /// JavaScript's legacy octal escape (`\12` with fewer than 12 groups): up to three octal digits.
    fn legacy_octal(&mut self) -> Node {
        let start = self.pos;
        let mut v = 0u32;
        while self.pos - start < 3 && self.peek().is_some_and(|c| ('0'..='7').contains(&c)) && v * 8 + 7 <= 0o377 + 7 {
            let d = self.peek().unwrap() as u32 - '0' as u32;
            if v * 8 + d > 0o377 {
                break;
            }
            v = v * 8 + d;
            self.pos += 1;
        }
        if self.pos == start {
            // `\8`, `\9`: an identity escape.
            let c = self.chars[self.pos];
            self.pos += 1;
            return self.literal(c as u32);
        }
        self.literal(v)
    }

    /// A single-character escape (`\n`, `\x41`, `\u{1F600}`, `\.`...), returning the code point.
    fn char_escape(&mut self, c: char) -> Result<u32, ParseError> {
        Ok(match c {
            'n' => 0x0A,
            't' => 0x09,
            'r' => 0x0D,
            'f' => 0x0C,
            'v' => 0x0B,
            'a' if self.dialect != Dialect::Js => 0x07,
            'e' if self.dialect == Dialect::Ruby => 0x1B,
            '0' => {
                if self.dialect == Dialect::Js && self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    if self.flags.unicode {
                        return Err(self.error("invalid decimal escape"));
                    }
                    self.pos -= 1;
                    return match self.legacy_octal() {
                        Node::Set(s) => Ok(s.ranges()[0].0),
                        _ => unreachable!(),
                    };
                }
                let mut v = 0;
                let mut n = 0;
                while n < 2 && self.dialect != Dialect::Js && self.peek().is_some_and(|c| ('0'..='7').contains(&c)) {
                    v = v * 8 + (self.next()? as u32 - '0' as u32);
                    n += 1;
                }
                v
            }
            'x' => {
                if self.dialect == Dialect::Ruby && self.peek() == Some('{') {
                    return self.braced_hex();
                }
                match self.hex(2) {
                    Some(v) => v,
                    None if self.dialect == Dialect::Js && !self.flags.unicode => 'x' as u32,
                    None if self.dialect == Dialect::Ruby => self.hex(1).ok_or_else(|| self.error("invalid hex escape"))?,
                    None => return Err(self.error("incomplete \\x escape")),
                }
            }
            'u' => {
                if (self.dialect == Dialect::Ruby || (self.dialect == Dialect::Js && self.flags.unicode)) && self.peek() == Some('{') {
                    return self.braced_hex();
                }
                match self.hex(4) {
                    Some(v) if self.dialect == Dialect::Js && (0xD800..0xDC00).contains(&v) && self.flags.unicode => {
                        // A surrogate pair written as two escapes.
                        let save = self.pos;
                        if self.eat_str("\\u")
                            && let Some(lo) = self.hex(4)
                            && (0xDC00..0xE000).contains(&lo)
                        {
                            return Ok(0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00));
                        }
                        self.pos = save;
                        v
                    }
                    Some(v) => v,
                    None if self.dialect == Dialect::Js && !self.flags.unicode => 'u' as u32,
                    None => return Err(self.error("incomplete \\u escape")),
                }
            }
            'U' if self.dialect == Dialect::Python => self.hex(8).ok_or_else(|| self.error("incomplete \\U escape"))?,
            'N' if self.dialect == Dialect::Python && self.peek() == Some('{') => {
                return Err(self.error("\\N{name} escapes are not supported"));
            }
            'c' if self.dialect != Dialect::Python => match self.peek() {
                Some(l) if l.is_ascii_alphabetic() => {
                    self.pos += 1;
                    l as u32 % 32
                }
                _ if self.dialect == Dialect::Js && !self.flags.unicode => {
                    self.pos -= 1;
                    '\\' as u32
                }
                _ => return Err(self.error("invalid control escape")),
            },
            c if c.is_ascii_alphanumeric() => {
                // Unknown letter escapes: JavaScript (without u) and Ruby take the letter itself; Python rejects them.
                if self.dialect == Dialect::Python || (self.dialect == Dialect::Js && self.flags.unicode) {
                    return Err(ParseError {
                        pos: self.pos - 2,
                        message: format!("bad escape \\{c}"),
                    });
                }
                c as u32
            }
            c => c as u32,
        })
    }

    fn hex(&mut self, digits: usize) -> Option<u32> {
        let s: String = self.chars.get(self.pos..self.pos + digits)?.iter().collect();
        if s.len() != digits || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let v = u32::from_str_radix(&s, 16).ok()?;
        self.pos += digits;
        (v <= crate::charset::MAX).then_some(v)
    }

    fn braced_hex(&mut self) -> Result<u32, ParseError> {
        self.pos += 1; // '{'
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            self.pos += 1;
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        if s.is_empty() || !self.eat('}') {
            return Err(self.error("invalid \\u{...} escape"));
        }
        u32::from_str_radix(&s, 16)
            .ok()
            .filter(|&v| v <= crate::charset::MAX)
            .ok_or_else(|| self.error("code point out of range"))
    }

    fn name_until(&mut self, close: char) -> Result<String, ParseError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c != close) {
            self.pos += 1;
        }
        let name: String = self.chars[start..self.pos].iter().collect();
        if !self.eat(close) || name.is_empty() {
            return Err(self.error("bad group name"));
        }
        Ok(name)
    }

    fn group(&mut self) -> Result<Option<Node>, ParseError> {
        let open = self.pos - 1;
        if !self.eat('?') {
            return Ok(Some(self.capture(None)?));
        }
        let kind = self.peek().ok_or_else(|| self.error("unexpected end after '(?'"))?;
        let node = match kind {
            ':' => {
                self.pos += 1;
                // Kept as a group (index 0: not capturing) so that `(?:a?)+` is not mistaken for a stacked `a?+`.
                Node::Group {
                    node: Box::new(self.close_group(open)?),
                    index: 0,
                }
            }
            '=' | '!' => {
                self.pos += 1;
                let inner = self.close_group(open)?;
                Node::Look {
                    node: Box::new(inner),
                    ahead: true,
                    negated: kind == '!',
                }
            }
            '<' if matches!(self.peek_at(1), Some('=') | Some('!')) => {
                let negated = self.peek_at(1) == Some('!');
                self.pos += 2;
                let inner = self.close_group(open)?;
                Node::Look {
                    node: Box::new(inner),
                    ahead: false,
                    negated,
                }
            }
            '<' | '\'' if kind == '<' || self.dialect == Dialect::Ruby => {
                self.pos += 1;
                let name = self.name_until(if kind == '<' { '>' } else { '\'' })?;
                self.capture(Some(name))?
            }
            'P' if self.dialect == Dialect::Python && self.peek_at(1) == Some('<') => {
                self.pos += 2;
                let name = self.name_until('>')?;
                self.capture(Some(name))?
            }
            'P' if self.dialect == Dialect::Python && self.peek_at(1) == Some('=') => {
                self.pos += 2;
                let name = self.name_until(')')?;
                match self.names.get(&name) {
                    Some(&n) => Node::Backref(n),
                    None => {
                        return Err(ParseError {
                            pos: open,
                            message: format!("unknown group name '{name}'"),
                        });
                    }
                }
            }
            '>' if self.dialect != Dialect::Js => {
                self.pos += 1;
                let inner = self.close_group(open)?;
                Node::Atomic(Box::new(inner))
            }
            '#' if self.dialect != Dialect::Js => {
                while self.peek().is_some_and(|c| c != ')') {
                    self.pos += 1;
                }
                if !self.eat(')') {
                    return Err(self.error("missing ')' after comment"));
                }
                return Ok(None);
            }
            '(' if self.dialect != Dialect::Js => {
                return Ok(Some(Node::Unsupported("conditional group (?(...)...)".into())));
            }
            _ => return self.flag_group(open),
        };
        Ok(Some(node))
    }

    /// `(?i)`, `(?i-m)`, `(?i:...)`, `(?-i:...)`.
    fn flag_group(&mut self, open: usize) -> Result<Option<Node>, ParseError> {
        let mut on = true;
        let mut flags = self.flags;
        loop {
            match self.next()? {
                '-' => on = false,
                ':' => {
                    let saved = std::mem::replace(&mut self.flags, flags);
                    let inner = self.close_group(open);
                    self.flags = saved;
                    return inner.map(|n| {
                        Some(Node::Group {
                            node: Box::new(n),
                            index: 0,
                        })
                    });
                }
                ')' => {
                    if self.dialect == Dialect::Js {
                        return Err(ParseError {
                            pos: open,
                            message: "invalid group".into(),
                        });
                    }
                    if self.dialect == Dialect::Python && open != 0 {
                        return Err(ParseError {
                            pos: open,
                            message: "global flags not at the start of the expression".into(),
                        });
                    }
                    // Ruby: applies to the rest of the enclosing group. Python: to the whole pattern (it is at the start).
                    self.flags = flags;
                    return Ok(None);
                }
                c => flags.set(self.dialect, c, on).map_err(|m| ParseError {
                    pos: self.pos - 1,
                    message: m,
                })?,
            }
        }
    }

    fn capture(&mut self, name: Option<String>) -> Result<Node, ParseError> {
        self.groups += 1;
        let index = self.groups;
        if let Some(name) = name
            && self.names.insert(name.clone(), index).is_some()
            && self.dialect != Dialect::Ruby
        {
            return Err(self.error(format!("duplicate group name '{name}'")));
        }
        let open = self.pos;
        let inner = self.close_group(open)?;
        Ok(Node::Group {
            node: Box::new(inner),
            index,
        })
    }

    /// Parses the inside of a group up to its `)`. Flag changes made inside (Ruby's `(?i)`) end with the group.
    fn close_group(&mut self, open: usize) -> Result<Node, ParseError> {
        let saved = self.flags;
        let inner = self.alternation()?;
        self.flags = saved;
        if !self.eat(')') {
            return Err(ParseError {
                pos: open,
                message: "missing ')'".into(),
            });
        }
        Ok(inner)
    }

    /// `[...]`: returns the set, case folding applied before any negation.
    fn class(&mut self) -> Result<CharSet, ParseError> {
        let open = self.pos - 1;
        let negated = self.eat('^');
        let mut set = CharSet::empty();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return Err(ParseError {
                    pos: open,
                    message: "unterminated character set".into(),
                });
            };
            if c == ']' && !(first && self.dialect != Dialect::Js) {
                self.pos += 1;
                break;
            }
            first = false;
            if self.dialect == Dialect::Ruby && self.eat_str("&&") {
                // Ruby intersection: [a-z&&[^aeiou]]. The rest of the class is the right-hand side.
                let rest = self.class_rest(open)?;
                let set = set.intersect(&rest);
                return Ok(self.finish_class(set, negated));
            }
            if c == '[' && self.dialect == Dialect::Ruby {
                if let Some(posix) = self.posix_class()? {
                    set = set.union(&posix);
                    continue;
                }
                self.pos += 1;
                let nested = self.class()?;
                set = set.union(&nested);
                continue;
            }
            let item = self.class_item()?;
            let lo = match item {
                ClassItem::Set(s) => {
                    set = set.union(&s);
                    continue;
                }
                ClassItem::Char(lo) => lo,
            };
            if self.peek() == Some('-') && self.peek_at(1).is_some_and(|c| c != ']') {
                let dash = self.pos;
                self.pos += 1;
                match self.class_item()? {
                    ClassItem::Char(hi) => {
                        if hi < lo {
                            return Err(ParseError {
                                pos: dash,
                                message: "bad character range".into(),
                            });
                        }
                        set = set.union(&CharSet::range(lo, hi));
                    }
                    ClassItem::Set(s) => {
                        if self.dialect == Dialect::Python || self.flags.unicode {
                            return Err(ParseError {
                                pos: dash,
                                message: "bad character range".into(),
                            });
                        }
                        set = set.union(&CharSet::single(lo)).union(&CharSet::single('-' as u32)).union(&s);
                    }
                }
            } else {
                set = set.union(&CharSet::single(lo));
            }
        }
        Ok(self.finish_class(set, negated))
    }

    /// The right-hand side of a Ruby `&&`, up to the closing `]` of the enclosing class.
    fn class_rest(&mut self, open: usize) -> Result<CharSet, ParseError> {
        let mut depth_set = CharSet::empty();
        loop {
            match self.peek() {
                None => {
                    return Err(ParseError {
                        pos: open,
                        message: "unterminated character set".into(),
                    });
                }
                Some(']') => {
                    self.pos += 1;
                    return Ok(depth_set);
                }
                Some('[') => {
                    if let Some(posix) = self.posix_class()? {
                        depth_set = depth_set.union(&posix);
                    } else {
                        self.pos += 1;
                        depth_set = depth_set.union(&self.class()?);
                    }
                }
                Some(_) => match self.class_item()? {
                    ClassItem::Set(s) => depth_set = depth_set.union(&s),
                    ClassItem::Char(lo) => {
                        if self.peek() == Some('-') && self.peek_at(1).is_some_and(|c| c != ']') {
                            self.pos += 1;
                            if let ClassItem::Char(hi) = self.class_item()? {
                                depth_set = depth_set.union(&CharSet::range(lo, hi));
                            }
                        } else {
                            depth_set = depth_set.union(&CharSet::single(lo));
                        }
                    }
                },
            }
        }
    }

    fn finish_class(&self, set: CharSet, negated: bool) -> CharSet {
        let set = self.fold(set);
        if negated { set.negate() } else { set }
    }

    /// Ruby's `[:alpha:]` (inside a class), or `None` if this `[` does not start one.
    fn posix_class(&mut self) -> Result<Option<CharSet>, ParseError> {
        let rest: String = self.chars[self.pos..].iter().take(12).collect();
        let Some(body) = rest.strip_prefix("[:") else { return Ok(None) };
        let Some(end) = body.find(":]") else { return Ok(None) };
        let (negated, name) = match body[..end].strip_prefix('^') {
            Some(n) => (true, n),
            None => (false, &body[..end]),
        };
        let table: &[(u32, u32)] = match name {
            "alpha" => tables::RB_POSIX_ALPHA,
            "alnum" => tables::RB_POSIX_ALNUM,
            "digit" => tables::RB_POSIX_DIGIT,
            "upper" => tables::RB_POSIX_UPPER,
            "lower" => tables::RB_POSIX_LOWER,
            "space" => tables::RB_POSIX_SPACE,
            "punct" => tables::RB_POSIX_PUNCT,
            "word" => tables::RB_POSIX_WORD,
            "xdigit" => tables::RB_POSIX_XDIGIT,
            "cntrl" => tables::RB_POSIX_CNTRL,
            "graph" => tables::RB_POSIX_GRAPH,
            "print" => tables::RB_POSIX_PRINT,
            "blank" => tables::RB_POSIX_BLANK,
            "ascii" => &[(0, 0x7F)],
            _ => return Err(self.error(format!("unknown POSIX class [:{name}:]"))),
        };
        self.pos += 2 + end + 2;
        let set = CharSet::from_ranges(table.iter().copied());
        Ok(Some(if negated { set.negate() } else { set }))
    }

    fn class_item(&mut self) -> Result<ClassItem, ParseError> {
        let c = self.next()?;
        if c != '\\' {
            return Ok(ClassItem::Char(c as u32));
        }
        let e = self.next().map_err(|_| self.error("unterminated character set"))?;
        if let Some(set) = self.class_escape(e) {
            return Ok(ClassItem::Set(set));
        }
        Ok(ClassItem::Char(match e {
            'b' => 0x08, // backspace inside a class
            '-' => '-' as u32,
            'p' | 'P' if self.dialect == Dialect::Ruby || (self.dialect == Dialect::Js && self.flags.unicode) => {
                return Err(self.error("Unicode properties are not supported"));
            }
            '1'..='9' if self.dialect != Dialect::Js || !self.flags.unicode => {
                self.pos -= 1;
                let start = self.pos;
                let mut v = 0u32;
                while self.pos - start < 3 && self.peek().is_some_and(|c| ('0'..='7').contains(&c)) {
                    v = v * 8 + (self.next()? as u32 - '0' as u32);
                }
                if self.pos == start {
                    if self.dialect == Dialect::Python {
                        return Err(self.error("bad escape in class"));
                    }
                    self.pos += 1;
                    e as u32
                } else {
                    v
                }
            }
            _ => self.char_escape(e)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pattern: &str, dialect: Dialect) -> Node {
        parse(pattern, dialect, Flags::default())
            .unwrap_or_else(|e| panic!("{pattern}: {e}"))
            .node
    }

    fn set(s: &str) -> Node {
        Node::Set(CharSet::from_ranges(s.chars().map(|c| (c as u32, c as u32))))
    }

    #[test]
    fn basics() {
        assert_eq!(p("ab", Dialect::Js), Node::Concat(vec![set("a"), set("b")]));
        assert_eq!(p("a|b|", Dialect::Js), Node::Alt(vec![set("a"), set("b"), Node::Empty]));
        assert_eq!(
            p("(a)+?", Dialect::Js),
            Node::Repeat {
                node: Box::new(Node::Group {
                    node: Box::new(set("a")),
                    index: 1
                }),
                min: 1,
                max: None,
                greedy: false,
                possessive: false
            }
        );
        assert!(matches!(p("a{2,5}", Dialect::Js), Node::Repeat { min: 2, max: Some(5), .. }));
        assert!(matches!(p("a{3}", Dialect::Js), Node::Repeat { min: 3, max: Some(3), .. }));
        assert!(matches!(p("a{3,}", Dialect::Js), Node::Repeat { min: 3, max: None, .. }));
        assert!(matches!(p("a*+", Dialect::Python), Node::Repeat { possessive: true, .. }));
    }

    #[test]
    fn braces_that_are_not_quantifiers_are_literal() {
        assert_eq!(
            p("a{,3}", Dialect::Js),
            Node::Concat(vec![set("a"), set("{"), set(","), set("3"), set("}")])
        );
        assert!(matches!(p("a{,3}", Dialect::Python), Node::Repeat { min: 0, max: Some(3), .. }));
        assert!(matches!(p("a{,3}", Dialect::Ruby), Node::Repeat { min: 0, max: Some(3), .. }));
        assert_eq!(p("{x", Dialect::Js), Node::Concat(vec![set("{"), set("x")]));
        assert!(parse("a{,3}", Dialect::Js, Flags::parse(Dialect::Js, "u").unwrap()).is_err());
    }

    #[test]
    fn anchors_follow_the_dialect() {
        let js = Flags::default();
        assert_eq!(p("^", Dialect::Js), Node::Assert(Assertion::TextStart));
        assert_eq!(p("$", Dialect::Js), Node::Assert(Assertion::TextEnd));
        assert_eq!(p("$", Dialect::Python), Node::Assert(Assertion::TextEndOrFinalNewline));
        assert_eq!(p("^", Dialect::Ruby), Node::Assert(Assertion::LineStartNotAtEnd));
        assert_eq!(p("\\z", Dialect::Ruby), Node::Assert(Assertion::TextEnd));
        assert_eq!(p("\\Z", Dialect::Python), Node::Assert(Assertion::TextEnd));
        let m = Flags { multiline: true, ..js };
        assert_eq!(
            parse("^", Dialect::Js, m).unwrap().node,
            Node::Assert(Assertion::LineStart(LineTerminators::Js))
        );
    }

    #[test]
    fn classes() {
        let Node::Set(s) = p("[a-c\\d_]", Dialect::Js) else { panic!() };
        assert!(s.contains('b' as u32) && s.contains('7' as u32) && s.contains('_' as u32) && !s.contains('d' as u32));
        let Node::Set(s) = p("[^a]", Dialect::Js) else { panic!() };
        assert!(!s.contains('a' as u32) && s.contains('b' as u32));
        let Node::Set(s) = p("[]a]", Dialect::Python) else { panic!() };
        assert!(s.contains(']' as u32) && s.contains('a' as u32));
        assert_eq!(p("[]", Dialect::Js), Node::Set(CharSet::empty()));
        let Node::Set(s) = p("[a-z&&[^aeiou]]", Dialect::Ruby) else {
            panic!()
        };
        assert!(s.contains('b' as u32) && !s.contains('e' as u32));
        let Node::Set(s) = p("[[:digit:]x]", Dialect::Ruby) else { panic!() };
        assert!(s.contains('5' as u32) && s.contains('x' as u32));
        let Node::Set(s) = parse(
            "[^a]",
            Dialect::Js,
            Flags {
                ignore_case: true,
                ..Flags::default()
            },
        )
        .unwrap()
        .node
        else {
            panic!()
        };
        assert!(!s.contains('A' as u32), "fold before negating: /[^a]/i does not match 'A'");
    }

    #[test]
    fn unicode_classes_follow_the_engine() {
        let Node::Set(py) = p("\\w", Dialect::Python) else { panic!() };
        let Node::Set(js) = p("\\w", Dialect::Js) else { panic!() };
        assert!(py.contains('é' as u32) && !js.contains('é' as u32));
        let Node::Set(rb) = p("\\s", Dialect::Ruby) else { panic!() };
        assert!(!rb.contains(0xA0));
    }

    #[test]
    fn groups_and_flags() {
        assert!(matches!(p("(?:a)", Dialect::Js), Node::Group { index: 0, .. }));
        assert!(matches!(
            p("(?=a)", Dialect::Js),
            Node::Look {
                ahead: true,
                negated: false,
                ..
            }
        ));
        assert!(matches!(
            p("(?<!a)", Dialect::Js),
            Node::Look {
                ahead: false,
                negated: true,
                ..
            }
        ));
        assert!(matches!(p("(?<n>a)\\k<n>", Dialect::Js), Node::Concat(_)));
        assert!(matches!(p("(?P<n>a)(?P=n)", Dialect::Python), Node::Concat(v) if matches!(v[1], Node::Backref(1))));
        assert!(matches!(p("(?>a+)", Dialect::Ruby), Node::Atomic(_)));
        let Node::Set(s) = p("(?i)a", Dialect::Python) else { panic!() };
        assert!(s.contains('A' as u32));
        let Node::Concat(v) = p("a(?i:b)c", Dialect::Python) else {
            panic!()
        };
        assert!(matches!(&v[1], Node::Group { node, .. } if matches!(&**node, Node::Set(s) if s.contains('B' as u32))));
        assert!(
            matches!(&v[2], Node::Set(s) if !s.contains('C' as u32)),
            "scoped flags end with the group"
        );
        assert!(
            parse("a(?i)b", Dialect::Python, Flags::default()).is_err(),
            "Python: global flags only at the start"
        );
        assert!(matches!(p("a # comment\n b", Dialect::Python), Node::Concat(_)));
        assert!(
            matches!(parse("a # c\n b", Dialect::Python, Flags { extended: true, ..Flags::default() }).unwrap().node, Node::Concat(v) if v.len() == 2)
        );
    }

    #[test]
    fn escapes() {
        assert_eq!(p("\\x41", Dialect::Js), set("A"));
        assert_eq!(p("\\u0041", Dialect::Python), set("A"));
        assert_eq!(p("\\cJ", Dialect::Js), set("\n"));
        assert_eq!(
            parse(
                "\\u{1F600}",
                Dialect::Js,
                Flags {
                    unicode: true,
                    ..Flags::default()
                }
            )
            .unwrap()
            .node,
            Node::Set(CharSet::single(0x1F600))
        );
        assert_eq!(p("\\101", Dialect::Python), set("A"), "Python octal");
        assert_eq!(p("\\1", Dialect::Js), set("\u{1}"), "JS: \\1 with no groups is an octal escape");
        assert!(matches!(p("(a)\\1", Dialect::Js), Node::Concat(v) if matches!(v[1], Node::Backref(1))));
        assert!(parse("\\q", Dialect::Python, Flags::default()).is_err());
        assert_eq!(p("\\q", Dialect::Js), set("q"));
    }

    #[test]
    fn errors() {
        for (pat, d) in [
            ("(a", Dialect::Js),
            ("a)", Dialect::Js),
            ("*a", Dialect::Js),
            ("[a", Dialect::Python),
            ("a**", Dialect::Python),
            ("[z-a]", Dialect::Js),
            ("a{3,2}", Dialect::Js),
        ] {
            assert!(parse(pat, d, Flags::default()).is_err(), "{pat} should not parse in {d:?}");
        }
        assert!(
            parse("a**", Dialect::Ruby, Flags::default()).is_ok(),
            "Ruby allows stacked quantifiers"
        );
    }

    #[test]
    fn ruby_reads_suffixes_after_braces_as_new_quantifiers() {
        let opt = |n: &Node| matches!(n, Node::Repeat { min: 0, max: Some(1), greedy: true, node, .. } if matches!(**node, Node::Repeat { min: 2, max: Some(2), .. }));
        assert!(opt(&p("a{2}?", Dialect::Ruby)), "{:?}", p("a{2}?", Dialect::Ruby));
        assert!(matches!(p("a{2}?", Dialect::Python), Node::Repeat { min: 2, greedy: false, .. }));
        assert!(matches!(
            p("a{2}+", Dialect::Ruby),
            Node::Repeat {
                min: 1,
                max: None,
                possessive: false,
                ..
            }
        ));
        assert!(matches!(
            p("a{2}+", Dialect::Python),
            Node::Repeat {
                min: 2,
                possessive: true,
                ..
            }
        ));
        assert!(
            matches!(p("a{1,3}?", Dialect::Ruby), Node::Repeat { min: 1, greedy: false, .. }),
            "a range is lazy in Ruby too"
        );
        assert!(matches!(p("a*+", Dialect::Ruby), Node::Repeat { possessive: true, .. }));
    }

    #[test]
    fn unsupported_features_are_reported() {
        assert_eq!(p("(a)\\1", Dialect::Python).unsupported(), vec!["backreference \\1".to_string()]);
        assert!(p("a+", Dialect::Js).unsupported().is_empty());
    }
}
