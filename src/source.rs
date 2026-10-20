//! Phase 4: pull regex literals out of source code.
//!
//! The extractors are hand-written character scanners, not regexes, so the tool that hunts ReDoS can never
//! be ReDoS'd by the code it scans. They cover the common ways a regex is written in each language:
//!
//! - JavaScript / TypeScript: `/pattern/flags` literals and `new RegExp("pattern", "flags")`.
//! - Python: `re.compile(...)` and `re.search/match/...` with a string first argument (raw or plain).
//! - Ruby: `/pattern/flags` and `%r{...}` literals, and `Regexp.new("pattern")`.
//!
//! Distinguishing a `/.../ ` regex from division is done with the standard heuristic (what the previous
//! meaningful token was). It is not a full parser, so it errs toward missing a regex rather than inventing
//! one; the known gaps are listed in the docs.

use std::path::Path;

use crate::ast::Dialect;

/// One regex literal found in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    /// The pattern as the regex engine receives it (string escapes already resolved).
    pub pattern: String,
    /// The flags as written (`"i"`, `"im"`, ...).
    pub flags: String,
    pub dialect: Dialect,
    /// 1-based line of the start of the literal.
    pub line: usize,
    /// 1-based column (characters) of the start of the literal.
    pub col: usize,
}

/// The dialect for a file, by extension, or `None` if the file is not a language we extract from.
pub fn dialect_for(path: &Path) -> Option<Dialect> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Dialect::Js),
        "py" | "pyi" => Some(Dialect::Python),
        "rb" => Some(Dialect::Ruby),
        _ => None,
    }
}

/// Extracts every regex literal from `text`, treating it as source in `dialect`.
pub fn extract(dialect: Dialect, text: &str) -> Vec<Literal> {
    let chars: Vec<char> = text.chars().collect();
    let mut s = Scanner::new(&chars, dialect);
    match dialect {
        Dialect::Js => s.scan_cstyle(true),
        Dialect::Ruby => s.scan_ruby(),
        Dialect::Python => s.scan_python(),
    }
    s.out
}

struct Scanner<'a> {
    c: &'a [char],
    i: usize,
    line: usize,
    col: usize,
    dialect: Dialect,
    out: Vec<Literal>,
    /// The last meaningful character seen (ignoring whitespace and comments): decides whether `/` is a regex
    /// or division.
    prev: char,
    /// The last identifier seen, to tell `return /re/` (a regex) from `x /re/` (division).
    prev_word: String,
}

impl<'a> Scanner<'a> {
    fn new(c: &'a [char], dialect: Dialect) -> Self {
        Scanner {
            c,
            i: 0,
            line: 1,
            col: 1,
            dialect,
            out: Vec::new(),
            prev: '\0',
            prev_word: String::new(),
        }
    }

    fn peek(&self) -> char {
        self.c.get(self.i).copied().unwrap_or('\0')
    }

    fn at(&self, k: usize) -> char {
        self.c.get(self.i + k).copied().unwrap_or('\0')
    }

    fn bump(&mut self) -> char {
        let ch = self.peek();
        self.i += 1;
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        ch
    }

    fn starts_with(&self, s: &str) -> bool {
        self.c[self.i..].iter().take(s.chars().count()).copied().eq(s.chars())
    }

    /// Whether the identifier `word` starts exactly at the cursor (standalone, not part of a longer name).
    fn at_word(&self, word: &str) -> bool {
        self.starts_with(word)
            && (self.i == 0 || !is_ident(self.c[self.i - 1]))
            && self.c.get(self.i + word.chars().count()).is_none_or(|&c| !is_ident(c))
    }

    // ---- C-style languages (JavaScript, and the `/.../` parts of Ruby) ----

    /// Scans JavaScript-like source: line/block comments, strings, `/.../ ` regexes and `new RegExp(...)`.
    fn scan_cstyle(&mut self, regexp_calls: bool) {
        while self.i < self.c.len() {
            let ch = self.peek();
            match ch {
                '/' if self.at(1) == '/' => self.line_comment(),
                '/' if self.at(1) == '*' => self.block_comment(),
                '/' if self.regex_allowed() => {
                    if !self.regex_literal(Dialect::Js) {
                        self.prev = '/';
                        self.bump();
                    }
                }
                '"' | '\'' | '`' => {
                    self.skip_string(ch);
                    self.prev = ch;
                }
                _ if regexp_calls && ch == 'R' && self.at_word("RegExp") => {
                    self.regexp_constructor(Dialect::Js, "RegExp");
                }
                _ if is_ident_start(ch) => self.read_word(),
                _ => {
                    if !ch.is_whitespace() {
                        self.prev = ch;
                        self.prev_word.clear();
                    }
                    self.bump();
                }
            }
        }
    }

    /// Consumes a whole identifier, recording it as `prev_word`.
    fn read_word(&mut self) {
        let mut w = String::new();
        while is_ident(self.peek()) {
            w.push(self.bump());
        }
        self.prev = 'a';
        self.prev_word = w;
    }

    fn line_comment(&mut self) {
        while self.i < self.c.len() && self.peek() != '\n' {
            self.bump();
        }
    }

    fn block_comment(&mut self) {
        self.bump();
        self.bump();
        while self.i < self.c.len() && !(self.peek() == '*' && self.at(1) == '/') {
            self.bump();
        }
        self.bump();
        self.bump();
    }

    /// A `/` begins a regex when the previous meaningful token is not a value. After most identifiers it is
    /// division, but after a keyword that expects an expression (`return /re/`) it is a regex.
    fn regex_allowed(&self) -> bool {
        const KEYWORDS: &[&str] = &[
            "return",
            "typeof",
            "instanceof",
            "in",
            "of",
            "new",
            "delete",
            "void",
            "do",
            "else",
            "yield",
            "await",
            "case",
            "throw",
            "if",
            "while",
            "and",
            "or",
            "not",
            "when",
            "then",
            "unless",
        ];
        match self.prev {
            ')' | ']' | '}' | '"' | '\'' | '`' | '.' | '0'..='9' => false,
            c if is_ident(c) => KEYWORDS.contains(&self.prev_word.as_str()),
            _ => true,
        }
    }

    /// Reads a `/pattern/flags` literal starting at the current `/`. Returns false if it does not look like a
    /// well-formed regex literal (then the caller treats `/` as an operator).
    fn regex_literal(&mut self, dialect: Dialect) -> bool {
        let (line, col) = (self.line, self.col);
        let start = self.i;
        self.bump(); // opening /
        let mut pattern = String::new();
        let mut in_class = false;
        loop {
            let ch = self.peek();
            match ch {
                '\0' | '\n' => {
                    // Unterminated: not a regex literal. Rewind.
                    self.rewind_to(start, line, col);
                    return false;
                }
                '\\' => {
                    pattern.push(self.bump());
                    if self.peek() == '\0' || self.peek() == '\n' {
                        self.rewind_to(start, line, col);
                        return false;
                    }
                    pattern.push(self.bump());
                }
                '[' => {
                    in_class = true;
                    pattern.push(self.bump());
                }
                ']' => {
                    in_class = false;
                    pattern.push(self.bump());
                }
                '/' if !in_class => {
                    self.bump(); // closing /
                    break;
                }
                _ => pattern.push(self.bump()),
            }
        }
        let mut flags = String::new();
        while is_flag_char(self.peek()) {
            flags.push(self.bump());
        }
        self.prev = '/';
        if pattern.is_empty() {
            return false;
        }
        self.out.push(Literal {
            pattern,
            flags,
            dialect,
            line,
            col,
        });
        true
    }

    fn rewind_to(&mut self, i: usize, line: usize, col: usize) {
        self.i = i;
        self.line = line;
        self.col = col;
    }

    /// Reads `RegExp("pattern", "flags")` / `Regexp.new("pattern")` starting at the constructor name.
    fn regexp_constructor(&mut self, dialect: Dialect, name: &str) {
        let (line, col) = (self.line, self.col);
        for _ in 0..name.chars().count() {
            self.bump();
        }
        self.skip_ws_comments();
        if self.dialect == Dialect::Ruby {
            if !self.starts_with(".new") {
                self.prev = 'p';
                return;
            }
            for _ in 0..4 {
                self.bump();
            }
            self.skip_ws_comments();
        }
        if self.peek() != '(' {
            self.prev = 'p';
            return;
        }
        self.bump();
        self.skip_ws_comments();
        let Some(pattern) = self.read_string_literal() else {
            self.prev = '(';
            return;
        };
        // Optional flags as a second string argument (JavaScript).
        let mut flags = String::new();
        self.skip_ws_comments();
        if dialect == Dialect::Js && self.peek() == ',' {
            self.bump();
            self.skip_ws_comments();
            if let Some(f) = self.read_string_literal() {
                flags = f.chars().filter(|c| is_flag_char(*c)).collect();
            }
        }
        if !pattern.is_empty() {
            self.out.push(Literal {
                pattern,
                flags,
                dialect,
                line,
                col,
            });
        }
        self.prev = ')';
    }

    fn skip_ws_comments(&mut self) {
        loop {
            while self.peek().is_whitespace() {
                self.bump();
            }
            if self.peek() == '/' && self.at(1) == '/' {
                self.line_comment();
            } else if self.peek() == '/' && self.at(1) == '*' {
                self.block_comment();
            } else if self.dialect != Dialect::Js && self.peek() == '#' {
                self.line_comment();
            } else {
                break;
            }
        }
    }

    /// Reads a quoted string literal at the cursor and returns its *resolved* value (escapes processed the
    /// way the language would), or `None` if the cursor is not on a string. Raw prefixes (`r"..."`) are
    /// honoured for Python.
    fn read_string_literal(&mut self) -> Option<String> {
        let raw = self.dialect == Dialect::Python && matches!(self.peek(), 'r' | 'R') && matches!(self.at(1), '"' | '\'');
        let byte = self.dialect == Dialect::Python && matches!(self.peek(), 'b' | 'B') && matches!(self.at(1), '"' | '\'');
        if raw || byte {
            self.bump();
        }
        let quote = self.peek();
        if quote != '"' && quote != '\'' {
            return None;
        }
        // Triple-quoted (Python).
        let triple = self.dialect == Dialect::Python && self.at(1) == quote && self.at(2) == quote;
        self.bump();
        if triple {
            self.bump();
            self.bump();
        }
        let mut value = String::new();
        loop {
            let ch = self.peek();
            if ch == '\0' {
                return None;
            }
            if ch == quote && (!triple || (self.at(1) == quote && self.at(2) == quote)) {
                self.bump();
                if triple {
                    self.bump();
                    self.bump();
                }
                return Some(value);
            }
            if ch == '\\' && !raw {
                self.bump();
                value.push_str(&self.decode_escape());
            } else if ch == '\\' && raw {
                // In a raw string the backslash is kept, but `\"` still does not end the string.
                value.push(self.bump());
                if self.peek() == quote {
                    value.push(self.bump());
                }
            } else {
                value.push(self.bump());
            }
        }
    }

    /// Decodes one escape sequence (the cursor is just past the backslash) to the characters the string
    /// actually holds. Unknown escapes keep the backslash, as all three languages do for regex-bound strings.
    fn decode_escape(&mut self) -> String {
        let ch = self.bump();
        match ch {
            'n' => "\n".into(),
            't' => "\t".into(),
            'r' => "\r".into(),
            '\\' => "\\".into(),
            '"' => "\"".into(),
            '\'' => "'".into(),
            '0' => "\0".into(),
            'x' => {
                let hex: String = (0..2).map_while(|_| self.peek().is_ascii_hexdigit().then(|| self.bump())).collect();
                char::from_u32(u32::from_str_radix(&hex, 16).unwrap_or(0))
                    .map(String::from)
                    .unwrap_or_default()
            }
            'u' => self.decode_unicode_escape(),
            // Unknown escape: keep the backslash so the regex sees `\d`, `\s`, etc.
            other => format!("\\{other}"),
        }
    }

    fn decode_unicode_escape(&mut self) -> String {
        let hex: String = if self.peek() == '{' {
            self.bump();
            let h: String = std::iter::from_fn(|| (self.peek() != '}' && self.peek() != '\0').then(|| self.bump())).collect();
            if self.peek() == '}' {
                self.bump();
            }
            h
        } else {
            (0..4).map_while(|_| self.peek().is_ascii_hexdigit().then(|| self.bump())).collect()
        };
        char::from_u32(u32::from_str_radix(&hex, 16).unwrap_or(0))
            .map(String::from)
            .unwrap_or_default()
    }

    fn skip_string(&mut self, quote: char) {
        self.bump();
        while self.i < self.c.len() {
            let ch = self.peek();
            if ch == '\\' {
                self.bump();
                self.bump();
            } else if ch == quote {
                self.bump();
                break;
            } else {
                self.bump();
            }
        }
    }

    // ---- Ruby ----

    fn scan_ruby(&mut self) {
        while self.i < self.c.len() {
            let ch = self.peek();
            match ch {
                '#' => self.line_comment(),
                '"' | '\'' | '`' => {
                    self.skip_string(ch);
                    self.prev = ch;
                }
                '%' if self.at(1) == 'r' => self.percent_r(),
                '/' if self.regex_allowed() => {
                    if !self.regex_literal(Dialect::Ruby) {
                        self.prev = '/';
                        self.bump();
                    }
                }
                'R' if self.at_word("Regexp") => {
                    self.regexp_constructor(Dialect::Ruby, "Regexp");
                }
                _ if is_ident_start(ch) => self.read_word(),
                _ => {
                    if !ch.is_whitespace() {
                        self.prev = ch;
                        self.prev_word.clear();
                    }
                    self.bump();
                }
            }
        }
    }

    /// `%r{...}`, `%r(...)`, `%r[...]`, `%r<...>`, `%r|...|` and friends.
    fn percent_r(&mut self) {
        let (line, col) = (self.line, self.col);
        self.bump(); // %
        self.bump(); // r
        let open = self.bump();
        let close = match open {
            '{' => '}',
            '(' => ')',
            '[' => ']',
            '<' => '>',
            other => other,
        };
        let nesting = open != close;
        let mut depth = 1;
        let mut pattern = String::new();
        loop {
            let ch = self.peek();
            if ch == '\0' {
                return;
            }
            if ch == '\\' {
                pattern.push(self.bump());
                pattern.push(self.bump());
                continue;
            }
            if nesting && ch == open {
                depth += 1;
            }
            if ch == close {
                depth -= 1;
                if depth == 0 {
                    self.bump();
                    break;
                }
            }
            pattern.push(self.bump());
        }
        let mut flags = String::new();
        while is_flag_char(self.peek()) {
            flags.push(self.bump());
        }
        self.prev = ')';
        if !pattern.is_empty() {
            self.out.push(Literal {
                pattern,
                flags,
                dialect: Dialect::Ruby,
                line,
                col,
            });
        }
    }

    // ---- Python ----

    fn scan_python(&mut self) {
        while self.i < self.c.len() {
            let ch = self.peek();
            match ch {
                '#' => self.line_comment(),
                '"' | '\'' => {
                    self.skip_python_string();
                    self.prev = ch;
                }
                'r' | 'R' | 'b' | 'B' if matches!(self.at(1), '"' | '\'') => {
                    // A string literal with a prefix; skip it (not a regex call).
                    self.bump();
                    self.skip_python_string();
                }
                'r' | 'R' if self.is_re_call() => self.python_re_call(),
                _ if is_ident_start(ch) => self.read_word(),
                _ => {
                    if !ch.is_whitespace() {
                        self.prev = ch;
                        self.prev_word.clear();
                    }
                    self.bump();
                }
            }
        }
    }

    /// Whether the cursor is at `re.<func>(` or `regex.<func>(` (the `r` of `re`/`regex`), and not a member
    /// access like `x.re.compile`.
    fn is_re_call(&self) -> bool {
        let clean_before = self.i == 0 || (!is_ident(self.c[self.i - 1]) && self.c[self.i - 1] != '.');
        clean_before && (self.starts_with("re.") || self.starts_with("regex."))
    }

    fn python_re_call(&mut self) {
        let module_len = if self.starts_with("regex.") { 6 } else { 3 };
        // Read the function name after the module.
        let mut j = self.i + module_len;
        let name_start = j;
        while j < self.c.len() && is_ident(self.c[j]) {
            j += 1;
        }
        let func: String = self.c[name_start..j].iter().collect();
        let takes_pattern = matches!(
            func.as_str(),
            "compile" | "match" | "fullmatch" | "search" | "sub" | "subn" | "split" | "findall" | "finditer"
        );
        // Advance to just after the module+name.
        while self.i < j {
            self.bump();
        }
        if !takes_pattern {
            self.prev = 'e';
            return;
        }
        self.skip_ws_comments();
        if self.peek() != '(' {
            self.prev = 'e';
            return;
        }
        let (line, col) = (self.line, self.col);
        self.bump();
        self.skip_ws_comments();
        if let Some(pattern) = self.read_string_literal() {
            self.skip_ws_comments();
            // Only a plain string argument; `"a" + var` or `"a" "b"` is not a literal we can trust.
            if !pattern.is_empty() && matches!(self.peek(), ',' | ')') {
                self.out.push(Literal {
                    pattern,
                    flags: String::new(),
                    dialect: Dialect::Python,
                    line,
                    col,
                });
            }
        }
        self.prev = 'e';
    }

    fn skip_python_string(&mut self) {
        let quote = self.peek();
        let triple = self.at(1) == quote && self.at(2) == quote;
        self.bump();
        if triple {
            self.bump();
            self.bump();
        }
        loop {
            let ch = self.peek();
            if ch == '\0' {
                return;
            }
            if ch == '\\' {
                self.bump();
                self.bump();
                continue;
            }
            if ch == quote && (!triple || (self.at(1) == quote && self.at(2) == quote)) {
                self.bump();
                if triple {
                    self.bump();
                    self.bump();
                }
                return;
            }
            self.bump();
        }
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == '$'
}

fn is_flag_char(c: char) -> bool {
    c.is_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(dialect: Dialect, text: &str) -> Vec<(String, String)> {
        extract(dialect, text).into_iter().map(|l| (l.pattern, l.flags)).collect()
    }

    #[test]
    fn javascript_regex_literals() {
        let src = "const a = /(a+)+$/g;\nif (x) return /foo|bar/im;\nconst d = 10 / 2 / 3;\nconst e = /[/]/;";
        let got = pats(Dialect::Js, src);
        assert!(got.contains(&("(a+)+$".into(), "g".into())));
        assert!(got.contains(&("foo|bar".into(), "im".into())));
        assert!(got.contains(&("[/]".into(), String::new())), "slash inside a class is literal");
        assert!(!got.iter().any(|(p, _)| p.contains("2")), "division is not a regex: {got:?}");
    }

    #[test]
    fn javascript_regexp_constructor() {
        let src = "new RegExp('\\\\d+\\\\s*', 'i'); RegExp(\"a.b\"); foo.RegExp(1);";
        let got = pats(Dialect::Js, src);
        assert!(got.contains(&("\\d+\\s*".into(), "i".into())), "escapes resolved: {got:?}");
        assert!(got.contains(&("a.b".into(), String::new())));
    }

    #[test]
    fn python_calls() {
        let src = "import re\nre.compile(r'(a+)+$')\nre.search('\\\\d{2,}', s)\nx.re.compile('ignored')\nre.compile(\"a\" + var)";
        let got = pats(Dialect::Python, src);
        assert!(got.contains(&("(a+)+$".into(), String::new())), "raw string: {got:?}");
        assert!(
            got.contains(&("\\d{2,}".into(), String::new())),
            "plain string escape resolved: {got:?}"
        );
        assert_eq!(got.len(), 2, "member access and non-literal args are skipped: {got:?}");
    }

    #[test]
    fn ruby_literals_and_percent_r() {
        let src = "re = /(a+)+$/i\nx = %r{foo\\d+}\ny = Regexp.new('ab+')\nz = 10 / 2";
        let got = pats(Dialect::Ruby, src);
        assert!(got.contains(&("(a+)+$".into(), "i".into())));
        assert!(got.contains(&("foo\\d+".into(), String::new())), "%r literal: {got:?}");
        assert!(got.contains(&("ab+".into(), String::new())));
    }

    #[test]
    fn strings_and_comments_are_not_mined() {
        let js = "// /not a regex/\nconst s = \"/also not/\";\n/* /nor this/ */";
        assert!(pats(Dialect::Js, js).is_empty(), "{:?}", pats(Dialect::Js, js));
        let py = "# re.compile('x')\ns = 're.compile(not)'";
        assert!(pats(Dialect::Python, py).is_empty());
    }

    #[test]
    fn line_numbers_are_right() {
        let src = "a\nb\nconst r = /x+/;";
        let lit = &extract(Dialect::Js, src)[0];
        assert_eq!((lit.line, lit.pattern.as_str()), (3, "x+"));
    }
}
