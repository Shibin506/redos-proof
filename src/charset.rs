//! Sets of characters, stored as sorted, non-overlapping, non-adjacent ranges of Unicode code points.
//!
//! The analysis needs set algebra on what an edge of the automaton can match ("can both branches read the
//! same character?"), so a class like `[a-z0-9]` is kept as ranges, not as a list of characters.

use std::fmt;

/// Code points above this do not exist.
pub const MAX: u32 = 0x10FFFF;

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct CharSet {
    /// Inclusive ranges, sorted, disjoint and never touching (`a-c` and `d-f` are merged into `a-f`).
    ranges: Vec<(u32, u32)>,
}

impl CharSet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn any() -> Self {
        Self { ranges: vec![(0, MAX)] }
    }

    pub fn single(c: u32) -> Self {
        Self { ranges: vec![(c, c)] }
    }

    pub fn range(lo: u32, hi: u32) -> Self {
        Self::from_ranges([(lo.min(hi), hi.max(lo))])
    }

    pub fn from_ranges(ranges: impl IntoIterator<Item = (u32, u32)>) -> Self {
        let mut v: Vec<(u32, u32)> = ranges.into_iter().filter(|&(lo, hi)| lo <= hi).collect();
        v.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
        for (lo, hi) in v {
            match out.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => out.push((lo, hi)),
            }
        }
        Self { ranges: out }
    }

    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, c: u32) -> bool {
        let i = self.ranges.partition_point(|&(_, hi)| hi < c);
        self.ranges.get(i).is_some_and(|&(lo, _)| lo <= c)
    }

    pub fn union(&self, other: &CharSet) -> CharSet {
        Self::from_ranges(self.ranges.iter().chain(other.ranges.iter()).copied())
    }

    pub fn negate(&self) -> CharSet {
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        let mut next = 0u32;
        for &(lo, hi) in &self.ranges {
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
        }
        if next <= MAX && self.ranges.last().is_none_or(|&(_, hi)| hi < MAX) {
            out.push((next, MAX));
        }
        Self { ranges: out }
    }

    pub fn intersect(&self, other: &CharSet) -> CharSet {
        let (mut i, mut j, mut out) = (0, 0, Vec::new());
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a, b) = (self.ranges[i], other.ranges[j]);
            let (lo, hi) = (a.0.max(b.0), a.1.min(b.1));
            if lo <= hi {
                out.push((lo, hi));
            }
            if a.1 < b.1 { i += 1 } else { j += 1 }
        }
        Self { ranges: out }
    }

    pub fn difference(&self, other: &CharSet) -> CharSet {
        self.intersect(&other.negate())
    }

    pub fn overlaps(&self, other: &CharSet) -> bool {
        !self.intersect(other).is_empty()
    }

    /// The smallest member, preferring a printable ASCII one (attack strings should be readable).
    pub fn example(&self) -> Option<u32> {
        let printable = self.intersect(&CharSet::range(0x21, 0x7E));
        printable.ranges.first().or(self.ranges.first()).map(|&(lo, _)| lo)
    }

    /// Adds every character the engine treats as the same letter as a member, given the engine's groups
    /// (`src/folds.rs`). Fold a class *before* negating it: `/[^a]/i` matches neither `a` nor `A`.
    pub fn case_fold(&self, groups: &[&[u32]]) -> CharSet {
        let mut extra = Vec::new();
        for group in groups {
            if group.iter().any(|&c| self.contains(c)) {
                extra.extend(group.iter().map(|&c| (c, c)));
            }
        }
        if extra.is_empty() {
            self.clone()
        } else {
            self.union(&Self::from_ranges(extra))
        }
    }
}

impl fmt::Debug for CharSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for CharSet {
    /// Regex-like: `a`, `[a-z0-9]`, `[^\n]`, `.` for (nearly) everything.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let show = |c: u32| -> String {
            match char::from_u32(c) {
                Some('\n') => "\\n".into(),
                Some('\r') => "\\r".into(),
                Some('\t') => "\\t".into(),
                Some(ch @ ('\\' | ']' | '[' | '-' | '^')) => format!("\\{ch}"),
                Some(ch) if (0x20..0x7F).contains(&c) => ch.to_string(),
                _ if c <= 0xFFFF => format!("\\u{c:04x}"),
                _ => format!("\\u{{{c:x}}}"),
            }
        };
        if *self == CharSet::any() {
            return write!(f, "[any]");
        }
        if let [(lo, hi)] = self.ranges[..]
            && lo == hi
        {
            return write!(f, "{}", show(lo));
        }
        let (neg, set) = if self.contains(MAX) && self.contains(0) {
            ("^", self.negate())
        } else {
            ("", self.clone())
        };
        write!(f, "[{neg}")?;
        for &(lo, hi) in &set.ranges {
            if lo == hi {
                write!(f, "{}", show(lo))?;
            } else {
                write!(f, "{}-{}", show(lo), show(hi))?;
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(s: &str) -> CharSet {
        CharSet::from_ranges(s.split(',').map(|r| {
            let b = r.as_bytes();
            (b[0] as u32, *b.last().unwrap() as u32)
        }))
    }

    #[test]
    fn ranges_are_merged_and_sorted() {
        assert_eq!(
            CharSet::from_ranges([(5, 9), (1, 3), (4, 4), (20, 30), (25, 26)]).ranges(),
            &[(1, 9), (20, 30)]
        );
    }

    #[test]
    fn algebra() {
        let az = set("az");
        let digits = set("09");
        let both = az.union(&digits);
        assert!(both.contains('q' as u32) && both.contains('5' as u32) && !both.contains('A' as u32));
        assert_eq!(both.intersect(&set("cz")), set("cz"));
        assert!(!az.overlaps(&digits));
        assert_eq!(az.negate().negate(), az);
        assert_eq!(CharSet::any().negate(), CharSet::empty());
        assert_eq!(CharSet::empty().negate(), CharSet::any());
        assert_eq!(set("az").difference(&set("bz")), set("aa"));
        assert!(CharSet::single(MAX).negate().contains(0) && !CharSet::single(MAX).negate().contains(MAX));
    }

    #[test]
    fn set_algebra_matches_membership_on_random_sets() {
        // A brute-force check over a small universe: every operation agrees with per-character membership.
        let mut seed = 0x1234_5678u64;
        let mut rnd = |n: u32| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as u32
        };
        for _ in 0..500 {
            let mut make = || CharSet::from_ranges((0..rnd(4)).map(|_| (rnd(60), rnd(60))));
            let (a, b) = (make(), make());
            for c in 0..64 {
                assert_eq!(a.union(&b).contains(c), a.contains(c) || b.contains(c));
                assert_eq!(a.intersect(&b).contains(c), a.contains(c) && b.contains(c));
                assert_eq!(a.negate().contains(c), !a.contains(c));
                assert_eq!(a.difference(&b).contains(c), a.contains(c) && !b.contains(c));
            }
        }
    }

    #[test]
    fn case_folding_follows_the_engine() {
        use crate::folds::{FOLD_JS_LEGACY, FOLD_PY};
        let folded = set("af").case_fold(FOLD_PY);
        assert!(folded.contains('A' as u32) && folded.contains('F' as u32) && !folded.contains('G' as u32));
        assert!(CharSet::single('é' as u32).case_fold(FOLD_PY).contains('É' as u32));
        assert!(
            CharSet::single('k' as u32).case_fold(FOLD_PY).contains(0x212A),
            "Python: k matches the Kelvin sign"
        );
        assert!(
            !CharSet::single('k' as u32).case_fold(FOLD_JS_LEGACY).contains(0x212A),
            "JavaScript without u: it does not"
        );
    }

    #[test]
    fn display() {
        assert_eq!(CharSet::single('a' as u32).to_string(), "a");
        assert_eq!(set("az,09").to_string(), "[0-9a-z]");
        assert_eq!(CharSet::single('\n' as u32).negate().to_string(), "[^\\n]");
    }
}
