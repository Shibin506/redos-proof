//! Phase 2: find structures that make a backtracking engine do super-linear work, and confirm each one by
//! measurement.
//!
//! The honest split, like a credential scanner that only reports what it can verify: the static side
//! *suspects* a vulnerable loop and proposes an input (`prefix` + `pump` repeated + `suffix`); the
//! simulator from Phase 1 then *confirms* it by counting steps as the input grows. A finding is reported
//! only when the measured work really does explode, so the attack string is the proof.
//!
//! Exponential blow-up (`(a+)+`, `(a*)*`, `(a|a)*`) is found with the classic product-automaton test, run
//! over the full ε-NFA so that ambiguity hidden in the loop structure (not just in reading different
//! characters) is caught: in the NFA paired with itself, a strongly connected component that holds both a
//! diagonal state `(q, q)` and an off-diagonal state `(p1, p2)` with `p1 != p2`, and at least one step that
//! reads a character, means one pass of the loop can match the same text two ways, so n passes match it 2^n
//! ways. Any candidate is then run to confirm the work really grows that fast.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::charset::CharSet;
use crate::matcher::{Outcome, match_at_start};
use crate::nfa::{Nfa, State, StateId};

/// Above this many NFA states, the product automaton is too big; the pattern is reported as not analysed
/// rather than analysed wrongly.
pub const MAX_STATES: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blowup {
    /// Work multiplies by a constant for each extra pump: the dangerous case.
    Exponential,
    /// Work grows like `length^degree` (degree >= 2).
    Polynomial { degree: u32 },
}

/// How the measured step count grew, kept as evidence.
#[derive(Debug, Clone)]
pub struct Growth {
    /// `(pump count, steps)` for the input `prefix + pump*count + suffix`.
    pub samples: Vec<(usize, u64)>,
    /// True if a sample hit the step cap (work so large the simulator gave up): itself proof of blow-up.
    pub hit_cap: bool,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub blowup: Blowup,
    /// The attack input is `prefix + pump.repeat(n) + suffix` (characters as code points).
    pub prefix: Vec<u32>,
    pub pump: Vec<u32>,
    pub suffix: Vec<u32>,
    pub growth: Growth,
}

impl Finding {
    /// The attack input with the pump repeated `n` times.
    pub fn input(&self, n: usize) -> String {
        self.prefix
            .iter()
            .chain(self.pump.iter().cycle().take(self.pump.len() * n))
            .chain(self.suffix.iter())
            .filter_map(|&c| char::from_u32(c))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeError {
    /// More states than [`MAX_STATES`]: not analysed.
    TooLarge,
}

/// Finds confirmed blow-up in `nfa`, most severe first. Empty means none was confirmed (not a promise of
/// safety: see the known limits in the docs).
pub fn analyze(nfa: &Nfa) -> Result<Vec<Finding>, AnalyzeError> {
    if nfa.states.len() > MAX_STATES {
        return Err(AnalyzeError::TooLarge);
    }
    let graph = Graph::build(nfa);
    let mut findings = Vec::new();
    if let Some(f) = graph.find_exponential(nfa) {
        findings.push(f);
    } else if let Some(f) = graph.find_polynomial(nfa) {
        // A pattern is either exponential or (at worst) polynomial; report the exponential if there is one.
        findings.push(f);
    }
    Ok(findings)
}

/// The NFA as a graph for analysis: which states are reachable without reading a character (ε-moves) and
/// which read one.
struct Graph {
    /// ε-successors of each state (branches, loop edges, and — skipped over — assertions and groups).
    eps: Vec<Vec<StateId>>,
    /// For a `Char` state: its set and the single state it goes to after reading.
    consume: Vec<Option<(CharSet, StateId)>>,
}

impl Graph {
    fn build(nfa: &Nfa) -> Self {
        let mut eps = vec![Vec::new(); nfa.states.len()];
        let mut consume = vec![None; nfa.states.len()];
        for (id, st) in nfa.states.iter().enumerate() {
            match st {
                State::Char { set, next } => consume[id] = Some((set.clone(), *next)),
                State::Split { first, second } => eps[id] = vec![*first, *second],
                State::LoopEnter { next, .. } => eps[id] = vec![*next],
                State::LoopCheck { next, exit, .. } => eps[id] = vec![*next, *exit],
                // Assertions and lookaround/atomic groups are stepped over: a pump through them may not hold,
                // but measurement is the gate, so missing a real one is the only risk, never a false alarm.
                State::Assert { next, .. } | State::Look { next, .. } | State::Atomic { next, .. } => eps[id] = vec![*next],
                State::Match => {}
            }
        }
        Graph { eps, consume }
    }

    fn is_char(&self, s: StateId) -> bool {
        self.consume[s].is_some()
    }

    // ---- exponential ----

    fn find_exponential(&self, nfa: &Nfa) -> Option<Finding> {
        let n = nfa.states.len();
        let node = |a: usize, b: usize| a * n + b;
        // Product automaton over pairs of states. ε on either side; a read-step when both read a shared char.
        let successors = |v: usize| -> Vec<usize> {
            let (a, b) = (v / n, v % n);
            let mut out = Vec::new();
            for &a2 in &self.eps[a] {
                out.push(node(a2, b));
            }
            for &b2 in &self.eps[b] {
                out.push(node(a, b2));
            }
            if let (Some((sa, na)), Some((sb, nb))) = (&self.consume[a], &self.consume[b])
                && sa.overlaps(sb)
            {
                out.push(node(*na, *nb));
            }
            out
        };
        // A read-step inside the component makes the pump non-empty.
        let has_read = |v: usize| -> bool {
            let (a, b) = (v / n, v % n);
            matches!((&self.consume[a], &self.consume[b]), (Some((sa, _)), Some((sb, _))) if sa.overlaps(sb))
        };
        let comp = tarjan(n * n, &successors);
        let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
        for (v, &c) in comp.iter().enumerate() {
            members.entry(c).or_default().push(v);
        }
        // A component with an off-diagonal node and a read-step holds exponential ambiguity. Any diagonal
        // state in it can be the pump point; try character states first, since the cycle through one is sure
        // to read a character (a non-character diagonal may only reach a read through a longer detour).
        let mut candidates: Vec<usize> = Vec::new(); // diagonal states q
        for group in members.values() {
            if group.len() < 2 {
                continue;
            }
            let off = group.iter().any(|&v| v / n != v % n);
            let reads = group.iter().any(|&v| has_read(v));
            if off && reads {
                candidates.extend(group.iter().filter(|&&v| v / n == v % n).map(|&v| v / n));
            }
        }
        candidates.sort_by_key(|&q| (!self.is_char(q), q));
        candidates.dedup();
        for q in candidates {
            let set: HashSet<usize> = members[&comp[q * n + q]].iter().copied().collect();
            let Some(pump) = self.cycle_string(&successors, &set, q * n + q, n) else {
                continue;
            };
            let Some(prefix) = self.prefix_to(nfa, q) else { continue };
            for suffix in self.suffix_candidates(q) {
                if let Some(growth) = confirm(nfa, &prefix, &pump, &suffix, Blowup::Exponential) {
                    return Some(Finding {
                        blowup: Blowup::Exponential,
                        prefix,
                        pump,
                        suffix,
                        growth,
                    });
                }
            }
        }
        None
    }

    /// A non-empty string spelled by a cycle `start -> start` through an off-diagonal node.
    fn cycle_string(&self, succ: &impl Fn(usize) -> Vec<usize>, scc: &HashSet<usize>, start: usize, n: usize) -> Option<Vec<u32>> {
        let to_off = self.bfs(succ, scc, start, |v| v / n != v % n)?;
        let off = *to_off.last().unwrap();
        let back = self.bfs(succ, scc, off, |v| v == start)?;
        let mut path = to_off;
        path.extend(back.into_iter().skip(1));
        let mut out = Vec::new();
        for pair in path.windows(2) {
            let (a, b) = (pair[0] / n, pair[0] % n);
            let (a2, b2) = (pair[1] / n, pair[1] % n);
            // A read-step advances both sides past a Char; an ε-step changes only one side.
            if let (Some((sa, na)), Some((sb, nb))) = (&self.consume[a], &self.consume[b])
                && *na == a2
                && *nb == b2
                && sa.overlaps(sb)
            {
                out.push(sa.intersect(sb).example()?);
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// Shortest path inside `scc` from `from` to a node satisfying `goal` (after at least one step).
    fn bfs(
        &self,
        succ: &impl Fn(usize) -> Vec<usize>,
        scc: &HashSet<usize>,
        from: usize,
        goal: impl Fn(usize) -> bool,
    ) -> Option<Vec<usize>> {
        let mut prev: HashMap<usize, usize> = HashMap::new();
        let mut queue = VecDeque::from([from]);
        let mut seen = HashSet::from([from]);
        let mut first = true;
        while let Some(v) = queue.pop_front() {
            if goal(v) && !first {
                let mut path = vec![v];
                let mut at = v;
                while let Some(&p) = prev.get(&at) {
                    path.push(p);
                    at = p;
                }
                path.reverse();
                return Some(path);
            }
            first = false;
            for w in succ(v) {
                if scc.contains(&w) && seen.insert(w) {
                    prev.insert(w, v);
                    queue.push_back(w);
                }
            }
        }
        None
    }

    /// Characters that bring the engine from input start to state `q`.
    fn prefix_to(&self, nfa: &Nfa, q: StateId) -> Option<Vec<u32>> {
        if nfa.start == q {
            return Some(Vec::new());
        }
        // BFS over the state graph (ε-moves free, read-moves emit a character); shortest to `q`.
        let mut prev: Vec<Option<(StateId, Option<u32>)>> = vec![None; nfa.states.len()];
        let mut seen = vec![false; nfa.states.len()];
        let mut queue = VecDeque::from([nfa.start]);
        seen[nfa.start] = true;
        while let Some(s) = queue.pop_front() {
            let mut edges: Vec<(StateId, Option<u32>)> = self.eps[s].iter().map(|&e| (e, None)).collect();
            if let Some((set, next)) = &self.consume[s] {
                edges.push((*next, Some(set.example()?)));
            }
            for (w, ch) in edges {
                if !seen[w] {
                    seen[w] = true;
                    prev[w] = Some((s, ch));
                    if w == q {
                        let mut out = Vec::new();
                        let mut at = q;
                        while let Some((p, c)) = prev[at] {
                            if let Some(c) = c {
                                out.push(c);
                            }
                            at = p;
                        }
                        out.reverse();
                        return Some(out);
                    }
                    queue.push_back(w);
                }
            }
        }
        None
    }

    /// Suffixes to try after the pump, to force the engine to fail and backtrack. The empty suffix works
    /// when the pattern is anchored (`$`); otherwise a character the loop cannot continue with does.
    fn suffix_candidates(&self, q: StateId) -> Vec<Vec<u32>> {
        let mut after = CharSet::empty();
        let mut seen = HashSet::from([q]);
        let mut stack = vec![q];
        while let Some(s) = stack.pop() {
            if let Some((set, _)) = &self.consume[s] {
                after = after.union(set);
            } else {
                for &e in &self.eps[s] {
                    if seen.insert(e) {
                        stack.push(e);
                    }
                }
            }
        }
        let mut out = vec![Vec::new()];
        if let Some(c) = after.negate().intersect(&CharSet::range(0x21, 0x7E)).example() {
            out.push(vec![c]);
        }
        if let Some(c) = after.negate().example() {
            out.push(vec![c]);
        }
        out
    }

    // ---- polynomial ----

    fn find_polynomial(&self, nfa: &Nfa) -> Option<Finding> {
        // Quadratic (or worse) blow-up needs two different loop positions that overlap: a character position
        // `a` that can repeat on itself, a later one `b` that can repeat on itself, `a` can reach `b`, and
        // they share a character. Pumping that character makes the engine re-split the run.
        let chars: Vec<StateId> = (0..nfa.states.len()).filter(|&s| self.is_char(s)).collect();
        let loops: Vec<StateId> = chars.iter().copied().filter(|&c| self.char_reaches(c, c)).collect();
        let mut best: Option<Finding> = None;
        for &a in &loops {
            for &b in &loops {
                if a == b {
                    continue;
                }
                let (Some((sa, _)), Some((sb, _))) = (&self.consume[a], &self.consume[b]) else {
                    continue;
                };
                let Some(ch) = sa.intersect(sb).example() else { continue };
                if !self.char_reaches(a, b) {
                    continue;
                }
                let Some(prefix) = self.prefix_to(nfa, a) else { continue };
                let pump = vec![ch];
                for suffix in self.suffix_candidates(b) {
                    if let Some(growth) = confirm(nfa, &prefix, &pump, &suffix, Blowup::Polynomial { degree: 2 }) {
                        let degree = growth_degree(&growth).max(2);
                        if best.as_ref().is_none_or(|f| degree > finding_degree(f)) {
                            best = Some(Finding {
                                blowup: Blowup::Polynomial { degree },
                                prefix: prefix.clone(),
                                pump: pump.clone(),
                                suffix,
                                growth,
                            });
                        }
                        break;
                    }
                }
            }
        }
        best
    }

    /// Whether, after reading at char state `a`, the engine can reach char state `b` by reading more (so `b`
    /// is a later loop that overlaps `a`).
    fn char_reaches(&self, a: StateId, b: StateId) -> bool {
        let start = self.consume[a].as_ref().unwrap().1;
        let mut seen = HashSet::new();
        let mut stack = vec![start];
        while let Some(s) = stack.pop() {
            if !seen.insert(s) {
                continue;
            }
            if s == b {
                return true;
            }
            for &e in &self.eps[s] {
                stack.push(e);
            }
            if let Some((_, next)) = &self.consume[s] {
                stack.push(*next);
            }
        }
        false
    }
}

fn finding_degree(f: &Finding) -> u32 {
    match f.blowup {
        Blowup::Polynomial { degree } => degree,
        Blowup::Exponential => u32::MAX,
    }
}

/// Tarjan's strongly-connected components over `n` nodes with successors from `succ`; returns a component
/// id per node. Iterative, to handle large product graphs.
fn tarjan(n: usize, succ: &impl Fn(usize) -> Vec<usize>) -> Vec<usize> {
    let mut index = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack = Vec::new();
    let mut comp = vec![usize::MAX; n];
    let mut next_index = 0usize;
    let mut next_comp = 0usize;
    for root in 0..n {
        if index[root] != usize::MAX {
            continue;
        }
        index[root] = next_index;
        low[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;
        let mut work: Vec<(usize, Vec<usize>, usize)> = vec![(root, succ(root), 0)];
        while let Some((v, edges, i)) = work.last_mut() {
            if *i < edges.len() {
                let w = edges[*i];
                *i += 1;
                if index[w] == usize::MAX {
                    index[w] = next_index;
                    low[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    let e = succ(w);
                    work.push((w, e, 0));
                } else if on_stack[w] {
                    let v = *v;
                    low[v] = low[v].min(index[w]);
                }
            } else {
                let v = *v;
                if low[v] == index[v] {
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w] = false;
                        comp[w] = next_comp;
                        if w == v {
                            break;
                        }
                    }
                    next_comp += 1;
                }
                work.pop();
                if let Some((p, _, _)) = work.last() {
                    let p = *p;
                    low[p] = low[p].min(low[v]);
                }
            }
        }
    }
    comp
}

/// The step cap for confirmation. Hitting it is itself proof of blow-up.
const CONFIRM_CAP: u64 = 20_000_000;

/// Runs the attack at growing pump counts and returns the measured growth if it is at least as bad as
/// `expect`; otherwise `None` (the static guess was not borne out).
fn confirm(nfa: &Nfa, prefix: &[u32], pump: &[u32], suffix: &[u32], expect: Blowup) -> Option<Growth> {
    if pump.is_empty() {
        return None;
    }
    let counts: &[usize] = match expect {
        Blowup::Exponential => &[8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
        Blowup::Polynomial { .. } => &[10, 20, 40, 80, 160, 320, 640],
    };
    let mut samples = Vec::new();
    let mut hit_cap = false;
    for &n in counts {
        let input: Vec<u32> = prefix
            .iter()
            .chain(pump.iter().cycle().take(pump.len() * n))
            .chain(suffix.iter())
            .copied()
            .collect();
        let s: String = input.iter().filter_map(|&c| char::from_u32(c)).collect();
        let run = match_at_start(nfa, &s, CONFIRM_CAP);
        samples.push((n, run.steps));
        if run.outcome == Outcome::StepLimit {
            hit_cap = true;
            break;
        }
    }
    let growth = Growth { samples, hit_cap };
    let ok = match expect {
        Blowup::Exponential => is_exponential(&growth),
        Blowup::Polynomial { .. } => growth_degree(&growth) >= 2,
    };
    ok.then_some(growth)
}

/// Exponential if the step count keeps multiplying (or it hit the cap).
fn is_exponential(growth: &Growth) -> bool {
    if growth.hit_cap {
        return true;
    }
    let s = &growth.samples;
    if s.len() < 4 {
        return false;
    }
    let ratios: Vec<f64> = s.windows(2).map(|w| (w[1].1.max(1) as f64) / (w[0].1.max(1) as f64)).collect();
    let span = s.last().unwrap().1 as f64 / s[0].1.max(1) as f64;
    // Pump counts rise by 2 each step, so a per-pump doubling shows up as a ratio near 4.
    let geometric = ratios.iter().filter(|&&r| r > 1.9).count() >= ratios.len() * 3 / 4;
    geometric && span > 100.0
}

/// The degree of polynomial growth from a log-log fit of steps against pump count (0 if linear).
fn growth_degree(growth: &Growth) -> u32 {
    if growth.hit_cap {
        return u32::MAX;
    }
    let pts: Vec<(f64, f64)> = growth
        .samples
        .iter()
        .filter(|&&(_, steps)| steps > 0)
        .map(|&(n, steps)| ((n as f64).ln(), (steps as f64).ln()))
        .collect();
    if pts.len() < 3 {
        return 0;
    }
    let tail = &pts[pts.len().saturating_sub(4)..];
    let k = tail.len() as f64;
    let sx: f64 = tail.iter().map(|p| p.0).sum();
    let sy: f64 = tail.iter().map(|p| p.1).sum();
    let sxx: f64 = tail.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = tail.iter().map(|p| p.0 * p.1).sum();
    let denom = k * sxx - sx * sx;
    if denom.abs() < 1e-9 {
        return 0;
    }
    let slope = (k * sxy - sx * sy) / denom;
    if slope < 1.5 { 0 } else { slope.round() as u32 }
}
