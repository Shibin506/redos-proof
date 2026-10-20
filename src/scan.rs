//! Phase 4: scan files and directories for vulnerable regexes.
//!
//! Walks a path, extracts regex literals from each source file ([`crate::source`]), analyses each one
//! ([`crate::analysis`]), and optionally proves the findings on the real engine ([`crate::prove`]).

use std::fs;
use std::path::{Path, PathBuf};

use crate::analysis::{Blowup, Finding, analyze};
use crate::ast::Dialect;
use crate::nfa::compile;
use crate::parser::Flags;
use crate::prove::{Proof, Verdict, prove};
use crate::source::{Literal, dialect_for, extract};

/// One vulnerable regex found in a file.
#[derive(Debug)]
pub struct Hit {
    pub file: PathBuf,
    pub literal: Literal,
    pub finding: Finding,
    /// Present when `--prove` ran the attack on the real engine.
    pub proof: Option<Proof>,
}

impl Hit {
    /// Whether the real engine reproduced the blow-up (or proving was not requested but the model flagged it).
    pub fn is_confirmed_on_engine(&self) -> bool {
        matches!(
            self.proof.as_ref().and_then(|p| p.verdict),
            Some(Verdict::Exponential | Verdict::Polynomial { .. })
        )
    }
}

/// Directories never worth scanning.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
];

/// The result of scanning one or more paths.
#[derive(Debug, Default)]
pub struct Report {
    pub hits: Vec<Hit>,
    pub files_scanned: usize,
    pub regexes_scanned: usize,
    /// Files skipped because the pattern used a feature the analysis cannot model.
    pub unanalysable: usize,
}

/// Scans `paths` (files or directories). `max_bytes` skips files larger than this (generated/minified code).
pub fn scan_paths(paths: &[PathBuf], prove_on_engine: bool, max_bytes: u64) -> Report {
    let mut report = Report::default();
    let mut files = Vec::new();
    for p in paths {
        collect_files(p, &mut files);
    }
    for file in files {
        let Some(dialect) = dialect_for(&file) else { continue };
        let Ok(meta) = fs::metadata(&file) else { continue };
        if meta.len() > max_bytes {
            continue;
        }
        let Ok(text) = fs::read_to_string(&file) else { continue };
        report.files_scanned += 1;
        for literal in extract(dialect, &text) {
            report.regexes_scanned += 1;
            scan_literal(&file, literal, dialect, prove_on_engine, &mut report);
        }
    }
    // Most severe first, then by file and line.
    report.hits.sort_by(|a, b| {
        severity(a)
            .cmp(&severity(b))
            .then(a.file.cmp(&b.file))
            .then(a.literal.line.cmp(&b.literal.line))
    });
    report
}

fn scan_literal(file: &Path, literal: Literal, dialect: Dialect, prove_on_engine: bool, report: &mut Report) {
    let Ok(flags) = Flags::parse(dialect, &literal.flags) else { return };
    let Ok(regex) = crate::parser::parse(&literal.pattern, dialect, flags) else {
        return;
    };
    let Ok(nfa) = compile(&regex) else {
        report.unanalysable += 1;
        return;
    };
    let Ok(findings) = analyze(&nfa) else {
        report.unanalysable += 1;
        return;
    };
    let Some(finding) = findings.into_iter().next() else { return };
    let proof = prove_on_engine.then(|| prove(&literal.pattern, dialect, flags, &finding));
    report.hits.push(Hit {
        file: file.to_path_buf(),
        literal,
        finding,
        proof,
    });
}

fn severity(h: &Hit) -> u32 {
    match h.finding.blowup {
        Blowup::Exponential => 0,
        Blowup::Polynomial { degree } => 100u32.saturating_sub(degree),
    }
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(path) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if !p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| SKIP_DIRS.contains(&n) || n.starts_with('.') && n.len() > 1)
            {
                collect_files(&p, out);
            }
        } else {
            out.push(p);
        }
    }
}
