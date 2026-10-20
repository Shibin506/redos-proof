//! Phase 4: scanning source trees for vulnerable regexes, and the SARIF output.

use std::fs;
use std::path::PathBuf;

use redos_proof::analysis::Blowup;
use redos_proof::scan::scan_paths;

/// A throwaway directory holding the files for one test.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("redos-scan-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Fixture { dir }
    }

    fn write(&self, rel: &str, contents: &str) -> &Self {
        let path = self.dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        self
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn scans_a_mixed_tree_and_skips_the_right_things() {
    let fx = Fixture::new("mixed");
    fx.write(
        "src/app.js",
        "const re = /(a+)+$/;\nconst ok = /^[a-z]+$/;\nconst d = a / b / c;\nconst r = new RegExp('(\\\\d+)*$');\n",
    )
    .write(
        "lib/val.py",
        "import re\nBAD = re.compile(r'(.*,)*$')\nOK = re.compile(r'\\\\d{4}')\n",
    )
    .write("lib/thing.rb", "A = /(x+x+)+y/\nB = /\\\\A\\\\d+\\\\z/\n")
    .write("node_modules/dep.js", "const bad = /(a+)+$/;\n")
    .write("README.md", "This file /(a+)+$/ is not code.\n");

    let report = scan_paths(std::slice::from_ref(&fx.dir), false, 2 << 20);

    // node_modules and the Markdown file are not scanned; the three source files are.
    assert_eq!(report.files_scanned, 3, "scanned files");
    let found: Vec<String> = report.hits.iter().map(|h| h.literal.pattern.clone()).collect();
    assert!(found.contains(&"(a+)+$".to_string()), "JS literal: {found:?}");
    assert!(found.contains(&"(\\d+)*$".to_string()), "JS RegExp constructor: {found:?}");
    assert!(found.contains(&"(.*,)*$".to_string()), "Python raw string: {found:?}");
    assert!(found.contains(&"(x+x+)+y".to_string()), "Ruby literal: {found:?}");
    // Safe patterns and division are not flagged.
    assert!(
        !found.iter().any(|p| p.contains("[a-z]") || p.contains("d{4}")),
        "safe patterns flagged: {found:?}"
    );
    assert!(
        report.hits.iter().all(|h| !h.file.to_string_lossy().contains("node_modules")),
        "node_modules scanned"
    );
    // All four of these are exponential.
    assert!(
        report.hits.iter().all(|h| matches!(h.finding.blowup, Blowup::Exponential)),
        "{found:?}"
    );
    assert_eq!(report.hits.len(), 4);
}

#[test]
fn a_clean_tree_has_no_hits() {
    let fx = Fixture::new("clean");
    fx.write("a.js", "const r = /^[a-z0-9_]+@[a-z]+\\.[a-z]+$/;\nconst n = x / y;\n")
        .write("b.py", "import re\nre.compile(r'\\\\d{4}-\\\\d{2}-\\\\d{2}')\n");
    let report = scan_paths(std::slice::from_ref(&fx.dir), false, 2 << 20);
    assert!(
        report.hits.is_empty(),
        "{:?}",
        report.hits.iter().map(|h| &h.literal.pattern).collect::<Vec<_>>()
    );
    assert_eq!(report.regexes_scanned, 2);
}

#[test]
fn hits_are_sorted_most_severe_first() {
    let fx = Fixture::new("severity");
    fx.write("a.js", "const poly = /.*.*=.*/;\nconst exp = /(a+)+$/;\n");
    let report = scan_paths(std::slice::from_ref(&fx.dir), false, 2 << 20);
    assert!(report.hits.len() >= 2);
    assert!(
        matches!(report.hits[0].finding.blowup, Blowup::Exponential),
        "exponential should sort first"
    );
}

#[test]
fn line_and_column_point_at_the_regex() {
    let fx = Fixture::new("loc");
    fx.write("x.js", "// header\n// another\nconst bad = /(a+)+$/;\n");
    let report = scan_paths(std::slice::from_ref(&fx.dir), false, 2 << 20);
    let hit = &report.hits[0];
    assert_eq!(hit.literal.line, 3);
    assert_eq!(hit.literal.col, 13, "column of the opening slash");
}
