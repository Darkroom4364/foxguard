use crate::rules::go_taint::GoImportAliases;
use crate::rules::javascript_taint::JsImportAliases;
use crate::rules::python_aliases::ImportAliases;
use crate::rules::{FileContext, RuleRegistry};
use crate::{Finding, Language};
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

/// Result of a scan with metadata.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
}

#[derive(Default)]
struct InlineIgnoreSpec {
    all_rules: bool,
    rule_ids: HashSet<String>,
}

impl InlineIgnoreSpec {
    fn matches(&self, rule_id: &str) -> bool {
        self.all_rules || self.rule_ids.contains(rule_id)
    }

    fn merge(&mut self, other: Self) {
        self.all_rules |= other.all_rules;
        self.rule_ids.extend(other.rule_ids);
    }
}

/// Detect language from file extension.
fn detect_language(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "py" | "pyw" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rb" | "rake" | "gemspec" => Some(Language::Ruby),
        "java" => Some(Language::Java),
        "php" => Some(Language::Php),
        "rs" => Some(Language::Rust),
        "cs" => Some(Language::CSharp),
        "swift" => Some(Language::Swift),
        _ => None,
    }
}

/// Default maximum file size (1 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1_048_576;

/// Scan a directory (or single file) and return findings with metadata.
pub fn scan_directory(root: &str, registry: &RuleRegistry, max_file_size: u64) -> ScanResult {
    let root_path = Path::new(root);

    let files: Vec<_> = if root_path.is_file() {
        if let Some(lang) = detect_language(root_path) {
            vec![(root_path.to_path_buf(), lang)]
        } else {
            vec![]
        }
    } else {
        WalkBuilder::new(root)
            .hidden(true) // skip hidden files
            .git_ignore(true) // respect .gitignore
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .filter_map(|entry| {
                let path = entry.into_path();
                detect_language(&path).map(|lang| (path, lang))
            })
            .collect()
    };

    scan_files(scan_root(root_path), files, registry, max_file_size)
}

/// Scan an explicit list of paths.
pub fn scan_paths(paths: &[PathBuf], registry: &RuleRegistry, max_file_size: u64) -> ScanResult {
    scan_paths_with_root(Path::new("."), paths, registry, max_file_size)
}

/// Scan an explicit list of paths relative to a scan root.
pub fn scan_paths_with_root(
    root: &Path,
    paths: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
) -> ScanResult {
    let files = paths
        .iter()
        .filter_map(|path| detect_language(path).map(|lang| (path.clone(), lang)))
        .collect();
    scan_files(scan_root(root), files, registry, max_file_size)
}

/// Check if a file path is in a directory that typically contains
/// test fixtures, vendored code, or generated assets.
fn is_noise_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let noise_dirs = [
        "/vendor/",
        "/node_modules/",
        "/__fixtures__/",
        "/__mocks__/",
        "/dist/",
        "/build/",
        "/.next/",
        "/coverage/",
        "/.cache/",
    ];
    for dir in &noise_dirs {
        if path_str.contains(dir) {
            return true;
        }
    }
    // Skip .min.js / .min.css files
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if name.contains(".min.") {
        return true;
    }
    false
}

/// Detect minified files: very long lines suggest bundled/compiled code.
fn is_minified(source: &str) -> bool {
    // If file is small, it's not minified
    if source.len() < 2000 {
        return false;
    }
    // Check the first line — minified files usually have one huge line
    if let Some(first_newline) = source.find('\n') {
        if first_newline > 1000 {
            return true;
        }
    } else {
        // No newline at all and file is over 2KB — definitely minified
        return source.len() > 2000;
    }
    // Check average line length
    let line_count = source.bytes().filter(|b| *b == b'\n').count().max(1);
    let avg_line_len = source.len() / line_count;
    avg_line_len > 300
}

fn inline_ignore_regex() -> &'static Regex {
    static INLINE_IGNORE_REGEX: OnceLock<Regex> = OnceLock::new();
    INLINE_IGNORE_REGEX.get_or_init(|| {
        // Accept both "foxguard: ignore" and "foxguard-ignore" forms.
        Regex::new(r"^foxguard(?:\s*:\s*|-\s*)ignore(?:\[(?P<rules>[^\]]*)\])?\s*$")
            .expect("invalid inline ignore regex")
    })
}

/// Regex to extract the content of a `/* ... */` block comment on a single line.
fn block_comment_regex() -> &'static Regex {
    static BLOCK_COMMENT_REGEX: OnceLock<Regex> = OnceLock::new();
    BLOCK_COMMENT_REGEX
        .get_or_init(|| Regex::new(r"/\*(?P<inner>.*?)\*/").expect("invalid block comment regex"))
}

fn inline_ignore_directives(source: &str, language: Language) -> HashMap<usize, InlineIgnoreSpec> {
    let lines: Vec<&str> = source.lines().collect();
    let mut directives = HashMap::new();

    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let Some((comment_only, spec)) = parse_inline_ignore(line, language) else {
            continue;
        };

        let target_line = if comment_only {
            next_code_line(&lines, line_number, language)
        } else {
            Some(line_number)
        };

        if let Some(target_line) = target_line {
            directives
                .entry(target_line)
                .or_insert_with(InlineIgnoreSpec::default)
                .merge(spec);
        }
    }

    directives
}

fn parse_inline_ignore(line: &str, language: Language) -> Option<(bool, InlineIgnoreSpec)> {
    let mut markers = comment_markers(language)
        .iter()
        .copied()
        .flat_map(|marker| {
            let mut positions = Vec::new();
            let mut start = 0;
            while let Some(offset) = line[start..].find(marker) {
                let index = start + offset;
                positions.push((index, marker));
                start = index + marker.len();
            }
            positions
        })
        .collect::<Vec<_>>();

    markers.sort_by_key(|(index, _)| *index);

    for (index, marker) in &markers {
        let comment_text = line[index + marker.len()..].trim();
        let Some(captures) = inline_ignore_regex().captures(comment_text) else {
            continue;
        };

        let spec = build_ignore_spec(&captures);
        let comment_only = line[..*index].trim().is_empty();
        return Some((comment_only, spec));
    }

    // Also check for block comments: /* foxguard: ignore */ or /* foxguard-ignore */
    for cap in block_comment_regex().captures_iter(line) {
        let inner = cap.name("inner").map(|m| m.as_str().trim()).unwrap_or("");
        let Some(captures) = inline_ignore_regex().captures(inner) else {
            continue;
        };

        let spec = build_ignore_spec(&captures);
        let block_start = cap.get(0).unwrap().start();
        let comment_only = line[..block_start].trim().is_empty();
        return Some((comment_only, spec));
    }

    None
}

/// Build an `InlineIgnoreSpec` from regex captures.
fn build_ignore_spec(captures: &regex::Captures<'_>) -> InlineIgnoreSpec {
    let mut spec = InlineIgnoreSpec::default();
    match captures.name("rules").map(|rules| rules.as_str().trim()) {
        None | Some("") => spec.all_rules = true,
        Some(rules) => {
            for rule_id in rules
                .split(',')
                .map(str::trim)
                .filter(|rule| !rule.is_empty())
            {
                spec.rule_ids.insert(rule_id.to_string());
            }
            if spec.rule_ids.is_empty() {
                spec.all_rules = true;
            }
        }
    }
    spec
}

fn next_code_line(lines: &[&str], line_number: usize, language: Language) -> Option<usize> {
    for (index, line) in lines.iter().enumerate().skip(line_number) {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_comment_only_line(trimmed, language) {
            continue;
        }
        return Some(index + 1);
    }
    None
}

fn is_comment_only_line(trimmed_line: &str, language: Language) -> bool {
    comment_markers(language)
        .iter()
        .any(|marker| trimmed_line.starts_with(marker))
}

fn comment_markers(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python | Language::Ruby => &["#"],
        Language::Php => &["//", "#"],
        Language::JavaScript
        | Language::Go
        | Language::Java
        | Language::Rust
        | Language::CSharp
        | Language::Swift => &["//"],
    }
}

fn apply_inline_ignores(
    findings: Vec<Finding>,
    directives: &HashMap<usize, InlineIgnoreSpec>,
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            !(finding.line..=finding.end_line).any(|line| {
                directives
                    .get(&line)
                    .is_some_and(|spec| spec.matches(&finding.rule_id))
            })
        })
        .collect()
}

fn scan_files(
    scan_root: &Path,
    files: Vec<(PathBuf, Language)>,
    registry: &RuleRegistry,
    max_file_size: u64,
) -> ScanResult {
    let start = Instant::now();
    let file_count = files.len();

    let mut results: Vec<Finding> = files
        .par_iter()
        .flat_map(|(path, language)| {
            // Skip files in test/vendor/fixture directories
            if is_noise_path(path) {
                return Vec::new();
            }

            // Skip files exceeding the size limit (fail closed on metadata error)
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    let size = metadata.len();
                    if size > max_file_size {
                        eprintln!(
                            "warning: skipping {} ({} bytes exceeds {} byte limit)",
                            path.display(),
                            size,
                            max_file_size
                        );
                        return Vec::new();
                    }
                }
                Err(_) => {
                    eprintln!(
                        "warning: skipping {} (cannot read file metadata)",
                        path.display()
                    );
                    return Vec::new();
                }
            }

            let Ok(source) = std::fs::read_to_string(path) else {
                return Vec::new();
            };

            // Skip minified files (likely bundled/compiled assets)
            if is_minified(&source) {
                return Vec::new();
            }

            let inline_ignores = inline_ignore_directives(&source, *language);

            let Some(tree) = super::parser::parse_file(&source, *language) else {
                return Vec::new();
            };

            let file_str = path.display().to_string();
            let relative_path = relative_scan_path(scan_root, path);
            let rules = registry.rules_for_language(*language);

            // Per-file analysis context. Python builds an import alias table so
            // rules can resolve aliased callees (`import pickle as p; p.loads(x)`)
            // back to their canonical dotted paths before sink matching.
            let python_aliases = if matches!(language, Language::Python) {
                Some(ImportAliases::from_tree(&source, &tree))
            } else {
                None
            };
            let javascript_aliases = if matches!(language, Language::JavaScript) {
                Some(JsImportAliases::from_tree(&source, &tree))
            } else {
                None
            };
            let go_aliases = if matches!(language, Language::Go) {
                Some(GoImportAliases::from_tree(&source, &tree))
            } else {
                None
            };
            let ctx = FileContext {
                python_aliases: python_aliases.as_ref(),
                javascript_aliases: javascript_aliases.as_ref(),
                go_aliases: go_aliases.as_ref(),
            };

            let mut file_findings = Vec::new();
            for rule in rules {
                if !rule.applies_to_path(&relative_path) {
                    continue;
                }
                let mut rule_findings = rule.check_with_context(&source, &tree, &ctx);
                for f in &mut rule_findings {
                    f.file = file_str.clone();
                }
                let rule_findings = apply_inline_ignores(rule_findings, &inline_ignores);
                file_findings.extend(rule_findings);
            }
            file_findings
        })
        .collect();
    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    ScanResult {
        findings: results,
        files_scanned: file_count,
        duration: start.elapsed(),
    }
}

fn scan_root(path: &Path) -> &Path {
    if path.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        path
    }
}

fn relative_scan_path(scan_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(scan_root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Severity};

    fn make_finding(rule_id: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            cwe: None,
            description: "test finding".to_string(),
            file: "test.py".to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 10,
            snippet: "some_code()".to_string(),
        }
    }

    // ── parse_inline_ignore tests ──────────────────────────────────────

    #[test]
    fn parse_inline_ignore_python_same_line() {
        let result = parse_inline_ignore("x = dangerous()  # foxguard: ignore", Language::Python);
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(!comment_only);
        assert!(spec.all_rules);
    }

    #[test]
    fn parse_inline_ignore_python_standalone() {
        let result = parse_inline_ignore("  # foxguard: ignore", Language::Python);
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(comment_only);
        assert!(spec.all_rules);
    }

    #[test]
    fn parse_inline_ignore_with_specific_rule_id() {
        let result = parse_inline_ignore(
            "x = foo()  # foxguard: ignore[sql-injection]",
            Language::Python,
        );
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(!comment_only);
        assert!(!spec.all_rules);
        assert!(spec.rule_ids.contains("sql-injection"));
    }

    #[test]
    fn parse_inline_ignore_with_multiple_rule_ids() {
        let result = parse_inline_ignore(
            "x = foo()  # foxguard: ignore[sql-injection, xss]",
            Language::Python,
        );
        assert!(result.is_some());
        let (_, spec) = result.unwrap();
        assert!(!spec.all_rules);
        assert!(spec.rule_ids.contains("sql-injection"));
        assert!(spec.rule_ids.contains("xss"));
    }

    #[test]
    fn parse_inline_ignore_block_comment_same_line() {
        let result = parse_inline_ignore(
            "x = dangerous() /* foxguard: ignore */",
            Language::JavaScript,
        );
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(!comment_only);
        assert!(spec.all_rules);
    }

    #[test]
    fn parse_inline_ignore_block_comment_standalone() {
        let result = parse_inline_ignore("  /* foxguard: ignore */", Language::JavaScript);
        assert!(result.is_some());
        let (comment_only, _) = result.unwrap();
        assert!(comment_only);
    }

    #[test]
    fn parse_inline_ignore_block_comment_with_rule() {
        let result = parse_inline_ignore(
            "x = foo() /* foxguard: ignore[xss] */",
            Language::JavaScript,
        );
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(!comment_only);
        assert!(!spec.all_rules);
        assert!(spec.rule_ids.contains("xss"));
    }

    #[test]
    fn parse_inline_ignore_hyphen_form() {
        let result = parse_inline_ignore("x = foo()  # foxguard-ignore", Language::Python);
        assert!(result.is_some());
        let (_, spec) = result.unwrap();
        assert!(spec.all_rules);
    }

    #[test]
    fn parse_inline_ignore_js_double_slash() {
        let result =
            parse_inline_ignore("let x = eval(s); // foxguard: ignore", Language::JavaScript);
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(!comment_only);
        assert!(spec.all_rules);
    }

    #[test]
    fn parse_inline_ignore_no_directive() {
        let result = parse_inline_ignore("x = dangerous()", Language::Python);
        assert!(result.is_none());
    }

    #[test]
    fn parse_inline_ignore_unrelated_comment() {
        let result = parse_inline_ignore(
            "x = foo()  # this is not a foxguard directive",
            Language::Python,
        );
        assert!(result.is_none());
    }

    // ── inline_ignore_directives tests ─────────────────────────────────

    #[test]
    fn directives_same_line_suppresses_that_line() {
        let source = "x = dangerous()  # foxguard: ignore\n";
        let directives = inline_ignore_directives(source, Language::Python);
        assert!(directives.contains_key(&1));
        assert!(directives.get(&1).unwrap().matches("any-rule"));
    }

    #[test]
    fn directives_line_above_suppresses_next_code_line() {
        let source = "# foxguard: ignore\nx = dangerous()\n";
        let directives = inline_ignore_directives(source, Language::Python);
        assert!(directives.contains_key(&2));
        assert!(!directives.contains_key(&1));
    }

    #[test]
    fn directives_line_above_with_blank_lines_skips_blanks() {
        let source = "# foxguard: ignore\n\n# another comment\nx = dangerous()\n";
        let directives = inline_ignore_directives(source, Language::Python);
        assert!(directives.contains_key(&4));
    }

    #[test]
    fn directives_separated_by_distant_code_does_not_suppress() {
        let source = "# foxguard: ignore\n\nx = safe()\ny = also_safe()\nz = dangerous()\n";
        let directives = inline_ignore_directives(source, Language::Python);
        // Targets line 3 only (x = safe()), not line 5
        assert!(directives.contains_key(&3));
        assert!(!directives.contains_key(&5));
    }

    #[test]
    fn directives_specific_rule_only_matches_that_rule() {
        let source = "x = foo()  # foxguard: ignore[sql-injection]\n";
        let directives = inline_ignore_directives(source, Language::Python);
        let spec = directives.get(&1).unwrap();
        assert!(spec.matches("sql-injection"));
        assert!(!spec.matches("xss"));
    }

    #[test]
    fn directives_multiple_ignores_in_same_file() {
        let source = concat!(
            "x = foo()  # foxguard: ignore[sql-injection]\n",
            "y = bar()\n",
            "# foxguard: ignore\n",
            "z = baz()\n",
        );
        let directives = inline_ignore_directives(source, Language::Python);
        // Line 1: specific rule ignore
        assert!(directives.get(&1).unwrap().matches("sql-injection"));
        assert!(!directives.get(&1).unwrap().matches("xss"));
        // Line 4: blanket ignore (from standalone directive on line 3)
        assert!(directives.get(&4).unwrap().matches("any-rule"));
    }

    #[test]
    fn directives_ignore_at_end_of_file_same_line() {
        let source = "x = dangerous()  # foxguard: ignore";
        let directives = inline_ignore_directives(source, Language::Python);
        assert!(directives.contains_key(&1));
    }

    #[test]
    fn directives_standalone_ignore_at_eof_no_following_code() {
        let source = "x = safe()\n# foxguard: ignore\n";
        let directives = inline_ignore_directives(source, Language::Python);
        assert!(directives.is_empty());
    }

    // ── apply_inline_ignores tests ─────────────────────────────────────

    #[test]
    fn apply_ignores_suppresses_matching_finding() {
        let mut directives = HashMap::new();
        directives.insert(
            5,
            InlineIgnoreSpec {
                all_rules: true,
                rule_ids: HashSet::new(),
            },
        );
        let findings = vec![make_finding("xss", 5)];
        let result = apply_inline_ignores(findings, &directives);
        assert!(result.is_empty());
    }

    #[test]
    fn apply_ignores_keeps_non_matching_finding() {
        let mut directives = HashMap::new();
        directives.insert(
            10,
            InlineIgnoreSpec {
                all_rules: true,
                rule_ids: HashSet::new(),
            },
        );
        let findings = vec![make_finding("xss", 5)];
        let result = apply_inline_ignores(findings, &directives);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn apply_ignores_specific_rule_suppresses_only_matching() {
        let mut rule_ids = HashSet::new();
        rule_ids.insert("sql-injection".to_string());
        let mut directives = HashMap::new();
        directives.insert(
            5,
            InlineIgnoreSpec {
                all_rules: false,
                rule_ids,
            },
        );
        let findings = vec![make_finding("sql-injection", 5), make_finding("xss", 5)];
        let result = apply_inline_ignores(findings, &directives);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "xss");
    }

    #[test]
    fn apply_ignores_multiline_finding() {
        let mut directives = HashMap::new();
        directives.insert(
            6,
            InlineIgnoreSpec {
                all_rules: true,
                rule_ids: HashSet::new(),
            },
        );
        let mut finding = make_finding("xss", 5);
        finding.end_line = 7;
        let result = apply_inline_ignores(vec![finding], &directives);
        assert!(result.is_empty());
    }

    #[test]
    fn apply_ignores_empty_directives_keeps_all() {
        let directives = HashMap::new();
        let findings = vec![make_finding("xss", 1), make_finding("sqli", 2)];
        let result = apply_inline_ignores(findings, &directives);
        assert_eq!(result.len(), 2);
    }

    // ── Integration: block comment in JavaScript ───────────────────────

    #[test]
    fn block_comment_ignore_in_js() {
        let source = "let x = eval(s); /* foxguard: ignore */\nlet y = eval(t);\n";
        let directives = inline_ignore_directives(source, Language::JavaScript);
        assert!(directives.contains_key(&1));
        assert!(!directives.contains_key(&2));
    }

    #[test]
    fn block_comment_standalone_targets_next_line() {
        let source = "/* foxguard: ignore */\nlet x = eval(s);\n";
        let directives = inline_ignore_directives(source, Language::JavaScript);
        assert!(directives.contains_key(&2));
        assert!(!directives.contains_key(&1));
    }
}
