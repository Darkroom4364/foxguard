use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn get_source_line(source: &str, byte_offset: usize) -> String {
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

fn walk_tree(
    node: tree_sitter::Node,
    source: &str,
    callback: &mut dyn FnMut(tree_sitter::Node, &str),
) {
    callback(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, source, callback);
    }
}

fn make_finding(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    node: tree_sitter::Node,
    source: &str,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet: get_source_line(source, node.start_byte()),
    }
}

// ─── Rule 1: no-eval ─────────────────────────────────────────────────────────

pub struct NoEval;

impl Rule for NoEval {
    fn id(&self) -> &str {
        "py/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval()/exec() allows arbitrary code execution"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "eval" || func_text == "exec" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}() allows arbitrary code execution — avoid using it with untrusted input",
                                func_text
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 2: no-hardcoded-secret ─────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "py/no-hardcoded-secret"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Hardcoded secret or credential detected"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern = Regex::new(
            r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)"
        )
        .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment: password = "hardcoded"
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) && right.kind() == "string" {
                        let val = &src[right.byte_range()];
                        // Strip quotes and check length
                        let inner = val
                            .trim_start_matches("f\"")
                            .trim_start_matches("f'")
                            .trim_matches(|c| c == '"' || c == '\'');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret in '{}' — use environment variables or a secrets manager",
                                    left_text
                                ),
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 3: no-sql-injection ────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "py/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string formatting"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_pattern = Regex::new(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s"
        )
        .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect f-strings with SQL: f"SELECT * FROM users WHERE id = {user_id}"
            if node.kind() == "string" {
                let text = &src[node.byte_range()];
                if text.starts_with("f\"") || text.starts_with("f'") || text.starts_with("f\"\"\"") {
                    if sql_pattern.is_match(text) {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "SQL query built with f-string — use parameterized queries",
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect: "SELECT ... WHERE id = %s" % user_id
            if node.kind() == "binary_operator" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "%" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if left.kind() == "string" {
                                let text = &src[left.byte_range()];
                                if sql_pattern.is_match(text) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "SQL query built with % formatting — use parameterized queries",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Detect: "SELECT ... WHERE id = {}".format(user_id)
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "attribute" {
                        if let Some(attr) = func.child_by_field_name("attribute") {
                            if &src[attr.byte_range()] == "format" {
                                if let Some(obj) = func.child_by_field_name("object") {
                                    if obj.kind() == "string" {
                                        let text = &src[obj.byte_range()];
                                        if sql_pattern.is_match(text) {
                                            findings.push(make_finding(
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
                                                "SQL query built with .format() — use parameterized queries",
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Detect string concatenation with SQL: "SELECT * FROM users WHERE id = " + user_id
            if node.kind() == "binary_operator" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "+" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if left.kind() == "string" {
                                let text = &src[left.byte_range()];
                                if sql_pattern.is_match(text) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "SQL query built with string concatenation — use parameterized queries",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}
