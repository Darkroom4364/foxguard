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
        file: String::new(), // filled in by scanner
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
        "js/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval() allows arbitrary code execution"
    }
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Look for call_expression where the function is `eval`
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "eval" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            self.description(),
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
        "js/no-hardcoded-secret"
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
        Language::JavaScript
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern = Regex::new(
            r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)"
        )
        .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // variable_declarator: const password = "hardcoded"
            if node.kind() == "variable_declarator" {
                if let (Some(name_node), Some(value_node)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    let name = &src[name_node.byte_range()];
                    let value_kind = value_node.kind();
                    if secret_pattern.is_match(name)
                        && (value_kind == "string" || value_kind == "template_string")
                    {
                        let val = &src[value_node.byte_range()];
                        // Skip empty strings and short placeholders
                        let inner = val.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret in variable '{}' — avoid committing credentials",
                                    name
                                ),
                                node,
                                src,
                            ));
                        }
                    }
                }
            }

            // assignment_expression: obj.password = "hardcoded"
            if node.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    let right_kind = right.kind();
                    if secret_pattern.is_match(left_text)
                        && (right_kind == "string" || right_kind == "template_string")
                    {
                        let val = &src[right.byte_range()];
                        let inner = val.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret assigned to '{}' — use environment variables instead",
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
        "js/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string concatenation or template literal"
    }
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_pattern = Regex::new(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s"
        )
        .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: query("SELECT * FROM users WHERE id = " + userId)
            if node.kind() == "binary_expression" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "+" {
                        if let Some(left) = node.child_by_field_name("left") {
                            let left_text = &src[left.byte_range()];
                            if (left.kind() == "string" || left.kind() == "template_string")
                                && sql_pattern.is_match(left_text)
                            {
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

            // Detect template literals with SQL: `SELECT * FROM users WHERE id = ${id}`
            if node.kind() == "template_string" {
                let text = &src[node.byte_range()];
                if sql_pattern.is_match(text) {
                    // Check it has interpolation
                    let mut cursor = node.walk();
                    let has_substitution = node
                        .children(&mut cursor)
                        .any(|c| c.kind() == "template_substitution");
                    if has_substitution {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "SQL query built with template literal interpolation — use parameterized queries",
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

// ─── Rule 4: no-xss-innerhtml ────────────────────────────────────────────────

pub struct NoXssInnerHtml;

impl Rule for NoXssInnerHtml {
    fn id(&self) -> &str {
        "js/no-xss-innerhtml"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-79")
    }
    fn description(&self) -> &str {
        "Assignment to innerHTML may lead to XSS"
    }
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment_expression where left side ends with .innerHTML
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "member_expression" {
                        if let Some(prop) = left.child_by_field_name("property") {
                            let prop_text = &src[prop.byte_range()];
                            if prop_text == "innerHTML" || prop_text == "outerHTML" {
                                // Check if right side is NOT a string literal (string literals are usually safe)
                                if let Some(right) = node.child_by_field_name("right") {
                                    if right.kind() != "string" {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            &format!(
                                                "Assignment to {} with dynamic content — use textContent or sanitize HTML",
                                                prop_text
                                            ),
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
        });
        findings
    }
}

// ─── Rule 5: no-command-injection ────────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "js/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via exec/spawn with dynamic input"
    }
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let dangerous_fns = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];

                    // Match child_process.exec(...) or exec(...)
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);

                    if dangerous_fns.contains(&func_name) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let kind = first_arg.kind();
                                // Flag if the argument is not a plain string literal
                                // (template strings with substitution, identifiers, binary expressions, etc.)
                                let is_dynamic = match kind {
                                    "string" => false,
                                    "template_string" => {
                                        let mut cursor = first_arg.walk();
                                        let has_sub = first_arg
                                            .children(&mut cursor)
                                            .any(|c| c.kind() == "template_substitution");
                                        has_sub
                                    }
                                    _ => true,
                                };

                                if is_dynamic {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{}() called with dynamic argument — risk of command injection",
                                            func_name
                                        ),
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
