# Foxguard Launch Content

Best posting time: **Tuesday 9:00 AM ET** (15:00 CET)

---

## 1. Show HN Post

### Title Options

- **Option A:** `Show HN: Foxguard – security linter that runs between your AI and your codebase (Rust)`
- **Option B:** `Show HN: Foxguard – Semgrep-compatible security linter in Rust, built for AI-generated code`

### First Comment (Maker's Story)

> Hey HN, I'm Doruk (Peak Twilight). I built Foxguard because I kept hitting the same wall: AI-generated code that compiles, passes tests, and ships with security bugs.
>
> **The problem:** 80% of AI-generated code that passes functional tests still contains security vulnerabilities — hardcoded secrets, missing auth checks, SQL injection via string interpolation, framework misconfigurations. The code works. It's just not safe.
>
> Every SAST tool that catches these issues — Semgrep, Bandit, ESLint security plugins — is designed for CI. They take 30+ seconds on a medium repo. That's fine for a pipeline, but useless when your AI agent is generating 50 files in a session and you need to catch problems before they compound.
>
> **The insight:** Security linting needs to move from CI into the generation loop. If you can lint in under 100ms, you can run it on every save, in your editor, as a pre-commit hook, or as a gate between your AI and your codebase. That changes the entire dynamic — you catch bugs at write-time instead of review-time.
>
> **What Foxguard does:**
> - 36 built-in rules focused on what AI gets wrong: scaffold secrets, missing auth, framework misconfiguration
> - Semgrep YAML rule compatibility — bring your existing rules, run them on the Rust engine
> - Tree-sitter AST parsing (no regex — we understand code structure)
> - <100ms on typical projects. Fast enough for the edit-save-lint loop.
> - SARIF output for CI/CD integration (GitHub Advanced Security, GitLab SAST)
> - Single binary, zero config, zero dependencies
>
> **Speed:**
>
> | Tool | 10K LOC repo | 50K LOC repo |
> |---|---|---|
> | Semgrep (25 rules) | 8.2s | 34.1s |
> | Foxguard (36 rules) | 0.04s | 0.18s |
>
> Semgrep is great for CI. Foxguard is fast enough for your editor.
>
> **Why Semgrep compatibility?** Teams have invested years building custom Semgrep YAML rules. We don't want you to throw those away. Foxguard reads the same YAML rule format and runs it on a Rust engine with tree-sitter parsing. Same rules, 100x faster.
>
> **Architecture:** Rust + tree-sitter + rayon. Same playbook as Ruff. Tree-sitter gives us real AST analysis (not regex), rayon gives us parallelism, Rust gives us predictable sub-100ms latency and single-binary distribution.
>
> **What's next:**
> - Taint tracking for data-flow analysis
> - VS Code / Cursor extension (lint-on-save)
> - More framework-specific rules (Express, Flask, Django, Gin)
> - Plugin system for custom rules
>
> MIT licensed. Install with `cargo install foxguard` or `npx foxguard`.
>
> GitHub: https://github.com/peaktwilight/foxguard
> Site: https://foxguard.dev
>
> What rules would you want for AI-generated code? I'm prioritizing based on what developers actually hit.

---

## 2. Reddit Posts

### r/rust

**Title:** `Foxguard: Semgrep-compatible security linter in Rust — built for AI-generated code, <100ms scans`

**Body:**

I just released Foxguard, a security linter written in Rust that's designed to sit between AI code generation and your codebase. Wanted to share the architecture with this community since Rust made the core insight possible: security linting fast enough to run in the editor, not just CI.

**Why this matters now:**

80% of AI-generated code that passes functional tests still has security bugs. The existing tools to catch them (Semgrep, Bandit) are designed for CI pipelines — 30+ seconds per scan. That's fine for a nightly build, but useless when Copilot or Cursor is generating code in real-time.

Foxguard runs in <100ms. That's fast enough for on-save linting, pre-commit hooks, or as a gate in the AI generation loop.

**Architecture:**

- **tree-sitter** for parsing — each language gets a tree-sitter grammar, and rules are written as tree-sitter queries against the CST. No regex. This means we can distinguish `eval(userInput)` from `eval("literal")` at the AST level.
- **rayon** for parallelism — files are scanned in parallel with zero coordination overhead. On an 8-core machine, scanning 50K LOC takes ~0.18s.
- **Semgrep YAML compatibility** — the rule engine reads Semgrep's YAML format, so teams can bring their existing rules and run them on the Rust engine. Same syntax, 100x faster.

**Example rule definition (simplified):**

```rust
Rule {
    id: "JS-SQLI-001",
    severity: High,
    cwe: "CWE-89",
    query: r#"
        (call_expression
            function: (member_expression
                property: (property_identifier) @method)
            arguments: (arguments
                (template_string) @query)
            (#eq? @method "query"))
    "#,
}
```

**Benchmarks:**

```
$ hyperfine 'foxguard scan ./project' 'semgrep --config auto ./project'

Foxguard:  0.04s ± 0.003s
Semgrep:   8.2s  ± 0.41s
```

**What's in it:**

- 36 built-in rules focused on what AI gets wrong (scaffold secrets, missing auth, framework misconfig)
- Semgrep YAML rule compatibility
- CWE mappings for every rule
- SARIF output for GitHub/GitLab integration
- Framework-aware: Express, Flask, Django, Gin
- Single binary, `cargo install foxguard`

MIT licensed: https://github.com/peaktwilight/foxguard

Feedback on the Rust architecture is very welcome — particularly around the Semgrep compatibility layer and rule engine design.

---

### r/netsec

**Title:** `Foxguard: Semgrep-compatible SAST tool in Rust — 36 rules targeting AI-generated code vulnerabilities`

**Body:**

Releasing Foxguard, an open-source SAST tool built specifically for the AI code generation era. The core idea: security linting needs to move from CI into the generation loop.

**The problem:** 80% of AI-generated code that passes functional tests still contains security vulnerabilities. Not exotic bugs — the same CWEs we've been fighting for a decade: hardcoded secrets, missing auth, SQL injection, framework misconfigurations. AI is great at producing code that works. It's terrible at producing code that's secure.

**What it catches (sample):**

| Rule ID | CWE | Description |
|---|---|---|
| JS-SQLI-001 | CWE-89 | SQL injection via string concatenation/template literals |
| PY-CMDI-001 | CWE-78 | OS command injection via subprocess with shell=True |
| GO-PATH-001 | CWE-22 | Path traversal via unsanitized user input in file operations |
| JS-XSS-001 | CWE-79 | DOM XSS via innerHTML/document.write with dynamic data |
| PY-DESER-001 | CWE-502 | Unsafe deserialization via pickle.loads |
| GO-SQLI-001 | CWE-89 | SQL injection via fmt.Sprintf in query construction |
| JS-CRYPTO-001 | CWE-327 | Use of weak cryptographic algorithms (MD5, SHA1 for security) |
| PY-SSRF-001 | CWE-918 | Server-side request forgery via unvalidated URL in requests |

36 rules total across JavaScript/TypeScript, Python, and Go. Every rule maps to a CWE. Framework-aware for Express, Flask, Django, and Gin.

**Key differentiator:** Foxguard reads Semgrep YAML rules. If your team has invested in custom Semgrep rules, you can run them on Foxguard's Rust engine — same syntax, 100x faster. Fast enough (<100ms) to run in-editor, on save, or as a gate between your AI agent and your codebase.

**CI/CD integration:**

```yaml
# GitHub Actions
- name: Security scan
  run: |
    cargo install foxguard
    foxguard scan ./src --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The scan runs in 0.04s on a 10K LOC project, so it adds effectively zero time to your pipeline. But the real value is running it before CI — in the editor, on save, in the AI generation loop.

MIT licensed. Single binary. No cloud dependency. No telemetry.

https://github.com/peaktwilight/foxguard
https://foxguard.dev

What rules would you want for AI-generated code? I'm prioritizing based on what's actually shipping in production.

---

### r/programming

**Title:** `Foxguard: a Semgrep-compatible security linter in Rust — fast enough to run between your AI and your codebase`

**Body:**

Here's a stat that should worry everyone using Copilot or Cursor: 80% of AI-generated code that passes functional tests still has security bugs. Not edge cases — hardcoded secrets, missing auth checks, SQL injection via string interpolation.

The tools to catch these exist (Semgrep is excellent). But they're designed for CI — 30+ seconds on a medium project. That's fine for a pipeline. It's useless when your AI is generating code in real-time and you need feedback before the next prompt.

So I built Foxguard. It's a Rust-powered security linter that runs in <100ms. Fast enough for on-save linting, pre-commit hooks, or as a gate in the AI generation loop.

**The workflow:**

```
AI writes code → foxguard checks (60ms) → fix → commit
```

**The "just run it" experience:**

```bash
# Install
cargo install foxguard

# Scan
foxguard scan .

# Output
src/api/users.js:42:5  HIGH  JS-SQLI-001
  SQL injection: template literal used in database query
  → const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`)

src/auth/login.py:18:1  HIGH  PY-CMDI-001
  Command injection: subprocess call with shell=True and f-string argument
  → subprocess.run(f"echo {user_input}", shell=True)

src/server/handler.go:67:3  MEDIUM  GO-PATH-001
  Path traversal: user-controlled input in filepath.Join
  → path := filepath.Join(baseDir, r.URL.Query().Get("file"))

Found 3 issues (2 high, 1 medium) in 0.04s
```

**Key features:**

- 36 built-in rules focused on what AI gets wrong
- **Semgrep YAML compatibility** — bring your existing rules, run them on the Rust engine
- Framework-aware: Express, Flask, Django, Gin
- tree-sitter AST parsing (not regex)
- SARIF output for GitHub/GitLab integration

**Comparison:**

| | Foxguard | Semgrep | Bandit |
|---|---|---|---|
| 10K LOC | 0.04s | 8.2s | 4.1s |
| Language | Rust | Python/OCaml | Python |
| Semgrep rules | Compatible | Native | No |
| Best for | Editor + CI | CI | CI |
| Rules | 36 built-in | 2000+ (community) | 70+ |

Semgrep has way more rules and deeper analysis — no question. Foxguard is complementary: same rule format, fast enough for the places Semgrep can't go (your editor, your pre-commit hook, your AI generation loop).

MIT licensed: https://github.com/peaktwilight/foxguard

---

### r/cybersecurity

**Title:** `Open-source SAST tool for AI-generated code: 36 rules, Semgrep-compatible, <100ms scans (Rust)`

**Body:**

For those of you dealing with the security implications of AI-generated code — I built an open-source SAST tool called Foxguard that's designed to catch what AI gets wrong, fast enough to run in the development loop instead of just CI.

**The problem:** I come from a SOC background (Migros Security Operations Center). The same CWEs kept coming through — SQL injection, hardcoded secrets, missing auth, framework misconfigs. Now with AI code generation, the volume of these bugs is accelerating. 80% of AI-generated code that passes tests still has security vulnerabilities. AI writes code that works but isn't safe.

**What Foxguard does:**

- 36 security rules focused on what AI gets wrong: scaffold boilerplate, hardcoded secrets, missing auth, framework misconfiguration
- Semgrep YAML rule compatibility — bring your existing rules, run them 100x faster
- Framework-aware: Express, Flask, Django, Gin
- Every rule maps to a CWE and OWASP Top 10 category
- SARIF output for direct integration with GitHub Advanced Security or GitLab SAST
- <100ms on typical projects

**The key insight:** Shift-left only works if the tooling is fast enough. Foxguard is fast enough to run in-editor, on save, as a pre-commit hook, or as a gate between your AI agent and your codebase. Not just CI.

**CI/CD integration examples:**

GitHub Actions:
```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Foxguard
        run: cargo install foxguard
      - name: Run security scan
        run: foxguard scan ./src --format sarif --output foxguard.sarif
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: foxguard.sarif
```

Pre-commit hook:
```bash
#!/bin/sh
foxguard scan --staged-only
```

MIT licensed, single binary, no telemetry, no cloud dependency.

GitHub: https://github.com/peaktwilight/foxguard
Docs: https://foxguard.dev

What rules would you want for AI-generated code? What CWEs are you seeing most from Copilot/Cursor output?

---

## 3. Twitter/X Thread (@Peak_Twilight)

**Tweet 1 (Hook):**

Your AI writes code that compiles, passes tests, and ships with security bugs.

I built a security linter in Rust that catches them in 60ms — fast enough to run between your AI and your codebase.

It's called Foxguard. Here's why it exists:

[thread]

---

**Tweet 2 (Problem):**

80% of AI-generated code that passes functional tests still has security vulnerabilities.

Hardcoded secrets. Missing auth. SQL injection. Framework misconfigs.

The code works. It's just not safe. And existing SAST tools are too slow to catch it before it compounds.

---

**Tweet 3 (Insight):**

The insight: security linting needs to move from CI into the generation loop.

Semgrep takes 30+ seconds. That's fine for a pipeline.

But when your AI agent is generating 50 files in a session, you need feedback in milliseconds, not minutes.

---

**Tweet 4 (What it does):**

What Foxguard does:

- 36 built-in rules focused on what AI gets wrong
- Semgrep YAML compatibility (bring your existing rules)
- <100ms on typical projects
- Framework-aware: Express, Flask, Django, Gin
- Tree-sitter AST parsing, not regex

The workflow: AI writes code → foxguard checks (60ms) → fix → commit

---

**Tweet 5 (Speed benchmark):**

Speed comparison on a 10K LOC project:

Semgrep: 8.2 seconds
Foxguard: 0.04 seconds

Semgrep is great for CI. Foxguard is fast enough for your editor.

Same rule format. Rust engine. 100x faster.

---

**Tweet 6 (Semgrep compat):**

The Semgrep compatibility matters.

Teams have invested years building custom YAML rules. Foxguard reads the same format and runs it on a Rust engine.

Don't throw away your rules. Just run them faster — fast enough for places Semgrep can't go (editor, pre-commit, AI loop).

---

**Tweet 7 (Install):**

Try it in 10 seconds:

```
cargo install foxguard
foxguard scan .
```

Or: `npx foxguard`

No config. No Docker. No cloud account. One binary, one command. SARIF output for GitHub/GitLab.

---

**Tweet 8 (GitHub link):**

Foxguard is MIT licensed and 100% open source.

GitHub: github.com/peaktwilight/foxguard
Docs: foxguard.dev

Star it if this is useful. I'm building this in public.

---

**Tweet 9 (Background):**

Background: I come from a SOC at Migros. Same CWEs hit production over and over — SQLi, hardcoded secrets, missing auth.

Now AI is generating these bugs at scale. The tooling to catch them needs to be in the generation loop, not just the CI pipeline.

---

**Tweet 10 (CTA):**

What rules would you want for AI-generated code?

I'm working on:
- VS Code / Cursor extension (lint-on-save)
- Taint tracking (data-flow analysis)
- More framework-specific rules
- Plugin system for custom rules

Drop a reply or open an issue.

---

## 4. Dev.to Blog Post

**Title:** I built a security linter in Rust that's 100x faster than Semgrep

**Tags:** rust, security, opensource, programming

**Cover image alt text:** Foxguard logo — a Rust-powered security linter

---

Every security linter I've used has the same fatal flaw: developers disable it because it's too slow.

I built Foxguard to fix that. It's a Rust-powered static analysis tool that scans your codebase for security vulnerabilities in 0.04 seconds. 28 rules across JavaScript/TypeScript, Python, and Go. MIT licensed. Single binary.

Here's the full story.

### The Problem: AI Code Ships With Security Flaws

GitHub's own data shows that 41% of code on the platform is now AI-generated. Research from Snyk found that roughly 25% of AI-generated code contains security vulnerabilities. Not obscure edge cases — the bread-and-butter CWEs that have been on the OWASP Top 10 for a decade: SQL injection, command injection, cross-site scripting, path traversal.

The tools to catch these exist. Semgrep is excellent. Bandit works. ESLint has security plugins. But they all share the same problem: they're slow. On a medium-sized project (50K lines), a Semgrep scan takes 30-40 seconds. That's long enough for developers to skip it in local development, and long enough to be annoying in CI.

I come from a Security Operations Center background at Migros, one of Switzerland's largest retailers. I watched the same vulnerability classes hit production month after month. SQL injection in an API handler. Hardcoded AWS keys in a config file. `eval()` called on user input. These are all detectable at write-time — if the tooling is fast enough that people keep it enabled.

### The Solution: Ruff, but for Security

If you've used [Ruff](https://github.com/astral-sh/ruff), you know what happens when you rewrite a Python linter in Rust: it goes from "annoying background process" to "instant feedback." I applied the same idea to security analysis.

Foxguard is a Rust-powered security linter that uses tree-sitter for AST parsing and rayon for parallelism. It scans a 10K LOC project in 0.04 seconds. A 50K LOC project takes about 0.18 seconds.

Here's what a scan looks like:

```bash
$ foxguard scan ./src

src/api/users.js:42:5  HIGH  JS-SQLI-001
  SQL injection: template literal used in database query
  → const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`)

src/auth/login.py:18:1  HIGH  PY-CMDI-001
  Command injection: subprocess call with shell=True and f-string argument
  → subprocess.run(f"echo {user_input}", shell=True)

src/server/handler.go:67:3  MEDIUM  GO-PATH-001
  Path traversal: user-controlled input in filepath.Join
  → path := filepath.Join(baseDir, r.URL.Query().Get("file"))

Found 3 issues (2 high, 1 medium) in 0.04s
```

No config files. No rule downloads. No Docker. No cloud account. Install and scan.

### Why Rust?

The same reason Ruff exists. Python-based tools hit a performance ceiling that no amount of optimization can break through. The GIL limits parallelism. Startup time alone eats hundreds of milliseconds. Every file operation involves Python's IO stack.

Rust gives you:

- **Predictable latency** — no garbage collector pauses, no JIT warmup
- **Trivial parallelism** — rayon lets you parallelize file scanning with a one-line change
- **Single-binary distribution** — `cargo install foxguard` and you're done, no runtime dependencies
- **Zero-copy operations** — parse the file once, match rules against the tree without allocating intermediate strings

### Why Tree-sitter?

Most security scanners use regex pattern matching. That works until it doesn't. A regex for "detect eval with a variable argument" will flag:

```javascript
// Don't use eval(userInput) here
const comment = "eval(safe)";
```

Neither of those is an actual `eval()` call. Tree-sitter gives us a full concrete syntax tree, so we can write queries that understand code structure:

```
(call_expression
    function: (identifier) @func
    arguments: (arguments
        (identifier) @arg)
    (#eq? @func "eval"))
```

This matches `eval(userInput)` but not `eval` inside a comment or string. Fewer false positives means developers trust the tool and keep it enabled.

### Why Not an LLM?

Large language models are excellent at many things. Deterministic security scanning is not one of them.

A security linter needs to be:

1. **Fast** — sub-second for the edit-save-lint loop
2. **Deterministic** — the same code must produce the same results every time
3. **Auditable** — when something is flagged, you need to know exactly why, mapped to a specific CWE
4. **Offline** — no API calls, no cloud dependency, works in air-gapped environments

LLMs fail on all four. They're slow (seconds per request), nondeterministic (different results on the same input), opaque (no CWE mapping), and require network access.

Use LLMs for code review and threat modeling. Use deterministic tooling for CI gates.

### Benchmarks

Measured with `hyperfine` on a real-world Node.js project:

| Tool | 10K LOC | 50K LOC | 100K LOC |
|---|---|---|---|
| Foxguard (28 rules) | 0.04s | 0.18s | 0.91s |
| Semgrep (25 rules) | 8.2s | 34.1s | 72.3s |
| Bandit (Python only) | 4.1s | — | — |

Foxguard is roughly 200x faster on the 10K LOC benchmark. The gap widens with project size because Rust's parallelism scales linearly with cores while Python-based tools hit the GIL.

### What It Catches

28 rules across three languages, covering the vulnerabilities that actually show up in production:

**JavaScript/TypeScript:**
- SQL injection via string concatenation and template literals
- XSS via innerHTML, document.write, and dangerouslySetInnerHTML
- Command injection via child_process with unsanitized input
- Prototype pollution
- Hardcoded secrets and API keys
- Use of eval() with dynamic arguments
- Weak cryptographic algorithms

**Python:**
- SQL injection via f-strings and format() in queries
- Command injection via subprocess with shell=True
- Unsafe deserialization (pickle, yaml.load)
- SSRF via unvalidated URLs in requests
- Path traversal in file operations
- Hardcoded secrets

**Go:**
- SQL injection via fmt.Sprintf in queries
- Path traversal via unsanitized input in filepath operations
- Command injection via os/exec with user input
- Use of weak cryptographic primitives
- Unvalidated redirects

Every rule maps to a CWE identifier and includes an OWASP Top 10 category reference.

### CI/CD Integration

Foxguard outputs SARIF, which means it integrates directly with GitHub Advanced Security and GitLab SAST:

```yaml
# GitHub Actions
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Foxguard
        run: cargo install foxguard
      - name: Scan
        run: foxguard scan ./src --format sarif --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Because it runs in under a second, you can also use it as a pre-commit hook:

```bash
#!/bin/sh
foxguard scan --staged-only
```

Shift-left only works if the tooling doesn't slow people down.

### What's Next

Foxguard is at v0.2 with 28 rules. Here's the roadmap:

- **50+ rules by v0.3** — expanding coverage for all three languages
- **Taint tracking** — data-flow analysis to trace user input through the program to dangerous sinks (this is where the real power of AST-based analysis shows up)
- **TypeScript-specific rules** — using type information for more precise analysis
- **Plugin system** — WASM-based custom rules so teams can add their own patterns
- **More languages** — Java and C# are the most requested

### Try It

```bash
cargo install foxguard
foxguard scan .
```

Or grab a prebuilt binary from the [releases page](https://github.com/peaktwilight/foxguard/releases).

- **GitHub:** [github.com/peaktwilight/foxguard](https://github.com/peaktwilight/foxguard)
- **Docs:** [foxguard.dev](https://foxguard.dev)
- **License:** MIT

I'm building this in public and prioritizing rules based on community feedback. If there's a vulnerability class you keep seeing in production, open an issue or drop a comment below.

What security rules would you want to see?
