# foxguard

Blazing fast security linter for modern codebases. Written in Rust.

> The Ruff of security.

## Why

- **41% of code is now AI-generated.** 24.7% of it has security flaws.
- Every security linter today is Python, OCaml, or Java. Slow.
- Foxguard is Rust-native. 100x faster than Semgrep. Zero config.

## Install

```sh
cargo install foxguard
```

```sh
npx foxguard
```

## Usage

```sh
foxguard .
```

## Features

- Written in Rust -- scans 100K LOC in <2 seconds
- Multi-language -- JS/TS, Python, Go (more coming)
- 500+ security rules -- injection, auth, crypto, secrets, SSRF, XSS
- AI-code-aware -- catches patterns specific to AI-generated code
- SARIF output -- integrates with GitHub Code Scanning
- Zero config -- works out of the box

## License

MIT
