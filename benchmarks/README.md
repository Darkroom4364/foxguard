# foxguard Benchmarks

Comparative benchmarks for foxguard against other security linters.

## Quick Start

```sh
# Build foxguard first
cargo build --release

# Run benchmarks
./benchmarks/run.sh
```

## Methodology

The benchmark suite measures foxguard and semgrep against three popular open-source repositories covering different languages:

| Repository | Language | Description |
|------------|----------|-------------|
| [express](https://github.com/expressjs/express) | JavaScript | Fast, unopinionated web framework for Node.js |
| [flask](https://github.com/pallets/flask) | Python | Lightweight WSGI web application framework |
| [gin](https://github.com/gin-gonic/gin) | Go | HTTP web framework written in Go |

### What is measured

- **Wall time** — Total elapsed time for the scan (using high-resolution Perl timer)
- **Files scanned** — Count of source files in the repository (.js, .ts, .py, .go)
- **Findings count** — Number of security issues reported

### How it works

1. Each repository is cloned at `--depth 1` (latest commit only) into `benchmarks/repos/`
2. foxguard runs with `--format json` to get machine-readable output
3. semgrep runs with `--config auto --json` (if installed)
4. Results are written to `benchmarks/results.md`

### Fairness

- Both tools scan the same repository checkout
- Both use their default/recommended rulesets
- Timing includes startup overhead (which favors Rust binaries)
- Repos are cached after first clone; delete `benchmarks/repos/` to re-clone

## Results

After running `./benchmarks/run.sh`, see `results.md` in this directory for the latest numbers.
