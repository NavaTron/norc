# Test Coverage Workflow (NavaTron NORC)

This project uses `cargo-llvm-cov` for unified coverage (line, branch, region) across workspace crates.

## Quick Start

```bash
# Install (once)
cargo install cargo-llvm-cov

# Run coverage (text summary)
cargo llvm-cov --workspace

# Enforce minimum line coverage (example 70%)
cargo llvm-cov --workspace --fail-under-lines 70

# Generate HTML report in target/llvm-cov/html
cargo llvm-cov --workspace --html
```

## CI Integration
The `xtask ci` command invokes an optional coverage step separately (not blocking). To enforce in CI:

```bash
cargo llvm-cov --workspace --fail-under-lines 80 --fail-under-branches 70
```

## Ignoring Generated / Uninteresting Code
Adjust with an `llvm-cov-config.json` if required later (not yet committed) to exclude:
- build.rs
- generated schema or FFI bindings

## Improving Coverage
1. Prioritize protocol framing edge cases (size limits, malformed lengths)
2. Add handshake error path tests (unsupported version, capability mismatch)
3. Exercise rate limiting under burst + sustained loads (unit tests)
4. Add TUI state transition tests for input editing and pane switching

## Roadmap
- Integrate coverage threshold into `xtask ci` behind env flag (e.g. `ENFORCE_COVERAGE=1`)
- Add badge generation (gh-action + uploading HTML as artifact)
- Track differential coverage in PRs
