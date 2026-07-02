# AGENTS.md

## Build & Test Commands

- Build: `cargo build` (release: `cargo build --release`)
- Check/Lint: `cargo clippy --all-targets --features generate-extras` (pedantic + restriction lints enabled)
- Format: `cargo +nightly fmt --check -- --config imports_granularity=Crate --config group_imports=StdExternalCrate`
- Test: `cargo test --features generate-extras`
- Single test: `cargo test <test_name>`

## Architecture

- **shh**: CLI tool for automatic systemd service hardening via strace profiling
- `src/main.rs`: Entry point, CLI handling
- `src/strace/`: Strace output parsing (nom-based parsers)
- `src/systemd/`: Systemd option generation and service management
- `src/summarize/`: Profiling data summarization
- `tests/`: Integration tests using `assert_cmd` and `insta` snapshots

## Code Style

- Rust 2024 edition, MSRV 1.88 (can be increased as needed)
- Strict Clippy: pedantic + many restriction lints (see `[lints.clippy]` in Cargo.toml)
- No `unwrap`/`expect`/`panic` in non-test code; use `anyhow` for errors
- Use `thiserror` for custom error types
- Imports:
  - Place all `use` statements at the top of the file; do not put them inside functions, `impl` blocks, or other inner scopes (the only exception is inside `#[cfg(...)]` modules such as `mod tests`, where the imports go at the top of that module)
  - Group std imports first, then external crates, then local modules
  - Never use fully-qualified paths (e.g., `std::path::Path` or `crate::ui::foo()`) in code; always import namespaces via `use` statements and refer to symbols by their short name
  - Import deep `std` namespaces aggressively (e.g., `use std::path::PathBuf;`, `use std::collections::HashMap;`), except for namespaces like `io` or `fs` whose symbols have very common names that may collide — import those at the module level instead (e.g., `use std::fs;`)
  - For third-party crates, prefer importing at the crate or module level (e.g., `use anyhow::Context as _;`, `use clap::Parser;`) rather than deeply importing individual symbols, to keep the origin of symbols clear when reading code — only import deeper when needed to avoid very long fully-qualified namespaces
- In format strings, never mix positional placeholders (`{}`) with named ones; for expression arguments, use named arguments (`{id}` … `id = loc.id`)
- When formatting paths in error messages or logs, always use debug formatting (`{:?}`) rather than `.display()` to preserve non-UTF-8 safety and show quoting
- Prefer `log` macros for logging; no `dbg!` or `todo!`
- Prefer `default-features = false` for dependencies
- Do not add `derive` traits unless they are required by the current code (compile errors) or actively used by tests/runtime behavior
- Comments (including doc comments):
  - Keep comments concise: prefer a short summary over restating implementation details, only mention exceptional cases when they affect behavior, and are not already conveyed by the types used, function signature, or code just below
  - Omit trailing periods in single-sentence comments
- In tests:
  - Use `use super::*;` to import from the parent module
  - Prefer `unwrap()` over `expect()` for conciseness
  - Do not add custom messages to `assert!`/`assert_eq!`/`assert_ne!` — the test name is sufficient
  - Prefer full type comparisons with `assert_eq!` over selectively checking nested attributes or unpacking; tag types with `#[cfg_attr(test, derive(Eq, PartialEq))]` if needed
  - Do not add section-separator comments (e.g., `// --- Some Section ---`) in test modules — test names are descriptive enough
- When moving or refactoring code, never remove comment lines — preserve all comments and move them along with the code they document

## Version control

- This repository uses the jujutsu VCS. **Never use any `jj` command that modifies the repository**.
- You can also use read-only git commands for inspecting repository state. **Never use any git command that modifies the repository**.
