//! All cpky integration tests in ONE test binary (one link of the whole dependency tree
//! instead of two). Each former `tests/<name>.rs` is the module `<name>`; its feature and platform
//! gate stays the inner `#![cfg(..)]` of that file. Nothing stays separate: both suites are native
//! (`not(target_arch = "wasm32")`), need no exclusive feature tier (CI runs them together in one
//! `cargo test --locked --all-features`), use no process-global state (each test builds its own
//! Tokio runtime and disposable `tempfile` Keyhole database), and no CI, tier or fixture file
//! names either target. The `tests/*.rs` files that remain under `tests/` are library `#[path]`
//! inputs (compiled into `--lib` unit tests via `src/lib.rs`), not integration targets.

mod persistent;
mod server;
