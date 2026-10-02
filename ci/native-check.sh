#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_HTTP_USER_AGENT=passkeys-ci
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc --version
cargo --version
# The composing runner supplies the one freshly resolved lock snapshot. This
# selector never refreshes it or treats native execution as browser qualification.
sha256sum Cargo.lock
formatted=0
cargo fmt --all --check || formatted=$?
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
exit "$formatted"
