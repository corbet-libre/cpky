#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
: "${CI_COMMIT_SHA:?verify requires the exact source revision}"
: "${ARTIFACT_ROOT:?verify requires an absolute ARTIFACT_ROOT}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 .github/scripts/check-first-party.py
python3 .github/scripts/test-source-coverage.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
version=$(python3 -c "import tomllib; print(next(p['version'] for p in tomllib.load(open('Cargo.lock','rb'))['package'] if p['name']=='wasm-bindgen'))")
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir -p "$RUNNER_TEMP/wasm-runner"
(cd "$RUNNER_TEMP/wasm-runner" && curl --fail --location --retry 3 --remote-name "$base/$archive" && curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum" && checksum=$(cut -d ' ' -f1 "$archive.sha256sum") && printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check && tar -xzf "$archive" --strip-components=1)
export PATH="$RUNNER_TEMP/wasm-runner:$PATH"
# Selenium comes from the pinned Nix tool set (run-cached.sh), not pip (nixpkgs python3 ships no pip).
python3 -c 'import selenium' || { echo "selenium is not provisioned; browser tests need it" >&2; exit 2; }
cargo clippy --locked --target wasm32-unknown-unknown --all-features --lib -- -D warnings
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "missing chromium at $CHROME_BIN" >&2; exit 2; }
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
# The canonical runner reads CHROMEDRIVER and CHROME_BIN from the environment (no patch needed).
runner_copy=.github/scripts/browser-runner.py
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 $runner_copy"
export WASM_BINDGEN_USE_BROWSER=1 WASM_BINDGEN_TEST_TIMEOUT=120
cargo test --locked --target wasm32-unknown-unknown --all-features --lib
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
# Coverage needs the nightly compiler for every rustc call, also behind sccache.
export RUSTC="$NIGHTLY_RUSTC" CARGO="$NIGHTLY_CARGO" RUSTUP_TOOLCHAIN=nightly
export PATH="$(dirname "$NIGHTLY_RUSTC"):$PATH"
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --branch --all-features --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
python3 .github/scripts/check-source-coverage.py coverage.lcov coverage.json
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB=1 WASM_BINDGEN_SPLIT_LINKED_MODULES=1 CPKY_COVERAGE=1 CC_wasm32_unknown_unknown=clang
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --all-features --lib --coverage-target-only --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --coverage-target-only --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
python3 .github/scripts/check-source-coverage.py wasm-coverage.lcov wasm-coverage.json
