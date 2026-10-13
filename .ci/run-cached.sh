#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify" ]; then
  echo "CHECKS must be exactly 'verify', got: $CHECKS" >&2
  exit 2
fi
test -f Cargo.lock || { echo 'Cargo.lock must be present (committed snapshot)' >&2; exit 2; }
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
ln -sfn "$state/moon-cache/hashes" .moon/cache/hashes
ln -sfn "$state/moon-cache/outputs" .moon/cache/outputs
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#python3" "$tool_source#chromedriver" "$tool_source#chromium" "$tool_source#clang" "$tool_source#cargo-llvm-cov" "$tool_source#llvmPackages.clang-unwrapped" "$tool_source#pkg-config" "$tool_source#openssl" "$tool_source#openssl.dev")
for path in $tool_paths; do PATH="$path/bin:$PATH"; [ -d "$path/lib/pkgconfig" ] && PKG_CONFIG_PATH="$path/lib/pkgconfig:${PKG_CONFIG_PATH:-}"; done
export PKG_CONFIG_PATH
# Python with selenium from Nix (nixpkgs python3 has no pip; the browser runners import selenium).
py_env=$(nix build --impure --no-link --print-out-paths --expr "(builtins.getFlake \"$tool_source\").legacyPackages.\${builtins.currentSystem}.python3.withPackages (ps: [ ps.selenium ])")
test -x "$py_env/bin/python3" || { echo 'python3 with selenium not built' >&2; exit 2; }
export PATH="$py_env/bin:$PATH"
openssl_out=$(nix build --no-link --print-out-paths "$tool_source#openssl.out")
export LD_LIBRARY_PATH="$openssl_out/lib:${LD_LIBRARY_PATH:-}"
export PROTO_HOME="$toolchains/proto" RUSTUP_HOME="$toolchains/rustup"
export CARGO_HOME="$toolchains/cargo" MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$CARGO_HOME/bin:$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [ -n "${GIT_CONFIG_COUNT:-}" ]; then
  echo 'GIT_CONFIG_COUNT is already set; refusing to overwrite job git config' >&2
  exit 2
fi
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0='url.https://git.corbet.ch/corbet-libs/.insteadOf'
export GIT_CONFIG_VALUE_0='https://github.com/corbet-libs/'
export GIT_CONFIG_KEY_1='url.https://git.corbet.ch/corbet-foss/.insteadOf'
export GIT_CONFIG_VALUE_1='https://github.com/corbet-foss/'
# Shared-first toolchain lock: production base helper verbatim (no MSRV extra;
# hosted uses stable only; nightly coverage rides the same gate->main flow).
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown nightly:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$("$CARGO_HOME/bin/rustup" which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
# wasm32 C code (minicov) needs an UNWRAPPED clang and llvm-ar: the Nix wrapper targets the host and leaks glibc headers.
wasm_llvm=$(nix build --no-link --print-out-paths "$tool_source#llvmPackages.clang-unwrapped" "$tool_source#llvmPackages.llvm")
for path in $wasm_llvm; do
  [ -x "$path/bin/clang" ] && wasm_cc="$path/bin/clang"
  [ -x "$path/bin/llvm-ar" ] && wasm_ar="$path/bin/llvm-ar"
done
test -x "${wasm_cc:-}" && test -x "${wasm_ar:-}" || { echo 'unwrapped clang/llvm-ar not found' >&2; exit 2; }
export CARGO_INSTALL_ROOT="$state/install-bin"
mkdir -p "$CARGO_INSTALL_ROOT/bin"
export PATH="$CARGO_INSTALL_ROOT/bin:$PATH"
export ARTIFACT_ROOT="${ARTIFACT_ROOT:-$state/release-artifacts}"
mkdir -p "$ARTIFACT_ROOT"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export SOURCE_SHA256="$(git archive --format=tar HEAD | sha256sum | cut -d ' ' -f 1)"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
python3 --version
chromedriver --version
chromium --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
# Checks inherit only PATH, not CC_* variables: shadow clang and llvm-ar for wasm32 with the unwrapped tools.
mkdir -p "$state/wasm-bin"
ln -sfn "$wasm_cc" "$state/wasm-bin/clang"
ln -sfn "$wasm_ar" "$state/wasm-bin/llvm-ar"
export PATH="$state/wasm-bin:$PATH"
"$CCID_BIN" cached --repo "$PWD" --check verify
test -s ".ccid/results/verify.jsonl"
