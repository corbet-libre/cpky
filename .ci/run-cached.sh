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
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#chromedriver" "$tool_source#chromium" "$tool_source#clang" "$tool_source#cargo-llvm-cov")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
# minicov's build script hardcodes `clang`, so every wasm32 C build uses
# whatever `clang` resolves on PATH (currently the x86_64 nix wrapper, which
# breaks on host glibc headers and wrapper-only flags). Resolve the pinned
# unwrapped compiler here (actual closure path from Nix at runtime, never a
# hardcoded store path) and export it for the cache fingerprint + the wasm
# legs in verify.sh. It stays off the global PATH so native builds and
# nightly coverage keep the wrapper.
CPKY_WASM_CLANG_BIN=""
for out in $(nix build --no-link --print-out-paths "$tool_source#llvmPackages.clang-unwrapped"); do
  if [ -x "$out/bin/clang" ]; then CPKY_WASM_CLANG_BIN="$out/bin"; fi
done
test -n "$CPKY_WASM_CLANG_BIN" || { echo 'pinned unwrapped clang provides no bin/clang' >&2; exit 2; }
export CPKY_WASM_CLANG_BIN
export CPKY_WASM_CLANG="$CPKY_WASM_CLANG_BIN/clang"
"$CPKY_WASM_CLANG" --version
# .github/requirements.txt needs selenium plus a working pip; the pinned
# python alone provides neither as usable modules here, so supply a pinned
# python3.withPackages env (selenium plus transitive deps and pip). Same
# nixpkgs revision; the 4.40.0 selenium satisfies the >=4 floor, and the
# verify `pip install` then succeeds as a fast no-op.
python_env=$(nix build --no-link --print-out-paths --impure --expr '(builtins.getFlake "'"$tool_source"'").legacyPackages.${builtins.currentSystem}.python3.withPackages (p: [ p.selenium p.pip ])')
test -n "$python_env" || { echo 'nix python selenium env resolution failed' >&2; exit 2; }
PATH="$python_env/bin:$PATH"
python3 -c 'import selenium; print(selenium.__version__)'
export PROTO_HOME="$toolchains/proto"
export MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
# Shared-first toolchain lock: production base helper verbatim (no MSRV extra;
# hosted uses stable only; nightly coverage rides the same gate->main flow).
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown nightly:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$(rustup which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
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
# The crate graph links OpenSSL via openssl-sys, so pkg-config, OpenSSL dev
# headers and shared libs, and a C compiler/linker must resolve; execute the
# check inside the pinned shell (NAR-pinned revision in check-shell.nix, same
# pin as the tool closure). Re-prepend the verified ccid directory inside the
# shell so `ccid` on PATH stays exact.
nix-shell .ci/check-shell.nix --run 'exec 2>&1; export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; pkg-config --version; openssl version; "$CCID_BIN" cached --repo "$PWD" --check verify; test -s ".ccid/results/verify.jsonl"'
