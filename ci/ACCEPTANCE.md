# Fixed Crow acceptance

The `.crow/acceptance.yaml` workflow verifies the exact committed source and
reviewed canonical dependency closure, runs original locked preflight, performs
one original CCID fresh Cargo resolution, then runs fixed native, Wasm, browser,
coverage and dependency-policy phases against that same candidate lock. No caller
can choose or omit gates. Native and Wasm coverage use original 100% checkers and
unchanged exclusions; actual browser execution is mandatory. Changed locks must
be reviewed and committed, then the new exact source must qualify before merge.

The maintained wasm-bindgen CLI/runner is selected only from the candidate lock,
its official release SHA is verified, only exact regular binary members are read,
and versions/binary/archive/checksum identities are retained outside source before
any owner compilation. Browser setup is the actual qualified Crow4114 immutable
closure; coverage-only setup is Crow4116, which exercised actual browser profile
capture and matching nightly/LLVM branch export. Product coverage is still required.
Preflight refuses missing stable/nightly Wasm stdlib and browser/driver tools.
These workflow files are source-ready, not executed acceptance or release proof.
Final audit retains native/Wasm coverage reports, original/resolved metadata,
all phase logs, matching runner identity and source/resolution receipts. No
protection transition or merger follows merely from the existence of this file.

The browser phase additionally builds and executes the synthetic HTTPS loopback
fixture. A real top-level HTTPS Wasm page uses production `complete_loopback`,
actual Chromium Navigator/WebAuthn test authenticator, exact numeric loopback
callback, and original native Keyhole/libSQL registration/authentication. PRF is
compared only inside native Rust; no secret getter/JS export is added. Launch
capabilities live only in private ephemeral test files/memory, certificate and
all private scratch are removed. The public receipt contains only artifact hashes
and boolean completion facts. This new fixture has not yet run; any refusal fails
the full browser phase. Neither a software-only HTTP test nor DOM probe substitutes.
