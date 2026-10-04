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
all private scratch are removed. The public receipt contains artifact identities,
completion facts and bounded refusal transcript counts. Any unexpected refusal fails the full browser phase. Neither a
software-only HTTP test nor DOM probe substitutes.

The coverage phase also executes this fixture using the same nightly compiler and
Wasm instrumentation as the library browser tests. It uses cargo-llvm-cov's
[`show-env` external-test interface](https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-external-tests)
and the existing test-only minicov runtime. The external fixture uses
the same explicitly selected persistent coverage target as the library tests;
the external build retains upstream's wrapper variables without shell evaluation.
Registration and authentication each
run in a fresh page, so the driver captures actual counters before each page is
discarded. It requires both profiles, matching Wasm module signatures and successful
original Keyhole verification, retains each raw profile and its hash, then exports
LCOV and LLVM JSON from the same merged inputs. Missing, empty, malformed or
mismatched captures fail; the original source coverage checker and thresholds are
unchanged. The example alone links the profiling exports; the production library
does not acquire a profiling dependency or export any secret.

Both Crow acceptance and hosted Wasm coverage call this same external fixture.
After the successful authentication, the same Wasm instance receives nine
deliberately invalid transcripts from a job-local numeric HTTP peer: refusal
status, redirect, missing/invalid/oversized/truncated/encoded length, invalid JSON and
invalid ceremony options. Each case awaits the original completion, requires
fragment consumption and refusal, and checks that the peer received its one GET
and no finish POST. No navigator API is replaced and this peer never emits a
successful ceremony. These real counters join the second navigation's profile.

Library browser tests also exercise actual foreign-RP WebAuthn refusal and an
actual privileged ceremony. Shared native/browser parser vectors check callback
destinations and canonical capabilities. Explicit dictionary and callback-frame
substitutions only prove conversion/encoding refusal, not signed authenticator
success or real unavailable-PRF behavior.

The encoded-length vector sends a real gzip body whose wire length is correct;
the browser's Fetch decoder exposes a different byte length to the original
callback. Dictionary vectors cover explicit null/undefined absence, and direct
fetch-helper vectors use the original Request/Headers APIs to reject invalid
method/header input before I/O. Silent mediation with no matching credential
must refuse through the original browser; it is not a simulated platform result.

The combined coverage path does not establish 100% coverage: remaining uncovered
refusal paths still fail the original gate and need real tests before acceptance.
