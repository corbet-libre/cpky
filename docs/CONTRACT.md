# Passkeys contract

Pass exact creation/request options from the authenticated server. Only the fixed PRF extension is added. Preserve challenge, RP, user handle, algorithms, UV, timeout, exclusions, authenticator policy and discoverable empty allowCredentials.

Member registration withholds its public response until PRF support and one valid 32-byte result are established. If creation only enables PRF, evaluate once with the newly created credential and exact RP, bound to the original ceremony; cancellation or unrelated results discard registration.

Strip secret extension outputs before any serialization or forwarding. The zeroizing opaque handover has no Debug, Clone, serde or raw getter. Browser-owned output buffers and Rust intermediates are wiped. Keys alone derives persistent roots; no cpky/ckmg dependency cycle.

Authentication returns a public assertion independently of PRF availability. Missing or malformed PRF keeps the vault locked. A ceremony is not verified server authentication, device authority, membership, local API capability or successful restore.

Root/admin registration is a distinct explicit operation without member PRF requirements. Test software authenticator selection is explicit and feature-gated. Unavailable production platforms return refusal.

Native and executed wasm tests must cover options, fixed salt, splitting, missing/disabled/malformed/two-output PRF, bound create/get, cancellation, discoverable restore and real server rejection. Browser protocol vectors do not imply platform support; actual browser WebAuthn evidence is recorded separately.

## Typed ports

`Client<A>::register_member(Value)` returns `Registration`, with private fields and
no deserializer. The member Foyer operation must accept this completed type before
forwarding its public credential to `register_finish`. It must never use
`register_privileged` for a member. Only root/admin flows select that separate
operation. The leaf owns no product HTTP client or server-finish operation. Its native loopback listener is solely a device-local ceremony handover.

`Registration::into_parts()` returns `(PublicCredential, UnlockSecret)`.
`Authentication::into_parts()` returns `(PublicCredential, VaultOutcome)`.
`VaultOutcome::Ready` means local PRF evaluation succeeded; server verification
is still required. `Locked` preserves the valid public assertion for independent
server authentication and never implies an unlocked vault.

`UnlockSecret::import<T>(self, receive: impl for<'a> FnOnce(&'a [u8; 32]) -> T) -> T`
is a consume-only, synchronous in-process custody port. The trusted Vault importer
constructs the opaque Keys `PrfOutput` inside this call. It cannot borrow the input
past the call. This is not a sandbox against a malicious caller copying bytes.
Neither this callback nor its input belongs in a JS export, local action registry,
HTTP, MCP or event. Keys owns every persistent root and locator.

## Browser and protocol limits

The browser adapter calls `navigator.credentials` in a window context. It retains
the browser's original `clientDataJSON`, including cross-origin information.
`Context` pins the exact configured origin and RP; it does not authenticate that
configuration. An allowed origin list alone does not make a cross-origin iframe
acceptable to the current server verifier. Composers must retain the server's
actual refusal until its owner supplies a supported, reviewed policy.

The explicit `test-authenticator` feature uses the maintained `passkey` 0.4
authenticator for real UV, signatures and PRF. It is synthetic test-root/demo
custody, never a production default or a production CLI custody decision.
`native::BrowserCeremony` is the production CLI browser route. `Unavailable` remains an explicit refusal adapter for unsupported platform selection.

The WebAuthn PRF input remains exactly
`blake3::derive_key("ckmg 2026-09 passkey PRF input for vault store unlock v1", b"")`.
No naming change may change this recipe. The WebAuthn client performs the standard
PRF input processing; this adapter must not prehash it a second time.

## Maintained implementations

- Browser protocol and PRF behavior follow [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/#prf-extension).
- JS bindings use `web-sys`, `js-sys` and `wasm-bindgen`; the prior Keys browser
  adapter supplied the binding pattern. Server options are now translated in full.
- Software tests use [passkey-rs](https://github.com/1Password/passkey-rs), and real
  Keyhole/libSQL verification checks the stripped responses.
- The browser runner uses Selenium and the maintained [Chrome WebAuthn virtual
  authenticator](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).
  Virtual-authenticator success establishes that runner's behavior, not support
  on every browser or hardware authenticator.
- Secret ownership uses `zeroize`; Blake3 and SHA-256 are maintained crates.
  No cryptographic primitive or authenticator is implemented here.

Native and wasm coverage gates use current stable/nightly toolchains. The tiny
test-only profiling crate uses maintained `minicov` master because current
`wasm-bindgen-test`'s optional exact 0.3.8 dependency conflicts with 0.3.9 under the
same registry source, while its bundled runtime cannot capture current LLVM
profiles. The separate source changes dependency identity, not compiler version
or measured counters. The driver captures the actual completed test module once.


## Native browser ceremony

`native::BrowserCeremony::start(Context, Url, CeremonyRequest)` binds an ephemeral
IPv4 loopback listener and returns the launch URL. `open_browser()` delegates to
the maintained [webbrowser](https://docs.rs/webbrowser/latest/webbrowser/) launcher.
`wait(self)` consumes exactly one typed `CeremonyResult`; `cancel(self)` and Drop
stop the listener and drop any retained result. The lifetime is 120 seconds.
The native composer supplies the exact authenticated origin/RP and complete server
options. The launch page must use that HTTPS origin, without query or fragment.

The random 256-bit callback capability appears only in the launch fragment and
`X-Cpky-Capability` request header. The browser Rust `complete_loopback(Context)`
consumes and removes the fragment before I/O, accepts only the numeric
`http://127.0.0.1:<port>/finish` destination, fetches the exact request dictionary,
runs the normal member/privileged/authentication operation, and posts the result
directly to loopback. Fetch omits cookies/referrers, refuses redirects and caching.
Local-network browser permission can be required; refusal is an unavailable result,
never a relay through the product server. See the maintained browser's
[local network access policy](https://developer.chrome.com/blog/local-network-access).
Actual HTTPS-browser-to-loopback execution remains a qualification gate.

The local wire is private bounded binary: version, ceremony kind, vault outcome,
little-endian public JSON byte length, sanitized public credential, and precisely
32 PRF bytes for a Ready result. No secret serde/JS export exists. Owned Rust and
browser byte intermediates are wiped; HTTP/browser transport internals are outside
that ownership guarantee. Origin, Host, capability, method, content type and bound
WebAuthn response are checked before one-use result consumption. Top-level CLI
ceremonies reject cross-origin clientData. Concurrent repeats cannot deliver two
results. Invalid requests leave the original operation pending until its timeout.
The listener drains an accepted response before its consuming wait closes it.

The trusted cmsg/Vault runtime consumes `UnlockSecret::import` in Rust. Product
JSON/MCP/TypeScript actions expose only redacted status. The launch URL contains a
bearer capability in its fragment and remains inside the trusted Rust runtime,
which invokes `BrowserCeremony::open_browser`; neither it nor the PRF or private
callback wire enters product JSON. Server signature verification remains Keyhole's job;
callback success is not membership, G3 authority or a completed server login.

## Sealed popup handover

`browser::PopupCeremony::prepare` retains one original request in the configured
vault frame. Its `open` requires a real activation in that frame and opens the
exact same-origin trusted page with `noopener,noreferrer`. `wait` consumes one
result. The popup consumes its fragment synchronously before any asynchronous
work, or accepts it from a trusted entry that has already removed it. The actual
page, HTTPS origin, top-level context and absence of an opener are checked.
`PopupHandoff::ready` receives the public request before the popup enables its
own Continue; `complete` requires that separate real user activation.

The frame generates a one-time X25519 key inside Wasm. The public launch pins
both its recipient key and a fresh 256-bit nonce. The popup uses the maintained
[HPKE implementation](https://github.com/rozbb/rust-hpke), RFC 9180 Base mode with
X25519/HKDF-SHA256/ChaCha20Poly1305. Associated data binds the recipient, nonce,
both exact origins, RP, requested ceremony and original options. Its private
callback codec remains inside Rust/Wasm: raw PRF never crosses this channel.
Only public handshake dictionaries and HPKE ciphertext enter JavaScript buffers.
There is no public key/secret codec or new cryptographic primitive.

BroadcastChannel events require the actual trusted same-origin sender, one
selected random peer, bounded binary messages and a bounded receive queue.
Wrong nonce, recipient, origin, request, replay or malformed ciphertext refuses.
The frame consumes its private key before any open attempt; ACK follows valid
decryption and the original challenge/top-level credential checks. Owned Rust
plaintext and JavaScript channel buffers are wiped. Keys also expire directly on
deadline/pagehide, including a prepared owner not yet awaited. Drop closes the
channel; pending authenticator work is aborted. No opener Window is retained,
and a blocked popup or unavailable storage partition times out without fallback.

The software-authenticator vectors exercise actual sealed PRF continuity and
binding refusals. Wasm tests use real BroadcastChannels. The original HTTPS
acceptance fixture adds real frame/popup clicks, same-site distinct origins,
ordinary browser PRF, opener refusal and early-close cancellation. All execution,
full native/browser coverage and browser qualification remain pending. The
external popup instances are not yet included in the existing three-navigation
coverage collector. Cross-origin isolation, installed browsers and other browser
engines require their real matrix; no thread/isolation policy is changed here.
Successful handover means only an opaque original result, never server
authentication, current device authority, unlocked Vault or complete login.
