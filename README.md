# Passkeys (cpky)

Device WebAuthn ceremonies with a local PRF handover. Keyhole (ckyh) is the server verifier; Keys (ckmg) owns key derivation and custody.

## Scope

### Purpose

cpky is the only device-side library that talks to WebAuthn for registration, sign-in, and adding a device, passing the resulting PRF secret to local key custody and keeping it out of anything sent for server verification.

### Owns

- Device ceremonies that use server-provided options unchanged, adding only the fixed PRF extension.
- A fixed, versioned PRF input covered by a test vector.
- Splitting each ceremony result into a public credential for the server and a PRF secret for the local vault handover.
- Refusing member registration when the PRF is absent, without contacting the server; privileged registration paths are exempt.
- Discoverable sign-in on an empty vault to support restore on a new device, plus local unlock ceremonies.
- A software authenticator that is available only behind an explicit test feature gate.

### Never

- Verify signatures; signature verification belongs to Keyhole (ckyh).
- Derive keys, persist the PRF secret, or depend on Keys (ckmg).
- Send the PRF secret to any server, build ceremony options locally, or accept an arbitrary origin or relying party.
- Store device names, mark agent devices, or ship software passkeys as the product default.
- Offer a password or other fallback unlock.

### States

Idle to ceremony pending to done, where done records whether the PRF is present or absent; member registration without a PRF is refused, and sign-in reports Ready or Locked for the vault independently of server verification.

### Test obligations

- One user prompt yields both an assertion and the PRF, and nothing sent to the server carries the PRF secret.
- Registration without a PRF is refused without server contact; discoverable restore on an empty vault works.
- Wrong origin or relying party, missing user verification, replayed or cross-session assertions, missing, disabled, malformed, or double PRF outputs, cancellation, and server-side rejection are all handled as failures.
- Native and browser builds share identical test vectors, with full line and branch coverage, real round trips, injected cancellation, corruption, and failure cases, bounded inputs, no secrets in errors or logs, reuse of maintained third-party libraries, and no custom cryptographic primitives.

## Implementation status

Device ceremonies and the native loopback adapter are implemented. Actual browser execution and full native/browser coverage acceptance remain pending. Production CLI custody and cross-origin iframe interoperability are separate integration requirements.

## Reuse

Use browser WebAuthn via maintained wasm-bindgen/web-sys, upstream passkey 0.4 for explicitly selected software test ceremonies, BLAKE3 for the existing fixed PRF input, and zeroize for owned secret buffers. No authenticator or cryptographic primitive is implemented here.

See [contract](docs/CONTRACT.md) and [license](LICENSE.md).

The native CLI browser route is `native::BrowserCeremony`: prepare with `start`,
launch with `open_browser`, then consume `wait` or `cancel`. The trusted HTTPS
page calls Rust `browser::complete_loopback`; the PRF goes directly to one local
listener as an opaque Rust result. The software authenticator remains explicitly
test/development-only. See [the contract](docs/CONTRACT.md#native-browser-ceremony)
for the origin/capability binding and outstanding real-browser qualification.
