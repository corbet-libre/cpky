# Passkeys (cpky)

Device WebAuthn ceremonies with a local PRF handover. Keyhole (ckyh) is the server verifier; Keys (ckmg) owns key derivation and custody.

## Scope

Own registration and authentication on the device, preserving server options and separating public credentials from secret PRF results. Member registration cannot finish without PRF. Sign-in and vault unlock have independent outcomes. This library grants no membership, device-signing authority or recovery guarantee.

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
