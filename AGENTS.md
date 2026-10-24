# Agent instructions

Write code, comments and documentation in English.

## Product boundary

- Passkeys is the sole device WebAuthn/PRF adapter. Keyhole (ckyh) verifies on the server; Keys (ckmg) derives and retains roots.
- Preserve exact server ceremony options; add only the fixed PRF extension. Never forward secret extensions.
- Member registration requires verified PRF before exposing a public registration response. Root/admin exemptions are distinct operations.
- No primitive crypto, persistent keys, raw-secret getters, logging, serialized PRF or domain authority.
- Reuse maintained browser/protocol/authenticator crates; document choices and platform limitations.
- Test authenticators are explicit test features, never the production default.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception.

## Quality boundary

- No local Cargo, including fmt and metadata. Public CI executes native and actual wasm tests.
- First-party Git dependencies follow branch main with one resolved revision per crate; preserve CI-generated Cargo.lock.
- Exact source line and branch coverage targets 100%, with no unjustified exclusions or weakened thresholds.
- Bounded serial implementation CI; expensive scale tests belong on the designated build infrastructure.
- Dependabot merges require all exact-head substantive checks and normal protected-branch enforcement.
- Explicit staging paths, plain English commits, no AI attribution, registry publication or secrets.
