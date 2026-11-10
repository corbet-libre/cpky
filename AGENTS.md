# cpky agent instructions

Write code, comments and documentation in English. Owned code forbids unsafe
Rust (`#![forbid(unsafe_code)]`, `src/lib.rs:2`).

## Build and test (lane: `~/agents/scratch/cbuild <lane> ...`)

- `fmt -p cpky -- --check`
- `test -p cpky --all-features`
  (lib 38 + it 6 + doc 4, exit 0;
  `--locked` needs CI's resolve refresh)
- `clippy -p cpky --all-features --all-targets -- -D warnings`
- `clippy -p cpky --target wasm32-unknown-unknown --all-features --lib -- -D warnings`
- CI-only (Crow `.ci/verify.sh`): wasm exec via the selenium browser runner
  with the virtual authenticator, nightly coverage gates; browser protocol
  vectors do not imply platform support (`docs/CONTRACT.md:62-64`)

## Hard invariants (each with its enforcing test)

- Preserve exact server ceremony options; add only the fixed PRF extension; never
  forward secret extensions (`docs/CONTRACT.md:3,7`):
  `tests::exact_options_and_fixed_input`, `tests::option_and_context_faults`.
- Member registration withholds its public response until PRF is verified
  (`docs/CONTRACT.md:5`):
  `tests::upstream::missing_prf_never_exposes_member_registration_but_privileged_and_login_are_separate`.
- Secrets never serialize: `Registration`/`Authentication`/`UnlockSecret` expose
  no Debug/Clone/serde/raw getter; secret extension outputs are stripped
  (`docs/CONTRACT.md:7,29-33`): `no_leak::errors_and_refusals_never_contain_seed_bytes`,
  `secret::UnlockSecret` compile-fail doctests (4).
- A ceremony is not server authentication, device authority or membership
  (`docs/CONTRACT.md:9`):
  `loopback_tests::member_registration_round_trips_and_every_frame_substitution_is_refused`,
  `popup::tests::original_bound_decoder_rejects_another_real_challenge_even_when_sealed`,
  `tests/it/server.rs::real_server_accepts_stripped_registration_discovery_and_refuses_revoked_signature`.
- Software test authenticator is explicit and feature-gated, never the production
  default (`docs/CONTRACT.md:11,45-48`): `test-authenticator` feature,
  `software::tests::*`, `native::BrowserCeremony` as the production CLI route.
- PRF input recipe is frozen
  (`blake3::derive_key("ckmg 2026-09 passkey PRF input for vault store unlock v1", b"")`,
  `docs/CONTRACT.md:50-53`): `tests::upstream::real_prf_create_get_and_fresh_device`.
- LGPL-3.0-only WITH linking exception (`LICENSE.md`).

Pointers: `docs/CONTRACT.md`, `ci/ACCEPTANCE.md`.
