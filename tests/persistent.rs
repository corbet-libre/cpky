//! The seed-derived credential against the real Keyhole server: registration,
//! discoverable sign-in from a fresh instance built only from the seed and the
//! stored user handle, identical PRF unlock secret, and refusal for another seed.
#![cfg(all(not(target_arch = "wasm32"), feature = "persistent-software"))]
use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
use cpky::{Client, Context, VaultOutcome, persistent::PersistentAuthenticator};
use zeroize::Zeroizing;
const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";

fn device(seed: u8) -> Client<PersistentAuthenticator> {
    Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        PersistentAuthenticator::new(ORIGIN, Zeroizing::new([seed; 32])).unwrap(),
    )
}

#[test]
fn seed_credential_registers_and_a_fresh_instance_signs_in_with_the_same_prf() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let url = Url::from_file_path(directory.path().join("community.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(url.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(
            1,
            "cpky_passkeys",
            ckyh::LIBSQL_SCHEMA,
        )]))
        .unwrap();
    let store = LibsqlStore::new(&db, "synthetic", runtime.handle().clone()).unwrap();
    let server = Passkeys::new(store, "synthetic", RP, &[Url::parse(ORIGIN).unwrap()]).unwrap();
    let member = Uuid::from_u128(23);

    // A keeper that cannot store the handle refuses the registration before any response.
    let mut unkept = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        PersistentAuthenticator::new(ORIGIN, Zeroizing::new([7; 32]))
            .unwrap()
            .keeping_handle(|_| false),
    );
    let (options, _) = server.start_registration(member).unwrap();
    assert!(matches!(
        futures::executor::block_on(unkept.register_member(serde_json::to_value(options).unwrap())),
        Err(cpky::Error::Unavailable)
    ));

    let kept = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
    let mut first = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        PersistentAuthenticator::new(ORIGIN, Zeroizing::new([7; 32]))
            .unwrap()
            .keeping_handle({
                let kept = kept.clone();
                move |handle| {
                    *kept.lock().unwrap() = Some(handle.to_vec());
                    true
                }
            }),
    );
    let (options, pending) = server.start_registration(member).unwrap();
    let (public, prf) =
        futures::executor::block_on(first.register_member(serde_json::to_value(options).unwrap()))
            .unwrap()
            .into_parts();
    let original = prf.import(|bytes| blake3::hash(bytes));
    let registration_id = public.credential_id().unwrap();
    let response = serde_json::from_value(public.into_json()).unwrap();
    let stored = server
        .finish_registration(pending, &response, CreationMonth::new(2026, 10).unwrap())
        .unwrap();
    assert_eq!(registration_id.as_slice(), stored.credential_id().as_ref());

    // New device: only the seed and the stored (non-secret) user handle.
    let handle = first.into_authenticator().user_handle().unwrap().to_vec();
    // The keeper held the same handle before the response left the device.
    assert_eq!(kept.lock().unwrap().as_deref(), Some(handle.as_slice()));

    // Without the stored handle the same seed's discoverable sign-in is refused: the
    // handle must be durable from the registration on.
    let mut forgetful = device(7);
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    if let Ok(done) =
        futures::executor::block_on(forgetful.sign_in(serde_json::to_value(options).unwrap()))
    {
        let (public, _) = done.into_parts();
        let response = serde_json::from_value(public.into_json()).unwrap();
        assert!(
            server
                .finish_discoverable_authentication(pending, &response)
                .is_err()
        );
    }
    let mut fresh = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        PersistentAuthenticator::new(ORIGIN, Zeroizing::new([7; 32]))
            .unwrap()
            .with_user_handle(handle),
    );
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let (public, vault) =
        futures::executor::block_on(fresh.sign_in(serde_json::to_value(options).unwrap()))
            .unwrap()
            .into_parts();
    let VaultOutcome::Ready(prf) = vault else {
        panic!("PRF required")
    };
    assert_eq!(original, prf.import(|bytes| blake3::hash(bytes)));
    assert_eq!(public.credential_id().unwrap(), registration_id);
    let response = serde_json::from_value(public.into_json()).unwrap();
    let auth = server
        .finish_discoverable_authentication(pending, &response)
        .unwrap();
    assert_eq!(auth.member(), member);

    // A different seed has a different credential: the server finds nothing.
    let mut other = device(8);
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    if let Ok(done) =
        futures::executor::block_on(other.sign_in(serde_json::to_value(options).unwrap()))
    {
        let (public, _) = done.into_parts();
        let response = serde_json::from_value(public.into_json()).unwrap();
        assert!(
            server
                .finish_discoverable_authentication(pending, &response)
                .is_err()
        );
    }
}

mod no_leak {
    use super::*;
    use static_assertions::assert_not_impl_any;
    use std::fmt::{Debug, Display};

    // No formatting or serialization path exists for the authenticator at all.
    assert_not_impl_any!(PersistentAuthenticator: Debug, Display, serde::Serialize, Clone);

    #[test]
    fn errors_and_refusals_never_contain_seed_bytes() {
        let seed = [0xA7u8; 32];
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        let b64 = {
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(seed)
        };
        let mut texts = Vec::new();
        // Refused constructions (zero seed, bad origin).
        for result in [
            PersistentAuthenticator::new(ORIGIN, Zeroizing::new([0; 32])),
            PersistentAuthenticator::new("not a url", Zeroizing::new(seed)),
        ] {
            let error = result.err().expect("construction must be refused");
            texts.push(format!("{error} {error:?}"));
        }
        // A ceremony with unusable options fails without echoing anything secret.
        let mut device = Client::new(
            Context::new(ORIGIN, RP).unwrap(),
            PersistentAuthenticator::new(ORIGIN, Zeroizing::new(seed)).unwrap(),
        );
        let error = futures::executor::block_on(device.register_member(serde_json::json!({})))
            .err()
            .expect("empty options must be refused");
        texts.push(format!("{error} {error:?}"));
        let error =
            futures::executor::block_on(device.sign_in(serde_json::json!({"publicKey": 1})))
                .err()
                .expect("malformed options must be refused");
        texts.push(format!("{error} {error:?}"));
        for text in texts {
            assert!(!text.contains(&hex) && !text.contains(&b64) && !text.contains("a7a7a7a7"));
        }
    }
}

/// Known-answer wire bytes of the seed-derived credential, pinned before the move of cpky's
/// own p256 (key derivation: HKDF-SHA256 -> P-256 scalar -> public key) to 0.14
/// (RUSTSEC-2026-0387). Seed [7;32], fixed options. Every value is cross-checked against
/// OpenSSL: the credential id and the scalar are the HKDF outputs, the SPKI key is the
/// scalar's public key, and the assertion signature is the RFC 6979 signature of that key
/// over authenticatorData || SHA-256(clientDataJSON).
mod vectors {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use sha2::{Digest, Sha256};

    const CREDENTIAL_ID: &str = "D0zQvz9A60p0NjWLN4Zv1epW31xdnNUocAOXsMu85BA";
    const SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUhjCUvSfLihK1rmSzqmltOfjxHIySDCp-PxTOJPxg8_AAKJUh7IxzgjKyuNbcvOoyksHhiI6tLivwrsTx3tI6w";
    const CREATE_CLIENT_DATA: &str = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS1NrcEtTa3BLU2twS1NrcEtTa3BLU2twS1NrcEtTa3BLU2twS1NrcEtTayIsIm9yaWdpbiI6Imh0dHBzOi8vbWVtYmVycy5leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    /// rpIdHash, flags UP|UV|BE|BS|AT, counter 0, empty AAGUID, the credential id and the
    /// COSE ES256 key (x, y of the derived public key).
    const CREATE_AUTH_DATA: &str = "leYsRMNCJ-JFyvqdsXwKrGqZMvn-O703GI6Ai4-gykhdAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA9M0L8_QOtKdDY1izeGb9XqVt9cXZzVKHADl7DLvOQQpQECAyYgASFYIFIYwlL0ny4oSta5ks6ppbTn48RyMkgwqfj8UziT8YPPIlggwACiVIeyMc4IysrjW3LzqMpLB4YiOrS4r8K7E8d7SOs";
    const ATTESTATION: &str = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikleYsRMNCJ-JFyvqdsXwKrGqZMvn-O703GI6Ai4-gykhdAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA9M0L8_QOtKdDY1izeGb9XqVt9cXZzVKHADl7DLvOQQpQECAyYgASFYIFIYwlL0ny4oSta5ks6ppbTn48RyMkgwqfj8UziT8YPPIlggwACiVIeyMc4IysrjW3LzqMpLB4YiOrS4r8K7E8d7SOs";
    const GET_CLIENT_DATA: &str = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTnpjM056YzNOemMzTnpjM056YzNOemMzTnpjM056YzNOemMzTnpjM056YyIsIm9yaWdpbiI6Imh0dHBzOi8vbWVtYmVycy5leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const GET_AUTH_DATA: &str = "leYsRMNCJ-JFyvqdsXwKrGqZMvn-O703GI6Ai4-gykgdAAAAAA";
    const SIGNATURE: &str = "MEUCIEqrGk2mDCpyQlttcSz3JTok3Ae2STTJnlsj_U93zvy3AiEA9bTVDkaN6Zc2zWYm_-MmiVG9IrB92_x2XworK_hQKT0";
    const USER_HANDLE: &str = "EREREREREREREREREREREQ";

    fn creation() -> serde_json::Value {
        serde_json::json!({"publicKey":{
            "rp":{"id":RP,"name":"Synthetic community"},
            "user":{"id":B64.encode([17;16]),"name":"synthetic-member","displayName":"Test member"},
            "challenge":B64.encode([41;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required","authenticatorAttachment":"platform"},
            "timeout":42000,"excludeCredentials":[],"attestation":"none",
            "extensions":{"credProps":true},"hints":["client-device"]
        }})
    }

    fn request() -> serde_json::Value {
        serde_json::json!({"publicKey":{"challenge":B64.encode([55;32]),"rpId":RP,"userVerification":"required","allowCredentials":[],"timeout":21000}})
    }

    #[test]
    fn seed_credential_wire_bytes_are_pinned() {
        let mut first = device(7);
        let (public, _) = futures::executor::block_on(first.register_member(creation()))
            .unwrap()
            .into_parts();
        let created = public.into_json();
        assert_eq!(created["rawId"], CREDENTIAL_ID);
        assert_eq!(created["response"]["publicKey"], SPKI);
        assert_eq!(created["response"]["publicKeyAlgorithm"], -7);
        assert_eq!(created["response"]["clientDataJSON"], CREATE_CLIENT_DATA);
        assert_eq!(created["response"]["authenticatorData"], CREATE_AUTH_DATA);
        assert_eq!(created["response"]["attestationObject"], ATTESTATION);

        let handle = first.into_authenticator().user_handle().unwrap().to_vec();
        let mut fresh = Client::new(
            Context::new(ORIGIN, RP).unwrap(),
            PersistentAuthenticator::new(ORIGIN, Zeroizing::new([7; 32]))
                .unwrap()
                .with_user_handle(handle),
        );
        let (public, _) = futures::executor::block_on(fresh.sign_in(request()))
            .unwrap()
            .into_parts();
        let asserted = public.into_json();
        assert_eq!(asserted["rawId"], CREDENTIAL_ID);
        assert_eq!(asserted["response"]["clientDataJSON"], GET_CLIENT_DATA);
        assert_eq!(asserted["response"]["authenticatorData"], GET_AUTH_DATA);
        assert_eq!(asserted["response"]["signature"], SIGNATURE);
        assert_eq!(asserted["response"]["userHandle"], USER_HANDLE);
    }

    #[test]
    fn stored_assertion_verifies_under_the_pinned_key() {
        let spki = B64.decode(SPKI).unwrap();
        // SPKI for P-256: 26-byte prefix, then the 65-byte uncompressed SEC1 point.
        let key = VerifyingKey::from_sec1_bytes(&spki[26..]).unwrap();
        let mut signed = B64.decode(GET_AUTH_DATA).unwrap();
        signed.extend_from_slice(&Sha256::digest(B64.decode(GET_CLIENT_DATA).unwrap()));
        let signature = Signature::from_der(&B64.decode(SIGNATURE).unwrap()).unwrap();
        assert!(key.verify(&signed, &signature).is_ok());
        signed[0] ^= 1;
        assert!(key.verify(&signed, &signature).is_err());
    }
}
