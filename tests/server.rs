//! Actual maintained authenticator and Keyhole server verification with real SQL storage.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-authenticator"))]
use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
use cpky::{
    Client, Context, VaultOutcome,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use serde_json::Value;
const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";

#[test]
fn real_server_accepts_stripped_registration_discovery_and_refuses_revoked_signature() {
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
    let member = Uuid::from_u128(17);
    let mut device = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    );
    let (options, pending) = server.start_registration(member).unwrap();
    let (public, prf) =
        futures::executor::block_on(device.register_member(serde_json::to_value(options).unwrap()))
            .unwrap()
            .into_parts();
    let original = prf.import(|bytes| blake3::hash(bytes));
    let response = serde_json::from_value(public.into_json()).unwrap();
    let stored = server
        .finish_registration(pending, &response, CreationMonth::new(2026, 10).unwrap())
        .unwrap();
    let mut fresh = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        device.into_authenticator().synced_test_device(),
    );
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let options = serde_json::to_value(options).unwrap();
    assert_eq!(
        options["publicKey"]["allowCredentials"],
        serde_json::json!([])
    );
    let (public, vault) = futures::executor::block_on(fresh.sign_in(options))
        .unwrap()
        .into_parts();
    let VaultOutcome::Ready(prf) = vault else {
        panic!("real PRF required")
    };
    assert_eq!(original, prf.import(|bytes| blake3::hash(bytes)));
    let response = serde_json::from_value(public.into_json()).unwrap();
    let auth = server
        .finish_discoverable_authentication(pending, &response)
        .unwrap();
    assert_eq!(auth.member(), member);
    assert_eq!(auth.credential_id(), stored.credential_id());
    // Corrupt real signed assertions at the wire boundary. The actual server,
    // not a substitute verifier, must reject origin/RP/UV/signature changes.
    for fault in [
        "origin",
        "crossOrigin",
        "challenge",
        "rp",
        "uv",
        "signature",
        "handle",
    ] {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let (options, pending) = server.start_discoverable_authentication().unwrap();
        let (public, _) =
            futures::executor::block_on(fresh.sign_in(serde_json::to_value(options).unwrap()))
                .unwrap()
                .into_parts();
        let mut public = public.into_json();
        if ["origin", "crossOrigin", "challenge"].contains(&fault) {
            let bytes = URL_SAFE_NO_PAD
                .decode(public["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap();
            let mut data: Value = serde_json::from_slice(&bytes).unwrap();
            data[fault] = match fault {
                "crossOrigin" => serde_json::json!(true),
                "origin" => serde_json::json!("https://other.example.com"),
                _ => serde_json::json!(URL_SAFE_NO_PAD.encode([99; 32])),
            };
            public["response"]["clientDataJSON"] =
                serde_json::json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap()));
        } else if ["rp", "uv"].contains(&fault) {
            let mut auth = URL_SAFE_NO_PAD
                .decode(public["response"]["authenticatorData"].as_str().unwrap())
                .unwrap();
            if fault == "rp" {
                auth[0] ^= 1;
            } else {
                auth[32] &= !4;
            }
            public["response"]["authenticatorData"] =
                serde_json::json!(URL_SAFE_NO_PAD.encode(auth));
        } else if fault == "signature" {
            public["response"]["signature"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 64]));
        } else {
            public["response"]["userHandle"] = serde_json::json!(URL_SAFE_NO_PAD.encode([99; 16]));
        }
        let response = serde_json::from_value(public).unwrap();
        assert!(
            server
                .finish_discoverable_authentication(pending, &response)
                .is_err(),
            "{fault}"
        );
    }
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let (public, _) =
        futures::executor::block_on(fresh.sign_in(serde_json::to_value(options).unwrap()))
            .unwrap()
            .into_parts();
    server.revoke(member, stored.credential_id()).unwrap();
    let response = serde_json::from_value(public.into_json()).unwrap();
    assert!(
        server
            .finish_discoverable_authentication(pending, &response)
            .is_err()
    );
    let rows: Value = serde_json::to_value(server.list(member).unwrap()).unwrap();
    assert!(!rows.to_string().contains("prf"));
}
