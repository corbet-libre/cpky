//! Actual maintained authenticator -> HPKE -> original bound credential decoder.
use super::seal::{self, Offer, Receiver};
use crate::{
    CeremonyKind, CeremonyRequest, CeremonyResult, Client, Context, Error,
    software::{SoftwareAuthenticator, TestConfiguration},
    tests::{ORIGIN, RP, creation},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn context() -> Context {
    Context::new(ORIGIN, RP).unwrap()
}
fn request() -> CeremonyRequest {
    CeremonyRequest {
        kind: CeremonyKind::MemberRegistration,
        options: creation(),
    }
}
fn platform() -> SoftwareAuthenticator {
    SoftwareAuthenticator::new(
        ORIGIN,
        TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap()
}
fn copy(offer: &Offer) -> Offer {
    serde_json::from_slice(&serde_json::to_vec(offer).unwrap()).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_registration_roundtrips_once_with_the_same_opaque_prf() {
    futures::executor::block_on(async {
        let mut device = Client::new(context(), platform());
        let registration = device.register_member(creation()).await.unwrap();
        let mut synced = Client::new(context(), device.into_authenticator().synced_test_device());
        let (_, vault) = synced
            .sign_in(crate::tests::request())
            .await
            .unwrap()
            .into_parts();
        let crate::VaultOutcome::Ready(secret) = vault else {
            panic!("real PRF required");
        };
        let expected = secret.import(|bytes| blake3::hash(bytes));
        let mut owner = Receiver::new(context(), request()).unwrap();
        let nonce = owner.offer().nonce;
        let sealed = seal::seal(
            owner.offer(),
            &context(),
            CeremonyResult::MemberRegistration(registration),
        )
        .unwrap();
        let CeremonyResult::MemberRegistration(opened) =
            owner.open(&nonce, ORIGIN, &sealed).unwrap()
        else {
            panic!("original registration required");
        };
        let (public, secret) = opened.into_parts();
        assert_eq!(secret.import(|bytes| blake3::hash(bytes)), expected);
        assert!(!public.as_json().to_string().contains("prf"));
        assert!(matches!(
            owner.open(&nonce, ORIGIN, &sealed),
            Err(Error::Cancelled)
        ));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn nonce_origins_recipient_request_and_ciphertext_are_bound() {
    futures::executor::block_on(async {
        for fault in 0..8 {
            let mut owner = Receiver::new(context(), request()).unwrap();
            let mut offer = copy(owner.offer());
            let nonce = offer.nonce;
            match fault {
                0 => offer.nonce[0] ^= 1,
                1 => {
                    offer.recipient = Receiver::new(context(), request())
                        .unwrap()
                        .offer()
                        .recipient
                }
                2 => {
                    offer.request.options["publicKey"]["challenge"] =
                        serde_json::json!(URL_SAFE_NO_PAD.encode([99; 32]))
                }
                3 => offer.frame_origin = "https://foreign.example.com".into(),
                4 => offer.popup_origin = "https://foreign.example.com".into(),
                5 => offer.rp = "example.com".into(),
                _ => {}
            }
            let registration = Client::new(context(), platform())
                .register_member(creation())
                .await
                .unwrap();
            let sealed = seal::seal(
                &offer,
                &context(),
                CeremonyResult::MemberRegistration(registration),
            );
            if (3..=5).contains(&fault) {
                assert!(matches!(sealed, Err(Error::WrongContext)));
                continue;
            }
            let mut sealed = sealed.unwrap();
            if fault == 6 {
                let last = sealed.len() - 1;
                sealed[last] ^= 1;
            }
            let origin = if fault == 7 {
                "https://foreign.example.com"
            } else {
                ORIGIN
            };
            assert!(owner.open(&nonce, origin, &sealed).is_err());
            assert!(matches!(
                owner.open(&nonce, ORIGIN, &sealed),
                Err(Error::Cancelled)
            ));
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_bound_decoder_rejects_another_real_challenge_even_when_sealed() {
    futures::executor::block_on(async {
        let mut owner = Receiver::new(context(), request()).unwrap();
        let mut different = creation();
        different["publicKey"]["challenge"] = serde_json::json!(URL_SAFE_NO_PAD.encode([99; 32]));
        let result = Client::new(context(), platform())
            .register_member(different)
            .await
            .unwrap();
        let nonce = owner.offer().nonce;
        let sealed = seal::seal(
            owner.offer(),
            &context(),
            CeremonyResult::MemberRegistration(result),
        )
        .unwrap();
        assert!(matches!(
            owner.open(&nonce, ORIGIN, &sealed),
            Err(Error::CeremonyMismatch)
        ));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_packets_consume_the_one_use_receiver() {
    for sealed in [
        vec![],
        vec![1; 49],
        vec![2; 50],
        vec![1; seal::MAX_SEALED + 1],
    ] {
        let mut owner = Receiver::new(context(), request()).unwrap();
        let nonce = owner.offer().nonce;
        assert!(owner.open(&nonce, ORIGIN, &sealed).is_err());
        assert!(matches!(
            owner.open(&nonce, ORIGIN, &sealed),
            Err(Error::Cancelled)
        ));
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn real_broadcast_channel_delivers_only_the_sealed_result_to_original_opening() {
    use super::channel::{Channel, Packet};
    let mut owner = Receiver::new(context(), request()).unwrap();
    let nonce = owner.offer().nonce;
    let actual_origin = web_sys::window().unwrap().location().origin().unwrap();
    let name = format!("cpky-test-{:?}", nonce);
    let mut receiving = Channel::new(&name, &actual_origin, 10_000).unwrap();
    let sending = Channel::new(&name, &actual_origin, 10_000).unwrap();
    let result = Client::new(context(), platform())
        .register_member(creation())
        .await
        .unwrap();
    let sealed = seal::seal(
        owner.offer(),
        &context(),
        CeremonyResult::MemberRegistration(result),
    )
    .unwrap();
    sending
        .post(&Packet::Result {
            peer: [7; 32],
            nonce,
            sealed,
        })
        .unwrap();
    let Packet::Result {
        peer,
        nonce,
        sealed,
    } = receiving.next().await.unwrap()
    else {
        panic!("result required");
    };
    assert_eq!(peer, [7; 32]);
    assert!(matches!(
        owner.open(&nonce, ORIGIN, &sealed),
        Ok(CeremonyResult::MemberRegistration(_))
    ));
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn real_channel_deadline_closes_without_a_result() {
    use super::channel::Channel;
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let mut channel = Channel::new("cpky-test-expiry", &origin, 1).unwrap();
    let mut owner = Receiver::new(context(), request()).unwrap();
    let nonce = owner.offer().nonce;
    channel.expire_with(owner.expire());
    assert!(matches!(channel.next().await, Err(Error::Cancelled)));
    assert!(matches!(channel.next().await, Err(Error::Cancelled)));
    // No owner wait/open was polled; the channel deadline itself dropped its key.
    assert!(matches!(
        owner.open(&nonce, ORIGIN, &[]),
        Err(Error::Cancelled)
    ));
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_channel_wrong_origin_and_oversized_payload_refuse_before_opening() {
    use super::channel::Channel;
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    for (name, expected, size) in [
        ("cpky-test-origin", "https://foreign.example.com", 2),
        (
            "cpky-test-size",
            origin.as_str(),
            seal::MAX_SEALED * 4 + 4097,
        ),
    ] {
        let mut receiver = Channel::new(name, expected, 10_000).unwrap();
        let sender = web_sys::BroadcastChannel::new(name).unwrap();
        let body = js_sys::Uint8Array::new_with_length(size as u32);
        sender.post_message(body.as_ref()).unwrap();
        assert!(matches!(receiver.next().await, Err(Error::Cancelled)));
        sender.close();
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn keyhole_accepts_actual_sealed_registration_and_discoverable_assertion() {
    use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let database = Url::from_file_path(directory.path().join("popup.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(database.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(1, "popup", ckyh::LIBSQL_SCHEMA)]))
        .unwrap();
    let store = LibsqlStore::new(&db, "synthetic", runtime.handle().clone()).unwrap();
    let server = Passkeys::new(store, "synthetic", RP, &[Url::parse(ORIGIN).unwrap()]).unwrap();
    let member = Uuid::from_u128(181);
    let mut device = Client::new(context(), platform());
    let (options, pending) = server.start_registration(member).unwrap();
    let options = serde_json::to_value(options).unwrap();
    let mut receiver = Receiver::new(
        context(),
        CeremonyRequest {
            kind: CeremonyKind::MemberRegistration,
            options: options.clone(),
        },
    )
    .unwrap();
    let result = runtime.block_on(device.register_member(options)).unwrap();
    let nonce = receiver.offer().nonce;
    let sealed = seal::seal(
        receiver.offer(),
        &context(),
        CeremonyResult::MemberRegistration(result),
    )
    .unwrap();
    let CeremonyResult::MemberRegistration(registration) =
        receiver.open(&nonce, ORIGIN, &sealed).unwrap()
    else {
        panic!("member registration required");
    };
    let (public, secret) = registration.into_parts();
    let original = secret.import(|bytes| blake3::hash(bytes));
    let stored = server
        .finish_registration(
            pending,
            &serde_json::from_value(public.into_json()).unwrap(),
            CreationMonth::new(2026, 10).unwrap(),
        )
        .unwrap();
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let options = serde_json::to_value(options).unwrap();
    let mut receiver = Receiver::new(
        context(),
        CeremonyRequest {
            kind: CeremonyKind::Authentication,
            options: options.clone(),
        },
    )
    .unwrap();
    let result = runtime.block_on(device.sign_in(options)).unwrap();
    let nonce = receiver.offer().nonce;
    let sealed = seal::seal(
        receiver.offer(),
        &context(),
        CeremonyResult::Authentication(result),
    )
    .unwrap();
    let CeremonyResult::Authentication(authentication) =
        receiver.open(&nonce, ORIGIN, &sealed).unwrap()
    else {
        panic!("authentication required");
    };
    let (public, vault) = authentication.into_parts();
    let crate::VaultOutcome::Ready(secret) = vault else {
        panic!("original PRF required");
    };
    assert_eq!(secret.import(|bytes| blake3::hash(bytes)), original);
    let result = server
        .finish_discoverable_authentication(
            pending,
            &serde_json::from_value(public.into_json()).unwrap(),
        )
        .unwrap();
    assert_eq!(result.member(), member);
    assert_eq!(result.credential_id(), stored.credential_id());
}
