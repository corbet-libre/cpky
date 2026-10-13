use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
static_assertions::assert_not_impl_any!(UnlockSecret: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(Registration: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(Authentication: std::fmt::Debug, Clone, serde::Serialize);

pub(crate) const ORIGIN: &str = "https://members.example.com";
pub(crate) const RP: &str = "members.example.com";
pub(crate) fn creation() -> Value {
    json!({"publicKey":{
        "rp":{"id":RP,"name":"Synthetic community"},
        "user":{"id":URL_SAFE_NO_PAD.encode([17;16]),"name":"synthetic-member","displayName":"Test member"},
        "challenge":URL_SAFE_NO_PAD.encode([41;32]),
        "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
        "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required","authenticatorAttachment":"platform"},
        "timeout":42000,"excludeCredentials":[],"attestation":"none",
        "extensions":{"credProps":true},"hints":["client-device"]
    }})
}
pub(crate) fn request() -> Value {
    json!({"publicKey":{"challenge":URL_SAFE_NO_PAD.encode([55;32]),"rpId":RP,"userVerification":"required","allowCredentials":[],"timeout":21000}})
}
fn context() -> Context {
    Context::new(ORIGIN, RP).unwrap()
}
fn protocol_response(create: bool) -> Value {
    let input = if create { creation() } else { request() };
    let data = json!({"type":if create{"webauthn.create"}else{"webauthn.get"},"origin":ORIGIN,"challenge":input["publicKey"]["challenge"],"crossOrigin":false});
    let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
    auth.extend_from_slice(&[5, 0, 0, 0, 0]);
    json!({"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap()),"authenticatorData":URL_SAFE_NO_PAD.encode(auth),"userHandle":creation()["publicKey"]["user"]["id"]},"clientExtensionResults":{}})
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_options_and_fixed_input() {
    #[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
    let _ = browser_coverage_runtime::__owned_test_module_signature();
    for create in [false, true] {
        let original = if create { creation() } else { request() };
        let mut prepared = context().prepare(original.clone(), create).unwrap();
        // Frozen output independently checked with upstream Python blake3 1.0.10.
        let expected = [
            0x4a, 0x5f, 0xd8, 0xdb, 0x4e, 0x94, 0xba, 0x16, 0xe6, 0xe2, 0x95, 0x58, 0x07, 0xff,
            0xe0, 0x15, 0x8f, 0x03, 0xe2, 0xcf, 0x39, 0x37, 0x15, 0xdd, 0xe5, 0xd6, 0x16, 0x34,
            0x23, 0x47, 0xfa, 0x2d,
        ];
        assert_eq!(prf_input(), expected);
        assert_eq!(
            prepared["publicKey"]["extensions"]["prf"]["eval"]["first"],
            URL_SAFE_NO_PAD.encode(expected)
        );
        assert_eq!(
            context().prepare(prepared.clone(), create).unwrap(),
            prepared
        );
        prepared["publicKey"]["extensions"]
            .as_object_mut()
            .unwrap()
            .remove("prf");
        if original["publicKey"].get("extensions").is_none() {
            prepared["publicKey"]
                .as_object_mut()
                .unwrap()
                .remove("extensions");
        }
        assert_eq!(prepared, original);
    }
    let original = creation();
    let created = protocol_response(true);
    let follow = context()
        .followup(
            &context().prepare(original.clone(), true).unwrap(),
            &created,
        )
        .unwrap();
    assert_eq!(follow["publicKey"]["rpId"], RP);
    assert_eq!(
        follow["publicKey"]["challenge"],
        original["publicKey"]["challenge"]
    );
    assert_eq!(
        follow["publicKey"]["allowCredentials"],
        json!([{"type":"public-key","id":"AQ"}])
    );
    assert_eq!(follow["publicKey"]["userVerification"], "required");
    assert_eq!(follow["publicKey"]["timeout"], 42000);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn option_and_context_faults() {
    for error in [
        Error::InvalidOptions,
        Error::WrongContext,
        Error::Unavailable,
        Error::Cancelled,
        Error::PrfUnavailable,
        Error::InvalidPrf,
        Error::CeremonyMismatch,
        Error::InvalidResponse,
    ] {
        assert!(!error.to_string().is_empty());
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error:?}").contains(ORIGIN));
    }
    assert!(
        Error::PrfUnavailable
            .to_string()
            .contains("current phone or browser")
    );
    for (origin, rp) in [
        ("invalid", RP),
        ("data:text/plain,x", RP),
        ("http://members.example.com", RP),
        (ORIGIN, ""),
        (ORIGIN, "evil.example.com"),
        ("https://members.example.com/path", RP),
    ] {
        assert!(Context::new(origin, rp).is_err());
    }
    assert!(Context::new("http://localhost:1234", "localhost").is_ok());
    assert!(Context::new("https://vault.members.example.com", RP).is_ok());
    assert_eq!(context().origin(), ORIGIN);
    assert_eq!(context().rp_id(), RP);
    for invalid in [
        Value::Null,
        json!([]),
        json!({"publicKey":[]}),
        json!({"publicKey":{"rpId":"other"}}),
    ] {
        assert!(context().prepare(invalid, false).is_err());
    }
    for value in [
        Value::Null,
        json!(""),
        json!("%%%"),
        json!("x".repeat(90000)),
    ] {
        let mut options = request();
        options["publicKey"]["challenge"] = value;
        assert!(context().prepare(options, false).is_err());
    }
    for value in [json!([]), json!({"prf":{"eval":{"first":"changed"}}})] {
        let mut options = request();
        options["publicKey"]["extensions"] = value;
        assert!(context().prepare(options, false).is_err());
    }
    let mut options = request();
    options["publicKey"]["extensions"] = Value::Null;
    assert!(context().prepare(options.clone(), false).is_ok());
    options["huge"] = json!("a".repeat(262145));
    assert!(context().prepare(options, false).is_err());
    let mut options = creation();
    options["publicKey"]["user"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    assert!(context().prepare(options, true).is_err());
    let mut options = request();
    options["publicKey"]
        .as_object_mut()
        .unwrap()
        .remove("challenge");
    assert!(context().prepare(options, false).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unrelated_ceremony_halves_refuse() {
    let response = protocol_response(false);
    assert!(context().bind(&response, &request(), false).is_ok());
    for path in ["id", "rawId", "type"] {
        let mut wrong = response.clone();
        wrong[path] = json!("different");
        assert!(context().bind(&wrong, &request(), false).is_err());
    }
    for field in ["origin", "challenge", "type"] {
        let mut wrong = response.clone();
        let bytes = options::decode(&wrong["response"]["clientDataJSON"]).unwrap();
        let mut data: Value = serde_json::from_slice(&bytes).unwrap();
        data[field] = json!("different");
        wrong["response"]["clientDataJSON"] =
            json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap()));
        assert!(context().bind(&wrong, &request(), false).is_err());
    }
    for bytes in [vec![], vec![0; 37], {
        let mut a = Sha256::digest(RP.as_bytes()).to_vec();
        a.extend_from_slice(&[1, 0, 0, 0, 0]);
        a
    }] {
        let mut wrong = response.clone();
        wrong["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode(bytes));
        assert!(context().bind(&wrong, &request(), false).is_err());
    }
    let mut allowed = request();
    allowed["publicKey"]["allowCredentials"] = json!([{"id":"Ag"}]);
    assert!(context().bind(&response, &allowed, false).is_err());
    allowed["publicKey"]["allowCredentials"] = json!([{"id":"AQ"}]);
    assert!(context().bind(&response, &allowed, false).is_ok());
    allowed["publicKey"]
        .as_object_mut()
        .unwrap()
        .remove("allowCredentials");
    assert!(context().bind(&response, &allowed, false).is_ok());
    allowed["publicKey"]["allowCredentials"] = Value::Null;
    assert!(context().bind(&response, &allowed, false).is_err());
    let mut wrong = response.clone();
    wrong["response"]["userHandle"] = json!("Ag");
    assert!(options::bind_handle(&wrong, &creation()).is_err());
    wrong["response"]["userHandle"] = Value::Null;
    assert!(options::bind_handle(&wrong, &creation()).is_ok());
    wrong["response"]
        .as_object_mut()
        .unwrap()
        .remove("userHandle");
    assert!(options::bind_handle(&wrong, &creation()).is_ok());
    assert!(options::bind_handle(&response, &creation()).is_ok());
}

#[cfg(feature = "test-authenticator")]
mod upstream {
    use super::*;
    use crate::software::{SoftwareAuthenticator, TestConfiguration};
    pub(crate) fn software(prf: bool, create: bool) -> SoftwareAuthenticator {
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf,
                evaluate_at_create: create,
            },
        )
        .unwrap()
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn native_platform_unavailable() {
        futures::executor::block_on(async {
            let mut client = Client::new(context(), Unavailable);
            assert!(matches!(
                client.register_member(creation()).await,
                Err(Error::Unavailable)
            ));
            assert!(matches!(
                client.sign_in(request()).await,
                Err(Error::Unavailable)
            ));
            assert!(matches!(
                client.register_privileged(creation()).await,
                Err(Error::Unavailable)
            ));
        });
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn real_prf_create_get_and_fresh_device() {
        futures::executor::block_on(async {
            for evaluate in [true, false] {
                let mut client = Client::new(context(), software(true, evaluate));
                let (registration, prf) = client
                    .register_member(creation())
                    .await
                    .unwrap()
                    .into_parts();
                assert!(
                    registration.as_json()["clientExtensionResults"]
                        .get("prf")
                        .is_none()
                );
                let first = prf.import(|bytes| blake3::hash(bytes));
                let authenticator = client.into_authenticator();
                let mut fresh = Client::new(context(), authenticator.synced_test_device());
                let (assertion, vault) = fresh.sign_in(request()).await.unwrap().into_parts();
                assert_eq!(
                    assertion.as_json()["rawId"],
                    registration.as_json()["rawId"]
                );
                assert_eq!(
                    assertion.as_json()["response"]["userHandle"],
                    creation()["publicKey"]["user"]["id"]
                );
                let VaultOutcome::Ready(prf) = vault else {
                    panic!("upstream PRF missing")
                };
                assert_eq!(first, prf.import(|bytes| blake3::hash(bytes)));
                assert!(!serde_json::to_string(&assertion).unwrap().contains("prf"));
            }
        });
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn missing_prf_never_exposes_member_registration_but_privileged_and_login_are_separate() {
        futures::executor::block_on(async {
            let mut client = Client::new(context(), software(false, false));
            assert!(matches!(
                client.register_member(creation()).await,
                Err(Error::PrfUnavailable)
            ));
            let mut admin = Client::new(context(), software(false, false));
            let public = admin.register_privileged(creation()).await.unwrap();
            assert!(
                public.into_json()["clientExtensionResults"]
                    .get("prf")
                    .is_none()
            );
            let (_, vault) = admin.sign_in(request()).await.unwrap().into_parts();
            assert!(matches!(vault, VaultOutcome::Locked(Error::PrfUnavailable)));
        });
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn context_origin_and_relying_party_rules_are_exact() {
    for (origin, rp) in [
        (ORIGIN, RP),
        ("https://a.members.example.com", RP),
        ("http://localhost:8080", "localhost"),
    ] {
        assert!(Context::new(origin, rp).is_ok(), "{origin} {rp}");
    }
    for (origin, rp) in [
        ("https://members.example.com/", RP),
        ("http://members.example.com", RP),
        ("http://localhost", ""),
        ("ftp://members.example.com", RP),
        ("https://evilmembers.example.com", RP),
        (ORIGIN, "other.example.com"),
    ] {
        assert!(Context::new(origin, rp).is_err(), "{origin} {rp}");
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn minimal_options_and_responses_take_the_other_branches() {
    // Registration options need a user handle.
    let mut no_user = creation();
    no_user["publicKey"].as_object_mut().unwrap().remove("user");
    assert_eq!(
        context().prepare(no_user, true).unwrap_err(),
        Error::InvalidOptions
    );
    let mut no_user_id = creation();
    no_user_id["publicKey"]["user"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    assert_eq!(
        context().prepare(no_user_id, true).unwrap_err(),
        Error::InvalidOptions
    );
    // The follow-up evaluation copies a timeout and user verification only when set.
    let mut minimal = creation();
    {
        let public = minimal["publicKey"].as_object_mut().unwrap();
        public.remove("timeout");
        public.remove("authenticatorSelection");
    }
    let prepared = context().prepare(minimal, true).unwrap();
    let follow = context()
        .followup(&prepared, &protocol_response(true))
        .unwrap();
    assert!(follow["publicKey"].get("timeout").is_none());
    assert!(follow["publicKey"].get("userVerification").is_none());
    // An undecodable user handle or client data is refused at its own step.
    let mut bad_user = creation();
    bad_user["publicKey"]["user"]["id"] = json!("not base64!");
    assert_eq!(
        context().prepare(bad_user, true).unwrap_err(),
        Error::InvalidOptions
    );
    let mut garbled = protocol_response(false);
    garbled["response"]["clientDataJSON"] = json!("not base64!");
    assert_eq!(
        context().bind(&garbled, &request(), false).unwrap_err(),
        Error::InvalidOptions
    );
    // Authenticator data shorter than the fixed header is refused.
    let mut short = protocol_response(false);
    short["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode([1; 36]));
    assert_eq!(
        context().bind(&short, &request(), false).unwrap_err(),
        Error::CeremonyMismatch
    );
    // A response without clientDataJSON is not a response.
    let mut response = protocol_response(false);
    response["response"]
        .as_object_mut()
        .unwrap()
        .remove("clientDataJSON");
    assert_eq!(
        context().bind(&response, &request(), false).unwrap_err(),
        Error::InvalidResponse
    );
    // Without a required user verification the flag is not demanded.
    let mut relaxed = request();
    relaxed["publicKey"]["userVerification"] = json!("preferred");
    let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
    auth.extend_from_slice(&[1, 0, 0, 0, 0]);
    let mut unverified = protocol_response(false);
    unverified["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode(auth));
    assert!(context().bind(&unverified, &relaxed, false).is_ok());
    assert!(context().bind(&unverified, &request(), false).is_err());
}
