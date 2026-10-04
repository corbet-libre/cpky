use super::*;
use crate::{Client, Context, VaultOutcome};

#[wasm_bindgen_test::wasm_bindgen_test]
fn consumed_loopback_launch_stays_opaque_and_requires_observable_consumption() {
    let window = web_sys::window().unwrap();
    let origin = window.location().origin().unwrap();
    let original = window.location().href().unwrap();
    let mut page = url::Url::parse(&original).unwrap();
    page.set_fragment(None);
    window
        .history()
        .unwrap()
        .replace_state_with_url(&JsValue::NULL, "", Some(page.as_str()))
        .unwrap();
    let context = || Context::new(&origin, "localhost").unwrap();
    let fragment = format!(
        "#cpky-v1=http%3A%2F%2F127.0.0.1%3A4242%2Ffinish&cap={}",
        URL_SAFE_NO_PAD.encode([21; 32])
    );
    // Preparation opens no socket and performs no WebAuthn operation.
    drop(LoopbackCeremony::from_consumed_fragment(context(), &fragment).unwrap());
    page.set_fragment(Some("retained"));
    window
        .history()
        .unwrap()
        .replace_state_with_url(&JsValue::NULL, "", Some(page.as_str()))
        .unwrap();
    assert!(matches!(
        LoopbackCeremony::from_consumed_fragment(context(), &fragment),
        Err(Error::WrongContext)
    ));
    page.set_fragment(None);
    window
        .history()
        .unwrap()
        .replace_state_with_url(&JsValue::NULL, "", Some(page.as_str()))
        .unwrap();
    for invalid in [
        "",
        "#wrong",
        "#cpky-v1=http%3A%2F%2Fforeign.test%3A4242%2Ffinish&cap=bad",
    ] {
        assert!(LoopbackCeremony::from_consumed_fragment(context(), invalid).is_err());
    }
    assert!(matches!(
        LoopbackCeremony::from_consumed_fragment(
            Context::new("https://elsewhere.example", "elsewhere.example").unwrap(),
            &fragment
        ),
        Err(Error::WrongContext)
    ));
    window
        .history()
        .unwrap()
        .replace_state_with_url(&JsValue::NULL, "", Some(&original))
        .unwrap();
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn options_preserve_exact_binary_and_policy_fields() {
    let original = crate::tests::creation();
    let context = Context::new(crate::tests::ORIGIN, crate::tests::RP).unwrap();
    let prepared = context.prepare(original.clone(), true).unwrap();
    let object = prepare_js(&prepared, true).unwrap();
    let pk = get(&object, "publicKey").unwrap();
    assert_eq!(
        encoded(&get(&pk, "challenge").unwrap()).unwrap(),
        original["publicKey"]["challenge"]
    );
    assert_eq!(
        encoded(&get(&get(&pk, "user").unwrap(), "id").unwrap()).unwrap(),
        original["publicKey"]["user"]["id"]
    );
    assert_eq!(get(&pk, "timeout").unwrap().as_f64(), Some(42000.0));
    assert_eq!(
        get(
            &get(&pk, "authenticatorSelection").unwrap(),
            "userVerification"
        )
        .unwrap()
        .as_string()
        .as_deref(),
        Some("required")
    );
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn every_owned_prf_buffer_is_wiped_even_on_malformed_two_output() {
    for (size, second, enabled) in [
        (32, false, true),
        (31, false, true),
        (33, false, true),
        (32, true, true),
        (32, false, false),
    ] {
        let first = Uint8Array::from(vec![7; size].as_slice());
        let extra = Uint8Array::from([9u8; 32].as_slice());
        let results = Object::new();
        set(&results, "first", &first.buffer()).unwrap();
        if second {
            set(&results, "second", &extra).unwrap();
        }
        let prf = Object::new();
        set(&prf, "results", &results).unwrap();
        set(&prf, "enabled", &enabled.into()).unwrap();
        let (reported, result) = take_prf(&prf);
        assert_eq!(reported, enabled);
        assert!(first.to_vec().iter().all(|b| *b == 0));
        if second {
            assert!(extra.to_vec().iter().all(|b| *b == 0));
        }
        if size == 32 && !second && enabled {
            assert_eq!(
                result
                    .unwrap()
                    .unwrap()
                    .import(|bytes| bytes.iter().sum::<u8>()),
                224
            );
        } else {
            assert!(result.is_err());
        }
    }
    assert!(take_prf(&JsValue::UNDEFINED).1.unwrap().is_none());
    assert!(take_prf(&JsValue::NULL).1.unwrap().is_none());
    let prf = Object::new();
    set(&prf, "enabled", &JsValue::TRUE).unwrap();
    assert!(take_prf(&prf).1.unwrap().is_none());
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_navigator_credentials_round_trip() {
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let mut options = crate::tests::creation();
    options["publicKey"]["rp"]["id"] = json!("localhost");
    let context = Context::new(&origin, "localhost").unwrap();
    let mut client = Client::new(context, Browser);
    let (created, prf) = client
        .register_member(options.clone())
        .await
        .unwrap()
        .into_parts();
    let first = prf.import(|bytes| blake3::hash(bytes));
    assert!(
        created.as_json()["clientExtensionResults"]
            .get("prf")
            .is_none()
    );
    let mut request = crate::tests::request();
    request["publicKey"]["rpId"] = json!("localhost");
    request["publicKey"]["allowCredentials"] =
        json!([{"id": created.as_json()["rawId"], "type": "public-key"}]);
    let (assertion, vault) = client.sign_in(request).await.unwrap().into_parts();
    assert_eq!(assertion.as_json()["rawId"], created.as_json()["rawId"]);
    let VaultOutcome::Ready(prf) = vault else {
        panic!("virtual authenticator PRF unavailable")
    };
    assert_eq!(first, prf.import(|bytes| blake3::hash(bytes)));
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_browser_refuses_a_foreign_relying_party() {
    // The options are valid for this foreign context, but the real browser runs
    // at localhost. Exercise navigator.credentials' rejection, not an API stub.
    let context = Context::new("https://127.0.0.1", "127.0.0.1").unwrap();
    for create in [true, false] {
        let mut options = if create {
            crate::tests::creation()
        } else {
            crate::tests::request()
        };
        if create {
            options["publicKey"]["rp"]["id"] = json!("127.0.0.1");
        } else {
            options["publicKey"]["rpId"] = json!("127.0.0.1");
        }
        let prepared = context.prepare(options, create).unwrap();
        assert_eq!(
            Browser.perform(&prepared, create).await.err(),
            Some(Error::Cancelled)
        );
    }
    assert_eq!(complete_loopback(context).await, Err(Error::WrongContext));
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_browser_silent_mediation_without_a_matching_credential_refuses() {
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let context = Context::new(&origin, "localhost").unwrap();
    let mut options = crate::tests::request();
    options["mediation"] = json!("silent");
    options["publicKey"]["rpId"] = json!("localhost");
    options["publicKey"]["timeout"] = json!(1000);
    options["publicKey"]["allowCredentials"] =
        json!([{"id": URL_SAFE_NO_PAD.encode([201; 32]), "type": "public-key"}]);
    let prepared = context.prepare(options, false).unwrap();
    // A genuine null credential or promise refusal both map to Cancelled.
    // Browser profiles, not a fabricated response, establish the actual path.
    assert_eq!(
        Browser.perform(&prepared, false).await.err(),
        Some(Error::Cancelled)
    );
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_request_and_headers_refuse_invalid_helper_input_before_io() {
    let endpoint = url::Url::parse("http://127.0.0.1:1/finish").unwrap();
    assert!(matches!(
        loopback_fetch(&endpoint, "GET\n", "test", None).await,
        Err(Error::InvalidOptions)
    ));
    assert!(matches!(
        loopback_fetch(&endpoint, "GET", "test\nheader", None).await,
        Err(Error::InvalidOptions)
    ));
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn explicit_absent_dictionary_values_and_malformed_eval_are_handled() {
    for missing in [JsValue::NULL, JsValue::UNDEFINED] {
        for create in [true, false] {
            assert!(matches!(split(&missing, create), Err(Error::Cancelled)));
        }
    }
    let prf = Object::new();
    set(&prf, "results", &JsValue::NULL).unwrap();
    assert!(take_prf(&prf).1.unwrap().is_none());
    let results = Object::new();
    let first = Uint8Array::from([7u8; 32].as_slice());
    set(&results, "first", &first).unwrap();
    set(&results, "second", &JsValue::NULL).unwrap();
    set(&prf, "results", &results).unwrap();
    set(&prf, "enabled", &JsValue::TRUE).unwrap();
    assert!(take_prf(&prf).1.unwrap().is_some());
    assert!(first.to_vec().iter().all(|value| *value == 0));
    let credential = dictionary(false, &Object::new());
    set(
        &get(&credential, "response").unwrap(),
        "userHandle",
        &JsValue::UNDEFINED,
    )
    .unwrap();
    assert_eq!(
        split(&credential, false).unwrap().public["response"]["userHandle"],
        Value::Null
    );
    let context = Context::new(crate::tests::ORIGIN, crate::tests::RP).unwrap();
    let mut prepared = context.prepare(crate::tests::request(), false).unwrap();
    prepared["publicKey"]["extensions"]["prf"]["eval"] = Value::Bool(false);
    assert_eq!(
        prepare_js(&prepared, false).err(),
        Some(Error::InvalidOptions)
    );
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_privileged_ceremony_and_callback_frames_keep_secret_states_separate() {
    use crate::callback::{self, CeremonyKind, CeremonyRequest, CeremonyResult};
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let context = Context::new(&origin, "localhost").unwrap();
    let mut options = crate::tests::creation();
    options["publicKey"]["rp"]["id"] = json!("localhost");
    options["publicKey"]["user"]["id"] = json!(URL_SAFE_NO_PAD.encode([23; 16]));
    let completed = callback::execute(
        Context::new(&origin, "localhost").unwrap(),
        CeremonyRequest {
            kind: CeremonyKind::PrivilegedRegistration,
            options,
        },
        Browser,
    )
    .await
    .unwrap();
    let CeremonyResult::PrivilegedRegistration(public) = completed else {
        panic!("privileged ceremony returned the wrong kind")
    };
    let registered_id = public.as_json()["rawId"].clone();
    let mut oversized = public.as_json().clone();
    oversized["oversized_test_field"] = json!("x".repeat(callback::MAX_CALLBACK));
    let bytes = callback::encode(CeremonyResult::PrivilegedRegistration(public)).unwrap();
    assert_eq!(&bytes[..3], &[1, 1, 1]);
    let public_length = u32::from_le_bytes(bytes[3..7].try_into().unwrap()) as usize;
    assert_eq!(
        bytes.len(),
        7 + public_length,
        "privileged frame carries no secret"
    );
    assert_eq!(
        callback::encode(CeremonyResult::PrivilegedRegistration(
            crate::PublicCredential(oversized)
        ))
        .err(),
        Some(Error::InvalidResponse)
    );

    let mut options = crate::tests::request();
    options["publicKey"]["rpId"] = json!("localhost");
    options["publicKey"]["allowCredentials"] = json!([{"id": registered_id, "type": "public-key"}]);
    let completed = callback::execute(
        context,
        CeremonyRequest {
            kind: CeremonyKind::Authentication,
            options,
        },
        Browser,
    )
    .await
    .unwrap();
    let CeremonyResult::Authentication(authentication) = completed else {
        panic!("authentication returned the wrong kind")
    };
    let (public, vault) = authentication.into_parts();
    assert!(
        matches!(vault, VaultOutcome::Ready(_)),
        "real authenticator must evaluate PRF"
    );
    assert_eq!(public.as_json()["rawId"], registered_id);
    // Encoder boundary vectors deliberately substitute a locked outcome for
    // this real assertion. They prove frame shape, not an actual PRF refusal.
    for (error, state) in [(Error::PrfUnavailable, 1), (Error::InvalidPrf, 2)] {
        let result = crate::Authentication {
            credential: crate::PublicCredential(public.as_json().clone()),
            vault: VaultOutcome::Locked(error),
        };
        let bytes = callback::encode(CeremonyResult::Authentication(result)).unwrap();
        assert_eq!(&bytes[..3], &[1, 2, state]);
        let length = u32::from_le_bytes(bytes[3..7].try_into().unwrap()) as usize;
        assert_eq!(bytes.len(), 7 + length, "locked frame carries no secret");
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes[7..]).unwrap(),
            *public.as_json()
        );
    }
}

// Binary dictionary vectors exercise conversion and refusal only; they are not
// evidence of a platform authenticator or a valid cryptographic signature.
fn dictionary(create: bool, extensions: &JsValue) -> JsValue {
    let credential = Object::new();
    for (name, value) in [
        ("id", "AQ"),
        ("type", "public-key"),
        ("authenticatorAttachment", "platform"),
    ] {
        set(&credential, name, &value.into()).unwrap();
    }
    set(
        &credential,
        "rawId",
        &Uint8Array::from([1u8].as_slice()).buffer(),
    )
    .unwrap();
    set(&credential, "extensions", extensions).unwrap();
    set(
        &credential,
        "getClientExtensionResults",
        &Function::new_no_args("return this.extensions"),
    )
    .unwrap();
    let response = Object::new();
    for name in [
        "clientDataJSON",
        "attestationObject",
        "authenticatorData",
        "signature",
    ] {
        set(
            &response,
            name,
            &Uint8Array::from([2u8; 32].as_slice()).buffer(),
        )
        .unwrap();
    }
    set(&response, "userHandle", &JsValue::NULL).unwrap();
    if create {
        set(
            &response,
            "getTransports",
            &Function::new_no_args("return ['internal']"),
        )
        .unwrap();
    }
    set(&credential, "response", &response).unwrap();
    credential.into()
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn split_strips_secrets_before_public_serialization() {
    for create in [false, true] {
        let first = Uint8Array::from([7u8; 32].as_slice());
        let legacy = Uint8Array::from([9u8; 32].as_slice());
        let extensions = Object::new();
        let prf = Object::new();
        let results = Object::new();
        set(&results, "first", &first.buffer()).unwrap();
        set(&prf, "results", &results).unwrap();
        set(&prf, "enabled", &JsValue::TRUE).unwrap();
        set(&extensions, "prf", &prf).unwrap();
        let hmac = Object::new();
        set(&hmac, "output1", &legacy.buffer()).unwrap();
        set(&extensions, "hmacGetSecret", &hmac).unwrap();
        let credential = dictionary(create, &extensions);
        let result = split(&credential, create).unwrap();
        assert!(result.enabled);
        assert!(result.prf.unwrap().is_some());
        assert_eq!(result.public["id"], "AQ");
        assert_eq!(result.public["rawId"], "AQ");
        let wire = result.public.to_string();
        assert!(!wire.contains("prf"));
        assert!(!wire.contains("hmac"));
        assert!(first.to_vec().iter().all(|value| *value == 0));
        assert!(legacy.to_vec().iter().all(|value| *value == 0));
    }
    let credential = dictionary(false, &Object::new());
    let response = get(&credential, "response").unwrap();
    set(&response, "userHandle", &Uint8Array::from([3u8].as_slice())).unwrap();
    assert_eq!(
        split(&credential, false).unwrap().public["response"]["userHandle"],
        "Aw"
    );
    set(&credential, "authenticatorAttachment", &JsValue::NULL).unwrap();
    assert!(
        split(&credential, false)
            .unwrap()
            .public
            .get("authenticatorAttachment")
            .is_none()
    );
    let credential = dictionary(true, &Object::new());
    set(
        &get(&credential, "response").unwrap(),
        "getTransports",
        &JsValue::UNDEFINED,
    )
    .unwrap();
    assert!(
        split(&credential, true).unwrap().public["response"]
            .get("transports")
            .is_none()
    );
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn throwing_or_malformed_prf_accessors_do_not_strand_owned_buffers() {
    let first = Uint8Array::from([7u8; 32].as_slice());
    let results = Object::new();
    set(&results, "first", &first.buffer()).unwrap();
    let throwing = Function::new_with_args(
        "value",
        "Object.defineProperty(value, 'second', {get() {throw new Error('synthetic');}})",
    );
    throwing.call1(&JsValue::UNDEFINED, &results).unwrap();
    let prf = Object::new();
    set(&prf, "results", &results).unwrap();
    assert!(take_prf(&prf).1.is_err());
    assert!(first.to_vec().iter().all(|value| *value == 0));
    let second = Uint8Array::from([9u8; 32].as_slice());
    let results = Object::new();
    set(&results, "first", &JsValue::TRUE).unwrap();
    set(&results, "second", &second.buffer()).unwrap();
    set(&prf, "results", &results).unwrap();
    assert!(take_prf(&prf).1.is_err());
    assert!(second.to_vec().iter().all(|value| *value == 0));
    set(&results, "first", &Uint8Array::from([1u8; 32].as_slice())).unwrap();
    set(&results, "second", &JsValue::TRUE).unwrap();
    assert!(take_prf(&prf).1.is_err());
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn malformed_public_dictionaries_and_cancellation_refuse() {
    assert!(get(&JsValue::NULL, "missing").is_err());
    let frozen = Object::freeze(&Object::new());
    assert!(set(&frozen, "field", &JsValue::TRUE).is_err());
    assert!(buffer(&JsValue::TRUE).is_err());
    assert!(split(&Object::new(), true).is_err());
    for (field, value) in [
        ("id", JsValue::TRUE),
        ("rawId", JsValue::NULL),
        ("type", JsValue::TRUE),
        ("response", JsValue::NULL),
    ] {
        let credential = dictionary(true, &Object::new());
        set(&credential, field, &value).unwrap();
        assert!(split(&credential, true).is_err());
    }
    let credential = dictionary(false, &Object::new());
    set(
        &credential,
        "getClientExtensionResults",
        &Function::new_no_args("throw new Error('synthetic')"),
    )
    .unwrap();
    assert!(split(&credential, false).is_err());
    let extensions = Object::freeze(&Object::new());
    let credential = dictionary(true, &extensions);
    // An absent property can still be deleted on a frozen object.
    assert!(split(&credential, true).is_ok());
    let controller = web_sys::AbortController::new().unwrap();
    let signal = controller.signal();
    let cancel = Cancel(controller);
    assert!(!signal.aborted());
    drop(cancel);
    assert!(signal.aborted());
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn hostile_dictionary_accessors_cannot_skip_secret_removal() {
    // Conversion-only vectors: these dictionaries never claim to be successful
    // platform ceremonies or valid signed credentials.
    let extensions = Object::new();
    set(&extensions, "prf", &JsValue::NULL).unwrap();
    let frozen = Object::freeze(&extensions);
    assert!(matches!(
        split(&dictionary(true, &frozen), true),
        Err(Error::InvalidResponse)
    ));
    let proxy = Function::new_no_args(
        "return new Proxy({}, {deleteProperty() {throw new Error('synthetic');}})",
    )
    .call0(&JsValue::UNDEFINED)
    .unwrap();
    assert!(matches!(
        split(&dictionary(true, &proxy), true),
        Err(Error::InvalidResponse)
    ));
    for body in [
        "throw new Error('synthetic')",
        "return Symbol('invalid transports')",
    ] {
        let credential = dictionary(true, &Object::new());
        set(
            &get(&credential, "response").unwrap(),
            "getTransports",
            &Function::new_no_args(body),
        )
        .unwrap();
        assert!(matches!(
            split(&credential, true),
            Err(Error::InvalidResponse)
        ));
    }
    let first = Uint8Array::from([7u8; 32].as_slice());
    let prf = Function::new_with_args(
        "first",
        "return {get enabled() {throw new Error('synthetic');}, results: {first}}",
    )
    .call1(&JsValue::UNDEFINED, &first)
    .unwrap();
    assert!(take_prf(&prf).1.is_err());
    assert!(first.to_vec().iter().all(|value| *value == 0));
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn every_credential_descriptor_is_translated_without_reconstruction() {
    let context = Context::new(crate::tests::ORIGIN, crate::tests::RP).unwrap();
    for create in [false, true] {
        let mut options = if create {
            crate::tests::creation()
        } else {
            crate::tests::request()
        };
        let field = if create {
            "excludeCredentials"
        } else {
            "allowCredentials"
        };
        options["publicKey"][field] =
            json!([{"id":"AQ","type":"public-key","transports":["internal","hybrid"]}]);
        let prepared = context.prepare(options.clone(), create).unwrap();
        let js = prepare_js(&prepared, create).unwrap();
        let pk = get(&js, "publicKey").unwrap();
        let descriptor = Array::from(&get(&pk, field).unwrap()).get(0);
        assert_eq!(encoded(&get(&descriptor, "id").unwrap()).unwrap(), "AQ");
        assert_eq!(
            Array::from(&get(&descriptor, "transports").unwrap()).length(),
            2
        );
        let mut invalid = prepared.clone();
        invalid["publicKey"][field] = json!(true);
        assert!(prepare_js(&invalid, create).is_err());
        invalid = prepared.clone();
        invalid["publicKey"][field][0]["id"] = Value::Null;
        assert!(prepare_js(&invalid, create).is_err());
        invalid = prepared.clone();
        invalid["publicKey"]["challenge"] = Value::Null;
        assert!(prepare_js(&invalid, create).is_err());
        if create {
            invalid = prepared;
            invalid["publicKey"]["user"]["id"] = Value::Null;
            assert!(prepare_js(&invalid, true).is_err());
        }
    }
}
