use super::*;
use crate::{Client, Context, VaultOutcome};

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
    let (assertion, vault) = client.sign_in(request).await.unwrap().into_parts();
    assert_eq!(assertion.as_json()["rawId"], created.as_json()["rawId"]);
    let VaultOutcome::Ready(prf) = vault else {
        panic!("virtual authenticator PRF unavailable")
    };
    assert_eq!(first, prf.import(|bytes| blake3::hash(bytes)));
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
