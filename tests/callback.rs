//! Shared callback parser vectors run natively and in the actual browser.
use crate::callback;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn loopback_destinations_are_numeric_local_and_capabilities_are_canonical() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let capability = URL_SAFE_NO_PAD.encode([7; 32]);
    for endpoint in [
        "https://127.0.0.1:5555/finish",
        "http://localhost:5555/finish",
        "http://127.0.0.2:5555/finish",
        "http://127.0.0.1/finish",
        "http://127.0.0.1:0/finish",
        "http://127.0.0.1:5555/other",
        "http://127.0.0.1:5555/finish?x=1",
        "http://user@127.0.0.1:5555/finish",
        "http://:secret@127.0.0.1:5555/finish",
        "http://127.0.0.1:5555/finish#fragment",
    ] {
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-v1", endpoint)
            .append_pair("cap", &capability)
            .finish();
        assert!(callback::destination(&fragment).is_err(), "{endpoint}");
    }
    for fragment in [
        "",
        "cap=x&cpky-v1=x",
        "other=x&cap=x",
        "cpky-v1=not-a-url&cap=x",
        "cpky-v1=http://127.0.0.1:5555/finish&cap=x",
        "cpky-v1=x&cap=x&cap=x",
        "cpky-v1=http://127.0.0.1:5555/finish&other=x",
    ] {
        assert!(callback::destination(fragment).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn loopback_destination_refuses_oversized_and_short_capabilities() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    assert!(callback::destination(&"a".repeat(1025)).is_err());
    let endpoint = "http://127.0.0.1:5555/finish";
    let fragment = |capability: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-v1", endpoint)
            .append_pair("cap", capability)
            .finish()
    };
    for capability in [
        URL_SAFE_NO_PAD.encode([7; 16]),
        URL_SAFE_NO_PAD.encode([7; 33]),
        "not base64!".to_string(),
    ] {
        assert!(callback::destination(&fragment(&capability)).is_err());
    }
    // The strict decoder already rejects non-canonical trailing bits.
    let mut noncanonical = URL_SAFE_NO_PAD.encode([7; 32]);
    noncanonical.pop();
    noncanonical.push('B');
    assert!(callback::destination(&fragment(&noncanonical)).is_err());
    assert!(callback::destination(&fragment(&URL_SAFE_NO_PAD.encode([7; 32]))).is_ok());
}
