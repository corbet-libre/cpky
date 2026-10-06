//! Synthetic acceptance page; no secret or credential is exported to JavaScript.
#[cfg(target_arch = "wasm32")]
#[path = "support/popup.rs"]
mod popup;
/// Run the production callback completion without exposing its secret result.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn complete() -> Result<(), wasm_bindgen::JsValue> {
    // Link the existing test-only profiling exports into this external fixture.
    // The production library has no profiling or JavaScript secret export.
    #[cfg(owned_browser_coverage)]
    let _ = browser_coverage_runtime::__owned_test_module_signature();
    let window = web_sys::window().ok_or_else(|| wasm_bindgen::JsValue::from_str("window"))?;
    let origin = window.location().origin()?;
    let context = cpky::Context::new(&origin, "localhost")
        .map_err(|_| wasm_bindgen::JsValue::from_str("context"))?;
    cpky::browser::complete_loopback(context)
        .await
        .map_err(|_| wasm_bindgen::JsValue::from_str("ceremony refused"))
}

/// Test-only assertion of the original callback's unavailable-environment error.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn navigation_refusal() -> Result<(), wasm_bindgen::JsValue> {
    let window = web_sys::window().ok_or_else(|| wasm_bindgen::JsValue::from_str("window"))?;
    let context = cpky::Context::new(&window.location().origin()?, "localhost")
        .map_err(|_| wasm_bindgen::JsValue::from_str("context"))?;
    if matches!(
        cpky::browser::complete_loopback(context).await,
        Err(cpky::Error::Unavailable)
    ) {
        Ok(())
    } else {
        Err(wasm_bindgen::JsValue::from_str(
            "expected navigation refusal",
        ))
    }
}

/// Test-only unavailable-platform probe; no credential or secret is returned.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn unavailable_platform(create: bool) -> Result<(), wasm_bindgen::JsValue> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    // A fictional public configuration lets the original client prepare its
    // options. The actual insecure realm must refuse in Browser, before any
    // credential or PRF result exists. Navigator and its methods are untouched.
    let context = cpky::Context::new("https://cpky-insecure.test", "cpky-insecure.test")
        .map_err(|_| wasm_bindgen::JsValue::from_str("context"))?;
    let mut client = cpky::Client::new(context, cpky::browser::Browser);
    let challenge = URL_SAFE_NO_PAD.encode([41; 32]);
    let refused = if create {
        let options = json!({"publicKey":{
            "rp":{"id":"cpky-insecure.test","name":"Synthetic refusal"},
            "user":{"id":URL_SAFE_NO_PAD.encode([17;16]),"name":"synthetic","displayName":"Test"},
            "challenge":challenge,"pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "timeout":1000
        }});
        matches!(
            client.register_privileged(options).await,
            Err(cpky::Error::Unavailable)
        )
    } else {
        let options = json!({"publicKey":{
            "rpId":"cpky-insecure.test","challenge":challenge,"allowCredentials":[],"timeout":1000
        }});
        matches!(client.sign_in(options).await, Err(cpky::Error::Unavailable))
    };
    if refused {
        Ok(())
    } else {
        Err(wasm_bindgen::JsValue::from_str(
            "expected unavailable platform",
        ))
    }
}
