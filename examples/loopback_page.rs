//! Synthetic acceptance page; no secret or credential is exported to JavaScript.
/// Run the production callback completion without exposing its secret result.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn complete() -> Result<(), wasm_bindgen::JsValue> {
    let window = web_sys::window().ok_or_else(|| wasm_bindgen::JsValue::from_str("window"))?;
    let origin = window.location().origin()?;
    let context = cpky::Context::new(&origin, "localhost")
        .map_err(|_| wasm_bindgen::JsValue::from_str("context"))?;
    cpky::browser::complete_loopback(context)
        .await
        .map_err(|_| wasm_bindgen::JsValue::from_str("ceremony refused"))
}
