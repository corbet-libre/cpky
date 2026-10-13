//! Test-only public progress around the original sealed owner. No success stub,
//! raw secret, HPKE codec, request result or frame capability is exported.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cpky::{
    CeremonyKind, CeremonyRequest, CeremonyResult, Context,
    browser::{PopupCeremony, PopupHandoff},
};
use wasm_bindgen::prelude::*;

fn refused(_: cpky::Error) -> JsValue {
    JsValue::from_str("popup refused")
}
fn context() -> Result<(Context, String), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("window"))?;
    let origin = window.location().origin()?;
    Ok((
        Context::new(&origin, "alpha.localhost").map_err(refused)?,
        format!("{origin}/popup.html"),
    ))
}

/// Test fixture retaining the real frame owner until completion or cancellation.
#[wasm_bindgen]
pub struct PopupFrame(Option<PopupCeremony>);
#[wasm_bindgen]
impl PopupFrame {
    /// Construct the original owner with fictional public registration options.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<PopupFrame, JsValue> {
        let (context, page) = context()?;
        let request = CeremonyRequest {
            kind: CeremonyKind::MemberRegistration,
            options: serde_json::json!({"publicKey": {
                "rp": {"id":"alpha.localhost", "name":"Synthetic popup"},
                "user": {"id":URL_SAFE_NO_PAD.encode([18;16]), "name":"synthetic", "displayName":"Test"},
                "challenge": URL_SAFE_NO_PAD.encode([44;32]), "pubKeyCredParams":[{"type":"public-key","alg":-7}],
                "authenticatorSelection":{"residentKey":"required", "userVerification":"required"},
                "timeout":30_000, "attestation":"none"
            }}),
        };
        Ok(Self(Some(
            PopupCeremony::prepare(context, request, &page, 30_000).map_err(refused)?,
        )))
    }
    /// Call synchronously from the real frame button.
    pub fn open(&mut self) -> Result<(), JsValue> {
        self.0
            .as_mut()
            .ok_or_else(|| JsValue::from_str("consumed"))?
            .open()
            .map_err(refused)
    }
    /// Drop the actual opaque credential/PRF in Rust after asserting its kind.
    pub async fn wait(mut self) -> Result<(), JsValue> {
        match self
            .0
            .take()
            .ok_or_else(|| JsValue::from_str("consumed"))?
            .wait()
            .await
            .map_err(refused)?
        {
            CeremonyResult::MemberRegistration(_) => Ok(()),
            _ => Err(JsValue::from_str("unexpected ceremony")),
        }
    }
}

/// Test fixture retaining the original popup, never a replacement authenticator.
#[wasm_bindgen]
pub struct Popup(Option<PopupHandoff>);
#[wasm_bindgen]
impl Popup {
    /// Trusted HTML consumes the public launch before loading this module.
    #[wasm_bindgen(constructor)]
    pub fn new(launch: &str) -> Result<Popup, JsValue> {
        let (context, page) = context()?;
        Ok(Self(Some(
            PopupHandoff::from_consumed_fragment(context, &page, launch).map_err(refused)?,
        )))
    }
    /// Enable the popup's own Continue only after original request acceptance.
    pub async fn ready(&mut self) -> Result<(), JsValue> {
        self.0
            .as_mut()
            .ok_or_else(|| JsValue::from_str("consumed"))?
            .ready()
            .await
            .map_err(refused)
    }
    /// Complete on the real popup button and report only acknowledged handover.
    pub async fn complete(mut self) -> Result<(), JsValue> {
        self.0
            .take()
            .ok_or_else(|| JsValue::from_str("consumed"))?
            .complete()
            .await
            .map_err(refused)
    }
}

/// A linked top-level popup must refuse on its actual opener relationship before
/// parsing the deliberately invalid launch. No Window getter is overwritten.
#[wasm_bindgen]
pub fn linked_popup_refuses() -> Result<bool, JsValue> {
    let (context, page) = context()?;
    Ok(matches!(
        PopupHandoff::from_consumed_fragment(context, &page, "#invalid"),
        Err(cpky::Error::WrongContext)
    ))
}
