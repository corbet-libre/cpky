//! Window-context WebAuthn adapter, intended to run with Keys inside vault custody.
//! No secret-bearing JS export exists. Reuses the former Keys browser adapter's
//! web-sys calls; server options are preserved instead of reconstructed.
use crate::{Authenticator, Error, PlatformResult, UnlockSecret, options, sealed};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Array, ArrayBuffer, Function, Object, Reflect, Uint8Array};
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

/// Actual navigator.credentials adapter. Workers and absent platforms refuse.
pub struct Browser;
impl sealed::Sealed for Browser {}
impl Authenticator for Browser {
    async fn perform(&mut self, options: &Value, create: bool) -> Result<PlatformResult, Error> {
        let window = web_sys::window().ok_or(Error::Unavailable)?;
        let request = prepare_js(options, create)?;
        let cancel = Cancel(web_sys::AbortController::new().map_err(|_| Error::Unavailable)?);
        set(&request, "signal", cancel.0.signal().as_ref())?;
        let credentials = window.navigator().credentials();
        let promise = if create {
            credentials.create_with_options(request.unchecked_ref())
        } else {
            credentials.get_with_options(request.unchecked_ref())
        }
        .map_err(|_| Error::Unavailable)?;
        let credential = JsFuture::from(promise)
            .await
            .map_err(|_| Error::Cancelled)?;
        split(&credential, create)
    }
}

struct Cancel(web_sys::AbortController);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn get(value: &JsValue, key: &str) -> Result<JsValue, Error> {
    Reflect::get(value, &JsValue::from_str(key)).map_err(|_| Error::InvalidResponse)
}
fn set(value: &JsValue, key: &str, data: &JsValue) -> Result<(), Error> {
    match Reflect::set(value, &JsValue::from_str(key), data) {
        Ok(true) => Ok(()),
        _ => Err(Error::InvalidOptions),
    }
}
fn buffer(value: &JsValue) -> Result<Uint8Array, Error> {
    if value.is_instance_of::<ArrayBuffer>() {
        return Ok(Uint8Array::new(value));
    }
    value
        .dyn_ref::<Uint8Array>()
        .cloned()
        .ok_or(Error::InvalidResponse)
}
fn encoded(value: &JsValue) -> Result<String, Error> {
    Ok(URL_SAFE_NO_PAD.encode(buffer(value)?.to_vec()))
}

fn prepare_js(options: &Value, create: bool) -> Result<JsValue, Error> {
    // The JSON dictionary is retained in full. Only WebAuthn's binary fields are
    // translated to BufferSources; no algorithms, challenge or policies rebuilt.
    let object = js_sys::JSON::parse(&options.to_string()).map_err(|_| Error::InvalidOptions)?;
    let pk = get(&object, "publicKey")?;
    let source = &options["publicKey"];
    set(
        &pk,
        "challenge",
        &Uint8Array::from(options::decode(&source["challenge"])?.as_slice()),
    )?;
    if create {
        set(
            &get(&pk, "user")?,
            "id",
            &Uint8Array::from(options::decode(&source["user"]["id"])?.as_slice()),
        )?;
    }
    for name in ["allowCredentials", "excludeCredentials"] {
        if let Some(list) = source.get(name) {
            let source = list.as_array().ok_or(Error::InvalidOptions)?;
            let target = Array::from(&get(&pk, name)?);
            for (index, item) in source.iter().enumerate() {
                set(
                    &target.get(index as u32),
                    "id",
                    &Uint8Array::from(options::decode(&item["id"])?.as_slice()),
                )?;
            }
        }
    }
    let prf = get(&get(&pk, "extensions")?, "prf")?;
    set(
        &get(&prf, "eval")?,
        "first",
        &Uint8Array::from(options::prf_input().as_slice()),
    )?;
    Ok(object)
}

struct Wipe(Vec<Uint8Array>);
impl Drop for Wipe {
    fn drop(&mut self) {
        for bytes in &self.0 {
            bytes.fill(0, 0, bytes.length());
        }
    }
}
fn take_prf(prf: &JsValue) -> (bool, Result<Option<UnlockSecret>, Error>) {
    if prf.is_null() || prf.is_undefined() {
        return (false, Ok(None));
    }
    let reported = get(prf, "enabled");
    let enabled = reported
        .as_ref()
        .ok()
        .and_then(JsValue::as_bool)
        .unwrap_or(false);
    (
        enabled,
        (|| {
            let results = get(prf, "results")?;
            if results.is_null() || results.is_undefined() {
                return Ok(None);
            }
            let mut wipe = Wipe(Vec::new());
            // Register both owned BufferSource views for wiping even when malformed.
            // A throwing second accessor must not strand an already obtained first.
            let a = get(&results, "first").and_then(|value| buffer(&value));
            if let Ok(view) = &a {
                wipe.0.push(view.clone());
            }
            let second = get(&results, "second")?;
            let b = if second.is_null() || second.is_undefined() {
                None
            } else {
                Some(buffer(&second))
            };
            if let Some(Ok(view)) = &b {
                wipe.0.push(view.clone());
            }
            let first = a.map_err(|_| Error::InvalidPrf)?;
            if b.is_some() || reported?.as_bool() == Some(false) {
                return Err(Error::InvalidPrf);
            }
            let bytes = Zeroizing::new(first.to_vec());
            UnlockSecret::take(&bytes).map(Some)
        })(),
    )
}

fn split(credential: &JsValue, create: bool) -> Result<PlatformResult, Error> {
    // All platform-result shape checks belong to this conversion boundary.
    if credential.is_null() || credential.is_undefined() {
        return Err(Error::Cancelled);
    }
    let method = get(credential, "getClientExtensionResults")?
        .dyn_into::<Function>()
        .map_err(|_| Error::InvalidResponse)?;
    let extensions = method
        .call0(credential)
        .map_err(|_| Error::InvalidResponse)?;
    let (enabled, prf) = take_prf(&get(&extensions, "prf")?);
    // Remove every server-recognized secret alias before converting public data.
    for name in ["prf", "hmacGetSecret", "hmac_get_secret"] {
        let secret = get(&extensions, name)?;
        if name != "prf" && secret.is_object() {
            for field in ["output1", "output2"] {
                if let Ok(view) = buffer(&get(&secret, field)?) {
                    view.fill(0, 0, view.length());
                }
            }
        }
        if !Reflect::delete_property(
            extensions.unchecked_ref::<Object>(),
            &JsValue::from_str(name),
        )
        .map_err(|_| Error::InvalidResponse)?
        {
            return Err(Error::InvalidResponse);
        }
    }
    let response = get(credential, "response")?;
    let mut public = json!({
        "id":get(credential,"id")?.as_string().ok_or(Error::InvalidResponse)?,
        "rawId":encoded(&get(credential,"rawId")?)?,
        "type":get(credential,"type")?.as_string().ok_or(Error::InvalidResponse)?,
        "response":{"clientDataJSON":encoded(&get(&response,"clientDataJSON")?)?},
        "clientExtensionResults":serde_wasm_bindgen::from_value::<Value>(extensions).map_err(|_| Error::InvalidResponse)?
    });
    if create {
        public["response"]["attestationObject"] =
            encoded(&get(&response, "attestationObject")?)?.into();
        let method = get(&response, "getTransports")?;
        if let Some(method) = method.dyn_ref::<Function>() {
            public["response"]["transports"] = serde_wasm_bindgen::from_value(
                method
                    .call0(&response)
                    .map_err(|_| Error::InvalidResponse)?,
            )
            .map_err(|_| Error::InvalidResponse)?;
        }
    } else {
        for field in ["authenticatorData", "signature"] {
            public["response"][field] = encoded(&get(&response, field)?)?.into();
        }
        let handle = get(&response, "userHandle")?;
        public["response"]["userHandle"] = if handle.is_null() || handle.is_undefined() {
            Value::Null
        } else {
            encoded(&handle)?.into()
        };
    }
    let attachment = get(credential, "authenticatorAttachment")?;
    if let Some(value) = attachment.as_string() {
        public["authenticatorAttachment"] = value.into();
    }
    Ok(PlatformResult {
        public,
        enabled,
        prf,
    })
}

#[cfg(test)]
#[path = "../tests/browser.rs"]
mod tests;

/// Complete a CLI-initiated ceremony in the exact trusted top-level HTTPS page.
/// The launch fragment is consumed before I/O. Secret output goes directly to the
/// numeric loopback listener, never to a product API, URL, storage, or JS export.
pub async fn complete_loopback(context: crate::Context) -> Result<(), Error> {
    LoopbackCeremony::prepare(context)?.complete().await
}

/// An inspected one-use CLI callback. The capability is consumed from the
/// address bar before this value exists; no request or authenticator runs until
/// the trusted page explicitly completes it. No field is exported to JavaScript.
pub struct LoopbackCeremony {
    context: crate::Context,
    finish: url::Url,
    capability: Zeroizing<String>,
}

impl LoopbackCeremony {
    /// Accept a launch removed synchronously by the trusted vault page before
    /// loading Wasm. Require observable consumption and the same exact origin;
    /// the original one-use listener still authenticates the capability.
    pub fn from_consumed_fragment(context: crate::Context, fragment: &str) -> Result<Self, Error> {
        let window = web_sys::window().ok_or(Error::Unavailable)?;
        let top = window
            .top()
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        if !js_sys::Object::is(window.as_ref(), top.as_ref())
            || window.location().origin().map_err(|_| Error::Unavailable)? != context.origin()
            || !window
                .location()
                .hash()
                .map_err(|_| Error::Unavailable)?
                .is_empty()
        {
            return Err(Error::WrongContext);
        }
        let (finish, capability) =
            crate::callback::destination(fragment.strip_prefix('#').ok_or(Error::InvalidOptions)?)?;
        Ok(Self {
            context,
            finish,
            capability,
        })
    }

    /// Consume the original launch fragment without network or WebAuthn work.
    pub fn prepare(context: crate::Context) -> Result<Self, Error> {
        let window = web_sys::window().ok_or(Error::Unavailable)?;
        if window.location().origin().map_err(|_| Error::Unavailable)? != context.origin() {
            return Err(Error::WrongContext);
        }
        let fragment = Zeroizing::new(
            window
                .location()
                .hash()
                .map_err(|_| Error::InvalidOptions)?,
        );
        let (finish, capability) =
            crate::callback::destination(fragment.strip_prefix('#').ok_or(Error::InvalidOptions)?)?;
        let mut page = url::Url::parse(&window.location().href().map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::WrongContext)?;
        page.set_fragment(None);
        window
            .history()
            .map_err(|_| Error::Unavailable)?
            .replace_state_with_url(&JsValue::NULL, "", Some(page.as_str()))
            .map_err(|_| Error::Unavailable)?;
        // Navigation API cancellation can leave the old URL intact even when
        // replaceState returns normally. Consume the capability before any I/O.
        if !window
            .location()
            .hash()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
        {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            context,
            finish,
            capability,
        })
    }

    /// Perform the original callback once after an explicit user gesture.
    /// Dropping this future aborts any fetch or platform ceremony in progress.
    pub async fn complete(self) -> Result<(), Error> {
        let Self {
            context,
            finish,
            capability,
        } = self;
        let mut request_url = finish.clone();
        request_url.set_path("/request");
        let (response, _request_cancel) =
            loopback_fetch(&request_url, "GET", &capability, None).await?;
        let length: usize = response
            .headers()
            .get("content-length")
            .map_err(|_| Error::InvalidResponse)?
            .ok_or(Error::InvalidResponse)?
            .parse()
            .map_err(|_| Error::InvalidResponse)?;
        if length > crate::callback::MAX_CALLBACK {
            return Err(Error::InvalidResponse);
        }
        let value = JsFuture::from(
            response
                .array_buffer()
                .map_err(|_| Error::InvalidResponse)?,
        )
        .await
        .map_err(|_| Error::InvalidResponse)?;
        let bytes = Uint8Array::new(&value);
        if bytes.length() as usize != length {
            return Err(Error::InvalidResponse);
        }
        let request =
            serde_json::from_slice(&bytes.to_vec()).map_err(|_| Error::InvalidResponse)?;
        let result = crate::callback::execute(context, request, Browser).await?;
        let bytes = crate::callback::encode(result)?;
        let body = Uint8Array::from(bytes.as_slice());
        let _wipe = Wipe(vec![body.clone()]);
        loopback_fetch(&finish, "POST", &capability, Some(&body)).await?;
        Ok(())
    }
}

async fn loopback_fetch(
    url: &url::Url,
    method: &str,
    capability: &str,
    body: Option<&Uint8Array>,
) -> Result<(web_sys::Response, Cancel), Error> {
    let window = web_sys::window().ok_or(Error::Unavailable)?;
    let cancel = Cancel(web_sys::AbortController::new().map_err(|_| Error::Unavailable)?);
    let init = web_sys::RequestInit::new();
    init.set_method(method);
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_cache(web_sys::RequestCache::NoStore);
    init.set_redirect(web_sys::RequestRedirect::Error);
    init.set_referrer_policy(web_sys::ReferrerPolicy::NoReferrer);
    init.set_signal(Some(&cancel.0.signal()));
    if let Some(body) = body {
        init.set_body(body.as_ref());
    }
    let request = web_sys::Request::new_with_str_and_init(url.as_str(), &init)
        .map_err(|_| Error::InvalidOptions)?;
    request
        .headers()
        .set("x-cpky-capability", capability)
        .map_err(|_| Error::InvalidOptions)?;
    if body.is_some() {
        request
            .headers()
            .set("content-type", "application/octet-stream")
            .map_err(|_| Error::InvalidOptions)?;
    }
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| Error::Unavailable)?;
    let response: web_sys::Response = response.dyn_into().map_err(|_| Error::InvalidResponse)?;
    if !response.ok() {
        return Err(Error::Cancelled);
    }
    Ok((response, cancel))
}
