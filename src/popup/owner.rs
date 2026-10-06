use super::{
    channel::{Channel, MAX_MILLIS, Packet},
    seal::{self, Offer, Receiver},
};
use crate::{CeremonyRequest, CeremonyResult, Context, Error, browser::Browser, callback};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{
    future::{Either, select},
    pin_mut,
};
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

/// One frame-owned passkey request. The ephemeral HPKE secret key and original
/// result are Rust-only; there is no JavaScript export or launch URL accessor.
pub struct PopupCeremony {
    receiver: Receiver,
    channel: Channel,
    page: url::Url,
    opened: bool,
}
impl PopupCeremony {
    /// Prepare in the configured vault frame, before its own Continue click.
    /// The exact trusted same-origin popup URL must have no query or fragment.
    pub fn prepare(
        context: Context,
        request: CeremonyRequest,
        popup_page: &str,
        millis: u32,
    ) -> Result<Self, Error> {
        environment(&context, false)?;
        let mut page = page(&context, popup_page)?;
        let receiver = Receiver::new(Context::new(context.origin(), context.rp_id())?, request)?;
        let offer = receiver.offer();
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-popup-v1", &URL_SAFE_NO_PAD.encode(offer.nonce))
            .append_pair("key", &URL_SAFE_NO_PAD.encode(offer.recipient))
            .append_pair("millis", &millis.to_string())
            .finish();
        page.set_fragment(Some(&fragment));
        let channel = Channel::new(&channel_name(&offer.nonce), context.origin(), millis)?;
        channel.expire_with(receiver.expire());
        Ok(Self {
            receiver,
            channel,
            page,
            opened: false,
        })
    }

    /// Open once from a real click inside the vault frame. No opener or returned
    /// Window handle is used; blocked popups become an ordinary bounded timeout.
    pub fn open(&mut self) -> Result<(), Error> {
        if self.opened {
            return Err(Error::Cancelled);
        }
        self.channel.check()?;
        gesture()?;
        self.opened = true;
        web_sys::window()
            .ok_or(Error::Unavailable)?
            .open_with_url_and_target_and_features(
                self.page.as_str(),
                "_blank",
                "noopener,noreferrer,popup",
            )
            .map_err(|_| Error::Unavailable)?;
        self.page.set_fragment(None);
        Ok(())
    }

    /// Retain this future until handover, cancellation or deadline. Successful
    /// opening authenticates no membership and does not initialize Vault custody.
    pub async fn wait(mut self) -> Result<CeremonyResult, Error> {
        if !self.opened {
            return Err(Error::Cancelled);
        }
        let Packet::Hello { peer } = self.channel.next().await? else {
            return Err(Error::InvalidResponse);
        };
        self.channel.cancel = Some(peer);
        let offer = self.receiver.offer();
        // Public request copy only. The one-time secret key is never cloned.
        let offer: Offer =
            serde_json::from_slice(&serde_json::to_vec(offer).map_err(|_| Error::InvalidOptions)?)
                .map_err(|_| Error::InvalidOptions)?;
        self.channel.post(&Packet::Offer { peer, offer })?;
        match self.channel.next().await? {
            Packet::Result {
                peer: sender,
                nonce,
                sealed,
            } if sender == peer => {
                let origin = self.receiver.offer().popup_origin.clone();
                let result = self.receiver.open(&nonce, &origin, &sealed)?;
                // ACK follows authenticated opening AND the original strict
                // response/challenge/top-level validation, never ciphertext alone.
                self.channel.post(&Packet::Ack { peer })?;
                self.channel.cancel = None;
                Ok(result)
            }
            Packet::Cancel { peer: sender } if sender == peer => Err(Error::Cancelled),
            _ => Err(Error::InvalidResponse),
        }
    }
}

/// Popup-owned ordinary top-level ceremony. The public launch is consumed before
/// any asynchronous work; only sealed ciphertext leaves this owner.
pub struct PopupHandoff {
    context: Context,
    channel: Channel,
    nonce: [u8; 32],
    recipient: [u8; 32],
    peer: [u8; 32],
    offer: Option<Offer>,
}
impl PopupHandoff {
    /// Consume the current popup fragment synchronously before I/O.
    pub fn prepare(context: Context, popup_page: &str) -> Result<Self, Error> {
        let window = environment(&context, true)?;
        let fragment = Zeroizing::new(window.location().hash().map_err(|_| Error::Unavailable)?);
        let expected = page(&context, popup_page)?;
        let mut actual =
            url::Url::parse(&window.location().href().map_err(|_| Error::Unavailable)?)
                .map_err(|_| Error::WrongContext)?;
        actual.set_fragment(None);
        if actual != expected {
            return Err(Error::WrongContext);
        }
        window
            .history()
            .map_err(|_| Error::Unavailable)?
            .replace_state_with_url(&JsValue::NULL, "", Some(expected.as_str()))
            .map_err(|_| Error::Unavailable)?;
        Self::from_consumed_fragment(context, popup_page, &fragment)
    }

    /// Accept a launch erased synchronously by the trusted popup entry before
    /// loading Wasm. Both actual page and observable fragment removal are checked.
    pub fn from_consumed_fragment(
        context: Context,
        popup_page: &str,
        fragment: &str,
    ) -> Result<Self, Error> {
        let window = environment(&context, true)?;
        let expected = page(&context, popup_page)?;
        if window.location().href().map_err(|_| Error::Unavailable)? != expected.as_str()
            || !window
                .location()
                .hash()
                .map_err(|_| Error::Unavailable)?
                .is_empty()
        {
            return Err(Error::WrongContext);
        }
        let (nonce, recipient, millis) = launch(fragment)?;
        let peer = *seal::random()?;
        let mut channel = Channel::new(&channel_name(&nonce), context.origin(), millis)?;
        channel.cancel = Some(peer);
        channel.post(&Packet::Hello { peer })?;
        Ok(Self {
            context,
            channel,
            nonce,
            recipient,
            peer,
            offer: None,
        })
    }

    /// Receive the public server request before enabling the popup's Continue
    /// button. This step never invokes an authenticator or reveals an unlock.
    pub async fn ready(&mut self) -> Result<(), Error> {
        if self.offer.is_some() {
            return Err(Error::Cancelled);
        }
        let Packet::Offer { peer, offer } = self.channel.next().await? else {
            return Err(Error::InvalidResponse);
        };
        if peer != self.peer || offer.nonce != self.nonce || offer.recipient != self.recipient {
            return Err(Error::WrongContext);
        }
        offer.context(&self.context)?;
        self.offer = Some(offer);
        Ok(())
    }

    /// Invoke ordinary navigator.credentials on the popup's own real click,
    /// seal in Wasm, and wait for the frame's post-decode ACK. Dropping aborts
    /// pending navigator.credentials and closes this one-use channel.
    pub async fn complete(mut self) -> Result<(), Error> {
        environment(&self.context, true)?;
        self.channel.check()?;
        gesture()?;
        let offer = self.offer.take().ok_or(Error::Cancelled)?;
        let request = CeremonyRequest {
            kind: offer.request.kind,
            options: offer.request.options.clone(),
        };
        let result = {
            let ceremony = callback::execute(
                Context::new(self.context.origin(), self.context.rp_id())?,
                request,
                Browser,
            );
            let cancellation = self.channel.next();
            pin_mut!(ceremony, cancellation);
            match select(ceremony, cancellation).await {
                Either::Left((result, _)) => result?,
                Either::Right(_) => return Err(Error::Cancelled),
            }
        };
        self.channel.check()?;
        let sealed = seal::seal(&offer, &self.context, result)?;
        self.channel.post(&Packet::Result {
            peer: self.peer,
            nonce: self.nonce,
            sealed,
        })?;
        match self.channel.next().await? {
            Packet::Ack { peer } if peer == self.peer => {
                self.channel.cancel = None;
                Ok(())
            }
            _ => Err(Error::Cancelled),
        }
    }
}

fn environment(context: &Context, top_level: bool) -> Result<web_sys::Window, Error> {
    let window = web_sys::window().ok_or(Error::Unavailable)?;
    let top = window
        .top()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    let parent = window
        .parent()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    if window.location().origin().map_err(|_| Error::Unavailable)? != context.origin()
        || !context.origin().starts_with("https://")
        || js_sys::Object::is(window.as_ref(), top.as_ref()) != top_level
        || (top_level && !window.opener().map_err(|_| Error::Unavailable)?.is_null())
        || (!top_level && !js_sys::Object::is(parent.as_ref(), top.as_ref()))
    {
        return Err(Error::WrongContext);
    }
    Ok(window)
}
fn gesture() -> Result<(), Error> {
    let navigator = web_sys::window().ok_or(Error::Unavailable)?.navigator();
    let activation = js_sys::Reflect::get(navigator.as_ref(), &JsValue::from_str("userActivation"))
        .map_err(|_| Error::Unavailable)?;
    let active = js_sys::Reflect::get(&activation, &JsValue::from_str("isActive"))
        .map_err(|_| Error::Unavailable)?
        .as_bool()
        == Some(true);
    if active {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}
fn page(context: &Context, value: &str) -> Result<url::Url, Error> {
    let page = url::Url::parse(value).map_err(|_| Error::InvalidOptions)?;
    if page.origin().ascii_serialization() != context.origin()
        || page.scheme() != "https"
        || !page.username().is_empty()
        || page.password().is_some()
        || page.query().is_some()
        || page.fragment().is_some()
    {
        return Err(Error::WrongContext);
    }
    Ok(page)
}
fn channel_name(nonce: &[u8; 32]) -> String {
    format!("cpky.popup.{}", URL_SAFE_NO_PAD.encode(nonce))
}
fn launch(fragment: &str) -> Result<([u8; 32], [u8; 32], u32), Error> {
    if fragment.len() > 1024 {
        return Err(Error::InvalidOptions);
    }
    let fragment = fragment.strip_prefix('#').ok_or(Error::InvalidOptions)?;
    let fields: Vec<_> = url::form_urlencoded::parse(fragment.as_bytes()).collect();
    if fields.len() != 3
        || fields[0].0 != "cpky-popup-v1"
        || fields[1].0 != "key"
        || fields[2].0 != "millis"
    {
        return Err(Error::InvalidOptions);
    }
    let decode = |s: &str| -> Result<[u8; 32], Error> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| Error::InvalidOptions)?
            .try_into()
            .map_err(|_| Error::InvalidOptions)
    };
    let millis: u32 = fields[2].1.parse().map_err(|_| Error::InvalidOptions)?;
    if millis == 0 || millis > MAX_MILLIS {
        return Err(Error::InvalidOptions);
    }
    Ok((decode(&fields[0].1)?, decode(&fields[1].1)?, millis))
}
