use crate::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

const MAX_OPTIONS: usize = 262_144;

/// Exact caller-configured WebAuthn origin/RP binding. Construction does not
/// authenticate server configuration: the composing owner must do that first.
pub struct Context {
    origin: String,
    rp: String,
}
impl Context {
    /// Pin one origin and relying-party ID. HTTPS is required except localhost
    /// for explicit local testing. No parent-RP or wildcard inference is performed.
    pub fn new(origin: &str, rp: &str) -> Result<Self, Error> {
        let url = Url::parse(origin).map_err(|_| Error::WrongContext)?;
        let host = url.host_str().ok_or(Error::WrongContext)?;
        if url.origin().ascii_serialization() != origin
            || !(url.scheme() == "https" || (url.scheme() == "http" && host == "localhost"))
            || rp.is_empty()
            || (host != rp && !host.ends_with(&format!(".{rp}")))
        {
            return Err(Error::WrongContext);
        }
        Ok(Self {
            origin: origin.into(),
            rp: rp.into(),
        })
    }
    /// The exact origin that browser clientData must report.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// The exact server relying-party ID.
    pub fn rp_id(&self) -> &str {
        &self.rp
    }

    pub(crate) fn prepare(&self, mut options: Value, create: bool) -> Result<Value, Error> {
        if options.to_string().len() > MAX_OPTIONS {
            return Err(Error::InvalidOptions);
        }
        let pk = options
            .get_mut("publicKey")
            .and_then(Value::as_object_mut)
            .ok_or(Error::InvalidOptions)?;
        let rp = if create {
            pk.get("rp").and_then(|v| v.get("id"))
        } else {
            pk.get("rpId")
        };
        if rp.and_then(Value::as_str) != Some(&self.rp) {
            return Err(Error::WrongContext);
        }
        decode(pk.get("challenge").ok_or(Error::InvalidOptions)?)?;
        if create {
            decode(
                pk.get("user")
                    .and_then(|v| v.get("id"))
                    .ok_or(Error::InvalidOptions)?,
            )?;
        }
        let extensions = pk.entry("extensions").or_insert_with(|| json!({}));
        if extensions.is_null() {
            *extensions = json!({});
        }
        let map = extensions.as_object_mut().ok_or(Error::InvalidOptions)?;
        let expected = json!({"eval":{"first":URL_SAFE_NO_PAD.encode(prf_input())}});
        if let Some(existing) = map.get("prf")
            && existing != &expected
        {
            return Err(Error::InvalidOptions);
        }
        map.insert("prf".into(), expected);
        Ok(options)
    }

    pub(crate) fn followup(&self, original: &Value, created: &Value) -> Result<Value, Error> {
        let id = created.get("rawId").ok_or(Error::InvalidResponse)?;
        decode(id)?;
        // This local PRF evaluation is deliberately bound to the original server
        // challenge, the same RP and precisely the newly created credential.
        // It is never sent as a server authentication or mixed with another get.
        let pk = &original["publicKey"];
        let mut result = json!({"publicKey":{
            "challenge":pk["challenge"], "rpId":self.rp,
            "allowCredentials":[{"type":"public-key","id":id}],
            "extensions":{"prf":pk["extensions"]["prf"]}
        }});
        if let Some(timeout) = pk.get("timeout") {
            result["publicKey"]["timeout"] = timeout.clone();
        }
        if let Some(uv) = pk
            .get("authenticatorSelection")
            .and_then(|v| v.get("userVerification"))
        {
            result["publicKey"]["userVerification"] = uv.clone();
        }
        Ok(result)
    }

    pub(crate) fn bind(
        &self,
        response: &Value,
        request: &Value,
        create: bool,
    ) -> Result<(), Error> {
        let raw = decode(response.get("rawId").ok_or(Error::InvalidResponse)?)?;
        if response.get("id").and_then(Value::as_str) != Some(URL_SAFE_NO_PAD.encode(&raw).as_str())
            || response.get("type").and_then(Value::as_str) != Some("public-key")
        {
            return Err(Error::CeremonyMismatch);
        }
        let bytes = decode(
            response
                .get("response")
                .and_then(|v| v.get("clientDataJSON"))
                .ok_or(Error::InvalidResponse)?,
        )?;
        let data: ClientData =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if data.origin != self.origin
            || data.kind
                != if create {
                    "webauthn.create"
                } else {
                    "webauthn.get"
                }
            || data.challenge
                != request["publicKey"]["challenge"]
                    .as_str()
                    .ok_or(Error::InvalidOptions)?
        {
            return Err(Error::CeremonyMismatch);
        }
        if !create {
            let auth = decode(&response["response"]["authenticatorData"])?;
            let expected = Sha256::digest(self.rp.as_bytes());
            if auth.len() < 37 || auth[..32] != expected[..] {
                return Err(Error::CeremonyMismatch);
            }
            if request["publicKey"]["userVerification"] == "required" && auth[32] & 0x04 == 0 {
                return Err(Error::CeremonyMismatch);
            }
            if let Some(allow) = request["publicKey"].get("allowCredentials") {
                let allow = allow.as_array().ok_or(Error::InvalidOptions)?;
                if !allow.is_empty()
                    && !allow
                        .iter()
                        .any(|item| item.get("id") == response.get("rawId"))
                {
                    return Err(Error::CeremonyMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

pub(crate) fn bind_handle(response: &Value, creation: &Value) -> Result<(), Error> {
    if let Some(handle) = response["response"]
        .get("userHandle")
        .filter(|v| !v.is_null())
        && handle != &creation["publicKey"]["user"]["id"]
    {
        return Err(Error::CeremonyMismatch);
    }
    Ok(())
}

pub(crate) fn decode(value: &Value) -> Result<Vec<u8>, Error> {
    let encoded = value.as_str().ok_or(Error::InvalidOptions)?;
    if encoded.is_empty() || encoded.len() > 87_384 {
        return Err(Error::InvalidOptions);
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidOptions)
}

/// Historical PRF input recipe. Renaming the adapter must never change keys or locators.
pub fn prf_input() -> [u8; 32] {
    blake3::derive_key(
        "ckmg 2026-09 passkey PRF input for vault store unlock v1",
        b"",
    )
}
