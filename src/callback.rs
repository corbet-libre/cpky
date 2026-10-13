//! Private bounded loopback wire. Secret bytes have no serde or public codec.
use crate::UnlockSecret;
use crate::{Authentication, Context, Error, PublicCredential, Registration, VaultOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(target_arch = "wasm32", feature = "embedded-authenticator"))]
use zeroize::Zeroizing;

pub(crate) const MAX_CALLBACK: usize = 262_144;

#[cfg(all(test, any(target_arch = "wasm32", feature = "test-authenticator")))]
#[path = "../tests/callback.rs"]
mod tests;

/// The exact requested ceremony; a privileged result cannot become a member registration.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyKind {
    /// Registration requiring a successfully evaluated PRF.
    MemberRegistration,
    /// Explicit privileged registration, without a vault unlock result.
    PrivilegedRegistration,
    /// Sign-in with an independent vault result.
    Authentication,
}

/// Public server options and the operation the native caller requested.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRequest {
    /// Required ceremony and response type.
    pub kind: CeremonyKind,
    /// The complete server dictionary; only the fixed PRF extension is added.
    pub options: Value,
}

/// Completed browser ceremony, confined to the trusted Rust runtime.
pub enum CeremonyResult {
    /// PRF-proven member registration.
    MemberRegistration(Registration),
    /// Explicit privileged public registration.
    PrivilegedRegistration(PublicCredential),
    /// Public sign-in and independent opaque vault result.
    Authentication(Authentication),
}

impl CeremonyRequest {
    pub(crate) fn prepare(&mut self, context: &Context) -> Result<(), Error> {
        self.options = context.prepare(
            self.options.take(),
            self.kind != CeremonyKind::Authentication,
        )?;
        Ok(())
    }
}

// Header: version, kind, vault outcome, little-endian public length; public JSON;
// exactly 32 secret bytes only for Ready. Error paths carry no platform messages.
#[cfg(any(target_arch = "wasm32", feature = "embedded-authenticator"))]
pub(crate) fn encode(result: CeremonyResult) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (kind, public, secret, state) = match result {
        CeremonyResult::MemberRegistration(value) => {
            let (public, secret) = value.into_parts();
            (0, public, Some(secret), 0)
        }
        CeremonyResult::PrivilegedRegistration(value) => (1, value, None, 1),
        CeremonyResult::Authentication(value) => {
            let (public, vault) = value.into_parts();
            let (secret, state) = match vault {
                VaultOutcome::Ready(secret) => (Some(secret), 0),
                VaultOutcome::Locked(Error::InvalidPrf) => (None, 2),
                VaultOutcome::Locked(_) => (None, 1),
            };
            (2, public, secret, state)
        }
    };
    let public = serde_json::to_vec(public.as_json()).map_err(|_| Error::InvalidResponse)?;
    if public.len() > MAX_CALLBACK - 39 {
        return Err(Error::InvalidResponse);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(7 + public.len() + 32));
    output.extend_from_slice(&[1, kind, state]);
    output.extend_from_slice(&(public.len() as u32).to_le_bytes());
    output.extend_from_slice(&public);
    if let Some(secret) = secret {
        secret.import(|bytes| output.extend_from_slice(bytes));
    }
    Ok(output)
}

#[cfg(any(target_arch = "wasm32", feature = "embedded-authenticator"))]
pub(crate) async fn execute<A: crate::Authenticator>(
    context: Context,
    request: CeremonyRequest,
    platform: A,
) -> Result<CeremonyResult, Error> {
    let mut request = request;
    request.prepare(&context)?;
    let mut client = crate::Client::new(context, platform);
    match request.kind {
        CeremonyKind::MemberRegistration => client
            .register_member(request.options)
            .await
            .map(CeremonyResult::MemberRegistration),
        CeremonyKind::PrivilegedRegistration => client
            .register_privileged(request.options)
            .await
            .map(CeremonyResult::PrivilegedRegistration),
        CeremonyKind::Authentication => client
            .sign_in(request.options)
            .await
            .map(CeremonyResult::Authentication),
    }
}

#[cfg(any(target_arch = "wasm32", feature = "embedded-authenticator"))]
pub(crate) fn destination(fragment: &str) -> Result<(url::Url, Zeroizing<String>), Error> {
    if fragment.len() > 1024 {
        return Err(Error::InvalidOptions);
    }
    let pairs: Vec<_> = url::form_urlencoded::parse(fragment.as_bytes()).collect();
    if pairs.len() != 2 || pairs[0].0 != "cpky-v1" || pairs[1].0 != "cap" {
        return Err(Error::InvalidOptions);
    }
    let url = url::Url::parse(&pairs[0].1).map_err(|_| Error::InvalidOptions)?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0)
        || url.path() != "/finish"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::WrongContext);
    }
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let capability = Zeroizing::new(pairs[1].1.to_string());
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(capability.as_bytes())
            .map_err(|_| Error::InvalidOptions)?,
    );
    // The strict canonical base64url decoder above already rejects every
    // non-canonical spelling, so only the decoded length remains to check.
    if bytes.len() != 32 {
        return Err(Error::InvalidOptions);
    }
    Ok((url, capability))
}

pub(crate) fn decode(
    bytes: &[u8],
    request: &CeremonyRequest,
    context: &Context,
) -> Result<CeremonyResult, Error> {
    if bytes.len() < 7 || bytes.len() > MAX_CALLBACK || bytes[0] != 1 {
        return Err(Error::InvalidResponse);
    }
    let kind = match request.kind {
        CeremonyKind::MemberRegistration => 0,
        CeremonyKind::PrivilegedRegistration => 1,
        CeremonyKind::Authentication => 2,
    };
    let length =
        u32::from_le_bytes(bytes[3..7].try_into().map_err(|_| Error::InvalidResponse)?) as usize;
    let end = 7usize.checked_add(length).ok_or(Error::InvalidResponse)?;
    let extra = if bytes[2] == 0 { 32 } else { 0 };
    if bytes[1] != kind || bytes[2] > 2 || end.checked_add(extra) != Some(bytes.len()) {
        return Err(Error::InvalidResponse);
    }
    let public: Value =
        serde_json::from_slice(&bytes[7..end]).map_err(|_| Error::InvalidResponse)?;
    if has_secret_alias(&public) {
        return Err(Error::InvalidResponse);
    }
    context.bind(&public, &request.options, kind != 2)?;
    let client_data = crate::options::decode(&public["response"]["clientDataJSON"])?;
    let client_data: Value =
        serde_json::from_slice(&client_data).map_err(|_| Error::InvalidResponse)?;
    // Native and sealed popup ceremonies run in the configured top-level page.
    if client_data
        .get("crossOrigin")
        .is_some_and(|v| v != &Value::Bool(false))
        || client_data.get("topOrigin").is_some()
    {
        return Err(Error::CeremonyMismatch);
    }
    let secret = if bytes[2] == 0 {
        Some(UnlockSecret::take(&bytes[end..])?)
    } else {
        None
    };
    let credential = PublicCredential(public);
    match request.kind {
        CeremonyKind::MemberRegistration => Ok(CeremonyResult::MemberRegistration(Registration {
            credential,
            unlock: secret.ok_or(Error::PrfUnavailable)?,
        })),
        CeremonyKind::PrivilegedRegistration if bytes[2] == 1 => {
            Ok(CeremonyResult::PrivilegedRegistration(credential))
        }
        CeremonyKind::PrivilegedRegistration => Err(Error::InvalidResponse),
        CeremonyKind::Authentication => Ok(CeremonyResult::Authentication(Authentication {
            credential,
            vault: match secret {
                Some(secret) => VaultOutcome::Ready(secret),
                None => VaultOutcome::Locked(if bytes[2] == 2 {
                    Error::InvalidPrf
                } else {
                    Error::PrfUnavailable
                }),
            },
        })),
    }
}

fn has_secret_alias(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(key.as_str(), "prf" | "hmacGetSecret" | "hmac_get_secret")
                || has_secret_alias(value)
        }),
        Value::Array(values) => values.iter().any(has_secret_alias),
        _ => false,
    }
}
