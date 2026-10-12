//! Device WebAuthn ceremonies. Public credentials and vault PRF custody are separate.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
pub mod browser;
mod callback;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
mod options;
#[cfg(any(target_arch = "wasm32", all(test, feature = "test-authenticator")))]
mod popup;
mod secret;
#[cfg(feature = "persistent-software")]
pub mod persistent;
#[cfg(feature = "test-authenticator")]
pub mod software;

pub use callback::{CeremonyKind, CeremonyRequest, CeremonyResult};
pub use options::{Context, prf_input};
pub use secret::UnlockSecret;
use serde::Serialize;
use serde_json::Value;

/// Coarse failures without browser messages, credential identifiers or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid or excessive ceremony input.
    #[error("The passkey request is invalid.")]
    InvalidOptions,
    /// Server options do not match the configured relying party.
    #[error("The passkey request belongs to a different site.")]
    WrongContext,
    /// The platform cannot perform this ceremony.
    #[error("Passkeys are unavailable in this context.")]
    Unavailable,
    /// User cancellation, timeout or platform refusal.
    #[error("The passkey operation was cancelled or refused.")]
    Cancelled,
    /// No usable PRF result. A current PRF-capable browser/authenticator is needed.
    #[error(
        "This passkey cannot unlock the vault. Use a current phone or browser with PRF support."
    )]
    PrfUnavailable,
    /// A malformed secret result was wiped and refused.
    #[error("The passkey returned an unusable vault result.")]
    InvalidPrf,
    /// The returned credential belongs to a different ceremony.
    #[error("The passkey response does not match this operation.")]
    CeremonyMismatch,
    /// Malformed public platform response.
    #[error("The passkey response is invalid.")]
    InvalidResponse,
}

/// Sanitized public response. No secret extension is serializable through this type.
#[derive(Serialize)]
#[serde(transparent)]
pub struct PublicCredential(Value);
impl PublicCredential {
    /// Borrow only the public server response. Signature bytes are unchanged.
    pub fn as_json(&self) -> &Value {
        &self.0
    }
    /// Decode the exact original credential ID already bound to this ceremony.
    /// This public routing value proves neither server acceptance nor custody.
    pub fn credential_id(&self) -> Result<Vec<u8>, Error> {
        options::decode(self.0.get("rawId").ok_or(Error::InvalidResponse)?)
    }
    /// Transfer the public server response to the owning server client.
    pub fn into_json(self) -> Value {
        self.0
    }
}

/// Member registration, constructible only after obtaining a bound usable PRF.
pub struct Registration {
    credential: PublicCredential,
    unlock: UnlockSecret,
}
impl Registration {
    /// Split inside the vault runtime: public credential to Foyer, secret to Keys.
    pub fn into_parts(self) -> (PublicCredential, UnlockSecret) {
        (self.credential, self.unlock)
    }
}

/// Independent vault outcome of authentication; not a server login verdict.
pub enum VaultOutcome {
    /// Opaque PRF handover, not membership or device authorization.
    Ready(UnlockSecret),
    /// Public authentication may still proceed, but no vault unlock is claimed.
    Locked(Error),
}

/// One public authentication assertion and an independent vault outcome.
pub struct Authentication {
    credential: PublicCredential,
    vault: VaultOutcome,
}
impl Authentication {
    /// Consume the ceremony outputs without serializing custody material.
    pub fn into_parts(self) -> (PublicCredential, VaultOutcome) {
        (self.credential, self.vault)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A platform adapter supplied by this crate. Implementations cannot be substituted
/// with caller-created successful domain verdicts.
#[allow(async_fn_in_trait)]
pub trait Authenticator: sealed::Sealed {
    /// Internal platform operation; its response has no public accessors or codecs.
    #[doc(hidden)]
    async fn perform(&mut self, options: &Value, create: bool) -> Result<PlatformResult, Error>;
}

/// Opaque platform response, never a forwardable registration or secret codec.
#[doc(hidden)]
pub struct PlatformResult {
    public: Value,
    enabled: bool,
    prf: Result<Option<UnlockSecret>, Error>,
}

/// Ceremony adapter bound to one exact configured origin and relying party.
/// It owns no HTTP client, persistent key, membership or server session.
pub struct Client<A> {
    context: Context,
    authenticator: A,
}
impl<A: Authenticator> Client<A> {
    /// Wire the platform and the authenticated service's exact origin/RP policy.
    pub fn new(context: Context, authenticator: A) -> Self {
        Self {
            context,
            authenticator,
        }
    }

    /// Return the platform adapter, without exposing its credential secrets.
    pub fn into_authenticator(self) -> A {
        self.authenticator
    }

    /// Register a member (also used for an additional member passkey). Nothing
    /// forwardable is returned before PRF support and evaluation are established.
    pub async fn register_member(&mut self, options: Value) -> Result<Registration, Error> {
        let options = self.context.prepare(options, true)?;
        let created = self.authenticator.perform(&options, true).await?;
        self.context.bind(&created.public, &options, true)?;
        if !created.enabled {
            return Err(Error::PrfUnavailable);
        }
        let unlock = match created.prf? {
            Some(secret) => secret,
            None => {
                let followup = self.context.followup(&options, &created.public)?;
                let result = self.authenticator.perform(&followup, false).await?;
                self.context.bind(&result.public, &followup, false)?;
                // bind also checks the singleton allowCredentials and original
                // challenge; userHandle, when returned, must be the created user.
                options::bind_handle(&result.public, &options)?;
                result.prf?.ok_or(Error::PrfUnavailable)?
            }
        };
        Ok(Registration {
            credential: PublicCredential(created.public),
            unlock,
        })
    }

    /// Explicit root/admin ceremony. Its public response cannot be mistaken for
    /// the PRF-proven member Registration type. Any supplied PRF is dropped/wiped.
    pub async fn register_privileged(&mut self, options: Value) -> Result<PublicCredential, Error> {
        let options = self.context.prepare(options, true)?;
        let result = self.authenticator.perform(&options, true).await?;
        self.context.bind(&result.public, &options, true)?;
        Ok(PublicCredential(result.public))
    }

    /// Sign in with the server's exact request, including discoverable requests
    /// with empty allowCredentials. Missing PRF never fabricates a vault unlock.
    pub async fn sign_in(&mut self, options: Value) -> Result<Authentication, Error> {
        let options = self.context.prepare(options, false)?;
        let result = self.authenticator.perform(&options, false).await?;
        self.context.bind(&result.public, &options, false)?;
        let vault = match result.prf {
            Ok(Some(secret)) => VaultOutcome::Ready(secret),
            Ok(None) => VaultOutcome::Locked(Error::PrfUnavailable),
            Err(error) => VaultOutcome::Locked(error),
        };
        Ok(Authentication {
            credential: PublicCredential(result.public),
            vault,
        })
    }
}

/// Honest native fallback until a production authenticator/custody port is chosen.
pub struct Unavailable;
impl sealed::Sealed for Unavailable {}
impl Authenticator for Unavailable {
    async fn perform(&mut self, _: &Value, _: bool) -> Result<PlatformResult, Error> {
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32"), feature = "test-authenticator"))]
#[path = "../tests/loopback.rs"]
mod loopback_tests;
