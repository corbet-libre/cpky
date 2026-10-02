//! Explicit test-only upstream software authenticator. Never a production default.
use crate::{Authenticator as Port, Error, PlatformResult, UnlockSecret, sealed};
use passkey::{
    authenticator::{Authenticator, UserCheck, UserValidationMethod, extensions::HmacSecretConfig},
    client::{Client, DefaultClientData},
    types::{
        Passkey,
        ctap2::{Aaguid, Ctap2Error},
        webauthn::{
            AuthenticationExtensionsPrfOutputs, AuthenticatorResponse, PublicKeyCredential,
        },
    },
};
use serde_json::Value;
use zeroize::Zeroize;

/// Explicit synthetic gesture configuration; no platform/user verification claim.
#[derive(Clone, Copy)]
pub struct TestConfiguration {
    /// Simulate a user-verified gesture in the upstream test authenticator.
    pub user_verified: bool,
    /// Enable the maintained authenticator's real PRF implementation.
    pub prf: bool,
    /// Allow PRF evaluation at create; false exercises create followed by get.
    pub evaluate_at_create: bool,
}

struct User(bool);
#[async_trait::async_trait]
impl UserValidationMethod for User {
    type PasskeyItem = Passkey;
    async fn check_user<'a>(
        &self,
        _: Option<&'a Passkey>,
        _: bool,
        _: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: self.0,
        })
    }
    fn is_presence_enabled(&self) -> bool {
        true
    }
    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// Test-only in-memory resident credential. No raw-key accessor, serde or Debug.
/// The explicit feature and constructor do not select production CLI custody.
pub struct SoftwareAuthenticator {
    credential: Option<Passkey>,
    origin: url::Url,
    config: TestConfiguration,
}
impl SoftwareAuthenticator {
    /// Construct only for synthetic test/demo input, with an explicit origin.
    pub fn new(origin: &str, config: TestConfiguration) -> Result<Self, Error> {
        Ok(Self {
            credential: None,
            origin: url::Url::parse(origin).map_err(|_| Error::WrongContext)?,
            config,
        })
    }
    /// Model the provider synchronizing the same credential to a fresh test device.
    /// This transfers upstream authenticator state, never a member vault snapshot.
    pub fn synced_test_device(&self) -> Self {
        Self {
            credential: self.credential.clone(),
            origin: self.origin.clone(),
            config: self.config,
        }
    }
}
impl sealed::Sealed for SoftwareAuthenticator {}
impl Port for SoftwareAuthenticator {
    async fn perform(&mut self, options: &Value, create: bool) -> Result<PlatformResult, Error> {
        let mut auth = Authenticator::new(
            Aaguid::new_empty(),
            self.credential.take(),
            User(self.config.user_verified),
        );
        if self.config.prf {
            let config = HmacSecretConfig::new_with_uv_only();
            auth = auth.hmac_secret(if self.config.evaluate_at_create {
                config.enable_on_make_credential()
            } else {
                config
            });
        }
        auth.set_make_credentials_with_signature_counter(true);
        let mut client = Client::new(auth);
        let result = if create {
            match serde_json::from_value(options.clone()) {
                Ok(options) => client
                    .register(&self.origin, options, DefaultClientData)
                    .await
                    .map_err(|_| Error::Cancelled)
                    .and_then(split),
                Err(_) => Err(Error::InvalidOptions),
            }
        } else {
            match serde_json::from_value(options.clone()) {
                Ok(options) => client
                    .authenticate(&self.origin, options, DefaultClientData)
                    .await
                    .map_err(|_| Error::Cancelled)
                    .and_then(split),
                Err(_) => Err(Error::InvalidOptions),
            }
        };
        self.credential = client.authenticator().store().clone();
        result
    }
}

fn split<R: AuthenticatorResponse + serde::Serialize>(
    mut credential: PublicKeyCredential<R>,
) -> Result<PlatformResult, Error> {
    // Take and wipe secret extensions BEFORE any serde or Debug operation.
    let (enabled, prf) = extract(credential.client_extension_results.prf.take());
    let public = serde_json::to_value(credential).map_err(|_| Error::InvalidResponse)?;
    Ok(PlatformResult {
        public,
        enabled,
        prf,
    })
}

fn extract(
    value: Option<AuthenticationExtensionsPrfOutputs>,
) -> (bool, Result<Option<UnlockSecret>, Error>) {
    let Some(mut value) = value else {
        return (false, Ok(None));
    };
    let result = value
        .results
        .as_ref()
        .map(|results| {
            if value.enabled == Some(false) || results.second.is_some() {
                return Err(Error::InvalidPrf);
            }
            UnlockSecret::take(&results.first)
        })
        .transpose();
    if let Some(results) = value.results.as_mut() {
        results.first.zeroize();
        if let Some(second) = &mut results.second {
            second.zeroize();
        }
    }
    (value.enabled.unwrap_or(false), result)
}

#[cfg(test)]
#[path = "../tests/software.rs"]
mod tests;
