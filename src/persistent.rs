//! Deterministic software authenticator for an operator identity whose 32-byte
//! seed lives in an external secret store (sops). It presents an ordinary
//! WebAuthn credential: attestation `none`, authenticator data flags UP|UV|AT|BE|BS
//! (plus ED when the stock extension data is present; BE/BS are the upstream's
//! and are right for a credential any device can rebuild from the seed), a
//! P-256 ES256 COSE key, signature counter 0. The server needs no special path and
//! sees no marker. User verification is asserted: possession of the seed is the
//! verification the operator delegated.
//!
//! The seed is consumed into a zeroizing buffer; no accessor, `Debug`, `serde`
//! or log path exposes it or any derived key. One seed per identity.
//!
//! Registration runs the maintained upstream client once for client data, RP
//! binding, extension negotiation and authenticator-data framing, then replaces
//! the credential id, public key and attested credential data with the
//! seed-derived values before anything leaves this module. Assertions use the
//! upstream authenticator with a credential rebuilt from the same derivation, so
//! signatures and PRF outputs are the maintained implementation's. PRF
//! evaluation at create is refused: the upstream would answer from random
//! secrets that differ from the derived ones.
use crate::{Authenticator as Port, Error, PlatformResult, UnlockSecret, sealed};
use hkdf::Hkdf;
use p256::{SecretKey, ecdsa::SigningKey};
use passkey::{
    authenticator::{
        Authenticator, UserCheck, UserValidationMethod, extensions::HmacSecretConfig,
        public_key_der_from_cose_key,
    },
    client::{Client, DefaultClientData},
    types::{
        Bytes, CredentialExtensions, Passkey, StoredHmacSecret,
        ctap2::{Aaguid, AttestedCredentialData, AuthenticatorData, Ctap2Error, Flags},
        encoding,
        webauthn::{
            AuthenticationExtensionsPrfOutputs, AuthenticatorResponse, PublicKeyCredential,
        },
    },
};
use serde_json::Value;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const SALT: &[u8] = b"cpky.persistent-software.v1";

struct User;
#[async_trait::async_trait]
impl UserValidationMethod for User {
    type PasskeyItem = Passkey;
    async fn check_user<'a>(
        &self,
        _: Option<&'a Passkey>,
        _: bool,
        _: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        // Seed possession is the delegated verification.
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }
    fn is_presence_enabled(&self) -> bool {
        true
    }
    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// Seed-derived credential material for one relying party.
struct Material {
    key: SecretKey,
    credential_id: Vec<u8>,
    with_uv: Vec<u8>,
    without_uv: Vec<u8>,
}
impl Drop for Material {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.with_uv.zeroize();
        self.without_uv.zeroize();
    }
}

/// Seed-bound software authenticator for exactly one origin; see the module notes.
pub struct PersistentAuthenticator {
    seed: Zeroizing<[u8; 32]>,
    origin: url::Url,
    user_handle: Option<Bytes>,
    keep: Option<Keep>,
}

/// Durable store for the server-chosen user handle; `false` means it was not kept.
type Keep = std::sync::Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

impl PersistentAuthenticator {
    /// `seed` must be uniformly random (for example 32 bytes from a CSPRNG stored
    /// once in the secret store); an all-zero seed is refused.
    pub fn new(origin: &str, seed: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(Error::WrongContext);
        }
        let origin = url::Url::parse(origin).map_err(|_| Error::WrongContext)?;
        if origin.host_str().is_none() {
            return Err(Error::WrongContext);
        }
        Ok(Self {
            seed,
            origin,
            user_handle: None,
            keep: None,
        })
    }

    /// Keep the user handle the moment a registration creates the credential, before
    /// the response leaves, as a device stores its credential at create: a process that
    /// stops right after the server accepted the registration signs in again with the
    /// stored handle. A keeper that answers `false` refuses the registration
    /// ([`Error::Unavailable`]); nothing reaches the server.
    #[must_use]
    pub fn keeping_handle(mut self, keep: impl Fn(&[u8]) -> bool + Send + Sync + 'static) -> Self {
        self.keep = Some(std::sync::Arc::new(keep));
        self
    }

    /// The server-chosen user handle learned at registration. It is not secret and
    /// is not derivable from the seed, so the operator stores it beside the seed;
    /// discoverable sign-in needs it on a fresh device.
    pub fn user_handle(&self) -> Option<&[u8]> {
        self.user_handle.as_deref().map(|bytes| bytes.as_slice())
    }

    /// Restore the stored user handle on a new device.
    #[must_use]
    pub fn with_user_handle(mut self, handle: Vec<u8>) -> Self {
        self.user_handle = Some(handle.into());
        self
    }

    fn derive(&self, rp_id: &str) -> Result<Material, Error> {
        let hk = Hkdf::<Sha256>::new(Some(SALT), self.seed.as_ref());
        let expand = |label: &str| -> Result<Zeroizing<[u8; 32]>, Error> {
            let mut info = Vec::with_capacity(label.len() + rp_id.len() + 1);
            info.extend_from_slice(label.as_bytes());
            info.push(0);
            info.extend_from_slice(rp_id.as_bytes());
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(&info, out.as_mut())
                .map_err(|_| Error::WrongContext)?;
            Ok(out)
        };
        // A non-scalar output has probability about 2^-128; the result is
        // deterministic, so it would be a stable refusal, never a retry.
        let key =
            SecretKey::from_slice(expand("p256-key")?.as_ref()).map_err(|_| Error::WrongContext)?;
        Ok(Material {
            key,
            credential_id: expand("credential-id")?.to_vec(),
            with_uv: expand("hmac-secret-uv")?.to_vec(),
            without_uv: expand("hmac-secret")?.to_vec(),
        })
    }

    fn rp_id(&self, options: &Value, create: bool) -> String {
        let public = &options["publicKey"];
        let declared = if create {
            public["rp"]["id"].as_str()
        } else {
            public["rpId"].as_str()
        };
        declared
            .map(str::to_owned)
            .unwrap_or_else(|| self.origin.host_str().unwrap_or_default().to_owned())
    }
}

fn cose_pair(key: &SecretKey) -> (coset::CoseKey, coset::CoseKey) {
    use coset::{CoseKeyBuilder, iana};
    let point = SigningKey::from(key)
        .verifying_key()
        .to_encoded_point(false);
    // An uncompressed point always carries both coordinates.
    let x = point.x().map(|v| v.to_vec()).unwrap_or_default();
    let y = point.y().map(|v| v.to_vec()).unwrap_or_default();
    let alg = iana::Algorithm::ES256;
    let private = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        x.clone(),
        y.clone(),
        key.to_bytes().to_vec(),
    )
    .algorithm(alg)
    .build();
    let public = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
        .algorithm(alg)
        .build();
    (private, public)
}

fn passkey(
    material: &Material,
    rp_id: &str,
    user_handle: Option<Bytes>,
) -> (Passkey, coset::CoseKey) {
    let (private, public) = cose_pair(&material.key);
    (
        Passkey {
            key: private,
            credential_id: material.credential_id.clone().into(),
            rp_id: rp_id.to_owned(),
            user_handle,
            // Counter 0 always: nothing is stored between ceremonies.
            counter: None,
            extensions: CredentialExtensions {
                hmac_secret: Some(StoredHmacSecret {
                    cred_with_uv: material.with_uv.clone(),
                    cred_without_uv: Some(material.without_uv.clone()),
                }),
            },
        },
        public,
    )
}

impl sealed::Sealed for PersistentAuthenticator {}
impl Port for PersistentAuthenticator {
    async fn perform(&mut self, options: &Value, create: bool) -> Result<PlatformResult, Error> {
        let rp_id = self.rp_id(options, create);
        let material = self.derive(&rp_id)?;
        let config = HmacSecretConfig::new_with_uv_only();
        if create {
            // Upstream registration with an empty store. PRF evaluation at create is
            // not enabled: the upstream's random secrets would not match ours.
            let auth =
                Authenticator::new(Aaguid::new_empty(), None::<Passkey>, User).hmac_secret(config);
            let mut client = Client::new(auth);
            let options =
                serde_json::from_value(options.clone()).map_err(|_| Error::InvalidOptions)?;
            let mut credential = client
                .register(&self.origin, options, DefaultClientData)
                .await
                .map_err(|_| Error::Cancelled)?;
            let user_handle = client
                .authenticator()
                .store()
                .as_ref()
                .and_then(|stored| stored.user_handle.clone());
            let (_, public) = cose_pair(&material.key);
            let mut data = AuthenticatorData::from_slice(&credential.response.authenticator_data)
                .map_err(|_| Error::InvalidResponse)?;
            // The framing must be exactly a user-verified attested registration.
            if !data.flags.contains(Flags::UP | Flags::UV | Flags::AT)
                || data.counter.unwrap_or(0) != 0
            {
                return Err(Error::InvalidResponse);
            }
            data.attested_credential_data = Some(
                AttestedCredentialData::new(
                    Aaguid::new_empty(),
                    material.credential_id.clone(),
                    public.clone(),
                )
                .map_err(|_| Error::InvalidResponse)?,
            );
            let auth_data = data.to_vec();
            use ciborium::Value;
            let attestation = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(Vec::new())),
                (
                    Value::Text("authData".into()),
                    Value::Bytes(auth_data.clone()),
                ),
            ]);
            let mut attestation_object = Vec::with_capacity(auth_data.len() + 32);
            ciborium::ser::into_writer(&attestation, &mut attestation_object)
                .map_err(|_| Error::InvalidResponse)?;
            credential.id = encoding::base64url(&material.credential_id);
            credential.raw_id = material.credential_id.clone().into();
            credential.response.authenticator_data = auth_data.into();
            credential.response.attestation_object = attestation_object.into();
            credential.response.public_key =
                Some(public_key_der_from_cose_key(&public).map_err(|_| Error::InvalidResponse)?);
            if let (Some(keep), Some(handle)) = (&self.keep, &user_handle)
                && !keep(handle.as_slice())
            {
                return Err(Error::Unavailable);
            }
            self.user_handle = user_handle;
            return split(credential);
        }
        // Assertion: the maintained authenticator signs with the derived credential.
        let (stored, _) = passkey(&material, &rp_id, self.user_handle.clone());
        let auth = Authenticator::new(Aaguid::new_empty(), Some(stored), User).hmac_secret(config);
        let mut client = Client::new(auth);
        let options = serde_json::from_value(options.clone()).map_err(|_| Error::InvalidOptions)?;
        let credential = client
            .authenticate(&self.origin, options, DefaultClientData)
            .await
            .map_err(|_| Error::Cancelled)?;
        split(credential)
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
