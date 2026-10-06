//! One-use RFC 9180 envelope; the maintained HPKE crate owns all cryptography.
//! Plaintext and the existing callback codec stay entirely in Rust/Wasm.
use crate::{CeremonyRequest, CeremonyResult, Context, Error, callback};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use zeroize::Zeroizing;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;
const INFO: &[u8] = b"cpky.popup.handoff.v1\0";
pub(super) const MAX_SEALED: usize = callback::MAX_CALLBACK + 49;

pub(super) fn random() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut bytes = Zeroizing::new([0; 32]);
    #[cfg(target_arch = "wasm32")]
    getrandom::getrandom(bytes.as_mut()).map_err(|_| Error::Unavailable)?;
    #[cfg(not(target_arch = "wasm32"))]
    getrandom::fill(bytes.as_mut()).map_err(|_| Error::Unavailable)?;
    Ok(bytes)
}

/// Public handshake data only, kept private to the original platform adapter.
/// The launch pins nonce and recipient key before this channel offer is read.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub nonce: [u8; 32],
    pub recipient: [u8; 32],
    pub frame_origin: String,
    pub popup_origin: String,
    pub rp: String,
    pub request: CeremonyRequest,
}
impl Offer {
    fn aad(&self) -> Result<Vec<u8>, Error> {
        // Exact origins, nonce, recipient and original public challenge/policies
        // are authenticated together. No alternate key or challenge is accepted.
        serde_json::to_vec(self).map_err(|_| Error::InvalidOptions)
    }

    pub(super) fn context(&self, actual: &Context) -> Result<Context, Error> {
        if self.frame_origin != actual.origin()
            || self.popup_origin != actual.origin()
            || self.rp != actual.rp_id()
        {
            return Err(Error::WrongContext);
        }
        Context::new(&self.popup_origin, &self.rp)
    }
}

pub(super) struct Receiver {
    // The maintained X25519 PrivateKey wraps zeroize-on-drop StaticSecret.
    // Never cloned, serialized, exported or reused after an opening attempt.
    private: Rc<RefCell<Option<<Kem as hpke::Kem>::PrivateKey>>>,
    offer: Offer,
    context: Context,
}
impl Receiver {
    pub(super) fn new(context: Context, mut request: CeremonyRequest) -> Result<Self, Error> {
        request.prepare(&context)?;
        let seed = random()?;
        let (private, public) = Kem::derive_keypair(seed.as_slice());
        let recipient = public
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Unavailable)?;
        let offer = Offer {
            nonce: *random()?,
            recipient,
            frame_origin: context.origin().into(),
            popup_origin: context.origin().into(),
            rp: context.rp_id().into(),
            request,
        };
        if offer.aad()?.len() > callback::MAX_CALLBACK {
            return Err(Error::InvalidOptions);
        }
        Ok(Self {
            private: Rc::new(RefCell::new(Some(private))),
            offer,
            context,
        })
    }

    pub(super) fn offer(&self) -> &Offer {
        &self.offer
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn expire(&self) -> impl FnMut() + 'static {
        // The channel receives only a weak invalidation action, never a key
        // copy or authority to open. Prepared-but-unpolled owners also expire.
        let private = Rc::downgrade(&self.private);
        move || {
            if let Some(private) = private.upgrade() {
                private.borrow_mut().take();
            }
        }
    }

    pub(super) fn open(
        &mut self,
        nonce: &[u8; 32],
        origin: &str,
        bytes: &[u8],
    ) -> Result<CeremonyResult, Error> {
        let private = self.private.borrow_mut().take().ok_or(Error::Cancelled)?;
        if nonce != &self.offer.nonce || origin != self.offer.popup_origin {
            return Err(Error::WrongContext);
        }
        if !(50..=MAX_SEALED).contains(&bytes.len()) || bytes[0] != 1 {
            return Err(Error::InvalidResponse);
        }
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&bytes[1..33])
            .map_err(|_| Error::InvalidResponse)?;
        let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private,
            &enc,
            INFO,
            &bytes[33..],
            &self.offer.aad()?,
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidResponse)?;
        callback::decode(&plaintext, &self.offer.request, &self.context)
    }
}

pub(super) fn seal(
    offer: &Offer,
    actual: &Context,
    result: CeremonyResult,
) -> Result<Vec<u8>, Error> {
    offer.context(actual)?;
    let aad = offer.aad()?;
    if aad.len() > callback::MAX_CALLBACK {
        return Err(Error::InvalidOptions);
    }
    let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(&offer.recipient)
        .map_err(|_| Error::InvalidOptions)?;
    let plaintext = callback::encode(result)?;
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient,
        INFO,
        &plaintext,
        &aad,
        &mut rand_chacha::ChaCha20Rng::from_seed(*random()?),
    )
    .map_err(|_| Error::InvalidResponse)?;
    let mut output = Vec::with_capacity(33 + ciphertext.len());
    output.push(1);
    output.extend_from_slice(enc.to_bytes().as_slice());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}
