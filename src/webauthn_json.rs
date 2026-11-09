//! WebAuthn JSON of a finished ceremony, as `PublicKeyCredential.toJSON()` defines it
//! (WebAuthn Level 3, 5.1.8/5.2.1.1/5.2.2.1): every binary member is a base64url string
//! without padding. passkey-types 0.6 serializes its `Bytes` as plain byte sequences (its
//! base64url switch is no longer a declared feature), so the upstream credential is
//! serialized as it is and exactly the binary members are encoded here. A byte sequence in
//! any other member is refused instead of leaving the device in a non-standard form.
use crate::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

/// The binary members of a registration or an authentication response.
const BINARY: [&str; 7] = [
    "/rawId",
    "/response/clientDataJSON",
    "/response/authenticatorData",
    "/response/publicKey",
    "/response/attestationObject",
    "/response/signature",
    "/response/userHandle",
];

/// The standard JSON form of an upstream `PublicKeyCredential`.
pub(crate) fn to_json<T: serde::Serialize>(credential: &T) -> Result<Value, Error> {
    let mut value = serde_json::to_value(credential).map_err(|_| Error::InvalidResponse)?;
    for pointer in BINARY {
        if let Some(member) = value.pointer_mut(pointer) {
            let bytes = byte_sequence(member).ok_or(Error::InvalidResponse)?;
            *member = Value::String(URL_SAFE_NO_PAD.encode(bytes));
        }
    }
    if holds_byte_sequence(&value) {
        return Err(Error::InvalidResponse);
    }
    Ok(value)
}

/// The bytes of a serialized byte sequence: an array of integers 0..=255.
fn byte_sequence(member: &Value) -> Option<Vec<u8>> {
    member
        .as_array()?
        .iter()
        .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

fn holds_byte_sequence(value: &Value) -> bool {
    match value {
        Value::Array(items) => {
            (!items.is_empty() && byte_sequence(value).is_some())
                || items.iter().any(holds_byte_sequence)
        }
        Value::Object(members) => members.values().any(holds_byte_sequence),
        _ => false,
    }
}

#[cfg(test)]
#[path = "../tests/webauthn_json.rs"]
mod tests;
