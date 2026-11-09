//! The WebAuthn JSON encoder: exactly the binary members become unpadded base64url.
use super::*;
use serde_json::json;

#[test]
fn binary_members_become_unpadded_base64url_and_nothing_else_changes() {
    let credential = json!({
        "id": "AQI", "rawId": [1, 2], "type": "public-key",
        "response": {
            "clientDataJSON": [123, 125], "authenticatorData": [0, 255],
            "publicKey": [48], "publicKeyAlgorithm": -7, "attestationObject": [],
            "signature": [1, 2, 3], "userHandle": [17, 17], "transports": ["internal", "hybrid"]
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {"credProps": {"rk": true}}
    });
    let encoded = to_json(&credential).unwrap();
    assert_eq!(
        encoded,
        json!({
            "id": "AQI", "rawId": "AQI", "type": "public-key",
            "response": {
                "clientDataJSON": "e30", "authenticatorData": "AP8",
                "publicKey": "MA", "publicKeyAlgorithm": -7, "attestationObject": "",
                "signature": "AQID", "userHandle": "ERE", "transports": ["internal", "hybrid"]
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {"credProps": {"rk": true}}
        })
    );
    // Absent optional members stay absent.
    let assertion = to_json(&json!({"rawId": [9], "response": {"signature": [8]}})).unwrap();
    assert_eq!(
        assertion,
        json!({"rawId": "CQ", "response": {"signature": "CA"}})
    );
}

#[test]
fn malformed_or_unknown_byte_sequences_are_refused() {
    for credential in [
        json!({"rawId": "already text"}),
        json!({"rawId": [256]}),
        json!({"rawId": [-1]}),
        json!({"response": {"signature": null}}),
        json!({"rawId": [1], "clientExtensionResults": {"largeBlob": {"blob": [1, 2]}}}),
    ] {
        assert!(matches!(to_json(&credential), Err(Error::InvalidResponse)));
    }
}
