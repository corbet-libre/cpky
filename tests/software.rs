//! Real upstream ceremonies with corruption/cancellation only at the platform boundary.
//! These refusal vectors do not substitute a successful domain implementation.
use super::*;
use crate::tests::{ORIGIN, RP, creation, request};
use crate::{Client, Context, VaultOutcome};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

fn platform() -> SoftwareAuthenticator {
    SoftwareAuthenticator::new(
        ORIGIN,
        TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum Fault {
    Cancel,
    Credential,
    Challenge,
    Handle,
    Missing,
    Malformed,
}
struct DamagedTransport {
    real: SoftwareAuthenticator,
    fault: Fault,
}
impl sealed::Sealed for DamagedTransport {}
impl Port for DamagedTransport {
    async fn perform(&mut self, options: &Value, create: bool) -> Result<PlatformResult, Error> {
        let mut actual = self.real.perform(options, create).await?;
        if !create {
            match self.fault {
                Fault::Cancel => return Err(Error::Cancelled),
                Fault::Credential => {
                    actual.public["id"] = json!("AQ");
                    actual.public["rawId"] = json!("AQ");
                }
                Fault::Challenge => {
                    let bytes =
                        crate::options::decode(&actual.public["response"]["clientDataJSON"])
                            .unwrap();
                    let mut data: Value = serde_json::from_slice(&bytes).unwrap();
                    data["challenge"] = json!(URL_SAFE_NO_PAD.encode([99; 32]));
                    actual.public["response"]["clientDataJSON"] =
                        json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap()));
                }
                Fault::Handle => actual.public["response"]["userHandle"] = json!("AQ"),
                Fault::Missing => actual.prf = Ok(None),
                Fault::Malformed => actual.prf = Err(Error::InvalidPrf),
            }
        }
        Ok(actual)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn no_registration_can_leave_a_failed_bound_followup() {
    futures::executor::block_on(async {
        for fault in [
            Fault::Cancel,
            Fault::Credential,
            Fault::Challenge,
            Fault::Handle,
            Fault::Missing,
            Fault::Malformed,
        ] {
            let mut client = Client::new(
                Context::new(ORIGIN, RP).unwrap(),
                DamagedTransport {
                    real: platform(),
                    fault,
                },
            );
            assert!(client.register_member(creation()).await.is_err());
        }
        let mut client = Client::new(
            Context::new(ORIGIN, RP).unwrap(),
            DamagedTransport {
                real: platform(),
                fault: Fault::Malformed,
            },
        );
        client.register_privileged(creation()).await.unwrap();
        let (public, vault) = client.sign_in(request()).await.unwrap().into_parts();
        assert!(matches!(vault, VaultOutcome::Locked(Error::InvalidPrf)));
        assert!(
            public.as_json()["clientExtensionResults"]
                .get("prf")
                .is_none()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn upstream_refusals_and_malformed_inputs() {
    assert!(
        SoftwareAuthenticator::new(
            "invalid",
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false
            }
        )
        .is_err()
    );
    futures::executor::block_on(async {
        let mut real = platform();
        for create in [false, true] {
            assert!(matches!(
                real.perform(&Value::Null, create).await,
                Err(Error::InvalidOptions)
            ));
        }
        let input = Context::new(ORIGIN, RP)
            .unwrap()
            .prepare(request(), false)
            .unwrap();
        assert!(matches!(
            real.perform(&input, false).await,
            Err(Error::Cancelled)
        ));
        let unverified = SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: false,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap();
        let mut client = Client::new(Context::new(ORIGIN, RP).unwrap(), unverified);
        assert!(client.register_member(creation()).await.is_err());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn upstream_typed_prf_splitting_fault_vectors() {
    use passkey::types::webauthn::AuthenticationExtensionsPrfValues;
    assert!(extract(None).1.unwrap().is_none());
    for enabled in [None, Some(true), Some(false)] {
        assert!(
            extract(Some(AuthenticationExtensionsPrfOutputs {
                enabled,
                results: None
            }))
            .1
            .unwrap()
            .is_none()
        );
        for size in [31, 32, 33] {
            for second in [false, true] {
                let value = AuthenticationExtensionsPrfOutputs {
                    enabled,
                    results: Some(AuthenticationExtensionsPrfValues {
                        first: vec![7; size].into(),
                        second: second.then(|| vec![9; 32].into()),
                    }),
                };
                let (reported, result) = extract(Some(value));
                assert_eq!(reported, enabled.unwrap_or(false));
                if enabled != Some(false) && size == 32 && !second {
                    assert_eq!(
                        result.unwrap().unwrap().import(|bytes| blake3::hash(bytes)),
                        blake3::hash(&[7; 32])
                    );
                } else {
                    assert!(matches!(result, Err(Error::InvalidPrf)));
                }
            }
        }
    }
}
