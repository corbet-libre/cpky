//! Real HTTP callback plus maintained software authenticator and Keyhole/SQL.
use crate::{
    Authentication, CeremonyKind, CeremonyRequest, CeremonyResult, Client, Context, Error,
    PublicCredential, Registration, UnlockSecret, VaultOutcome, callback,
    native::BrowserCeremony,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
use reqwest::{Client as Http, StatusCode};

const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";
fn context() -> Context {
    Context::new(ORIGIN, RP).unwrap()
}
fn page() -> Url {
    Url::parse("https://members.example.com/passkeys/cli").unwrap()
}

#[test]
fn real_callback_keeps_custody_local_and_rejects_replay_origin_capability_and_substitution() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let database = Url::from_file_path(directory.path().join("community.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(database.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(
            1,
            "cpky_loopback",
            ckyh::LIBSQL_SCHEMA,
        )]))
        .unwrap();
    let store = LibsqlStore::new(&db, "synthetic", runtime.handle().clone()).unwrap();
    let server = Passkeys::new(store, "synthetic", RP, &[Url::parse(ORIGIN).unwrap()]).unwrap();
    let member = Uuid::from_u128(171);
    let platform = SoftwareAuthenticator::new(
        ORIGIN,
        TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap();
    let mut browser = Client::new(context(), platform);
    let (options, pending) = server.start_registration(member).unwrap();
    let registration = runtime
        .block_on(browser.register_member(serde_json::to_value(options).unwrap()))
        .unwrap();
    let (public, original) = registration.into_parts();
    let original = original.import(|bytes| blake3::hash(bytes));
    server
        .finish_registration(
            pending,
            &serde_json::from_value(public.into_json()).unwrap(),
            CreationMonth::new(2026, 10).unwrap(),
        )
        .unwrap();
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let options = serde_json::to_value(options).unwrap();
    let result = runtime.block_on(async {
        let ceremony = BrowserCeremony::start(
            context(),
            page(),
            CeremonyRequest {
                kind: CeremonyKind::Authentication,
                options: options.clone(),
            },
        )
        .await
        .unwrap();
        let (finish, capability) =
            callback::destination(ceremony.launch_url().fragment().unwrap()).unwrap();
        let mut request_url = finish.clone();
        request_url.set_path("/request");
        let http = Http::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for (origin, token) in [
            ("https://foreign.example.com", capability.as_str()),
            ("null", capability.as_str()),
            (ORIGIN, "wrong"),
        ] {
            assert_eq!(
                http.get(request_url.clone())
                    .header("origin", origin)
                    .header("x-cpky-capability", token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            http.get(request_url.clone())
                .header("origin", ORIGIN)
                .header("host", "foreign.example.com")
                .header("x-cpky-capability", capability.as_str())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let preflight = http
            .request(reqwest::Method::OPTIONS, finish.clone())
            .header("origin", ORIGIN)
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "content-type,x-cpky-capability",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(preflight.headers()["access-control-allow-origin"], ORIGIN);
        let response = http
            .get(request_url.clone())
            .header("origin", ORIGIN)
            .header("x-cpky-capability", capability.as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let request: CeremonyRequest =
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let request_options = request.options.clone();
        assert_eq!(
            request_options["publicKey"]["challenge"],
            options["publicKey"]["challenge"]
        );
        let completed = callback::execute(
            context(),
            request,
            browser.into_authenticator().synced_test_device(),
        )
        .await
        .unwrap();
        let bytes = callback::encode(completed).unwrap();
        // A valid capability cannot turn a different ceremony or leaked public PRF into a result.
        let mut wrong = bytes.to_vec();
        wrong[1] = 0;
        for body in [wrong, vec![0; callback::MAX_CALLBACK + 1]] {
            assert_eq!(
                http.post(finish.clone())
                    .header("origin", ORIGIN)
                    .header("x-cpky-capability", capability.as_str())
                    .header("content-type", "application/octet-stream")
                    .body(body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            http.post(finish.clone())
                .header("origin", ORIGIN)
                .header("x-cpky-capability", capability.as_str())
                .header("content-type", "application/octet-stream")
                .body(bytes.to_vec())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            http.post(finish.clone())
                .header("origin", ORIGIN)
                .header("x-cpky-capability", capability.as_str())
                .header("content-type", "application/octet-stream")
                .body(bytes.to_vec())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        assert_eq!(
            http.get(request_url)
                .header("origin", ORIGIN)
                .header("x-cpky-capability", capability.as_str())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        let result = ceremony.wait().await.unwrap();
        tokio::task::yield_now().await;
        assert!(http.post(finish).send().await.is_err());
        result
    });
    let CeremonyResult::Authentication(authentication) = result else {
        panic!("wrong result type")
    };
    let (public, vault) = authentication.into_parts();
    let VaultOutcome::Ready(secret) = vault else {
        panic!("missing actual PRF")
    };
    assert_eq!(original, secret.import(|bytes| blake3::hash(bytes)));
    let response = serde_json::from_value(public.into_json()).unwrap();
    assert_eq!(
        server
            .finish_discoverable_authentication(pending, &response)
            .unwrap()
            .member(),
        member
    );
}

#[test]
fn loopback_destinations_are_numeric_local_and_capabilities_are_canonical() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let capability = URL_SAFE_NO_PAD.encode([7; 32]);
    for endpoint in [
        "https://127.0.0.1:5555/finish",
        "http://localhost:5555/finish",
        "http://127.0.0.2:5555/finish",
        "http://127.0.0.1:0/finish",
        "http://127.0.0.1:5555/other",
        "http://127.0.0.1:5555/finish?x=1",
        "http://user@127.0.0.1:5555/finish",
        "http://:secret@127.0.0.1:5555/finish",
        "http://127.0.0.1:5555/finish#fragment",
    ] {
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-v1", endpoint)
            .append_pair("cap", &capability)
            .finish();
        assert!(callback::destination(&fragment).is_err(), "{endpoint}");
    }
    for fragment in [
        "",
        "cap=x&cpky-v1=x",
        "cpky-v1=http://127.0.0.1:5555/finish&cap=x",
        "cpky-v1=x&cap=x&cap=x",
        "cpky-v1=http://127.0.0.1:5555/finish&other=x",
    ] {
        assert!(callback::destination(fragment).is_err());
    }
}

#[test]
fn cancelling_closes_the_operation_including_existing_keepalive_connections() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let options = serde_json::json!({"publicKey":{"rpId":RP,"challenge":URL_SAFE_NO_PAD.encode([3;32]),"userVerification":"required"}});
        for origin in ["http://members.example.com/passkeys/cli", "https://foreign.example.com/passkeys/cli", "https://members.example.com/passkeys/cli?x=1", "https://members.example.com/passkeys/cli#x", "https://user@members.example.com/passkeys/cli", "https://:secret@members.example.com/passkeys/cli"] {
            assert!(BrowserCeremony::start(context(), Url::parse(origin).unwrap(), CeremonyRequest {kind:CeremonyKind::Authentication,options:options.clone()}).await.is_err());
        }
        let ceremony = BrowserCeremony::start(context(), page(), CeremonyRequest {kind:CeremonyKind::Authentication,options}).await.unwrap();
        let (mut url, capability) = callback::destination(ceremony.launch_url().fragment().unwrap()).unwrap();
        url.set_path("/request");
        let http = Http::builder().no_proxy().build().unwrap();
        let response = http.get(url.clone()).header("origin",ORIGIN).header("x-cpky-capability",capability.as_str()).send().await.unwrap();
        assert_eq!(response.status(),StatusCode::OK);
        response.bytes().await.unwrap();
        ceremony.cancel();
        if let Ok(response) = http.get(url).header("origin",ORIGIN).header("x-cpky-capability",capability.as_str()).send().await {
            assert_eq!(response.status(),StatusCode::FORBIDDEN);
        }
    });
}

#[test]
fn late_wait_uses_the_original_ceremony_deadline() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let ceremony = BrowserCeremony::start(
                context(),
                page(),
                CeremonyRequest {
                    kind: CeremonyKind::Authentication,
                    options: crate::tests::request(),
                },
            )
            .await
            .unwrap();
            tokio::time::advance(std::time::Duration::from_secs(121)).await;
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(1), ceremony.wait()).await;
            assert!(matches!(result, Ok(Err(crate::Error::Cancelled))));
        });
}

fn frame(kind: u8, state: u8, public: &serde_json::Value, secret: &[u8]) -> Vec<u8> {
    let public = serde_json::to_vec(public).unwrap();
    let mut bytes = vec![1, kind, state];
    bytes.extend_from_slice(&(public.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&public);
    bytes.extend_from_slice(secret);
    bytes
}

fn prepared(kind: CeremonyKind, options: serde_json::Value) -> CeremonyRequest {
    let mut request = CeremonyRequest { kind, options };
    request.prepare(&context()).unwrap();
    request
}

fn software(prf: bool) -> SoftwareAuthenticator {
    SoftwareAuthenticator::new(
        ORIGIN,
        TestConfiguration {
            user_verified: true,
            prf,
            evaluate_at_create: false,
        },
    )
    .unwrap()
}

/// Rewrite the browser's clientDataJSON inside a public response.
fn with_client_data(
    public: &serde_json::Value,
    edit: impl FnOnce(&mut serde_json::Value),
) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut public = public.clone();
    let encoded = public["response"]["clientDataJSON"].as_str().unwrap();
    let mut data: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    edit(&mut data);
    public["response"]["clientDataJSON"] =
        serde_json::Value::String(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap()));
    public
}

#[test]
fn member_registration_round_trips_and_every_frame_substitution_is_refused() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut client = Client::new(context(), software(true));
        let registration = client
            .register_member(crate::tests::creation())
            .await
            .unwrap();
        let (public, secret) = registration.into_parts();
        let original = secret.import(|bytes| *bytes);
        let json = public.as_json().clone();
        let again = Registration {
            credential: public,
            unlock: UnlockSecret::take(&original).unwrap(),
        };
        let bytes = callback::encode(CeremonyResult::MemberRegistration(again)).unwrap();
        let request = prepared(CeremonyKind::MemberRegistration, crate::tests::creation());
        let Ok(CeremonyResult::MemberRegistration(decoded)) =
            callback::decode(&bytes, &request, &context())
        else {
            panic!("member registration did not decode")
        };
        let (decoded_public, decoded_secret) = decoded.into_parts();
        assert_eq!(decoded_public.as_json(), &json);
        assert_eq!(decoded_secret.import(|bytes| *bytes), original);

        let refuse = |bytes: &[u8]| callback::decode(bytes, &request, &context()).err();
        // Version, size, ceremony kind, vault state and secret length are exact.
        let mut wrong = bytes.to_vec();
        wrong[0] = 2;
        assert_eq!(refuse(&wrong), Some(Error::InvalidResponse));
        assert_eq!(refuse(&bytes[..6]), Some(Error::InvalidResponse));
        assert_eq!(
            refuse(&vec![1; callback::MAX_CALLBACK + 1]),
            Some(Error::InvalidResponse)
        );
        let mut wrong = bytes.to_vec();
        wrong[1] = 1;
        assert_eq!(refuse(&wrong), Some(Error::InvalidResponse));
        let mut wrong = bytes.to_vec();
        wrong[2] = 3;
        assert_eq!(refuse(&wrong), Some(Error::InvalidResponse));
        assert_eq!(
            refuse(&bytes[..bytes.len() - 1]),
            Some(Error::InvalidResponse)
        );
        let mut wrong = bytes.to_vec();
        wrong[3..7].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(refuse(&wrong), Some(Error::InvalidResponse));
        // A frame without public JSON that parses is refused before any binding.
        let mut garbage = vec![1, 0, 0, 1, 0, 0, 0, b'{'];
        garbage.extend_from_slice(&[0; 32]);
        assert_eq!(refuse(&garbage), Some(Error::InvalidResponse));
        // A member registration needs the PRF secret: state 1 carries none.
        assert_eq!(
            refuse(&frame(0, 1, &json, &[])),
            Some(Error::PrfUnavailable)
        );
        // Secret extension aliases are refused anywhere in the public response.
        for alias in ["prf", "hmacGetSecret", "hmac_get_secret"] {
            let mut tainted = json.clone();
            tainted["clientExtensionResults"] = serde_json::json!({"nested": [{ alias: true }]});
            assert_eq!(
                refuse(&frame(0, 0, &tainted, &original)),
                Some(Error::InvalidResponse)
            );
        }
        let mut benign = json.clone();
        benign["unrelated"] = serde_json::json!([1, "x", null, {"y": false}]);
        assert!(callback::decode(&frame(0, 0, &benign, &original), &request, &context()).is_ok());
        // The CLI ceremony never runs in an embed: crossOrigin and topOrigin refuse.
        let embedded = with_client_data(&json, |data| data["crossOrigin"] = true.into());
        assert_eq!(
            refuse(&frame(0, 0, &embedded, &original)),
            Some(Error::CeremonyMismatch)
        );
        let top = with_client_data(&json, |data| {
            data["crossOrigin"] = false.into();
            data["topOrigin"] = "https://other.example.com".into();
        });
        assert_eq!(
            refuse(&frame(0, 0, &top, &original)),
            Some(Error::CeremonyMismatch)
        );
        let explicit = with_client_data(&json, |data| data["crossOrigin"] = false.into());
        assert!(callback::decode(&frame(0, 0, &explicit, &original), &request, &context()).is_ok());
        // A different pending request cannot accept this response.
        let mut other_options = crate::tests::creation();
        other_options["publicKey"]["challenge"] = serde_json::Value::String(
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9; 32]),
        );
        let other = prepared(CeremonyKind::MemberRegistration, other_options);
        assert_eq!(
            callback::decode(&bytes, &other, &context()).err(),
            Some(Error::CeremonyMismatch)
        );
    });
}

#[test]
fn privileged_registration_never_carries_or_accepts_a_vault_secret() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let completed = callback::execute(
            context(),
            CeremonyRequest {
                kind: CeremonyKind::PrivilegedRegistration,
                options: crate::tests::creation(),
            },
            software(true),
        )
        .await
        .unwrap();
        let CeremonyResult::PrivilegedRegistration(public) = completed else {
            panic!("wrong ceremony result")
        };
        let json = public.as_json().clone();
        let bytes = callback::encode(CeremonyResult::PrivilegedRegistration(public)).unwrap();
        let request = prepared(
            CeremonyKind::PrivilegedRegistration,
            crate::tests::creation(),
        );
        let Ok(CeremonyResult::PrivilegedRegistration(decoded)) =
            callback::decode(&bytes, &request, &context())
        else {
            panic!("privileged registration did not decode")
        };
        assert_eq!(decoded.as_json(), &json);
        // Any other vault state, with or without a secret, is a substitution.
        let mut wrong = bytes.to_vec();
        wrong[2] = 2;
        assert_eq!(
            callback::decode(&wrong, &request, &context()).err(),
            Some(Error::InvalidResponse)
        );
        assert_eq!(
            callback::decode(&frame(1, 0, &json, &[7; 32]), &request, &context()).err(),
            Some(Error::InvalidResponse)
        );
        // The encoded size is bounded before any frame is produced.
        let huge = PublicCredential(serde_json::Value::String(
            "x".repeat(callback::MAX_CALLBACK),
        ));
        assert_eq!(
            callback::encode(CeremonyResult::PrivilegedRegistration(huge)).err(),
            Some(Error::InvalidResponse)
        );
    });
}

#[test]
fn authentication_wire_keeps_the_vault_outcome_independent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut client = Client::new(context(), software(true));
        client
            .register_member(crate::tests::creation())
            .await
            .unwrap();
        let authentication = client.sign_in(crate::tests::request()).await.unwrap();
        let (public, vault) = authentication.into_parts();
        let VaultOutcome::Ready(secret) = vault else {
            panic!("the software authenticator must evaluate the PRF")
        };
        let original = secret.import(|bytes| *bytes);
        let json = public.as_json().clone();
        let request = prepared(CeremonyKind::Authentication, crate::tests::request());
        let outcomes = [
            VaultOutcome::Ready(UnlockSecret::take(&original).unwrap()),
            VaultOutcome::Locked(Error::PrfUnavailable),
            VaultOutcome::Locked(Error::InvalidPrf),
            VaultOutcome::Locked(Error::Cancelled),
        ];
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let result = CeremonyResult::Authentication(Authentication {
                credential: PublicCredential(json.clone()),
                vault: outcome,
            });
            let bytes = callback::encode(result).unwrap();
            let Ok(CeremonyResult::Authentication(decoded)) =
                callback::decode(&bytes, &request, &context())
            else {
                panic!("authentication did not decode")
            };
            let (decoded_public, vault) = decoded.into_parts();
            assert_eq!(decoded_public.as_json(), &json);
            match (index, vault) {
                (0, VaultOutcome::Ready(secret)) => {
                    assert_eq!(secret.import(|bytes| *bytes), original)
                }
                (1 | 3, VaultOutcome::Locked(Error::PrfUnavailable))
                | (2, VaultOutcome::Locked(Error::InvalidPrf)) => {}
                _ => panic!("vault outcome changed on the wire"),
            }
        }
        // A secret next to a locked state, or a missing one, is a malformed frame.
        assert_eq!(
            callback::decode(&frame(2, 1, &json, &[7; 32]), &request, &context()).err(),
            Some(Error::InvalidResponse)
        );
        assert_eq!(
            callback::decode(&frame(2, 0, &json, &[]), &request, &context()).err(),
            Some(Error::InvalidResponse)
        );
    });
}

#[test]
fn executing_each_requested_kind_returns_only_that_kind() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let member = callback::execute(
            context(),
            CeremonyRequest {
                kind: CeremonyKind::MemberRegistration,
                options: crate::tests::creation(),
            },
            software(true),
        )
        .await;
        assert!(matches!(member, Ok(CeremonyResult::MemberRegistration(_))));
        // Options that are not a WebAuthn dictionary never reach the platform.
        let invalid = callback::execute(
            context(),
            CeremonyRequest {
                kind: CeremonyKind::PrivilegedRegistration,
                options: serde_json::json!({}),
            },
            software(true),
        )
        .await;
        assert!(matches!(invalid, Err(Error::InvalidOptions)));
    });
}

#[test]
fn loopback_destination_refuses_oversized_and_short_capabilities() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    assert!(callback::destination(&"a".repeat(1025)).is_err());
    let endpoint = "http://127.0.0.1:5555/finish";
    let fragment = |capability: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-v1", endpoint)
            .append_pair("cap", capability)
            .finish()
    };
    for capability in [
        URL_SAFE_NO_PAD.encode([7; 16]),
        URL_SAFE_NO_PAD.encode([7; 33]),
        "not base64!".to_string(),
    ] {
        assert!(callback::destination(&fragment(&capability)).is_err());
    }
    // The strict decoder already rejects non-canonical trailing bits.
    let mut noncanonical = URL_SAFE_NO_PAD.encode([7; 32]);
    noncanonical.pop();
    noncanonical.push('B');
    assert!(callback::destination(&fragment(&noncanonical)).is_err());
    assert!(callback::destination(&fragment(&URL_SAFE_NO_PAD.encode([7; 32]))).is_ok());
}

#[test]
fn without_a_default_browser_opening_one_reports_unavailable() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let ceremony = BrowserCeremony::start(
                context(),
                page(),
                CeremonyRequest {
                    kind: CeremonyKind::Authentication,
                    options: crate::tests::request(),
                },
            )
            .await
            .unwrap();
            // Never launch a real browser from a test: only a host that has none
            // can answer this deterministically.
            if !webbrowser::Browser::is_available() {
                assert_eq!(ceremony.open_browser(), Err(Error::Unavailable));
            }
            ceremony.cancel();
        });
}
