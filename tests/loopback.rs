//! Real HTTP callback plus maintained software authenticator and Keyhole/SQL.
use crate::{
    CeremonyKind, CeremonyRequest, CeremonyResult, Client, Context, VaultOutcome, callback,
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
        for origin in ["http://members.example.com/passkeys/cli", "https://foreign.example.com/passkeys/cli", "https://members.example.com/passkeys/cli?x=1", "https://members.example.com/passkeys/cli#x"] {
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
