//! Deterministic checks of the loopback gate predicates and handlers, without sockets.
use super::*;
use crate::CeremonyKind;

const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";
const HOST: &str = "127.0.0.1:4242";
const CAPABILITY: &str = "capability";

fn pending_with(
    sender: Option<oneshot::Sender<CeremonyResult>>,
    active: bool,
    lifetime: Duration,
) -> Arc<Pending> {
    Arc::new(Pending {
        context: Context::new(ORIGIN, RP).unwrap(),
        request: CeremonyRequest {
            kind: CeremonyKind::Authentication,
            options: crate::tests::request(),
        },
        capability: Zeroizing::new(CAPABILITY.to_string()),
        host: HOST.to_string(),
        sender: Mutex::new(sender),
        active: AtomicBool::new(active),
        deadline: tokio::time::Instant::now() + lifetime,
    })
}

/// A live pending ceremony whose receiver is already gone.
fn pending() -> Arc<Pending> {
    pending_with(Some(oneshot::channel().0), true, Duration::from_secs(60))
}

fn good() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("origin", HeaderValue::from_static(ORIGIN));
    headers.insert("host", HeaderValue::from_static(HOST));
    headers.insert("x-cpky-capability", HeaderValue::from_static(CAPABILITY));
    headers
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn browser_ceremony_reports_its_original_monotonic_lifetime() {
    runtime().block_on(async {
        let ceremony = BrowserCeremony::start(
            Context::new(ORIGIN, RP).unwrap(),
            url::Url::parse(&format!("{ORIGIN}/cli-login.html")).unwrap(),
            CeremonyRequest {
                kind: CeremonyKind::Authentication,
                options: crate::tests::request(),
            },
        )
        .await
        .unwrap();
        assert!(ceremony.remaining_lifetime() <= LIFETIME);
        assert!(!ceremony.remaining_lifetime().is_zero());
        ceremony.cancel();
    });
}

#[test]
fn every_platform_failure_is_the_same_coarse_refusal() {
    assert_eq!(unavailable("detail"), Error::Unavailable);
    assert_eq!(
        unavailable(std::io::Error::other("detail")),
        Error::Unavailable
    );
}

#[test]
fn gate_predicates_require_every_binding() {
    let now = tokio::time::Instant::now();
    let live = pending();
    assert!(valid_origin(&live, &good(), now));
    assert!(authorized(&live, &good(), now));
    // The ceremony must be live and unexpired at the instant of the request.
    assert!(!valid_origin(
        &pending_with(None, false, Duration::from_secs(60)),
        &good(),
        now
    ));
    assert!(!valid_origin(&live, &good(), now + Duration::from_secs(61)));
    for (name, value) in [
        ("origin", "https://foreign.example.com"),
        ("host", "evil.example.com:1"),
    ] {
        let mut headers = good();
        headers.insert(name, HeaderValue::from_static(value));
        assert!(!valid_origin(&live, &headers, now));
    }
    for name in ["origin", "host"] {
        let mut missing = good();
        missing.remove(name);
        assert!(!valid_origin(&live, &missing, now));
        let mut doubled = good();
        doubled.append(name, doubled[name].clone());
        assert!(!valid_origin(&live, &doubled, now));
    }
    // Exactly one capability header, equal in constant time.
    let mut wrong = good();
    wrong.insert("x-cpky-capability", HeaderValue::from_static("other"));
    assert!(!authorized(&live, &wrong, now));
    let mut missing = good();
    missing.remove("x-cpky-capability");
    assert!(!authorized(&live, &missing, now));
    let mut doubled = good();
    doubled.append("x-cpky-capability", HeaderValue::from_static(CAPABILITY));
    assert!(!authorized(&live, &doubled, now));
}

#[test]
fn preflight_answers_only_the_exact_method_and_headers() {
    let live = pending();
    let ask = |method: Option<&str>, requested: Option<&str>, origin_ok: bool| {
        let mut headers = good();
        if let Some(method) = method {
            headers.insert(
                "access-control-request-method",
                HeaderValue::from_str(method).unwrap(),
            );
        }
        if let Some(requested) = requested {
            headers.insert(
                "access-control-request-headers",
                HeaderValue::from_str(requested).unwrap(),
            );
        }
        if !origin_ok {
            headers.insert(
                "origin",
                HeaderValue::from_static("https://foreign.example.com"),
            );
        }
        preflight(&live, &headers, "POST")
    };
    let accepted = ask(Some("POST"), Some("content-type, x-cpky-capability"), true);
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
    assert_eq!(accepted.headers()["access-control-allow-methods"], "POST");
    assert_eq!(
        ask(Some("POST"), Some("x-cpky-capability"), true).status(),
        StatusCode::NO_CONTENT
    );
    for (method, requested, origin_ok) in [
        (Some("GET"), Some("x-cpky-capability"), true),
        (None, Some("x-cpky-capability"), true),
        (Some("POST"), None, true),
        (Some("POST"), Some("content-type"), true),
        (Some("POST"), Some("x-cpky-capability, authorization"), true),
        (Some("POST"), Some("x-cpky-capability"), false),
    ] {
        assert_eq!(
            ask(method, requested, origin_ok).status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[test]
fn request_handler_serves_only_the_authorized_live_ceremony() {
    runtime().block_on(async {
        let live = pending();
        let get = |headers: HeaderMap, method: Method| {
            request_options(State(live.clone()), method, headers)
        };
        let served = get(good(), Method::GET).await;
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(served.headers()["content-type"], "application/json");
        assert_eq!(served.headers()["cache-control"], "no-store");
        let mut wrong = good();
        wrong.insert("x-cpky-capability", HeaderValue::from_static("other"));
        assert_eq!(
            get(wrong, Method::GET).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get(good(), Method::POST).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut preflight = good();
        preflight.insert(
            "access-control-request-method",
            HeaderValue::from_static("GET"),
        );
        preflight.insert(
            "access-control-request-headers",
            HeaderValue::from_static("x-cpky-capability"),
        );
        assert_eq!(
            get(preflight, Method::OPTIONS).await.status(),
            StatusCode::NO_CONTENT
        );
        // After the one result was taken the request is gone.
        live.sender.lock().await.take();
        assert_eq!(get(good(), Method::GET).await.status(), StatusCode::GONE);
    });
}

#[test]
fn finish_handler_refuses_every_unauthorized_or_malformed_delivery() {
    runtime().block_on(async {
        let live = pending();
        let call = |headers: HeaderMap, method: Method, body: Body| {
            finish(State(live.clone()), method, headers, body)
        };
        let mut octets = good();
        octets.insert(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let mut preflight = good();
        preflight.insert(
            "access-control-request-method",
            HeaderValue::from_static("POST"),
        );
        preflight.insert(
            "access-control-request-headers",
            HeaderValue::from_static("content-type, x-cpky-capability"),
        );
        assert_eq!(
            call(preflight, Method::OPTIONS, Body::empty())
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(octets.clone(), Method::GET, Body::empty())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(good(), Method::POST, Body::empty()).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut json = good();
        json.insert("content-type", HeaderValue::from_static("application/json"));
        assert_eq!(
            call(json, Method::POST, Body::empty()).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut wrong = octets.clone();
        wrong.insert("x-cpky-capability", HeaderValue::from_static("other"));
        assert_eq!(
            call(wrong, Method::POST, Body::empty()).await.status(),
            StatusCode::FORBIDDEN
        );
        // Unreadable, oversized and undecodable bodies never deliver a result.
        let failing = Body::from_stream(futures::stream::once(async {
            Err::<Vec<u8>, std::io::Error>(std::io::Error::other("closed"))
        }));
        assert_eq!(
            call(octets.clone(), Method::POST, failing).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                octets.clone(),
                Method::POST,
                Body::from(vec![0; callback::MAX_CALLBACK + 1])
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(octets.clone(), Method::POST, Body::from(vec![1, 0, 0]))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(live.sender.lock().await.is_some());
    });
}

#[test]
fn a_body_cannot_outlive_the_ceremony_deadline() {
    runtime().block_on(async {
        let short = pending_with(Some(oneshot::channel().0), true, Duration::from_millis(50));
        let mut octets = good();
        octets.insert(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let never =
            Body::from_stream(futures::stream::pending::<Result<Vec<u8>, std::io::Error>>());
        let response = finish(State(short.clone()), Method::POST, octets, never).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(short.sender.lock().await.is_some());
    });
}

#[cfg(feature = "test-authenticator")]
#[test]
fn a_valid_delivery_is_accepted_once_and_never_after_the_receiver_is_gone() {
    use crate::software::{SoftwareAuthenticator, TestConfiguration};
    runtime().block_on(async {
        let platform = SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap();
        let mut client = crate::Client::new(Context::new(ORIGIN, RP).unwrap(), platform);
        client
            .register_member(crate::tests::creation())
            .await
            .unwrap();
        let authentication = client.sign_in(crate::tests::request()).await.unwrap();
        let (public, _vault) = authentication.into_parts();
        let json = public.as_json().clone();
        let mut octets = good();
        octets.insert(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        // A locked authentication frame needs no secret and decodes against the request.
        let frame = || {
            callback::encode(CeremonyResult::Authentication(crate::Authentication {
                credential: crate::PublicCredential(json.clone()),
                vault: crate::VaultOutcome::Locked(Error::PrfUnavailable),
            }))
            .unwrap()
        };
        // Receiver alive: delivered once, then gone.
        let (sender, mut receiver) = oneshot::channel();
        let live = pending_with(Some(sender), true, Duration::from_secs(60));
        let delivered = finish(
            State(live.clone()),
            Method::POST,
            octets.clone(),
            Body::from(frame().to_vec()),
        )
        .await;
        assert_eq!(delivered.status(), StatusCode::NO_CONTENT);
        assert!(matches!(
            receiver.try_recv(),
            Ok(CeremonyResult::Authentication(_))
        ));
        let again = finish(
            State(live),
            Method::POST,
            octets.clone(),
            Body::from(frame().to_vec()),
        )
        .await;
        assert_eq!(again.status(), StatusCode::GONE);
        // Receiver dropped (ceremony ended): nothing is delivered.
        let ended = pending();
        let response = finish(
            State(ended),
            Method::POST,
            octets,
            Body::from(frame().to_vec()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::GONE);
    });
}

#[cfg(feature = "test-authenticator")]
#[test]
fn original_http_callback_accepts_real_signature_once_and_keeps_prf_opaque() {
    use crate::software::{SoftwareAuthenticator, TestConfiguration};
    runtime().block_on(async {
        let context = Context::new(ORIGIN, RP).unwrap();
        let platform = SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap();
        let mut client = crate::Client::new(Context::new(ORIGIN, RP).unwrap(), platform);
        client
            .register_member(crate::tests::creation())
            .await
            .unwrap();
        let platform = client.into_authenticator();
        let retry = platform.synced_test_device();
        let ceremony = BrowserCeremony::start(
            context,
            Url::parse(&format!("{ORIGIN}/cli-login.html")).unwrap(),
            CeremonyRequest {
                kind: CeremonyKind::Authentication,
                options: crate::tests::request(),
            },
        )
        .await
        .unwrap();
        ceremony
            .complete_with_test_authenticator(platform)
            .await
            .unwrap();
        assert!(
            ceremony
                .complete_with_test_authenticator(retry)
                .await
                .is_err()
        );
        let CeremonyResult::Authentication(authentication) = ceremony.wait().await.unwrap() else {
            panic!("wrong original ceremony result");
        };
        let (credential, custody) = authentication.into_parts();
        assert!(credential.as_json()["response"]["signature"].is_string());
        assert!(
            credential
                .as_json()
                .pointer("/clientExtensionResults/prf")
                .is_none()
        );
        assert!(matches!(custody, crate::VaultOutcome::Ready(_)));
    });
}

/// Guard: wherever reqwest is built with rustls (`rustls-no-provider`, unified in
/// here through the crlt dev-dependency), `build()` panics while the process has
/// no crypto provider. In a fresh process, where nothing has selected one yet,
/// the product's callback client must select it itself.
#[cfg(feature = "embedded-authenticator")]
#[test]
fn callback_client_selects_its_tls_provider_in_a_fresh_process() {
    const CHILD: &str = "CPKY_TLS_PROVIDER_CHILD";
    const NAME: &str = "callback_client_selects_its_tls_provider_in_a_fresh_process";
    if std::env::var_os(CHILD).is_some() {
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_none(),
            "the child process must start without a crypto provider"
        );
        callback_client().unwrap();
        return;
    }
    let (_, module) = module_path!().split_once("::").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &format!("{module}::{NAME}"), "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(" 1 passed"),
        "fresh-process run failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
