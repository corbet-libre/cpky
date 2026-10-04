//! One-use, origin-bound browser handover on an ephemeral IPv4 loopback listener.
//! The capability is carried only in the launch fragment and request headers.
use crate::{CeremonyRequest, CeremonyResult, Context, Error, callback};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot},
    task::JoinHandle,
};
use url::Url;
use zeroize::Zeroizing;

const LIFETIME: Duration = Duration::from_secs(120);
const BODY_LIMIT: Duration = Duration::from_secs(10);

/// Every platform failure is the same coarse refusal; no detail leaves this module.
fn unavailable<E>(_: E) -> Error {
    Error::Unavailable
}

struct Pending {
    context: Context,
    request: CeremonyRequest,
    capability: Zeroizing<String>,
    host: String,
    sender: Mutex<Option<oneshot::Sender<CeremonyResult>>>,
    active: AtomicBool,
    deadline: tokio::time::Instant,
}

/// A single pending browser ceremony. Drop/cancel destroys the listener and custody result.
/// No Debug or serializer exposes the launch capability or returned secret.
pub struct BrowserCeremony {
    launch: Url,
    result: Option<oneshot::Receiver<CeremonyResult>>,
    shutdown: Option<oneshot::Sender<()>>,
    server: JoinHandle<()>,
    pending: Arc<Pending>,
}

impl BrowserCeremony {
    /// Bind loopback before returning the browser URL. The trusted composer supplies
    /// the exact HTTPS ceremony page and authenticated service options/RP context.
    pub async fn start(
        context: Context,
        mut page: Url,
        mut request: CeremonyRequest,
    ) -> Result<Self, Error> {
        if page.scheme() != "https"
            || page.origin().ascii_serialization() != context.origin()
            || !page.username().is_empty()
            || page.password().is_some()
            || page.fragment().is_some()
            || page.query().is_some()
        {
            return Err(Error::WrongContext);
        }
        request.prepare(&context)?;
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut()).map_err(unavailable)?;
        let capability = Zeroizing::new(URL_SAFE_NO_PAD.encode(*entropy));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(unavailable)?;
        let address = listener.local_addr().map_err(unavailable)?;
        let callback = format!("http://{address}/finish");
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cpky-v1", &callback)
            .append_pair("cap", &capability)
            .finish();
        page.set_fragment(Some(&fragment));
        let (sender, receiver) = oneshot::channel();
        let pending = Arc::new(Pending {
            context,
            request,
            capability,
            host: address.to_string(),
            sender: Mutex::new(Some(sender)),
            active: AtomicBool::new(true),
            deadline: tokio::time::Instant::now() + LIFETIME,
        });
        let app = Router::new()
            .route("/request", any(request_options))
            .route("/finish", any(finish))
            .with_state(pending.clone());
        let (shutdown, stopping) = oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = tokio::time::timeout(LIFETIME, async {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = stopping.await;
                    })
                    .await
            })
            .await;
        });
        Ok(Self {
            launch: page,
            result: Some(receiver),
            shutdown: Some(shutdown),
            server,
            pending,
        })
    }

    /// Open this URL in the normal browser. Never log or persist its fragment.
    pub fn launch_url(&self) -> &Url {
        &self.launch
    }

    /// Open the prepared ceremony in the platform's default browser using the
    /// maintained browser launcher. Failure leaves cancellation under caller control.
    pub fn open_browser(&self) -> Result<(), Error> {
        webbrowser::open(self.launch.as_str()).map_err(unavailable)
    }

    /// Remaining lifetime for public progress displays. The listener continues
    /// to enforce its own monotonic deadline independently of the display clock.
    pub fn remaining_lifetime(&self) -> Duration {
        self.pending
            .deadline
            .saturating_duration_since(tokio::time::Instant::now())
    }

    /// Exercise the original callback over actual HTTP with the explicitly
    /// test-only software authenticator. Never selected by production callers.
    #[cfg(feature = "test-authenticator")]
    pub async fn complete_with_test_authenticator(
        &self,
        platform: crate::software::SoftwareAuthenticator,
    ) -> Result<(), Error> {
        let (finish, capability) =
            callback::destination(self.launch.fragment().ok_or(Error::InvalidOptions)?)?;
        let client = reqwest::Client::builder()
            .timeout(BODY_LIMIT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(unavailable)?;
        let mut request_url = finish.clone();
        request_url.set_path("/request");
        let response = client
            .get(request_url)
            .header("origin", self.pending.context.origin())
            .header("x-cpky-capability", capability.as_str())
            .send()
            .await
            .map_err(unavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::InvalidResponse);
        }
        let bytes = response.bytes().await.map_err(unavailable)?;
        if bytes.len() > callback::MAX_CALLBACK {
            return Err(Error::InvalidResponse);
        }
        let request = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidOptions)?;
        let result = callback::execute(
            Context::new(self.pending.context.origin(), self.pending.context.rp_id())?,
            request,
            platform,
        )
        .await?;
        let frame = callback::encode(result)?;
        let response = client
            .post(finish)
            .header("origin", self.pending.context.origin())
            .header("x-cpky-capability", capability.as_str())
            .header("content-type", "application/octet-stream")
            .body(frame.to_vec())
            .send()
            .await
            .map_err(unavailable)?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }

    /// Consume the one result. Timeout, cancellation, and a closed listener refuse.
    pub async fn wait(mut self) -> Result<CeremonyResult, Error> {
        let receiver = self.result.take().expect("wait consumes the ceremony once");
        // The pending state owns the sender for this ceremony's whole life, so the
        // only way to no result is the shared deadline.
        let Ok(Ok(result)) = tokio::time::timeout_at(self.pending.deadline, receiver).await else {
            return Err(Error::Cancelled);
        };
        // Stopping is requested exactly once, here; a missing handle is impossible.
        let _ = self.shutdown.take().map(|shutdown| shutdown.send(()));
        // Drain the accepted HTTP response before Drop stops remaining connections.
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.server).await;
        Ok(result)
    }

    /// Close the listener and discard any completed result.
    pub fn cancel(self) {
        drop(self);
    }
}

impl Drop for BrowserCeremony {
    fn drop(&mut self) {
        self.pending.active.store(false, Ordering::Release);
        self.server.abort();
        self.launch.set_fragment(None);
    }
}

fn valid_origin(pending: &Pending, headers: &HeaderMap, now: tokio::time::Instant) -> bool {
    pending.active.load(Ordering::Acquire)
        && now < pending.deadline
        && headers.get("origin").and_then(|v| v.to_str().ok()) == Some(pending.context.origin())
        && headers.get("host").and_then(|v| v.to_str().ok()) == Some(pending.host.as_str())
        && headers.get_all("origin").iter().count() == 1
        && headers.get_all("host").iter().count() == 1
}

fn authorized(pending: &Pending, headers: &HeaderMap, now: tokio::time::Instant) -> bool {
    valid_origin(pending, headers, now)
        && headers.get_all("x-cpky-capability").iter().count() == 1
        && headers
            .get("x-cpky-capability")
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(pending.capability.as_bytes())))
}

fn response(pending: &Pending, status: StatusCode, body: impl Into<Body>) -> Response {
    let mut response = (status, body.into()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "access-control-allow-origin",
        // Context::new only accepts an ASCII serialization of an origin.
        HeaderValue::from_str(pending.context.origin()).expect("a validated origin is a header"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("vary", HeaderValue::from_static("Origin"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn preflight(pending: &Pending, headers: &HeaderMap, expected: &str) -> Response {
    if !valid_origin(pending, headers, tokio::time::Instant::now())
        || headers
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            != Some(expected)
        || !headers
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                let names: Vec<_> = v.split(',').map(str::trim).collect();
                names.contains(&"x-cpky-capability")
                    && names
                        .iter()
                        .all(|name| ["content-type", "x-cpky-capability"].contains(name))
            })
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut result = response(pending, StatusCode::NO_CONTENT, Body::empty());
    result.headers_mut().insert(
        "access-control-allow-methods",
        HeaderValue::from_str(expected).expect("static method"),
    );
    result.headers_mut().insert(
        "access-control-allow-headers",
        HeaderValue::from_static("content-type, x-cpky-capability"),
    );
    result.headers_mut().insert(
        "access-control-allow-private-network",
        HeaderValue::from_static("true"),
    );
    result
}

async fn request_options(
    State(pending): State<Arc<Pending>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return preflight(&pending, &headers, "GET");
    }
    if method != Method::GET || !authorized(&pending, &headers, tokio::time::Instant::now()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if pending.sender.lock().await.is_none() {
        return response(&pending, StatusCode::GONE, Body::empty());
    }
    // A request is plain JSON values and strings; serialization cannot fail.
    let bytes = serde_json::to_vec(&pending.request).expect("a ceremony request is plain JSON");
    let mut result = response(&pending, StatusCode::OK, bytes);
    result
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    result
}

async fn finish(
    State(pending): State<Arc<Pending>>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if method == Method::OPTIONS {
        return preflight(&pending, &headers, "POST");
    }
    let now = tokio::time::Instant::now();
    if method != Method::POST
        || !authorized(&pending, &headers, now)
        || headers.get("content-type").and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The body can never outlive the ceremony: its read is bounded by both the
    // body limit and the time left, so no recheck is needed after the await.
    let allowed = BODY_LIMIT.min(pending.deadline.saturating_duration_since(now));
    let bytes = match tokio::time::timeout(allowed, to_bytes(body, callback::MAX_CALLBACK)).await {
        Ok(Ok(bytes)) => Zeroizing::new(bytes.to_vec()),
        _ => return response(&pending, StatusCode::BAD_REQUEST, Body::empty()),
    };
    let result = match callback::decode(&bytes, &pending.request, &pending.context) {
        Ok(result) => result,
        Err(_) => return response(&pending, StatusCode::BAD_REQUEST, Body::empty()),
    };
    let mut sender = pending.sender.lock().await;
    let Some(sender) = sender.take() else {
        return response(&pending, StatusCode::GONE, Body::empty());
    };
    // A vanished receiver means the ceremony ended: nothing is delivered.
    let status = sender
        .send(result)
        .map_or(StatusCode::GONE, |()| StatusCode::NO_CONTENT);
    response(&pending, status, Body::empty())
}

#[cfg(test)]
#[path = "../tests/native.rs"]
mod tests;
