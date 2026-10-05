//! Private same-origin popup custody. Only sealed result bytes may cross JS.
#[cfg(target_arch = "wasm32")]
mod channel;
#[cfg(target_arch = "wasm32")]
mod owner;
mod seal;
#[cfg(target_arch = "wasm32")]
pub use owner::{PopupCeremony, PopupHandoff};
#[cfg(all(test, feature = "test-authenticator"))]
#[path = "../tests/popup.rs"]
mod tests;
