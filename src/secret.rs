use crate::Error;
use zeroize::Zeroizing;

/// One-use PRF handover confined to the trusted vault runtime. No Debug, Clone,
/// serialization, raw getter or WebAssembly export is implemented.
///
/// ```compile_fail
/// fn leak(value: cpky::UnlockSecret) { println!("{value:?}"); }
/// ```
/// ```compile_fail
/// fn copy(value: cpky::UnlockSecret) { let _ = value.clone(); }
/// ```
/// ```compile_fail
/// fn serialize(value: cpky::UnlockSecret) { let _ = serde_json::to_vec(&value); }
/// ```
pub struct UnlockSecret(Zeroizing<[u8; 32]>);
impl UnlockSecret {
    pub(crate) fn take(bytes: &[u8]) -> Result<Self, Error> {
        let mut owned = Zeroizing::new([0; 32]);
        if bytes.len() != owned.len() {
            return Err(Error::InvalidPrf);
        }
        owned.copy_from_slice(bytes);
        Ok(Self(owned))
    }

    /// Consume into the trusted vault's narrow Keys importer. The borrow cannot
    /// escape; our owned copy is wiped on return and unwinding. The callback is
    /// custody plumbing, not a sandbox against malicious in-process copying.
    /// Never expose this callback through HTTP, MCP, JS or a frontend registry.
    ///
    /// ```compile_fail
    /// fn leak(value: cpky::UnlockSecret) -> &'static [u8;32] { value.import(|bytes| bytes) }
    /// ```
    pub fn import<T>(self, receive: impl for<'a> FnOnce(&'a [u8; 32]) -> T) -> T {
        receive(&self.0)
    }
}
