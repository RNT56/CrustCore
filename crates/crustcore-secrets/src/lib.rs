// SPDX-License-Identifier: Apache-2.0
//! Typed secrets + the secret broker (`ROADMAP.md` §8.1, §9.4–§9.5; Phase 8).
//! **CONTRACT FILE** — changes are serialized and reviewed (CLAUDE.md §7.3).
//!
//! This crate makes secret leakage *unrepresentable* (invariants 1–3;
//! `docs/secrets.md`):
//!
//! - [`SecretHandle`] is the only secret-related thing the model ever sees: an id
//!   + a label. It carries no bytes and is safe to log/serialize/show.
//! - [`SecretMaterial`] holds the raw bytes and deliberately implements **none** of
//!   `Debug`, `Display`, `Clone`, or `Serialize`, and has **no** conversion to
//!   model-visible text — so a leak is a *compile error*, not a runtime hope
//!   (compile-fail doctests below assert each missing impl). Its bytes are
//!   zeroized on drop.
//! - The only way bytes leave the broker is a one-shot, scoped, expiring
//!   [`ApprovedSecretView`], or — preferred — a [`CredentialProxy`] that injects
//!   the secret into an outbound request without handing the consumer the bytes.
//! - [`Redactor`] scrubs known secret values out of any text *before* it crosses a
//!   model/log/Telegram/GitHub boundary, and [`ModelVisibleText`] can be built
//!   **only** by the redactor — so the boundary is sealed by construction, not by
//!   a filter that might be forgotten.
//!
//! Scope (Phase 8): the trust-critical types, the redactor/taint boundary, the
//! broker request flow, and the credential-proxy pattern are implemented here,
//! nano-linked and std-only. The native OS keychain (P8.2) and the encrypted-file
//! vault (P8.3) are [`SecretStore`] backends that live **outside nano** (they pull
//! platform/crypto code) and are `TODO(P8-store)`; [`InMemoryStore`] stands in and
//! is what tests and the dev broker use. Nano stores only `secret://` handles.
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::BTreeMap;

use crustcore_types::{ApprovalId, BoundedText, SecretId, Timestamp};

// ---------------------------------------------------------------------------
// The model-visible reference
// ---------------------------------------------------------------------------

/// The model-visible reference to a secret: an id and a human label. Carries no
/// secret bytes and is safe to log, serialize, and show to a model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle {
    /// Stable id of the secret in the store.
    pub id: SecretId,
    /// A non-sensitive label (e.g. "github-token"), never the value.
    pub label: BoundedText,
}

/// Whether a secret is currently available to the broker (the model may be told
/// this; it never sees the value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretAvailability {
    /// The secret is present in the store and can be injected for approved ops.
    Available,
    /// The secret is configured but not currently resolvable.
    Unavailable,
    /// No such secret is configured.
    Missing,
}

// ---------------------------------------------------------------------------
// The raw bytes — leakage made unrepresentable
// ---------------------------------------------------------------------------

/// Raw secret bytes.
///
/// INVARIANTS (enforced by this type — do **not** add the listed impls;
/// invariant 3, `docs/secrets.md` §2.2):
/// - no `Debug` (cannot be `{:?}`-printed into logs/panics)
/// - no `Display` / `to_string()` (same reason)
/// - no `Clone` (cannot be silently duplicated; the broker keeps one copy)
/// - no `Serialize` (cannot be written to the event log / JSONL / artifacts /
///   config — this crate does not even depend on serde)
/// - no conversion to [`ModelVisibleText`] (the model boundary is sealed by the
///   *absence* of any `SecretMaterial -> ModelVisibleText` function)
/// - bytes are zeroized on drop
///
/// Each forbidden impl is asserted by a compile-fail doctest:
///
/// `Debug` does not compile:
/// ```compile_fail
/// let m = crustcore_secrets::SecretMaterial::new(b"x".to_vec());
/// let _ = format!("{m:?}");
/// ```
/// `Display`/`to_string()` does not compile:
/// ```compile_fail
/// let m = crustcore_secrets::SecretMaterial::new(b"x".to_vec());
/// let _ = m.to_string();
/// ```
/// `Clone` does not compile:
/// ```compile_fail
/// let m = crustcore_secrets::SecretMaterial::new(b"x".to_vec());
/// let _ = m.clone();
/// ```
/// There is no conversion to model-visible text (S1 is structural):
/// ```compile_fail
/// let m = crustcore_secrets::SecretMaterial::new(b"x".to_vec());
/// let _: crustcore_secrets::ModelVisibleText = m.into();
/// ```
pub struct SecretMaterial {
    bytes: Vec<u8>,
}

impl SecretMaterial {
    /// Wraps raw bytes. Constructed only by trusted store/broker code.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretMaterial { bytes }
    }

    /// Length in bytes (non-sensitive metadata).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the material is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Crate-private byte access. The only public read path is an
    /// [`ApprovedSecretView`] (or a [`CredentialProxy`]); this accessor is what
    /// those — and the broker, which registers the value with its [`Redactor`] —
    /// use internally. Not `pub`, so no code outside this audited crate can read
    /// the bytes directly.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        // Best-effort zeroization without `unsafe` or an external crate: zero the
        // bytes, then force the optimizer to treat the buffer as observed so the
        // dead store is not elided (`black_box` is std + stable). A `zeroize`-backed
        // `Zeroizing<Vec<u8>>` (volatile writes + fences) is the out-of-nano
        // hardening (`docs/secrets.md` §2.1); nano keeps this dep-free, no-`unsafe`
        // best-effort version.
        for b in &mut self.bytes {
            *b = 0;
        }
        std::hint::black_box(&self.bytes);
    }
}

// ---------------------------------------------------------------------------
// The redaction / taint boundary
// ---------------------------------------------------------------------------

/// The marker substituted for a redacted secret in outbound text.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Text that has passed through the [`Redactor`] and is therefore safe to put in
/// front of a model, a log, Telegram, or a GitHub comment. The boundary is sealed
/// by construction: the **only** way to build a `ModelVisibleText` is
/// [`Redactor::to_model_visible`], and there is no `From<SecretMaterial>` — so a
/// raw secret cannot become model-visible text (invariant 1; `docs/secrets.md` §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelVisibleText(String);

impl ModelVisibleText {
    /// The redacted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ModelVisibleText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Scrubs known secret values out of text before it crosses a boundary. The broker
/// registers every stored secret's value here, so tool stdout/stderr, error
/// strings, worker transcripts, MCP results, and channel drafts can all be passed
/// through [`redact`](Self::redact) / [`to_model_visible`](Self::to_model_visible)
/// before becoming model- or world-visible (`docs/security-model.md` §4–§5,
/// invariant 2).
#[derive(Default, Clone)]
pub struct Redactor {
    // (label, secret-value) pairs. Stored longest-first so an overlapping longer
    // secret is redacted before a shorter one.
    needles: Vec<(String, String)>,
}

impl Redactor {
    /// An empty redactor (a no-op until secrets are registered).
    #[must_use]
    pub fn new() -> Self {
        Redactor {
            needles: Vec::new(),
        }
    }

    /// Registers a secret value (with a label, used only inside the marker) to be
    /// scrubbed. Empty values are ignored (a zero-length needle would match
    /// everywhere). Kept sorted longest-first.
    pub fn register(&mut self, label: &str, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        let value = String::from_utf8_lossy(value).into_owned();
        if value.is_empty() {
            return;
        }
        self.needles.push((label.to_string(), value));
        // Longest needle first, so a superstring secret is replaced before a
        // substring secret (avoids leaving a fragment behind).
        self.needles
            .sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    }

    /// Redacts every registered secret occurrence in `text`, returning scrubbed
    /// text. Each hit becomes `[REDACTED:<label>]`.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (label, value) in &self.needles {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("[REDACTED:{label}]"));
            }
        }
        out
    }

    /// Redacts `text` and seals it as [`ModelVisibleText`] — the sole constructor
    /// of that type, so any model-visible text has provably been redacted.
    #[must_use]
    pub fn to_model_visible(&self, text: &str) -> ModelVisibleText {
        ModelVisibleText(self.redact(text))
    }

    /// Whether any registered secret appears in `text` (a leak check for tests /
    /// defense in depth).
    #[must_use]
    pub fn would_leak(&self, text: &str) -> bool {
        self.needles.iter().any(|(_, v)| text.contains(v.as_str()))
    }
}

/// A wrapper marking data as **tainted** (potentially secret-bearing). The only
/// way to derive model-visible text from tainted data is through a [`Redactor`],
/// so taint cannot silently cross a boundary (`docs/security-model.md` §4).
#[derive(Debug, Clone)]
pub struct Tainted<T>(T);

impl<T: AsRef<str>> Tainted<T> {
    /// Marks a value tainted.
    pub fn new(value: T) -> Self {
        Tainted(value)
    }

    /// The raw tainted value, for trusted in-process use only (never a boundary).
    pub fn raw(&self) -> &T {
        &self.0
    }

    /// Declassify by redacting — the only path from tainted to model-visible.
    #[must_use]
    pub fn declassify(&self, redactor: &Redactor) -> ModelVisibleText {
        redactor.to_model_visible(self.0.as_ref())
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Where the broker keeps secrets. Implemented by [`InMemoryStore`] (dev/tests)
/// and, **outside nano**, by the native OS keychain (P8.2) and encrypted-file
/// vault (P8.3) backends — `TODO(P8-store)`. Nano links only the trait + the
/// in-memory store; the keychain/vault crates are sidecars.
pub trait SecretStore {
    /// The material for `id`, if present.
    fn get(&self, id: SecretId) -> Option<&SecretMaterial>;

    /// The non-sensitive handles for every configured secret.
    fn handles(&self) -> Vec<SecretHandle>;

    /// Availability of `id` (present / configured-but-unresolvable / missing).
    fn availability(&self, id: SecretId) -> SecretAvailability {
        match self.get(id) {
            Some(_) => SecretAvailability::Available,
            None => SecretAvailability::Missing,
        }
    }
}

/// A simple in-process store. The dev/test backend and the stand-in until the
/// native keychain / encrypted vault backends land (`TODO(P8-store)`).
#[derive(Default)]
pub struct InMemoryStore {
    entries: BTreeMap<u32, (BoundedText, SecretMaterial)>,
}

impl InMemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        InMemoryStore {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a secret under `id` with `label`. The value is moved in; there is no
    /// way to read it back except through the broker's view/proxy.
    pub fn insert(&mut self, id: SecretId, label: &str, value: Vec<u8>) {
        self.entries.insert(
            id.0,
            (
                BoundedText::truncated(label, BoundedText::DEFAULT_MAX),
                SecretMaterial::new(value),
            ),
        );
    }
}

impl SecretStore for InMemoryStore {
    fn get(&self, id: SecretId) -> Option<&SecretMaterial> {
        self.entries.get(&id.0).map(|(_, m)| m)
    }

    fn handles(&self) -> Vec<SecretHandle> {
        self.entries
            .iter()
            .map(|(id, (label, _))| SecretHandle {
                id: SecretId(*id),
                label: label.clone(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The broker
// ---------------------------------------------------------------------------

/// Why exposing an [`ApprovedSecretView`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewError {
    /// The one-shot view was already consumed.
    AlreadyConsumed,
    /// The view has expired (its TTL elapsed).
    Expired,
}

impl core::fmt::Display for ViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ViewError::AlreadyConsumed => write!(f, "secret view already consumed (one-shot)"),
            ViewError::Expired => write!(f, "secret view expired"),
        }
    }
}

impl std::error::Error for ViewError {}

/// Why the broker refused to mint a view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// No secret with that id is configured/available.
    Unavailable(SecretId),
}

impl core::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BrokerError::Unavailable(id) => write!(f, "secret {} is not available", id.0),
        }
    }
}

impl std::error::Error for BrokerError {}

/// The trusted secret broker: owns a [`SecretStore`] and a [`Redactor`], and is the
/// only thing that materializes a secret for an approved operation. The model
/// interacts with it only through handles and availability (`docs/secrets.md` §3).
pub struct SecretBroker<S: SecretStore> {
    store: S,
    redactor: Redactor,
}

impl<S: SecretStore> SecretBroker<S> {
    /// Builds a broker over `store`, pre-registering every stored secret's value
    /// with the redactor so outbound text can be scrubbed.
    #[must_use]
    pub fn new(store: S) -> Self {
        let mut redactor = Redactor::new();
        for h in store.handles() {
            if let Some(m) = store.get(h.id) {
                redactor.register(h.label.as_str(), m.bytes());
            }
        }
        SecretBroker { store, redactor }
    }

    /// The non-sensitive handles the model may see.
    #[must_use]
    pub fn handles(&self) -> Vec<SecretHandle> {
        self.store.handles()
    }

    /// Availability of a secret (model-safe).
    #[must_use]
    pub fn availability(&self, id: SecretId) -> SecretAvailability {
        self.store.availability(id)
    }

    /// The broker's redactor (pre-loaded with all stored secrets), for scrubbing
    /// outbound text at any boundary.
    #[must_use]
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Mints a one-shot, expiring view authorizing `approval_id` to use the secret
    /// `id` until `now + ttl_millis`. The view borrows the broker, so the bytes
    /// cannot escape the broker's lifetime (`docs/secrets.md` §5).
    ///
    /// # Errors
    /// [`BrokerError::Unavailable`] if the secret is not present.
    pub fn authorize(
        &self,
        id: SecretId,
        approval_id: ApprovalId,
        now: Timestamp,
        ttl_millis: u64,
    ) -> Result<ApprovedSecretView<'_>, BrokerError> {
        let material = self.store.get(id).ok_or(BrokerError::Unavailable(id))?;
        Ok(ApprovedSecretView {
            material,
            secret_id: id,
            approval_id,
            expires_at: Timestamp::from_millis(now.as_millis().saturating_add(ttl_millis)),
            consumed: Cell::new(false),
        })
    }
}

/// A one-shot, scoped, expiring authorization to expose a specific secret to one
/// approved operation. Carries no bytes itself and — like [`SecretMaterial`] — is
/// intentionally not `Clone`/`Debug`/`Serialize`. The `'b` borrow of the broker is
/// what makes it **non-escaping**: it cannot be stored past the call that holds the
/// broker (`docs/secrets.md` §5).
pub struct ApprovedSecretView<'b> {
    material: &'b SecretMaterial,
    secret_id: SecretId,
    approval_id: ApprovalId,
    expires_at: Timestamp,
    consumed: Cell<bool>,
}

impl ApprovedSecretView<'_> {
    /// The secret this view authorizes.
    #[must_use]
    pub fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    /// The approval that unlocked this view.
    #[must_use]
    pub fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Exposes the bytes to trusted, non-model code **once**. The view is consumed
    /// (a second call fails) and rejected after expiry — bounding the blast radius
    /// of any mishandling. The returned slice is borrowed from the broker, so it
    /// cannot be stored past the borrow.
    ///
    /// # Errors
    /// [`ViewError::AlreadyConsumed`] / [`ViewError::Expired`].
    pub fn expose(&self, now: Timestamp) -> Result<&[u8], ViewError> {
        if self.consumed.get() {
            return Err(ViewError::AlreadyConsumed);
        }
        if now.as_millis() >= self.expires_at.as_millis() {
            return Err(ViewError::Expired);
        }
        self.consumed.set(true);
        Ok(self.material.bytes())
    }
}

// ---------------------------------------------------------------------------
// The credential proxy (preferred: never hand over the bytes)
// ---------------------------------------------------------------------------

/// An outbound HTTP authorization header value produced by the [`CredentialProxy`].
/// It holds the secret-bearing header internally and, like [`SecretMaterial`],
/// implements **no** `Debug`/`Display`/`Clone`/`Serialize` — only trusted outbound
/// code reads it via [`reveal`](Self::reveal), and a log/model only ever sees its
/// [`redacted`](Self::redacted) form.
pub struct HeaderInjection {
    header_name: String,
    value: SecretMaterial,
    label: String,
}

impl HeaderInjection {
    /// The header name (non-sensitive, e.g. `Authorization`).
    #[must_use]
    pub fn header_name(&self) -> &str {
        &self.header_name
    }

    /// The secret header value, for the trusted process making the request only.
    /// Crate-external trusted code (the net/git sidecar) reads it here; it never
    /// reaches the model.
    #[must_use]
    pub fn reveal(&self) -> &[u8] {
        self.value.bytes()
    }

    /// A model-/log-safe rendering: the value is replaced by a redaction marker.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("{}: [REDACTED:{}]", self.header_name, self.label)
    }
}

/// The credential-proxy pattern (`docs/secrets.md` §6, injection order #3): a
/// trusted proxy injects a secret into an outbound request at the last moment, so
/// the consumer (and the model, and the sandbox env) never holds the raw bytes.
/// This is the primitive the `crustcore-net`/GitHub sidecars use to authenticate
/// requests; it is what unblocks live providers (the model key never enters nano,
/// the sandbox, or model context).
pub struct CredentialProxy;

impl CredentialProxy {
    /// Consumes a one-shot [`ApprovedSecretView`] and produces an outbound header
    /// injection (e.g. `Authorization: Bearer <token>`). The token is moved into a
    /// non-model-visible [`HeaderInjection`]; the model/logs only ever see its
    /// redacted form. Consuming the view enforces one-shot use.
    ///
    /// # Errors
    /// [`ViewError`] if the view is consumed/expired.
    pub fn bearer(
        view: &ApprovedSecretView<'_>,
        now: Timestamp,
        label: &str,
    ) -> Result<HeaderInjection, ViewError> {
        let token = view.expose(now)?;
        let mut value = b"Bearer ".to_vec();
        value.extend_from_slice(token);
        Ok(HeaderInjection {
            header_name: "Authorization".to_string(),
            value: SecretMaterial::new(value),
            label: label.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn handle_is_safe_metadata() {
        let h = SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("github-token").unwrap(),
        };
        // The handle is debuggable/cloneable on purpose; it carries no value.
        let _ = format!("{h:?}");
        assert_eq!(h.clone(), h);
    }

    #[test]
    fn material_reports_len_and_zeroizes_on_drop() {
        let m = SecretMaterial::new(b"hunter2".to_vec());
        assert_eq!(m.len(), 7);
        assert!(!m.is_empty());
        // Zeroization-on-drop runs in Drop; its effect is not safely observable
        // from outside, so we assert the dep-free path compiles and runs.
        drop(m);
    }

    // --- broker request flow + one-shot/expiry (P8.4) ---

    fn broker_with_token() -> SecretBroker<InMemoryStore> {
        let mut store = InMemoryStore::new();
        store.insert(SecretId(7), "model-key", b"sk-SENTINELxyz".to_vec());
        SecretBroker::new(store)
    }

    #[test]
    fn broker_exposes_only_through_a_one_shot_view() {
        let broker = broker_with_token();
        let view = broker
            .authorize(SecretId(7), ApprovalId(1), ts(1000), 5000)
            .unwrap();
        // First exposure works.
        assert_eq!(view.expose(ts(1001)).unwrap(), b"sk-SENTINELxyz");
        // One-shot: a second exposure fails.
        assert_eq!(view.expose(ts(1002)), Err(ViewError::AlreadyConsumed));
    }

    #[test]
    fn view_is_rejected_after_expiry() {
        let broker = broker_with_token();
        let view = broker
            .authorize(SecretId(7), ApprovalId(1), ts(1000), 100)
            .unwrap();
        // now >= expires_at (1000 + 100) → expired.
        assert_eq!(view.expose(ts(1100)), Err(ViewError::Expired));
    }

    #[test]
    fn broker_refuses_a_missing_secret() {
        let broker = broker_with_token();
        // `authorize` returns the non-Debug `ApprovedSecretView` on success, so we
        // match rather than assert_eq! (which would require Debug on the view —
        // exactly the impl the view must not have).
        let r = broker.authorize(SecretId(999), ApprovalId(1), ts(1), 1000);
        assert!(matches!(r, Err(BrokerError::Unavailable(SecretId(999)))));
    }

    #[test]
    fn model_sees_only_handles_and_availability() {
        let broker = broker_with_token();
        let handles = broker.handles();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].label.as_str(), "model-key");
        // No bytes anywhere in the handle's debug form.
        assert!(!format!("{:?}", handles[0]).contains("SENTINEL"));
        assert_eq!(
            broker.availability(SecretId(7)),
            SecretAvailability::Available
        );
        assert_eq!(
            broker.availability(SecretId(0)),
            SecretAvailability::Missing
        );
    }

    // --- credential proxy (P8.6) ---

    #[test]
    fn credential_proxy_injects_without_exposing_to_model() {
        let broker = broker_with_token();
        let view = broker
            .authorize(SecretId(7), ApprovalId(1), ts(1000), 5000)
            .unwrap();
        let inj = CredentialProxy::bearer(&view, ts(1001), "model-key").unwrap();
        // Trusted outbound code can read the real header.
        assert_eq!(inj.reveal(), b"Bearer sk-SENTINELxyz");
        assert_eq!(inj.header_name(), "Authorization");
        // The model/log-safe rendering never contains the token.
        let shown = inj.redacted();
        assert!(
            !shown.contains("SENTINEL"),
            "redacted header leaked: {shown}"
        );
        assert!(shown.contains("[REDACTED:model-key]"));
        // The view was consumed by the proxy (one-shot).
        assert_eq!(view.expose(ts(1002)), Err(ViewError::AlreadyConsumed));
    }

    // --- redactor / taint (P8.5): the runtime S-matrix ---

    #[test]
    fn redactor_scrubs_secret_for_every_runtime_boundary() {
        // The broker pre-registers stored secrets with its redactor.
        let broker = broker_with_token();
        let r = broker.redactor();
        let secret = "sk-SENTINELxyz";

        // S2 stdout, S3 stderr, S6 tool error, S7 GitHub error, S8 Telegram draft,
        // S9 worker transcript, S10 MCP result — each is just outbound text routed
        // through the redactor before it crosses the boundary.
        for (label, text) in [
            ("S2 stdout", format!("running with token {secret}\n")),
            ("S3 stderr", format!("error: auth {secret} rejected")),
            ("S6 tool error", format!("failed: bad credential {secret}")),
            (
                "S7 github error",
                format!("422: token {secret} lacks scope"),
            ),
            ("S8 telegram draft", format!("deploying with {secret} now")),
            (
                "S9 worker transcript",
                format!("I used the key {secret} to push"),
            ),
            ("S10 mcp result", format!("{{\"key\":\"{secret}\"}}")),
        ] {
            assert!(r.would_leak(&text), "{label}: setup should contain secret");
            let safe = r.redact(&text);
            assert!(
                !safe.contains(secret),
                "{label}: secret survived redaction: {safe}"
            );
            assert!(safe.contains("[REDACTED:model-key]"), "{label}: no marker");
            // The sealed model-visible form is likewise scrubbed.
            assert!(
                !r.to_model_visible(&text).as_str().contains(secret),
                "{label}: MVT leaked"
            );
        }
    }

    #[test]
    fn redactor_handles_overlapping_secrets_longest_first() {
        let mut r = Redactor::new();
        r.register("short", b"abc");
        r.register("long", b"abcdef");
        // The longer secret is redacted first, so no "def" fragment is left over.
        let out = r.redact("value=abcdef end");
        assert!(!out.contains("abcdef"));
        assert!(!out.contains("abc "), "left a fragment: {out}");
        assert!(out.contains("[REDACTED:long]"));
    }

    #[test]
    fn empty_secret_is_not_registered() {
        let mut r = Redactor::new();
        r.register("empty", b"");
        // A zero-length needle must not redact everything.
        assert_eq!(r.redact("hello world"), "hello world");
        assert!(!r.would_leak("anything"));
    }

    #[test]
    fn model_visible_text_only_comes_from_the_redactor() {
        // The sole constructor is Redactor::to_model_visible (asserted by the
        // absence of any public ModelVisibleText constructor / From<SecretMaterial>;
        // see the compile-fail doctest on SecretMaterial).
        let r = Redactor::new();
        let mvt = r.to_model_visible("plain text");
        assert_eq!(mvt.as_str(), "plain text");
    }

    #[test]
    fn tainted_only_declassifies_through_the_redactor() {
        let broker = broker_with_token();
        let t = Tainted::new("log line with sk-SENTINELxyz inside".to_string());
        // raw() is for trusted in-process use; declassify is the only boundary path.
        assert!(t.raw().contains("SENTINEL"));
        let safe = t.declassify(broker.redactor());
        assert!(!safe.as_str().contains("SENTINEL"));
    }
}
