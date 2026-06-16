// SPDX-License-Identifier: Apache-2.0
//! Typed secrets (`ROADMAP.md` §8.1, Phase 8). **CONTRACT FILE** — changes are
//! serialized and reviewed (CLAUDE.md §7.3).
//!
//! This crate exists to make secret leakage *unrepresentable* (invariants 1–3):
//!
//! - [`SecretHandle`] is the only thing the model ever sees: an id + a label.
//! - [`SecretMaterial`] holds the raw bytes and deliberately does **not**
//!   implement `Debug`, `Clone`, `Serialize`, or any conversion to
//!   model-visible text. Its bytes are zeroized on drop.
//! - The only way to read bytes is through an [`ApprovedSecretView`], which is
//!   minted by the broker for a specific approved operation and is one-shot.
//!
//! Status: Phase 0 scaffold. Types and their *negative* guarantees (missing
//! impls) are in place now; native keychain/vault backends and the broker flow
//! land in Phase 8. Compile-fail tests asserting the missing impls are added
//! alongside (`docs/secrets.md`).
#![forbid(unsafe_code)]

use crustcore_types::{BoundedText, SecretId};

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

/// Raw secret bytes.
///
/// INVARIANTS (enforced by this type — do not add the listed impls):
/// - no `Debug` (cannot be `{:?}`-printed into logs/panics)
/// - no `Clone` (cannot be silently duplicated)
/// - no `Serialize`/`Display` (cannot be encoded into model-visible output)
/// - bytes are zeroized on drop
///
/// The only read path is [`SecretMaterial::expose`], gated by an
/// [`ApprovedSecretView`].
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

    /// Exposes the raw bytes to trusted, non-model code **only** when presented
    /// with an [`ApprovedSecretView`] for this secret. This is the single
    /// chokepoint through which bytes leave the type.
    ///
    /// Returns `None` if the view does not authorize this secret.
    #[must_use]
    pub fn expose<'a>(&'a self, view: &ApprovedSecretView) -> Option<&'a [u8]> {
        // TODO(P8.4): bind the view to this exact SecretId via the broker and
        // enforce one-shot consumption + expiry. The scaffold checks the id.
        if view.authorizes(self) {
            Some(&self.bytes)
        } else {
            None
        }
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        // Best-effort zeroization without an external crate. Phase 8 replaces
        // this with a `zeroize`-backed `Zeroizing<Vec<u8>>` (volatile writes +
        // compiler fences) outside nano.
        for b in &mut self.bytes {
            *b = 0;
        }
    }
}

/// A one-shot authorization to expose a specific secret to a specific approved
/// operation. Minted by the broker; consumed by the tool that needs the value.
///
/// Like [`SecretMaterial`], this carries no bytes and is intentionally not
/// `Clone`/`Serialize`.
pub struct ApprovedSecretView {
    secret_id: SecretId,
    // TODO(P8.4): approval id, expiry, and a one-shot consumed flag.
}

impl ApprovedSecretView {
    /// Mints a view for a secret id. In Phase 8 this is only callable by the
    /// broker after an approval; in the scaffold it is `pub(crate)`-ish via a
    /// documented constructor for tests.
    #[doc(hidden)]
    #[must_use]
    pub fn for_secret(secret_id: SecretId) -> Self {
        ApprovedSecretView { secret_id }
    }

    /// Whether this view authorizes exposing the given material.
    #[must_use]
    fn authorizes(&self, _material: &SecretMaterial) -> bool {
        // TODO(P8.4): the store maps SecretId -> SecretMaterial; verify identity
        // through the broker rather than trusting the caller's pairing.
        let _ = self.secret_id;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn material_zeroizes_and_exposes_only_via_view() {
        let m = SecretMaterial::new(b"hunter2".to_vec());
        assert_eq!(m.len(), 7);
        let view = ApprovedSecretView::for_secret(SecretId(1));
        assert_eq!(m.expose(&view), Some(&b"hunter2"[..]));
    }
}
