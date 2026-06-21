// SPDX-License-Identifier: Apache-2.0
//! Opaque artifact handles (C4.5; invariant 20).
//!
//! Sessions reference diffs, logs, and transcripts **by content hash only**. An
//! [`ArtifactHandle`] wraps a kernel [`ArtifactId`] and is the only thing a view,
//! snapshot, or conversation projection ever carries for an artifact — its
//! contents are **never inlined**. Resolution to bytes is by-hash against a
//! content-addressed store via the [`ArtifactResolver`] trait, behind a
//! `BoundedArtifact` accessor that returns bytes only to trusted, non-model code
//! and never to a model-visible projection.

use crustcore_types::ArtifactId;
use serde::{Deserialize, Serialize};

/// The maximum number of bytes the bounded accessor will ever hand back for one
/// artifact. Contents are for trusted in-process use only; this cap keeps an
/// accidental large read bounded (invariant 11).
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

/// An opaque, by-hash reference to an artifact. Carries the content address only —
/// never the bytes. Safe to embed in a snapshot, a view, or a conversation
/// projection because it inlines nothing (invariant 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtifactHandle(#[serde(with = "crate::serde_compat::artifact_id")] pub ArtifactId);

impl ArtifactHandle {
    /// Wraps a content address.
    #[must_use]
    pub fn new(id: ArtifactId) -> Self {
        ArtifactHandle(id)
    }

    /// The underlying content address.
    #[must_use]
    pub fn id(self) -> ArtifactId {
        self.0
    }

    /// The content hash as bytes (non-secret metadata).
    #[must_use]
    pub fn hash(self) -> [u8; 32] {
        self.0 .0
    }

    /// The content hash as lowercase hex — a stable, model-safe label that still
    /// inlines no content.
    #[must_use]
    pub fn hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 .0 {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

/// Resolves an [`ArtifactHandle`] to its content-addressed bytes. Implemented by
/// the daemon's artifact store. The session layer only ever *references* artifacts
/// by handle; resolution is an explicit, trusted, out-of-band step.
pub trait ArtifactResolver {
    /// The raw bytes for `handle`, if present in the store. Trusted callers only —
    /// these bytes must never enter a model-visible projection (invariant 20).
    fn resolve(&self, handle: ArtifactHandle) -> Option<Vec<u8>>;
}

/// A bounded, by-hash accessor over an [`ArtifactResolver`]. Hands artifact bytes
/// to trusted code only, capped at [`MAX_ARTIFACT_BYTES`], and exposes **no** path
/// that returns contents into a snapshot/view/conversation projection.
pub struct BoundedArtifact<'r, R: ArtifactResolver> {
    resolver: &'r R,
}

impl<'r, R: ArtifactResolver> BoundedArtifact<'r, R> {
    /// Wraps a resolver.
    #[must_use]
    pub fn new(resolver: &'r R) -> Self {
        BoundedArtifact { resolver }
    }

    /// Whether the artifact exists in the store (model-safe presence check; no
    /// content is read).
    #[must_use]
    pub fn exists(&self, handle: ArtifactHandle) -> bool {
        self.resolver.resolve(handle).is_some()
    }

    /// Reads at most [`MAX_ARTIFACT_BYTES`] of the artifact for **trusted,
    /// non-model** use. Returns `None` if the artifact is absent. The result is
    /// raw bytes for an in-process consumer — by contract it is never threaded into
    /// a model-visible projection.
    #[must_use]
    pub fn read_bounded(&self, handle: ArtifactHandle) -> Option<Vec<u8>> {
        let mut bytes = self.resolver.resolve(handle)?;
        bytes.truncate(MAX_ARTIFACT_BYTES);
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MapStore(BTreeMap<[u8; 32], Vec<u8>>);

    impl ArtifactResolver for MapStore {
        fn resolve(&self, handle: ArtifactHandle) -> Option<Vec<u8>> {
            self.0.get(&handle.hash()).cloned()
        }
    }

    fn handle(byte: u8) -> ArtifactHandle {
        ArtifactHandle::new(ArtifactId([byte; 32]))
    }

    #[test]
    fn handle_is_opaque_and_hex_safe() {
        let h = handle(0xab);
        assert_eq!(h.hash(), [0xab; 32]);
        assert_eq!(h.hex().len(), 64);
        assert!(h.hex().starts_with("abab"));
    }

    #[test]
    fn handle_round_trips_through_serde() {
        let h = handle(0x01);
        let json = serde_json::to_string(&h).unwrap();
        let back: ArtifactHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn bounded_accessor_caps_content_length() {
        let mut store = BTreeMap::new();
        store.insert([0x01; 32], vec![7u8; MAX_ARTIFACT_BYTES * 2]);
        let store = MapStore(store);
        let acc = BoundedArtifact::new(&store);

        assert!(acc.exists(handle(0x01)));
        let bytes = acc.read_bounded(handle(0x01)).unwrap();
        assert_eq!(bytes.len(), MAX_ARTIFACT_BYTES, "read was not bounded");
        // A missing artifact resolves to nothing.
        assert!(acc.read_bounded(handle(0x02)).is_none());
        assert!(!acc.exists(handle(0x02)));
    }
}
