// SPDX-License-Identifier: Apache-2.0
//! Approvals view (`C7.6`, read side). Surfaces *pending* approvals — the typed view the
//! UI shows **before** a resolution.
//!
//! This module is strictly read-only: it renders the [`ApprovalView`]s the backend holds
//! (each already redacted + bounded, each carrying its operation binding: approval id +
//! op-hash). The UI shows the operation summary and its op-hash so the user resolves the
//! exact operation displayed. The *resolution* is a separate, gated, mutating path
//! ([`crate::mutation`]) that the UI never short-circuits — this view mints nothing.

use crate::backend::{ApprovalView, ReadOnlyBackend};

/// Render the pending-approval list from a read-only backend. Pure read.
#[must_use]
pub fn render(backend: &dyn ReadOnlyBackend) -> Vec<ApprovalView> {
    backend.pending_approvals()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DevBackend, MockDevBackend};
    use crustcore_types::Timestamp;

    #[test]
    fn surfaces_pending_with_op_binding() {
        let mut mock = MockDevBackend::new();
        let op_hash = mock.request_approval(
            1,
            "merge PR #42",
            "Merge PR #42",
            Timestamp::from_millis(10_000),
        );
        let views = render(mock.read_only());
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].approval_id, 1);
        // The surfaced op-hash binds the resolution to THIS operation.
        assert_eq!(views[0].op_hash_hex, op_hash);
        assert_eq!(views[0].summary, "Merge PR #42");
        assert_eq!(views[0].expires_at_millis, 10_000);
    }

    #[test]
    fn empty_when_nothing_pending() {
        let mock = MockDevBackend::new();
        assert!(render(mock.read_only()).is_empty());
    }
}
