// SPDX-License-Identifier: Apache-2.0
//! Timestamps. A monotonic-ish wall-clock millisecond stamp used in events,
//! receipts, and approvals. Kept as a plain newtype so the kernel stays free of
//! a time/chrono dependency.

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// The zero timestamp (epoch). Useful as a default/sentinel.
    pub const EPOCH: Timestamp = Timestamp(0);

    /// Constructs a timestamp from milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Timestamp(ms)
    }

    /// Returns milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}
