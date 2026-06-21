// SPDX-License-Identifier: Apache-2.0
//! `serde` bridges for the external `crustcore-types` newtypes.
//!
//! `crustcore-types` is std-only and nano-linked, so it deliberately carries no
//! `serde` dependency (invariants 19, 20). This sidecar crate persists snapshots
//! to disk, so it serializes those ids **here**, by their inner representation,
//! via `#[serde(with = ...)]` modules — keeping `serde` entirely inside the
//! sidecar and out of the nano graph.

use crustcore_types::{ArtifactId, EventSeq, TaskId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `TaskId` <-> its inner `u128`.
pub mod task_id {
    use super::*;

    /// Serializes a [`TaskId`] as its inner `u128`.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(id: &TaskId, s: S) -> Result<S::Ok, S::Error> {
        id.0.serialize(s)
    }

    /// Deserializes a [`TaskId`] from a `u128`.
    ///
    /// # Errors
    /// Propagates the deserializer's error.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<TaskId, D::Error> {
        Ok(TaskId(u128::deserialize(d)?))
    }
}

/// `EventSeq` <-> its inner `u64`.
pub mod event_seq {
    use super::*;

    /// Serializes an [`EventSeq`] as its inner `u64`.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(seq: &EventSeq, s: S) -> Result<S::Ok, S::Error> {
        seq.0.serialize(s)
    }

    /// Deserializes an [`EventSeq`] from a `u64`.
    ///
    /// # Errors
    /// Propagates the deserializer's error.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EventSeq, D::Error> {
        Ok(EventSeq(u64::deserialize(d)?))
    }
}

/// `ArtifactId` <-> its inner `[u8; 32]`.
pub mod artifact_id {
    use super::*;

    /// Serializes an [`ArtifactId`] as its inner `[u8; 32]`.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(id: &ArtifactId, s: S) -> Result<S::Ok, S::Error> {
        id.0.serialize(s)
    }

    /// Deserializes an [`ArtifactId`] from a `[u8; 32]`.
    ///
    /// # Errors
    /// Propagates the deserializer's error.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ArtifactId, D::Error> {
        Ok(ArtifactId(<[u8; 32]>::deserialize(d)?))
    }
}
