// SPDX-License-Identifier: Apache-2.0
//! Opaque session / conversation identity newtypes (C4.1).
//!
//! A session is addressed by a [`SessionId`] scoped to a kernel
//! [`TaskId`](crustcore_types::TaskId): a session is "a run" of one task, indexed
//! over that task's frames in the event log. A [`ConversationId`] addresses the
//! user/model/tool turn stream of a session. Both are plain, copyable handles —
//! they carry no chain state and grant nothing; they are safe to log and
//! serialize.

use crustcore_types::TaskId;
use serde::{Deserialize, Serialize};

/// Opaque identifier for an application-level session — "a run" of one task.
///
/// It wraps the kernel [`TaskId`] the session indexes over: the event log is the
/// source of truth, and a session is a view over the frames bound to this task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionId(#[serde(with = "crate::serde_compat::task_id")] pub TaskId);

impl SessionId {
    /// Builds a session id over a kernel task.
    #[must_use]
    pub fn new(task_id: TaskId) -> Self {
        SessionId(task_id)
    }

    /// The kernel task this session indexes over.
    #[must_use]
    pub fn task_id(self) -> TaskId {
        self.0
    }
}

impl From<TaskId> for SessionId {
    fn from(task_id: TaskId) -> Self {
        SessionId(task_id)
    }
}

/// Opaque identifier for the user/model/tool turn stream of a session.
///
/// Distinct from [`SessionId`] so a single run can, in principle, host more than
/// one logical conversation; today it mirrors the session's task. It carries no
/// chain state and grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConversationId(pub u128);

impl ConversationId {
    /// Builds a conversation id from a raw value.
    #[must_use]
    pub fn new(raw: u128) -> Self {
        ConversationId(raw)
    }

    /// The conversation id that mirrors a session (its task id value).
    #[must_use]
    pub fn for_session(session: SessionId) -> Self {
        ConversationId(session.task_id().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_wraps_task_id() {
        let s = SessionId::new(TaskId(42));
        assert_eq!(s.task_id(), TaskId(42));
        assert_eq!(SessionId::from(TaskId(42)), s);
    }

    #[test]
    fn conversation_id_mirrors_session() {
        let s = SessionId::new(TaskId(7));
        assert_eq!(ConversationId::for_session(s), ConversationId(7));
    }

    #[test]
    fn ids_round_trip_through_serde() {
        let s = SessionId::new(TaskId(123));
        let json = serde_json::to_string(&s).unwrap();
        let back: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);

        let c = ConversationId::new(9);
        let json = serde_json::to_string(&c).unwrap();
        let back: ConversationId = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
