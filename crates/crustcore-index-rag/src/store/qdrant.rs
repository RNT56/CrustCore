// SPDX-License-Identifier: Apache-2.0
//! Qdrant vector-store backend (C5.3) — behind the off-by-default `qdrant` feature.
//!
//! A thin [`VectorStore`](super::VectorStore) adapter over the **Qdrant REST API**
//! (<https://qdrant.tech/documentation/concepts/>), built on the shared blocking
//! [`ureq`] client in [`super::http`]. The request-building and response-parsing are
//! **implemented and unit-tested without a network**; only the live socket round-trip is
//! `TODO(C5-qdrant-live)` (it needs a running Qdrant, so the round-trip test is
//! `#[ignore]`d).
//!
//! ## API surface targeted
//!
//! - `upsert`  → `PUT  /collections/<c>/points` with `{ "points": [ { id, vector,
//!   payload } ] }` (Qdrant's points-upsert body).
//! - `nearest` → `POST /collections/<c>/points/search` with `{ "vector": [...],
//!   "limit": k, "score_threshold": floor, "with_payload": false }`; the response
//!   `{ "result": [ { "id", "score" }, ... ] }` is parsed into [`StoreHit`]s.
//! - `delete`  → `POST /collections/<c>/points/delete` with `{ "points": [ id ] }`.
//!
//! (REST endpoints are stable across Qdrant 1.x; the bodies above match the documented
//! shapes. The newer query API `POST /collections/<c>/points/query` is a superset; this
//! adapter targets the classic `/points/search` for the widest compatibility.)
//!
//! ## Trust posture (unchanged from the inert stub)
//!
//! Retrieval only — grants nothing. The store's **scores are not trusted**:
//! [`crate::plan::QueryPlanner`] re-ranks every hit by cosine to the query embedding and
//! redact-then-bounds it, so a NaN/forged Qdrant score cannot reorder or smuggle a
//! fragment. The parsed hits are additionally bounded ([`super::MAX_STORE_HITS`]) and
//! score-sanitized here as defense in depth.
//!
//! ## Credential flow (invariants 1, 3; `docs/secrets.md` §6)
//!
//! Any Qdrant API key resolves ONLY through [`crustcore_secrets::CredentialProxy`] /
//! [`crustcore_secrets::SecretBroker`] at send time, injected as Qdrant's native
//! `api-key: <token>` header via [`super::http::apply_auth`]. The key is read once from a
//! one-shot [`crustcore_secrets::ApprovedSecretView`] straight onto the outbound request —
//! never from the sandbox env, never placed in a span/log, never model-visible. The
//! adapter holds only a [`crustcore_secrets::SecretHandle`] (id + label), not the bytes.

use super::http::{
    self, bound_hits, sanitize_score, BrokerAuth, EndpointAuth, StoreHit, StoreSendError,
};
use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// Configuration for the Qdrant backend. Holds only non-secret connection metadata + the
/// auth *descriptor* (a handle, never the key bytes); the API key is resolved via the
/// broker/`CredentialProxy` at request time.
#[derive(Debug, Clone)]
pub struct QdrantConfig {
    /// Collection (namespace) name.
    pub collection: String,
    /// Loopback/remote endpoint, e.g. `http://127.0.0.1:6333` (non-secret).
    pub endpoint: String,
    /// How to authenticate to the endpoint. Defaults to [`EndpointAuth::None`] (a loopback
    /// dev Qdrant needs no key); Qdrant Cloud uses `EndpointAuth::header("api-key", h)`.
    pub auth: EndpointAuth,
}

impl QdrantConfig {
    /// A config for `collection` at `endpoint` with no auth (loopback default).
    #[must_use]
    pub fn new(collection: impl Into<String>, endpoint: impl Into<String>) -> Self {
        QdrantConfig {
            collection: collection.into(),
            endpoint: endpoint.into(),
            auth: EndpointAuth::None,
        }
    }

    /// Sets the broker-mediated auth descriptor (builder style).
    #[must_use]
    pub fn with_auth(mut self, auth: EndpointAuth) -> Self {
        self.auth = auth;
        self
    }
}

/// A thin Qdrant REST adapter. The request-building/response-parsing is implemented;
/// `TODO(C5-qdrant-live)`: only the live socket round-trip remains (it needs a running
/// Qdrant). The [`VectorStore`] trait methods are inert (they carry no broker/approval to
/// authenticate with); the broker-taking [`Self::upsert_with_broker`] /
/// [`Self::nearest_with_broker`] / [`Self::delete_with_broker`] perform the real work.
#[derive(Debug)]
pub struct QdrantVectorStore {
    config: QdrantConfig,
    namespace: String,
}

impl QdrantVectorStore {
    /// Builds an adapter from non-secret config. No network or credential access happens
    /// here; the live transport is `TODO(C5-qdrant-live)`.
    #[must_use]
    pub fn new(config: QdrantConfig) -> Self {
        let namespace = config.collection.clone();
        QdrantVectorStore { config, namespace }
    }

    /// The collection currently scoped to (the active namespace, falling back to the
    /// configured collection).
    #[must_use]
    fn collection(&self) -> &str {
        if self.namespace.is_empty() {
            &self.config.collection
        } else {
            &self.namespace
        }
    }

    /// `<endpoint>/collections/<collection>/points` (upsert URL). Non-secret.
    #[must_use]
    pub fn upsert_url(&self) -> String {
        format!(
            "{}/collections/{}/points",
            self.config.endpoint.trim_end_matches('/'),
            self.collection()
        )
    }

    /// `<endpoint>/collections/<collection>/points/search` (search URL). Non-secret.
    #[must_use]
    pub fn search_url(&self) -> String {
        format!(
            "{}/collections/{}/points/search",
            self.config.endpoint.trim_end_matches('/'),
            self.collection()
        )
    }

    /// `<endpoint>/collections/<collection>/points/delete` (delete URL). Non-secret.
    #[must_use]
    pub fn delete_url(&self) -> String {
        format!(
            "{}/collections/{}/points/delete",
            self.config.endpoint.trim_end_matches('/'),
            self.collection()
        )
    }
}

// ---------------------------------------------------------------------------
// Pure request-building + response-parsing (network-free, CI-tested)
// ---------------------------------------------------------------------------

/// Builds the Qdrant points-upsert body: `{ "points": [ { "id", "vector", "payload" } ] }`.
///
/// The chunk id is sent as a string point id (Qdrant accepts string ids), and the
/// [`ChunkMeta`] is flattened into a non-secret `payload` (provenance only — path, span,
/// symbol, source, redact flag). The payload is *not* trusted on read-back: the planner
/// resolves content + embedding from its own resolver and re-ranks, so a tampered payload
/// cannot smuggle authority.
#[must_use]
pub fn build_upsert_body(items: &[(ChunkId, Vec<f32>, ChunkMeta)]) -> serde_json::Value {
    use serde_json::json;
    let points: Vec<serde_json::Value> = items
        .iter()
        .map(|(id, vector, meta)| {
            json!({
                "id": id.as_str(),
                "vector": vector,
                "payload": {
                    "path": meta.path,
                    "byte_start": meta.byte_span.start,
                    "byte_end": meta.byte_span.end,
                    "symbol": meta.symbol,
                    "source": source_str(meta.source),
                    "redact_required": meta.redact_required,
                },
            })
        })
        .collect();
    json!({ "points": points })
}

/// Builds the Qdrant search body: the query vector, the (already-capped) `limit`, the
/// `score_threshold` floor, and `with_payload: false` (we don't trust or need the payload
/// on read — the planner resolves + re-ranks). Bounded by construction.
#[must_use]
pub fn build_search_body(query: &[f32], k: usize, floor: f32) -> serde_json::Value {
    use serde_json::json;
    let mut body = json!({
        "vector": query,
        "limit": k,
        "with_payload": false,
    });
    // Only send a finite, positive floor (Qdrant rejects NaN; a 0 floor is the default
    // and need not be sent).
    if floor.is_finite() && floor > 0.0 {
        body["score_threshold"] = json!(floor);
    }
    body
}

/// Builds the Qdrant points-delete body: `{ "points": [ "<id>" ] }`.
#[must_use]
pub fn build_delete_body(id: &ChunkId) -> serde_json::Value {
    use serde_json::json;
    json!({ "points": [ id.as_str() ] })
}

/// Parses a Qdrant search response `{ "result": [ { "id", "score" }, ... ] }` into bounded,
/// score-sanitized [`StoreHit`]s.
///
/// Robust to a hostile/buggy store: a missing `result`, non-array, or malformed entry
/// yields no hit rather than an error; ids are coerced to strings (Qdrant point ids may be
/// integers or UUIDs); scores are sanitized to finite-or-`0.0`; the list is capped to
/// [`super::MAX_STORE_HITS`]. Scores are **not trusted** — the planner re-ranks — so this
/// only needs to be safe, not authoritative.
#[must_use]
pub fn parse_search_response(body: &serde_json::Value) -> Vec<StoreHit> {
    let Some(arr) = body.get("result").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    let hits: Vec<StoreHit> = arr
        .iter()
        .filter_map(|item| {
            let id = coerce_id(item.get("id")?)?;
            let score = item
                .get("score")
                .and_then(serde_json::Value::as_f64)
                .map(|s| sanitize_score(s as f32))
                .unwrap_or(0.0);
            Some(StoreHit {
                id: ChunkId::new(id),
                score,
            })
        })
        .collect();
    bound_hits(hits)
}

/// Coerces a Qdrant point id (string, integer, or UUID-as-string) to a `String`. Returns
/// `None` for an id shape we can't represent (a forged/odd id simply yields no hit).
fn coerce_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Stable, non-secret string tag for a chunk's provenance (for the Qdrant payload only).
fn source_str(source: crustcore_index::MemorySource) -> &'static str {
    match source {
        crustcore_index::MemorySource::RepoFile => "repo_file",
        crustcore_index::MemorySource::ToolObservation => "tool_observation",
        crustcore_index::MemorySource::PriorRun => "prior_run",
        crustcore_index::MemorySource::UserNote => "user_note",
    }
}

// ---------------------------------------------------------------------------
// Broker-mediated live transport (TODO(C5-qdrant-live): only the live socket)
// ---------------------------------------------------------------------------

impl QdrantVectorStore {
    /// Upserts `items` to the collection via `PUT /points`, authenticating per request
    /// through the broker. `TODO(C5-qdrant-live)`: opens a real socket, so it is only
    /// smoke-tested against a running Qdrant; the body shape is unit-tested via
    /// [`build_upsert_body`].
    ///
    /// # Errors
    /// [`StoreSendError`] on a serialization, auth, transport, or non-2xx-status failure.
    /// No secret bytes are ever included in the error.
    pub fn upsert_with_broker<S: crustcore_secrets::SecretStore>(
        &self,
        items: &[(ChunkId, Vec<f32>, ChunkMeta)],
        ctx: &BrokerAuth<'_, S>,
    ) -> Result<u16, StoreSendError> {
        let body = build_upsert_body(items);
        let payload = serde_json::to_vec(&body).map_err(|_| StoreSendError::Serialize)?;
        let req = http::agent()
            .put(&self.upsert_url())
            .set("Content-Type", "application/json");
        let req = http::apply_auth(req, &self.config.auth, ctx)?;
        send_expecting_ok(req, &payload).map(|(status, _body)| status)
    }

    /// Queries the collection via `POST /points/search` and returns bounded,
    /// score-sanitized [`StoreHit`]s (id + advisory score). `TODO(C5-qdrant-live)`: opens a
    /// real socket; the request/response shaping is unit-tested via [`build_search_body`] /
    /// [`parse_search_response`].
    ///
    /// The returned scores are **not** authoritative — the planner re-ranks by cosine — so
    /// the caller in `plan.rs` maps these ids to its own resolved content.
    ///
    /// # Errors
    /// [`StoreSendError`] on a serialization, auth, transport, non-2xx-status, or
    /// malformed-response failure.
    pub fn nearest_with_broker<S: crustcore_secrets::SecretStore>(
        &self,
        query: &[f32],
        k: usize,
        floor: f32,
        ctx: &BrokerAuth<'_, S>,
    ) -> Result<Vec<StoreHit>, StoreSendError> {
        let body = build_search_body(query, k, floor);
        let payload = serde_json::to_vec(&body).map_err(|_| StoreSendError::Serialize)?;
        let req = http::agent()
            .post(&self.search_url())
            .set("Content-Type", "application/json");
        let req = http::apply_auth(req, &self.config.auth, ctx)?;
        let (_status, resp_body) = send_expecting_ok(req, &payload)?;
        let json: serde_json::Value =
            serde_json::from_str(&resp_body).map_err(|_| StoreSendError::BadResponse)?;
        Ok(parse_search_response(&json))
    }

    /// Deletes a point by id via `POST /points/delete`. `TODO(C5-qdrant-live)`: live socket
    /// only; the body shape is unit-tested via [`build_delete_body`].
    ///
    /// # Errors
    /// [`StoreSendError`] on a serialization, auth, transport, or non-2xx-status failure.
    pub fn delete_with_broker<S: crustcore_secrets::SecretStore>(
        &self,
        id: &ChunkId,
        ctx: &BrokerAuth<'_, S>,
    ) -> Result<u16, StoreSendError> {
        let body = build_delete_body(id);
        let payload = serde_json::to_vec(&body).map_err(|_| StoreSendError::Serialize)?;
        let req = http::agent()
            .post(&self.delete_url())
            .set("Content-Type", "application/json");
        let req = http::apply_auth(req, &self.config.auth, ctx)?;
        send_expecting_ok(req, &payload).map(|(status, _body)| status)
    }
}

/// Sends `payload` on `req`, returning `(status, body)` on a 2xx and mapping a non-2xx to
/// [`StoreSendError::Status`] and a transport failure to [`StoreSendError::Transport`]. The
/// error never carries the request body or the auth header.
fn send_expecting_ok(req: ureq::Request, payload: &[u8]) -> Result<(u16, String), StoreSendError> {
    match req.send_bytes(payload) {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.into_string().unwrap_or_default();
            Ok((status, body))
        }
        Err(ureq::Error::Status(status, _resp)) => Err(StoreSendError::Status(status)),
        Err(ureq::Error::Transport(t)) => Err(StoreSendError::Transport(t.to_string())),
    }
}

// ---------------------------------------------------------------------------
// VectorStore trait: namespacing is real; the I/O methods are inert without a
// broker (fail-closed, mirroring the OTLP exporter's no-broker flush path). The
// real I/O is the *_with_broker methods above.
// ---------------------------------------------------------------------------

impl VectorStore for QdrantVectorStore {
    fn upsert(&mut self, _items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        // The trait method carries no broker/approval, so it cannot authenticate a write.
        // Fail-closed: a real upsert goes through `upsert_with_broker`. (TODO(C5-qdrant-live)
        // wires a broker-carrying store wrapper into the indexer's write path.)
    }

    fn nearest(&self, _query: &[f32], _k: usize, _floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        // The trait method carries no broker/approval, so it cannot authenticate a query.
        // Fail-closed: a real query goes through `nearest_with_broker` (and the planner
        // re-ranks the returned ids). Empty here (TODO(C5-qdrant-live)).
        Vec::new()
    }

    fn delete(&mut self, _id: &ChunkId) {
        // See `upsert`: real deletes go through `delete_with_broker`.
    }

    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }

    fn namespace(&self) -> &str {
        if self.namespace.is_empty() {
            DEFAULT_NAMESPACE
        } else {
            &self.namespace
        }
    }

    fn len(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ByteSpan;
    use crustcore_index::MemorySource;

    fn meta(path: &str) -> ChunkMeta {
        ChunkMeta::new(path, ByteSpan::new(3, 17), MemorySource::RepoFile).with_symbol("fn_x")
    }

    fn store() -> QdrantVectorStore {
        QdrantVectorStore::new(QdrantConfig::new("chunks", "http://127.0.0.1:6333"))
    }

    /// Asserts a JSON array equals an f32 vector, element-wise with f32 tolerance (f32
    /// values widen to f64 in JSON, so exact equality is the wrong comparison).
    fn assert_vec_close(v: &serde_json::Value, expected: &[f32]) {
        let arr = v.as_array().expect("vector is an array");
        assert_eq!(arr.len(), expected.len(), "vector length");
        for (got, want) in arr.iter().zip(expected) {
            let g = got.as_f64().expect("numeric element") as f32;
            assert!((g - want).abs() < 1e-6, "element {g} != {want}");
        }
    }

    #[test]
    fn urls_are_well_formed_and_collection_scoped() {
        let mut s = store();
        assert_eq!(
            s.upsert_url(),
            "http://127.0.0.1:6333/collections/chunks/points"
        );
        assert_eq!(
            s.search_url(),
            "http://127.0.0.1:6333/collections/chunks/points/search"
        );
        assert_eq!(
            s.delete_url(),
            "http://127.0.0.1:6333/collections/chunks/points/delete"
        );
        // set_namespace re-scopes the collection in the URL.
        s.set_namespace("other");
        assert_eq!(
            s.search_url(),
            "http://127.0.0.1:6333/collections/other/points/search"
        );
        // A trailing slash on the endpoint is collapsed.
        let s2 = QdrantVectorStore::new(QdrantConfig::new("c", "http://h:6333/"));
        assert_eq!(s2.upsert_url(), "http://h:6333/collections/c/points");
    }

    #[test]
    fn upsert_body_has_points_with_id_vector_payload() {
        let items = vec![
            (ChunkId::new("a"), vec![0.1, 0.2, 0.3], meta("a.rs")),
            (ChunkId::new("b"), vec![0.4, 0.5], meta("b.rs")),
        ];
        let body = build_upsert_body(&items);
        let points = body["points"].as_array().expect("points array");
        assert_eq!(points.len(), 2);
        assert_eq!(points[0]["id"], "a");
        // The embedding is sent as the f32 vector verbatim (compared with tolerance, since
        // f32 widens to f64 in JSON).
        assert_vec_close(&points[0]["vector"], &[0.1, 0.2, 0.3]);
        // Payload is non-secret provenance.
        assert_eq!(points[0]["payload"]["path"], "a.rs");
        assert_eq!(points[0]["payload"]["byte_start"], 3);
        assert_eq!(points[0]["payload"]["byte_end"], 17);
        assert_eq!(points[0]["payload"]["symbol"], "fn_x");
        assert_eq!(points[0]["payload"]["source"], "repo_file");
        assert_eq!(points[0]["payload"]["redact_required"], true);
    }

    #[test]
    fn search_body_carries_vector_limit_and_floor() {
        let body = build_search_body(&[1.0, 0.0, -1.0], 8, 0.25);
        assert_eq!(body["vector"], serde_json::json!([1.0, 0.0, -1.0]));
        assert_eq!(body["limit"], 8);
        assert_eq!(body["with_payload"], false);
        assert_eq!(body["score_threshold"], 0.25);
    }

    #[test]
    fn search_body_omits_floor_when_zero_or_nonfinite() {
        let zero = build_search_body(&[1.0], 4, 0.0);
        assert!(zero.get("score_threshold").is_none());
        let nan = build_search_body(&[1.0], 4, f32::NAN);
        assert!(nan.get("score_threshold").is_none());
    }

    #[test]
    fn delete_body_lists_the_point_id() {
        let body = build_delete_body(&ChunkId::new("z"));
        assert_eq!(body["points"], serde_json::json!(["z"]));
    }

    #[test]
    fn parse_search_response_maps_id_and_score() {
        let resp = serde_json::json!({
            "result": [
                { "id": "a", "score": 0.9 },
                { "id": 42, "score": 0.5 },
                { "id": "c", "score": 0.1 }
            ]
        });
        let hits = parse_search_response(&resp);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].id, ChunkId::new("a"));
        assert!((hits[0].score - 0.9).abs() < 1e-6);
        // Integer point id coerced to its string form.
        assert_eq!(hits[1].id, ChunkId::new("42"));
    }

    #[test]
    fn parse_search_response_sanitizes_and_survives_garbage() {
        // A hostile response: NaN score, missing score, malformed entry, missing result.
        let resp = serde_json::json!({
            "result": [
                { "id": "nan", "score": f64::NAN },
                { "id": "noscore" },
                { "score": 0.7 },
                { "id": { "nested": true }, "score": 0.7 },
                "not-an-object"
            ]
        });
        let hits = parse_search_response(&resp);
        // Only the two entries with a usable id survive; their scores are finite.
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.score.is_finite()));
        // A NaN score is sanitized to 0.0 (not trusted anyway — the planner re-ranks).
        let nan_hit = hits.iter().find(|h| h.id == ChunkId::new("nan")).unwrap();
        assert_eq!(nan_hit.score, 0.0);
        // No `result` key => no hits (no panic).
        assert!(parse_search_response(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn trait_methods_are_inert_without_a_broker() {
        // Fail-closed: the broker-less trait methods perform no I/O and return empty.
        let mut s = store();
        s.upsert(vec![(ChunkId::new("a"), vec![1.0], meta("a.rs"))]);
        assert!(s.nearest(&[1.0], 5, 0.0).is_empty());
        s.delete(&ChunkId::new("a"));
        assert_eq!(s.len(), 0);
        assert_eq!(s.namespace(), "chunks");
    }

    /// The live socket round-trip: needs a running Qdrant on the endpoint, so it is
    /// `#[ignore]`d in CI. `TODO(C5-qdrant-live)`: run against a real Qdrant. Proves the
    /// broker-mediated auth + REST shape compiles and round-trips end-to-end.
    #[test]
    #[ignore = "needs a running Qdrant on 127.0.0.1:6333 (TODO(C5-qdrant-live))"]
    fn live_upsert_search_delete_roundtrip() {
        use crustcore_secrets::{InMemoryStore, SecretBroker};
        use crustcore_types::{ApprovalId, Timestamp};

        // Loopback dev Qdrant: no auth. (Cloud would set
        // QdrantConfig::with_auth(EndpointAuth::header("api-key", handle)).)
        let s = store();
        let broker = SecretBroker::new(InMemoryStore::new());
        let now = Timestamp::from_millis(0);
        let ctx = super::BrokerAuth::new(&broker, ApprovalId(1), now, 5_000);
        let items = vec![(ChunkId::new("a"), vec![0.1, 0.2, 0.3], meta("a.rs"))];
        s.upsert_with_broker(&items, &ctx).expect("upsert");
        let hits = s
            .nearest_with_broker(&[0.1, 0.2, 0.3], 5, 0.0, &ctx)
            .expect("search");
        assert!(hits.iter().any(|h| h.id == ChunkId::new("a")));
        s.delete_with_broker(&ChunkId::new("a"), &ctx)
            .expect("delete");
    }
}
