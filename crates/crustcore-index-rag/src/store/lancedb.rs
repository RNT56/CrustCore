// SPDX-License-Identifier: Apache-2.0
//! LanceDB vector-store backend (C5.3) — behind the off-by-default `lancedb` feature.
//!
//! A thin [`VectorStore`](super::VectorStore) adapter over LanceDB's **HTTP (remote /
//! Cloud) API**, built on the shared blocking [`ureq`] client in [`super::http`]. The
//! request-building and response-parsing are **implemented and unit-tested without a
//! network**; only the live socket round-trip is `TODO(C5-lancedb-live)`.
//!
//! ## Which API surface this targets, honestly
//!
//! LanceDB is *primarily an embedded* engine (the `lancedb` crate opens a local dataset
//! directory, no HTTP). It has **no simple stable embedded REST API** to call over a
//! socket. LanceDB **Cloud / Enterprise** and a self-hosted LanceDB server *do* expose an
//! HTTP+JSON API; the request/response *building* below targets that documented remote
//! shape:
//!
//! - `upsert`  → `POST <uri>/v1/table/<table>/insert`  with `{ "data": [ { "id",
//!   "vector", ...payload } ] }` (insert/add rows; `mode: "overwrite"`-by-id is the
//!   `merge_insert` upsert semantics on the server).
//! - `nearest` → `POST <uri>/v1/table/<table>/query`   with `{ "vector": [...], "k": n,
//!   "filter": ..., "columns": ["id"] }`; the response `{ "rows"/"data": [ { "id",
//!   "_distance"/"score" }, ... ] }` is parsed into [`StoreHit`]s.
//! - `delete`  → `POST <uri>/v1/table/<table>/delete`  with `{ "predicate": "id = '<id>'" }`.
//!
//! **The exact endpoint paths/field names of LanceDB's remote API are versioned and not as
//! universally stable as Qdrant's** — they are marked clearly below
//! ([`UPSERT_PATH`]/[`QUERY_PATH`]/[`DELETE_PATH`] + the parse fallbacks). A self-hosted
//! deployment may differ; the live wiring (`TODO(C5-lancedb-live)`) pins the concrete
//! version. The *structure* — broker auth, bounded request, score-sanitized parse — is
//! identical to the Qdrant adapter and to the `VectorStore` contract.
//!
//! ## Trust posture + credential flow (unchanged)
//!
//! Retrieval only — grants nothing. The store's **distances/scores are not trusted**:
//! [`crate::plan::QueryPlanner`] re-ranks every hit by cosine to the query embedding and
//! redact-then-bounds it. Any credential resolves ONLY through
//! [`crustcore_secrets::CredentialProxy`] / [`crustcore_secrets::SecretBroker`] at send
//! time as an `Authorization: Bearer <token>` header (LanceDB Cloud's scheme), via
//! [`super::http::apply_auth`] — never the sandbox env, never logged, never model-visible
//! (invariants 1, 3). The adapter holds only a [`crustcore_secrets::SecretHandle`].

use super::http::{
    self, bound_hits, sanitize_score, BrokerAuth, EndpointAuth, StoreHit, StoreSendError,
};
use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// Remote insert path (LanceDB Cloud/server). Versioned — see the module note; the live
/// wiring pins the concrete deployment's path (`TODO(C5-lancedb-live)`).
const INSERT_PATH: &str = "insert";
/// Remote query path. Versioned (see module note).
const QUERY_PATH: &str = "query";
/// Remote delete path. Versioned (see module note).
const DELETE_PATH: &str = "delete";

/// Configuration for the LanceDB backend (non-secret connection metadata + the auth
/// *descriptor*; the credential is resolved via the broker at request time).
#[derive(Debug, Clone)]
pub struct LanceDbConfig {
    /// Table (namespace) name.
    pub table: String,
    /// Dataset/server base URI, e.g. `https://<db>.<region>.api.lancedb.com` for Cloud or
    /// a self-hosted server base (non-secret).
    pub uri: String,
    /// How to authenticate. Defaults to [`EndpointAuth::None`]; LanceDB Cloud uses
    /// `EndpointAuth::bearer(handle)` (an `Authorization: Bearer <api-key>` header).
    pub auth: EndpointAuth,
}

impl LanceDbConfig {
    /// A config for `table` at `uri` with no auth.
    #[must_use]
    pub fn new(table: impl Into<String>, uri: impl Into<String>) -> Self {
        LanceDbConfig {
            table: table.into(),
            uri: uri.into(),
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

/// A thin LanceDB remote-API adapter. Request-building/response-parsing implemented;
/// `TODO(C5-lancedb-live)`: only the live socket round-trip remains. As with Qdrant, the
/// [`VectorStore`] trait methods are inert (no broker to authenticate with); the
/// broker-taking `*_with_broker` methods do the real work.
#[derive(Debug)]
pub struct LanceDbVectorStore {
    config: LanceDbConfig,
    namespace: String,
}

impl LanceDbVectorStore {
    /// Builds an adapter from non-secret config. No network/credential access here.
    #[must_use]
    pub fn new(config: LanceDbConfig) -> Self {
        let namespace = config.table.clone();
        LanceDbVectorStore { config, namespace }
    }

    /// The table currently scoped to (active namespace, falling back to configured table).
    #[must_use]
    fn table(&self) -> &str {
        if self.namespace.is_empty() {
            &self.config.table
        } else {
            &self.namespace
        }
    }

    /// `<uri>/v1/table/<table>/<op>` for a remote operation. Non-secret.
    #[must_use]
    fn op_url(&self, op: &str) -> String {
        format!(
            "{}/v1/table/{}/{}",
            self.config.uri.trim_end_matches('/'),
            self.table(),
            op
        )
    }

    /// The remote insert URL. Non-secret.
    #[must_use]
    pub fn insert_url(&self) -> String {
        self.op_url(INSERT_PATH)
    }

    /// The remote query URL. Non-secret.
    #[must_use]
    pub fn query_url(&self) -> String {
        self.op_url(QUERY_PATH)
    }

    /// The remote delete URL. Non-secret.
    #[must_use]
    pub fn delete_url(&self) -> String {
        self.op_url(DELETE_PATH)
    }
}

// ---------------------------------------------------------------------------
// Pure request-building + response-parsing (network-free, CI-tested)
// ---------------------------------------------------------------------------

/// Builds the LanceDB insert body: `{ "data": [ { "id", "vector", <payload cols> } ] }`.
/// Each row carries the embedding under `vector` and the non-secret [`ChunkMeta`] as flat
/// columns (provenance only). Read-back metadata is *not* trusted: the planner resolves
/// content + re-ranks, so a tampered row cannot smuggle authority.
#[must_use]
pub fn build_insert_body(items: &[(ChunkId, Vec<f32>, ChunkMeta)]) -> serde_json::Value {
    use serde_json::json;
    let rows: Vec<serde_json::Value> = items
        .iter()
        .map(|(id, vector, meta)| {
            json!({
                "id": id.as_str(),
                "vector": vector,
                "path": meta.path,
                "byte_start": meta.byte_span.start,
                "byte_end": meta.byte_span.end,
                "symbol": meta.symbol,
                "source": source_str(meta.source),
                "redact_required": meta.redact_required,
            })
        })
        .collect();
    json!({ "data": rows })
}

/// Builds the LanceDB query body: the query `vector`, top-`k`, and `columns: ["id"]` (we
/// fetch only the id — the planner resolves content + re-ranks). A finite, positive `floor`
/// is sent as a `_distance`-based predicate is *not* applied here (LanceDB returns
/// distances, not similarities, and conventions vary); instead the floor is enforced by the
/// planner's re-rank. Bounded by construction.
#[must_use]
pub fn build_query_body(query: &[f32], k: usize, _floor: f32) -> serde_json::Value {
    use serde_json::json;
    json!({
        "vector": query,
        "k": k,
        "columns": ["id"],
    })
}

/// Builds the LanceDB delete body: a SQL-ish predicate `{ "predicate": "id = '<id>'" }`.
/// The id is single-quote-escaped so an adversarial id cannot break out of the predicate
/// (defense in depth — chunk ids are derived from confined paths + spans, not user input).
#[must_use]
pub fn build_delete_body(id: &ChunkId) -> serde_json::Value {
    use serde_json::json;
    let escaped = id.as_str().replace('\'', "''");
    json!({ "predicate": format!("id = '{escaped}'") })
}

/// Parses a LanceDB query response into bounded, score-sanitized [`StoreHit`]s.
///
/// LanceDB's remote API has returned the row array under either `rows` or `data` across
/// versions, and the per-row similarity under `score` or the row's `_distance` (a
/// *distance*, lower = closer). This parser accepts both shapes; when only `_distance` is
/// present it stores its sanitized value as the (advisory) score — **scores are not trusted
/// for ranking** (the planner re-ranks by cosine), so the exact orientation does not affect
/// correctness, only the advisory field. Robust to a hostile/malformed response: a missing
/// array / id yields no hit; the list is capped to [`super::MAX_STORE_HITS`].
#[must_use]
pub fn parse_query_response(body: &serde_json::Value) -> Vec<StoreHit> {
    let arr = body
        .get("rows")
        .and_then(|r| r.as_array())
        .or_else(|| body.get("data").and_then(|d| d.as_array()));
    let Some(arr) = arr else {
        return Vec::new();
    };
    let hits: Vec<StoreHit> = arr
        .iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(coerce_id)?;
            let score = item
                .get("score")
                .and_then(serde_json::Value::as_f64)
                .or_else(|| item.get("_distance").and_then(serde_json::Value::as_f64))
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

/// Coerces a row id (string or integer) to a `String`; `None` for an unrepresentable shape.
fn coerce_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Stable, non-secret string tag for a chunk's provenance (for the row payload only).
fn source_str(source: crustcore_index::MemorySource) -> &'static str {
    match source {
        crustcore_index::MemorySource::RepoFile => "repo_file",
        crustcore_index::MemorySource::ToolObservation => "tool_observation",
        crustcore_index::MemorySource::PriorRun => "prior_run",
        crustcore_index::MemorySource::UserNote => "user_note",
    }
}

// ---------------------------------------------------------------------------
// Broker-mediated live transport (TODO(C5-lancedb-live): only the live socket)
// ---------------------------------------------------------------------------

impl LanceDbVectorStore {
    /// Inserts `items` to the table via the remote insert endpoint, authenticating per
    /// request through the broker. `TODO(C5-lancedb-live)`: only the live socket remains;
    /// the body shape is unit-tested via [`build_insert_body`].
    ///
    /// # Errors
    /// [`StoreSendError`] on a serialization, auth, transport, or non-2xx-status failure.
    pub fn upsert_with_broker<S: crustcore_secrets::SecretStore>(
        &self,
        items: &[(ChunkId, Vec<f32>, ChunkMeta)],
        ctx: &BrokerAuth<'_, S>,
    ) -> Result<u16, StoreSendError> {
        let body = build_insert_body(items);
        let payload = serde_json::to_vec(&body).map_err(|_| StoreSendError::Serialize)?;
        let req = http::agent()
            .post(&self.insert_url())
            .set("Content-Type", "application/json");
        let req = http::apply_auth(req, &self.config.auth, ctx)?;
        send_expecting_ok(req, &payload).map(|(status, _body)| status)
    }

    /// Queries the table via the remote query endpoint and returns bounded,
    /// score-sanitized [`StoreHit`]s. `TODO(C5-lancedb-live)`: live socket only; the
    /// request/response shaping is unit-tested via [`build_query_body`] /
    /// [`parse_query_response`]. Scores are advisory — the planner re-ranks the ids.
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
        let body = build_query_body(query, k, floor);
        let payload = serde_json::to_vec(&body).map_err(|_| StoreSendError::Serialize)?;
        let req = http::agent()
            .post(&self.query_url())
            .set("Content-Type", "application/json");
        let req = http::apply_auth(req, &self.config.auth, ctx)?;
        let (_status, resp_body) = send_expecting_ok(req, &payload)?;
        let json: serde_json::Value =
            serde_json::from_str(&resp_body).map_err(|_| StoreSendError::BadResponse)?;
        Ok(parse_query_response(&json))
    }

    /// Deletes a row by id via the remote delete endpoint. `TODO(C5-lancedb-live)`: live
    /// socket only; the body shape is unit-tested via [`build_delete_body`].
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
// VectorStore trait: namespacing real; broker-less I/O methods inert (fail-closed).
// ---------------------------------------------------------------------------

impl VectorStore for LanceDbVectorStore {
    fn upsert(&mut self, _items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        // No broker on the trait method => fail-closed. Real inserts go through
        // `upsert_with_broker` (TODO(C5-lancedb-live)).
    }

    fn nearest(&self, _query: &[f32], _k: usize, _floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        // No broker on the trait method => fail-closed (empty). Real queries go through
        // `nearest_with_broker`; the planner re-ranks the returned ids.
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
        ChunkMeta::new(path, ByteSpan::new(5, 9), MemorySource::ToolObservation)
    }

    fn store() -> LanceDbVectorStore {
        LanceDbVectorStore::new(LanceDbConfig::new("chunks", "https://db.example.com"))
    }

    /// Asserts a JSON array equals an f32 vector element-wise with f32 tolerance (f32
    /// widens to f64 in JSON, so exact equality is the wrong comparison).
    fn assert_vec_close(v: &serde_json::Value, expected: &[f32]) {
        let arr = v.as_array().expect("vector is an array");
        assert_eq!(arr.len(), expected.len(), "vector length");
        for (got, want) in arr.iter().zip(expected) {
            let g = got.as_f64().expect("numeric element") as f32;
            assert!((g - want).abs() < 1e-6, "element {g} != {want}");
        }
    }

    #[test]
    fn urls_are_well_formed_and_table_scoped() {
        let mut s = store();
        assert_eq!(
            s.insert_url(),
            "https://db.example.com/v1/table/chunks/insert"
        );
        assert_eq!(
            s.query_url(),
            "https://db.example.com/v1/table/chunks/query"
        );
        assert_eq!(
            s.delete_url(),
            "https://db.example.com/v1/table/chunks/delete"
        );
        s.set_namespace("other");
        assert_eq!(s.query_url(), "https://db.example.com/v1/table/other/query");
        // Trailing slash collapsed.
        let s2 = LanceDbVectorStore::new(LanceDbConfig::new("t", "https://h/"));
        assert_eq!(s2.insert_url(), "https://h/v1/table/t/insert");
    }

    #[test]
    fn insert_body_has_data_rows_with_id_vector_payload() {
        let items = vec![(ChunkId::new("a"), vec![0.1, 0.2], meta("a.rs"))];
        let body = build_insert_body(&items);
        let rows = body["data"].as_array().expect("data array");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "a");
        assert_vec_close(&rows[0]["vector"], &[0.1, 0.2]);
        assert_eq!(rows[0]["path"], "a.rs");
        assert_eq!(rows[0]["byte_start"], 5);
        assert_eq!(rows[0]["byte_end"], 9);
        assert_eq!(rows[0]["source"], "tool_observation");
        assert_eq!(rows[0]["redact_required"], true);
    }

    #[test]
    fn query_body_carries_vector_k_and_id_column() {
        let body = build_query_body(&[1.0, 2.0, 3.0], 7, 0.3);
        assert_eq!(body["vector"], serde_json::json!([1.0, 2.0, 3.0]));
        assert_eq!(body["k"], 7);
        assert_eq!(body["columns"], serde_json::json!(["id"]));
    }

    #[test]
    fn delete_body_predicate_escapes_quotes() {
        let body = build_delete_body(&ChunkId::new("a'b"));
        // Single quote doubled so the predicate cannot be broken out of.
        assert_eq!(body["predicate"], "id = 'a''b'");
    }

    #[test]
    fn parse_query_response_accepts_rows_or_data_and_score_or_distance() {
        // `rows` + explicit score.
        let rows = serde_json::json!({
            "rows": [ { "id": "a", "score": 0.9 }, { "id": 7, "score": 0.2 } ]
        });
        let h1 = parse_query_response(&rows);
        assert_eq!(h1.len(), 2);
        assert_eq!(h1[0].id, ChunkId::new("a"));
        assert_eq!(h1[1].id, ChunkId::new("7"));

        // `data` + `_distance` fallback.
        let data = serde_json::json!({
            "data": [ { "id": "x", "_distance": 0.05 } ]
        });
        let h2 = parse_query_response(&data);
        assert_eq!(h2.len(), 1);
        assert_eq!(h2[0].id, ChunkId::new("x"));
        assert!((h2[0].score - 0.05).abs() < 1e-6);
    }

    #[test]
    fn parse_query_response_sanitizes_and_survives_garbage() {
        let resp = serde_json::json!({
            "rows": [
                { "id": "nan", "_distance": f64::NAN },
                { "id": "noid?" , "score": 0.5 },
                { "score": 0.5 },
                "garbage"
            ]
        });
        let hits = parse_query_response(&resp);
        assert!(hits.iter().all(|h| h.score.is_finite()));
        // The entry with a NaN distance survives (id present) with a sanitized 0.0 score.
        let nan = hits.iter().find(|h| h.id == ChunkId::new("nan")).unwrap();
        assert_eq!(nan.score, 0.0);
        // No array key => empty (no panic).
        assert!(parse_query_response(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn trait_methods_are_inert_without_a_broker() {
        let mut s = store();
        s.upsert(vec![(ChunkId::new("a"), vec![1.0], meta("a.rs"))]);
        assert!(s.nearest(&[1.0], 5, 0.0).is_empty());
        s.delete(&ChunkId::new("a"));
        assert_eq!(s.len(), 0);
        assert_eq!(s.namespace(), "chunks");
    }

    /// The live socket round-trip: needs a running LanceDB (Cloud/server) on the URI, so it
    /// is `#[ignore]`d. `TODO(C5-lancedb-live)`: run against a real LanceDB remote endpoint
    /// (and pin the concrete path/field versions noted in the module docs).
    #[test]
    #[ignore = "needs a running LanceDB remote endpoint (TODO(C5-lancedb-live))"]
    fn live_insert_query_delete_roundtrip() {
        use crustcore_secrets::{InMemoryStore, SecretBroker, SecretHandle};
        use crustcore_types::{ApprovalId, BoundedText, SecretId, Timestamp};

        // Cloud would carry an API key; here we demonstrate the bearer auth wiring with a
        // sentinel secret (the live endpoint determines whether auth is required).
        let mut secret_store = InMemoryStore::new();
        secret_store.insert(SecretId(1), "lancedb-api-key", b"tok-XXXX".to_vec());
        let broker = SecretBroker::new(secret_store);
        let handle = SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("lancedb-api-key").unwrap(),
        };
        let s = LanceDbVectorStore::new(
            LanceDbConfig::new("chunks", "https://db.example.com")
                .with_auth(EndpointAuth::bearer(handle)),
        );
        let now = Timestamp::from_millis(0);
        let ctx = super::BrokerAuth::new(&broker, ApprovalId(1), now, 5_000);
        let items = vec![(ChunkId::new("a"), vec![0.1, 0.2, 0.3], meta("a.rs"))];
        s.upsert_with_broker(&items, &ctx).expect("insert");
        let _hits = s
            .nearest_with_broker(&[0.1, 0.2, 0.3], 5, 0.0, &ctx)
            .expect("query");
        s.delete_with_broker(&ChunkId::new("a"), &ctx)
            .expect("delete");
    }
}
