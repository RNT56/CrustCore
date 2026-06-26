// SPDX-License-Identifier: Apache-2.0
//! `crustcore-dev` — the loopback developer launcher + inspector UI (Track C,
//! phase **C7-devui**; `docs/roadmap-v0.2.md` §C7).
//!
//! A dev UI is an *inbound control surface*. Built naively it becomes a back door:
//! an unauthenticated, off-loopback, mutation-capable second chat channel that can
//! rubber-stamp a model's side effects. CrustCore's dev UI is built fail-safe so it
//! **structurally cannot** be any of those things.
//!
//! ## Core / `serve` split (keep the web stack out of the default build)
//!
//! - **Core (this module tree, always compiled, fully CI-tested):** a [`DevBackend`]
//!   trait abstracting *all* data access (inspect/replay the event log, probe
//!   providers, the MCP registry, flow-graph steps, session snapshots) into typed
//!   *view models*; a [`backend::MockDevBackend`] for CI; pure per-route handler
//!   functions `handle_*(backend, &DevRequest) -> DevResponse`; bearer-token auth
//!   ([`auth`]); a [`route_class::RouteClass`] type-split so a read handler **cannot
//!   reach a mutating backend method**; the approval-dispatch logic ([`views::approvals`],
//!   [`mutation`]); loopback config ([`config`]). No `axum`/`tokio`/`hyper` here.
//! - **`serve` feature ([`serve`], self-verified, not in the default gate):** an
//!   `axum`/`hyper` server bound to `127.0.0.1` that maps HTTP requests to the core
//!   handler functions and sets the right `Content-Type` for the embedded SPA. The static
//!   single-page inspector ([`assets`]) is now served at `/` (HTML) and `/assets` (CSS);
//!   live websocket streaming (`/ws`) and real provider/MCP/spawned-helper wiring remain
//!   `TODO(C7-serve-live)`.
//!
//! ## Trust posture (enforced structurally, not by convention)
//!
//! - **Loopback by default (a).** [`config::DevConfig`] binds `127.0.0.1`; an
//!   off-loopback bind is an explicit, warned opt-in via
//!   [`config::DevConfig::bind_host`] — `0.0.0.0` is never a silent default.
//! - **Auth on every route (b).** Every [`request::DevRequest`] is checked by
//!   [`auth::Authenticator`] (constant-time bearer compare) *before* dispatch,
//!   including the asset and websocket route classes. The token never appears in a
//!   response or a log.
//! - **Read-only by default (c).** [`route_class::RouteClass`] splits `ReadOnly` from
//!   `Mutating`. A read handler is handed a [`backend::ReadOnlyBackend`] view that has
//!   **no** mutating method — reaching one is a compile error, not a runtime check.
//!   The inspector/replay/flow path mints nothing, writes nothing, appends no frame,
//!   and never reaches `verify::run_verify` / produces a `VerifiedPatch`.
//! - **No self-minted approvals (d).** The UI surfaces a *pending* approval and
//!   dispatches a resolution into the existing
//!   [`crustcore_daemon::telegram::ApprovalEngine`] — the same engine Telegram uses,
//!   where `AuthorizedUser::approve` is the sole `Approved<T>` minter. The UI never
//!   constructs an `Approved<T>` itself and a resolution is *operation-bound*
//!   (nonce + op-hash) so it cannot approve a different operation than the one shown.
//! - **No secret leak (e).** Every user-visible render passes through
//!   [`crustcore_secrets::Redactor`]; the provider tester renders only
//!   [`backend::ModelCardView`]/usage metadata, never a key.
//! - **Untrusted input (f).** Every header/query/body is length-bounded and validated
//!   ([`request`]); server/MCP/repo content and any loaded graph are untrusted data,
//!   never directives.
//! - **No second chat channel (g).** The UI renders typed views only; there is no
//!   `send_to_model(text)` / `send_to_user(text)` surface (invariants 15, 16).
//!
//! ## Non-nano
//!
//! This is a sidecar crate. It is never added to the nano feature graph; the web
//! stack (`axum`/`tokio`/`hyper`) is `serve`-gated and absent from the default build.
#![forbid(unsafe_code)]

pub mod assets;
pub mod auth;
pub mod backend;
pub mod config;
pub mod mutation;
pub mod request;
pub mod route_class;
pub mod views;

#[cfg(feature = "serve")]
pub mod serve;

#[cfg(feature = "serve")]
pub mod serve_entry;

pub use assets::{INSPECTOR_CSS, INSPECTOR_HTML, TITLE_MARKER};
pub use auth::{AuthOutcome, Authenticator, BearerToken};
pub use backend::{
    ApprovalView, DevBackend, FlowGraphView, FlowStepView, McpServerView, MockDevBackend,
    ModelCardView, MutatingBackend, ReadOnlyBackend, ReplayView, RunInspectorView, SessionListView,
};
pub use config::{ConfigError, DevConfig};
pub use mutation::{route, ApprovalDispatch, MutationError, MutationGate};
pub use request::{DevRequest, DevResponse, RequestError, Status};
pub use route_class::{RouteClass, RouteSpec};
