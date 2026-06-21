// SPDX-License-Identifier: Apache-2.0
//! The read-only / mutating route split (`C7.2`, dimension (c)).
//!
//! Every route is classified [`RouteClass::ReadOnly`] or [`RouteClass::Mutating`]. The
//! split is not a convention checked at runtime: a [`RouteClass::ReadOnly`] handler is
//! handed a [`crate::backend::ReadOnlyBackend`] (via [`crate::backend::DevBackend::read_only`]),
//! which exposes **no** mutating method — so reaching a side effect from a read view is a
//! *compile error*. A [`RouteClass::Mutating`] handler is the only one that can obtain a
//! [`crate::backend::MutatingBackend`], and even then only after the launch flag and the
//! operation-bound approval gate (`C7.6`) admit it.

/// Whether a route may have a side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    /// Renders a typed view. The handler receives only a read-only backend; it cannot
    /// mint, write, append a frame, or reach the verifier.
    ReadOnly,
    /// Dispatches an operation-bound approval resolution into the existing approval
    /// engine. Unreachable unless the launch flag enables it AND a valid
    /// operation-bound token is presented (`C7.6`).
    Mutating,
}

impl RouteClass {
    /// Whether this route may mutate.
    #[must_use]
    pub fn is_mutating(self) -> bool {
        matches!(self, RouteClass::Mutating)
    }
}

/// A registered route: its path, method, and class. The router uses this table to apply
/// auth at the root, classify the handler, and (for [`RouteClass::Mutating`]) gate on the
/// launch flag. Assets and the websocket route are registered here too, so the auth +
/// loopback checks cover them (dimension (b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// The path prefix this route serves (exact-match for control routes).
    pub path: &'static str,
    /// The method (`GET` for reads, `POST` for control).
    pub method: crate::request::Method,
    /// The route's class.
    pub class: RouteClass,
}

impl RouteSpec {
    /// A read-only `GET` route.
    #[must_use]
    pub const fn read(path: &'static str) -> Self {
        RouteSpec {
            path,
            method: crate::request::Method::Get,
            class: RouteClass::ReadOnly,
        }
    }

    /// A mutating `POST` route.
    #[must_use]
    pub const fn mutating(path: &'static str) -> Self {
        RouteSpec {
            path,
            method: crate::request::Method::Post,
            class: RouteClass::Mutating,
        }
    }
}

/// The full route table of the dev UI. Auth + loopback are applied to every entry; the
/// asset and websocket routes are read-only and authenticated like the rest.
pub const ROUTES: &[RouteSpec] = &[
    // Static single-page UI assets (still authenticated — dimension (b)).
    RouteSpec::read("/"),
    RouteSpec::read("/assets"),
    // The websocket upgrade endpoint for live snapshots (still authenticated).
    RouteSpec::read("/ws"),
    // Read-first views.
    RouteSpec::read("/inspector"),
    RouteSpec::read("/replay"),
    RouteSpec::read("/provider"),
    RouteSpec::read("/mcp"),
    RouteSpec::read("/flow"),
    RouteSpec::read("/sessions"),
    RouteSpec::read("/approvals"),
    // The single mutating route: dispatch an approval resolution into the approval
    // engine. Off unless the launch flag enables it AND a valid op-bound token arrives.
    RouteSpec::mutating("/approvals/resolve"),
];

/// Looks up the [`RouteSpec`] for a `(method, path)`, if any. Exact path match keeps the
/// surface small and predictable (no path traversal into a mutating handler).
#[must_use]
pub fn lookup(method: crate::request::Method, path: &str) -> Option<RouteSpec> {
    ROUTES
        .iter()
        .find(|r| r.method == method && r.path == path)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Method;

    #[test]
    fn only_one_route_is_mutating() {
        let mutating: Vec<_> = ROUTES.iter().filter(|r| r.class.is_mutating()).collect();
        assert_eq!(mutating.len(), 1);
        assert_eq!(mutating[0].path, "/approvals/resolve");
        assert_eq!(mutating[0].method, Method::Post);
    }

    #[test]
    fn every_read_route_is_get() {
        for r in ROUTES.iter().filter(|r| !r.class.is_mutating()) {
            assert_eq!(r.method, Method::Get, "{} should be GET", r.path);
        }
    }

    #[test]
    fn asset_and_ws_routes_are_registered() {
        // They must be in the table so auth/loopback cover them (dimension (b)).
        assert!(lookup(Method::Get, "/assets").is_some());
        assert!(lookup(Method::Get, "/ws").is_some());
        assert!(lookup(Method::Get, "/").is_some());
    }

    #[test]
    fn unknown_route_is_none() {
        assert!(lookup(Method::Get, "/does-not-exist").is_none());
        // The mutating path is not reachable via GET.
        assert!(lookup(Method::Get, "/approvals/resolve").is_none());
    }
}
