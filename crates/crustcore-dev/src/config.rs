// SPDX-License-Identifier: Apache-2.0
//! Launch configuration (`C7.1`). The safe path is the easy path (Track C P2).
//!
//! [`DevConfig::default`] binds `127.0.0.1` and keeps mutation **off**. Listening
//! off-loopback is an *explicit, warned* opt-in via [`DevConfig::bind_host`]; the
//! sentinel `0.0.0.0` (and `::`) can never be reached silently — it requires the
//! caller to also acknowledge the exposure flag, or construction fails closed.

use std::net::{IpAddr, Ipv4Addr};

/// Default loopback host.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default port for the dev UI.
pub const DEFAULT_PORT: u16 = 8787;

/// Why a configuration was rejected (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A non-loopback bind was requested without the explicit exposure acknowledgement.
    /// `0.0.0.0` / `::` is never a silent default (dimension (a)).
    OffLoopbackNotAcknowledged(IpAddr),
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::OffLoopbackNotAcknowledged(ip) => write!(
                f,
                "refusing to bind off-loopback ({ip}) without explicit acknowledgement; \
                 the dev UI is loopback-only by default"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Launch configuration for the dev server.
///
/// The default is loopback-only, read-only. To listen off-loopback the operator must
/// call [`DevConfig::bind_host`] with `acknowledge_exposure = true`; otherwise
/// construction fails closed. To enable mutating routes at all, the operator must call
/// [`DevConfig::enable_mutation`] — and even then every mutation still goes through the
/// typed operation-bound approval engine (`C7.6`); the flag only *unlocks the route*.
#[derive(Debug, Clone)]
pub struct DevConfig {
    host: IpAddr,
    port: u16,
    mutation_enabled: bool,
    off_loopback: bool,
}

impl Default for DevConfig {
    fn default() -> Self {
        DevConfig {
            host: LOOPBACK,
            port: DEFAULT_PORT,
            mutation_enabled: false,
            off_loopback: false,
        }
    }
}

impl DevConfig {
    /// The fail-safe default: loopback `127.0.0.1`, read-only.
    #[must_use]
    pub fn loopback() -> Self {
        DevConfig::default()
    }

    /// Sets the listen port.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Requests a specific bind host. A loopback host is always accepted. A
    /// **non-loopback** host (including the wildcard `0.0.0.0` / `::`) is accepted
    /// **only** when `acknowledge_exposure` is `true` — an explicit, deliberate
    /// operator choice, never a silent default. When off-loopback is acknowledged the
    /// returned config carries the warning flag so the launcher logs it loudly.
    pub fn bind_host(
        mut self,
        host: IpAddr,
        acknowledge_exposure: bool,
    ) -> Result<Self, ConfigError> {
        if host.is_loopback() {
            self.host = host;
            self.off_loopback = false;
            return Ok(self);
        }
        if !acknowledge_exposure {
            return Err(ConfigError::OffLoopbackNotAcknowledged(host));
        }
        self.host = host;
        self.off_loopback = true;
        Ok(self)
    }

    /// Unlocks the *mutating* route class. Off by default. Even when enabled, a
    /// mutation is dispatched only through the operation-bound approval engine
    /// ([`crate::mutation`]); this flag alone never authorizes a side effect.
    #[must_use]
    pub fn enable_mutation(mut self) -> Self {
        self.mutation_enabled = true;
        self
    }

    /// The configured host.
    #[must_use]
    pub fn host(&self) -> IpAddr {
        self.host
    }

    /// The configured port.
    #[must_use]
    pub fn port_num(&self) -> u16 {
        self.port
    }

    /// Whether mutating routes are unlocked.
    #[must_use]
    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }

    /// Whether the bind is off-loopback (the launcher should warn loudly).
    #[must_use]
    pub fn is_off_loopback(&self) -> bool {
        self.off_loopback
    }

    /// A one-line exposure warning, when off-loopback. The launcher prints this to the
    /// terminal so an off-loopback bind is never silent.
    #[must_use]
    pub fn exposure_warning(&self) -> Option<String> {
        self.off_loopback.then(|| {
            format!(
                "WARNING: crustcore-dev is bound OFF-LOOPBACK on {}:{} — it is reachable from \
                 the network. Ensure this is intentional.",
                self.host, self.port
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn default_is_loopback_read_only() {
        let cfg = DevConfig::default();
        assert!(cfg.host().is_loopback());
        assert_eq!(cfg.host(), LOOPBACK);
        assert!(!cfg.mutation_enabled());
        assert!(!cfg.is_off_loopback());
        assert!(cfg.exposure_warning().is_none());
    }

    #[test]
    fn off_loopback_requires_explicit_acknowledgement() {
        let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // 0.0.0.0
                                                          // Without acknowledgement: fails closed.
        assert_eq!(
            DevConfig::default().bind_host(wildcard, false).unwrap_err(),
            ConfigError::OffLoopbackNotAcknowledged(wildcard)
        );
        // Even a routable host fails closed without ack.
        let routable = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert!(DevConfig::default().bind_host(routable, false).is_err());
        // IPv6 wildcard also fails closed.
        let v6wild = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert!(DevConfig::default().bind_host(v6wild, false).is_err());
    }

    #[test]
    fn off_loopback_with_ack_warns() {
        let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let cfg = DevConfig::default().bind_host(wildcard, true).unwrap();
        assert!(cfg.is_off_loopback());
        assert!(cfg.exposure_warning().is_some());
    }

    #[test]
    fn loopback_host_never_needs_acknowledgement() {
        // 127.0.0.1 and ::1 are always accepted, ack flag irrelevant.
        let cfg = DevConfig::default()
            .bind_host(IpAddr::V6(Ipv6Addr::LOCALHOST), false)
            .unwrap();
        assert!(cfg.host().is_loopback());
        assert!(!cfg.is_off_loopback());
    }

    #[test]
    fn mutation_is_off_by_default_and_opt_in() {
        assert!(!DevConfig::default().mutation_enabled());
        assert!(DevConfig::default().enable_mutation().mutation_enabled());
    }
}
