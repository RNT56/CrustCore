// SPDX-License-Identifier: Apache-2.0
//! Opt-in telemetry configuration (C6T.8), defaulting to **fully off**.
//!
//! The whole telemetry surface is fail-closed: [`Config::default`] has
//! `enabled = false`, so an unconfigured deployment emits nothing. The default
//! exporter is the in-memory one (no network), the default collector endpoint is
//! loopback (`127.0.0.1`), and the batch is bounded ([`Config::batch_bound`]) so a
//! large/adversarial log cannot blow the exporter (invariant 11).

use crate::auth::OtlpEndpointAuth;

/// Which exporter the run driver feeds.
#[derive(Debug, Clone, Default)]
pub enum ExporterChoice {
    /// Capture spans/metrics in memory (CI default, no network).
    #[default]
    InMemory,
    /// Send to an OTLP collector at `endpoint` using `auth` (broker-mediated).
    /// The live transport requires the `otlp` cargo feature.
    Otlp {
        /// The collector endpoint (non-secret). Defaults to a loopback collector;
        /// an off-loopback endpoint is an explicit operator choice.
        endpoint: String,
        /// How to authenticate (broker-mediated; never env/model-visible).
        auth: OtlpEndpointAuth,
    },
}

/// Telemetry configuration. Default = off, in-memory, loopback, bounded.
#[derive(Debug, Clone)]
pub struct Config {
    /// Master switch. **`false` by default** — telemetry is opt-in and fails closed.
    pub enabled: bool,
    /// Emit 1 of every `sample_rate` projectable frames (`1` = all). `0` is treated
    /// as `1` (never divide-by-zero, never silently drop everything).
    pub sample_rate: u32,
    /// Maximum number of frames processed per run (bounds work + exporter load).
    pub batch_bound: usize,
    /// Which exporter to feed.
    pub exporter: ExporterChoice,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false,
            sample_rate: 1,
            batch_bound: 1024,
            exporter: ExporterChoice::InMemory,
        }
    }
}

impl Config {
    /// The default OTLP collector endpoint: loopback HTTP. Off-loopback is an
    /// explicit operator choice, never a silent default (the safe path is the easy
    /// path, Track C P2).
    pub const DEFAULT_LOOPBACK_ENDPOINT: &'static str = "http://127.0.0.1:4318";

    /// A config explicitly enabled with the in-memory exporter (for tests/dev).
    #[must_use]
    pub fn enabled_in_memory() -> Self {
        Config {
            enabled: true,
            ..Config::default()
        }
    }

    /// The effective sample rate (treating `0` as `1`).
    #[must_use]
    pub fn effective_sample_rate(&self) -> u32 {
        self.sample_rate.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_fully_off_and_loopback() {
        let c = Config::default();
        assert!(!c.enabled, "telemetry must default OFF (fail-closed)");
        assert!(matches!(c.exporter, ExporterChoice::InMemory));
        assert_eq!(c.effective_sample_rate(), 1);
        assert!(Config::DEFAULT_LOOPBACK_ENDPOINT.contains("127.0.0.1"));
    }

    #[test]
    fn zero_sample_rate_never_divides_by_zero() {
        let c = Config {
            sample_rate: 0,
            ..Config::default()
        };
        assert_eq!(c.effective_sample_rate(), 1);
    }

    #[test]
    fn batch_bound_is_set() {
        assert!(Config::default().batch_bound > 0);
    }
}
