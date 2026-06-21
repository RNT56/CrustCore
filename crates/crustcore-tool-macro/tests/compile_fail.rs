// SPDX-License-Identifier: Apache-2.0
//! Compile-fail (trybuild) UI tests for `#[crust_tool]` bypass attempts (C2.8).
//!
//! These prove STRUCTURALLY that the ergonomic layer cannot be misused: an
//! unsupported parameter type, a non-`Result` return, a missing host handle, an
//! unknown/typo'd `reversibility` value, and a body that references a
//! self-authorization / receipt-forgery symbol all FAIL TO COMPILE (dimensions c, f).
//!
//! They are GATED behind the `trybuild` cargo feature and therefore NEVER run in the
//! default `cargo test --workspace`: trybuild pins `.stderr` snapshots that are
//! sensitive to the exact rustc version and would otherwise make the gate flaky. Run
//! them deliberately, out of band:
//!
//! ```sh
//! cargo test -p crustcore-tool-macro --features trybuild --test compile_fail
//! ```
#![cfg(feature = "trybuild")]

#[test]
fn crust_tool_bypass_attempts_fail_to_compile() {
    let t = trybuild::TestCases::new();
    // Each fixture is a single deliberate misuse that must not compile. We assert the
    // *failure* (compile_fail) but, to stay rustc-version-robust, we do not require a
    // pinned message — trybuild still confirms the build fails.
    t.compile_fail("tests/ui/*.rs");
}
