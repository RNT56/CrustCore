// SPDX-License-Identifier: Apache-2.0
//! Integration test: spawn the real `crustcore-net` helper binary and talk the
//! local protocol to it over a pipe (`docs/model-routing.md` §6, Phase 7
//! acceptance "Nano can call net helper without linking HTTP/TLS").
//!
//! This exercises the genuine subprocess + protocol path — the caller links only
//! `crustcore-netproto` (std-only) and reaches the model transport by *spawning*
//! the sidecar, exactly as nano would.

use crustcore_netproto::{
    BoundedText, CompleteRequest, Require, Role, SpawnedHelper, MAX_TEXT_BYTES,
};

/// Cargo sets `CARGO_BIN_EXE_<name>` for a bin in the crate under test.
const HELPER: &str = env!("CARGO_BIN_EXE_crustcore-net");

fn req(role: Role, prompt: &str) -> CompleteRequest {
    CompleteRequest {
        role,
        system: BoundedText::truncated("", MAX_TEXT_BYTES),
        prompt: BoundedText::truncated(prompt, MAX_TEXT_BYTES),
        max_tokens: 64,
        stream: true,
        max_cost_micros: 0,
        require: Require::default(),
    }
}

#[test]
fn spawned_helper_probes_and_completes_over_a_pipe() {
    let mut spawned = SpawnedHelper::spawn(HELPER, &[]).expect("spawn the net helper binary");

    // Probe: the dynamic registry comes back over the pipe.
    let models = spawned.helper().probe().expect("probe");
    assert!(
        models.iter().any(|m| m.model == "strong-1" && m.healthy),
        "registry from the spawned helper should include the strong model: {models:?}"
    );
    assert!(
        models.iter().any(|m| m.model == "local-1"),
        "registry should include the local model: {models:?}"
    );

    // Complete (Advisor → strongest), collecting streamed chunks.
    let mut streamed = String::new();
    let fin = spawned
        .helper()
        .complete(&req(Role::Advisor, "design a kernel"), |c| {
            streamed.push_str(c)
        })
        .expect("complete");
    assert_eq!(fin.model, "strong-1");
    assert_eq!(fin.provider, "mock-remote");
    assert!(fin.text.as_str().contains("design a kernel"));
    // Streamed chunks concatenate to the final text (streaming works over the pipe).
    assert_eq!(streamed, fin.text.as_str());
    assert!(fin.usage.output_tokens > 0);
}

#[test]
fn spawned_helper_routes_local_only_to_a_local_model() {
    let mut spawned = SpawnedHelper::spawn(HELPER, &[]).expect("spawn the net helper binary");
    let mut r = req(Role::Implementation, "keep this private");
    r.require.local_only = true;
    let fin = spawned
        .helper()
        .complete(&r, |_| {})
        .expect("complete local-only");
    assert_eq!(fin.provider, "mock-local");
}
