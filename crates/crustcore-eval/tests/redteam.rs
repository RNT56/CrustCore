// SPDX-License-Identifier: Apache-2.0
//! Red-team scenario suite (`ROADMAP.md` §19.3, `THREAT_MODEL.md`).
//!
//! Each scenario is `#[ignore]`d until the phase that defends it implements the
//! fixture and un-ignores it. Ignored tests keep the suite honest: they show as
//! "ignored", never as false green. A change that adds a new attack surface must
//! add the matching fixture in the same PR (`INVARIANTS.md`).

use crustcore_eval::required_redteam_scenarios;

#[test]
fn redteam_scenarios_are_enumerated() {
    // Sanity: the canonical scenario list is non-empty and stable.
    assert_eq!(required_redteam_scenarios().len(), 12);
}

/// Red-team (P3.5): an untrusted repository plants a malicious repo-local
/// `.git/config` (a `textconv` diff driver that runs an arbitrary command) and an
/// executable hook. The hardened git wrappers must neither execute the textconv
/// driver (RCE) nor run hooks (Phase 3 acceptance: "git commands cannot execute
/// hooks or read model-written config").
#[test]
fn git_config_and_hooks_do_not_execute() {
    use crustcore_path::WorktreeRoot;
    use crustcore_policy::FsReadCap;
    use crustcore_policy::FsWriteCap;
    use crustcore_types::ScopeId;
    use crustcore_worktree::{git_apply, git_diff, git_log, git_status};

    let mut dir = std::env::temp_dir();
    dir.push(format!("cc-redteam-git-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Initialize a repo with one commit, using a config-scrubbed git for setup.
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .current_dir(&dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .args(args)
            .status()
    };
    let Ok(init) = git(&["init", "-q"]) else {
        eprintln!("skipping: git unavailable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    if !init.success() {
        eprintln!("skipping: git init failed");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    std::fs::write(dir.join("README.md"), b"hello\n").unwrap();
    let _ = git(&["add", "."]);
    let _ = git(&[
        "-c",
        "user.email=ci@cc",
        "-c",
        "user.name=ci",
        "commit",
        "-q",
        "-m",
        "init",
    ]);

    let diff_marker = dir.join("PWNED_DIFF");
    let hook_marker = dir.join("PWNED_HOOK");

    // Malicious repo-local config: a textconv driver running an arbitrary command.
    let mut config = std::fs::read_to_string(dir.join(".git/config")).unwrap_or_default();
    config.push_str(&format!(
        "[diff \"evil\"]\n\ttextconv = touch {}\n",
        diff_marker.display()
    ));
    std::fs::write(dir.join(".git/config"), config).unwrap();
    std::fs::write(dir.join(".gitattributes"), b"README.md diff=evil\n").unwrap();
    std::fs::write(dir.join("README.md"), b"hello\nchanged\n").unwrap();

    // An executable hook that would fire if hooks were honored.
    std::fs::create_dir_all(dir.join(".git/hooks")).unwrap();
    let hook = dir.join(".git/hooks/post-index-change");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\ntouch {}\n", hook_marker.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let cap = FsReadCap {
        root: WorktreeRoot::open(&dir).unwrap(),
        scope: ScopeId(1),
    };

    // Also plant a clean/smudge filter driver mapped by a committed
    // .gitattributes — this is the git_apply (smudge) / git_diff (clean) RCE.
    let filter_marker = dir.join("PWNED_FILTER");
    let mut config = std::fs::read_to_string(dir.join(".git/config")).unwrap();
    config.push_str(&format!(
        "[filter \"evil\"]\n\tclean = touch {0}\n\tsmudge = touch {0}\n",
        filter_marker.display()
    ));
    std::fs::write(dir.join(".git/config"), config).unwrap();
    std::fs::write(dir.join(".gitattributes"), b"*.rs filter=evil\n").unwrap();
    std::fs::write(dir.join("a.rs"), b"x\n").unwrap();
    let _ = git(&["add", "."]);
    let _ = git(&[
        "-c",
        "user.email=ci@cc",
        "-c",
        "user.name=ci",
        "commit",
        "-q",
        "-m",
        "attrs",
    ]);
    // Clear any markers created by the (un-hardened) setup git calls, so a marker
    // present after the wrappers run is attributable to a wrapper.
    let _ = std::fs::remove_file(&filter_marker);
    let _ = std::fs::remove_file(&hook_marker);
    let _ = std::fs::remove_file(&diff_marker);

    // Exercise every wrapper; none may execute the planted command/hook/filter.
    let _ = git_status(&cap);
    let _ = git_diff(&cap);
    let _ = git_log(&cap, 10);
    let wcap = FsWriteCap {
        root: WorktreeRoot::open(&dir).unwrap(),
        scope: ScopeId(1),
    };
    let patch = concat!(
        "--- a/a.rs\n",
        "+++ b/a.rs\n",
        "@@ -1 +1,2 @@\n",
        " x\n",
        "+added\n"
    );
    let _ = git_apply(&wcap, patch.as_bytes());

    assert!(
        !diff_marker.exists(),
        "git wrapper executed a repo-local textconv driver (RCE)"
    );
    assert!(!hook_marker.exists(), "git wrapper executed a repo hook");
    assert!(
        !filter_marker.exists(),
        "git wrapper executed a repo-local clean/smudge filter driver (RCE)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Red-team (P3.6): a malicious relative path tries to escape the worktree — via
/// `..`, an absolute path, or a symlink pointing outside the root. The confined
/// path resolver rejects all of them, so no escaping path can reach a file tool
/// (invariant 7; Phase 3 acceptance "symlink escapes fail").
#[test]
fn symlink_escape_is_blocked() {
    use crustcore_path::{PathError, WorktreeRoot};

    let mut dir = std::env::temp_dir();
    dir.push(format!("cc-redteam-symesc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A symlink inside the worktree pointing at a sensitive location outside it.
    std::os::unix::fs::symlink("/etc", dir.join("escape")).unwrap();

    let root = WorktreeRoot::open(&dir).unwrap();

    // Lexical escapes.
    assert_eq!(
        root.confine_read("../../etc/passwd").unwrap_err(),
        PathError::Escape
    );
    assert_eq!(
        root.confine_write("/etc/passwd").unwrap_err(),
        PathError::AbsoluteNotAllowed
    );
    // Symlink escape: reading or writing through the escaping symlink fails.
    assert_eq!(
        root.confine_read("escape/passwd").unwrap_err(),
        PathError::SymlinkEscape
    );
    assert_eq!(
        root.confine_write("escape/evil").unwrap_err(),
        PathError::SymlinkEscape
    );
    // A legitimate in-root path still resolves.
    assert!(root.confine_write("src/main.rs").is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Red-team (P4.7, R11): a malicious environment tries loader injection
/// (`LD_PRELOAD`) and a path-list escape (an empty/relative `PATH` component =
/// current directory). The env sanitizer strips loader/credential vars and the
/// path-list validator rejects bad components (a single one fails the whole
/// variable) — so neither reaches a sandboxed process (invariant 9;
/// `docs/sandbox.md` §5).
#[test]
fn path_env_escape_is_blocked() {
    use crustcore_sandbox::{sanitize_env, validate_path_list, SandboxProfile};
    use std::collections::BTreeMap;

    let profile = SandboxProfile::default_sandboxed();

    // An empty leading PATH component (current dir) fails the whole variable.
    let mut hostile = BTreeMap::new();
    hostile.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
    hostile.insert("PATH".to_string(), ":/usr/bin".to_string());
    assert!(sanitize_env(&hostile, &profile).is_err());

    // With a clean PATH, the loader var is dropped and PATH survives.
    let mut env = BTreeMap::new();
    env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
    env.insert(
        "DYLD_INSERT_LIBRARIES".to_string(),
        "/tmp/evil.dylib".to_string(),
    );
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let out = sanitize_env(&env, &profile).unwrap();
    assert!(!out.contains_key("LD_PRELOAD"));
    assert!(!out.contains_key("DYLD_INSERT_LIBRARIES"));
    assert_eq!(out.get("PATH").map(String::as_str), Some("/usr/bin:/bin"));

    // Direct validator coverage of the component checks.
    assert!(validate_path_list("/usr/bin:/bin").is_ok());
    assert!(validate_path_list("/usr/bin:.").is_err());
    assert!(validate_path_list("relative").is_err());
    assert!(validate_path_list("/a::/b").is_err());
}

/// Red-team (P2.6): a model/worker fabricates a tool result. Receipts make a
/// model-visible tool result unforgeable (invariant 10): a receipt minted under a
/// key the model does not hold is the only thing that verifies, and the shown
/// result must hash to the receipt's `result_hash`. P6.6 extends this to the
/// external-worker transcript path.
#[test]
fn fabricated_tool_result_is_rejected() {
    use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams};
    use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

    let params = |result: &'static [u8]| ReceiptParams {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        tool_name: b"run_command",
        args: b"cargo test",
        result,
        artifacts: &[],
        event_seq: EventSeq(1),
    };

    // CrustCore mints a genuine receipt for a real tool call with its secret key.
    let mut crustcore = ReceiptChain::new(MacKey::new([0x11; 32]));
    let genuine = crustcore.mint(&params(b"tests passed"));

    // The genuine receipt verifies, and the shown result must match its hash.
    assert!(crustcore.verify(std::slice::from_ref(&genuine)).is_intact());
    assert!(genuine.result_matches(b"tests passed"));
    assert!(!genuine.result_matches(b"tests failed"));

    // (a) The model fabricates a receipt by minting one under a guessed key. It
    // cannot verify under CrustCore's key (the model never holds it).
    let mut forger = ReceiptChain::new(MacKey::new([0x22; 32]));
    let forged = forger.mint(&params(b"tests passed"));
    assert!(
        !crustcore.verify(&[forged]).is_intact(),
        "a receipt forged under the wrong key must not verify"
    );

    // (b) The model keeps a real receipt but swaps the shown result: the receipt
    // no longer matches what is shown, and tampering its result_hash breaks MAC.
    let mut tampered = genuine.clone();
    tampered.result_hash[0] ^= 0xff;
    assert!(!crustcore.verify(&[tampered]).is_intact());
}

#[test]
#[ignore = "TODO(P8.5): secret never reaches model output / logs / telegram"]
fn secret_never_leaks_to_model() {}

#[test]
#[ignore = "TODO(P6.6): external worker writing outside the worktree is rejected"]
fn worker_write_outside_worktree_is_rejected() {}

#[test]
#[ignore = "TODO(P13.6): MCP server returning hidden instructions is treated as data"]
fn mcp_hidden_instructions_are_inert() {}
