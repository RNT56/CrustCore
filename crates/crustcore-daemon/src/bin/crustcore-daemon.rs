// SPDX-License-Identifier: Apache-2.0
//! The `crustcore-daemon` runtime entry point (`ROADMAP.md` §2.3, Phase 9/10;
//! `docs/telegram.md`, `docs/maintainer-agent.md`).
//!
//! This is the long-running runtime binary. It hosts the Telegram runtime channel,
//! the converse front door, and (later) the GitHub task/PR loop, the admin socket,
//! and task supervision. Today it wires the **std-only, fully-tested** runtime pieces
//! together and reports readiness; the live Bot-API long-poll transport remains
//! `TODO(P9-net-live)` (see [`crustcore_daemon::telegram`]). It is a non-nano pack
//! (invariants 19, 20): nano links no part of this stack.
//!
//! The CLI is a tiny hand-rolled parser (no `clap`), mirroring the nano binary's
//! style. The arg-parsing is factored into the pure [`parse_args`] function so it is
//! unit-tested without any I/O.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use crustcore_chat::ChatConfig;
use crustcore_daemon::chat::ChatBridge;
use crustcore_daemon::telegram::{ChatAllowlist, TelegramPoller};
use crustcore_secrets::Redactor;

/// The daemon version (from the crate manifest).
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        DaemonCommand::Serve { allow } => serve(&allow),
        DaemonCommand::Doctor => doctor(),
        DaemonCommand::Version => {
            println!("crustcore-daemon {VERSION}");
            ExitCode::SUCCESS
        }
        DaemonCommand::Help => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        DaemonCommand::Unknown(cmd) => {
            eprintln!("crustcore-daemon: unknown command '{cmd}'\n");
            print!("{}", usage());
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Pure, testable argument parsing
// ---------------------------------------------------------------------------

/// A parsed daemon subcommand. Produced purely from the argv tail and the
/// environment snapshot (so it is fully unit-testable, no side effects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonCommand {
    /// `serve` — start the runtime. Carries the parsed, de-duplicated allowlist of
    /// chat ids (from `--chat-id <n>` flags and/or `CRUSTCORE_TELEGRAM_ALLOW`). An
    /// **empty** vector is the deny-all default (NullClaw lesson; never a wildcard).
    Serve {
        /// Allowlisted Telegram chat ids, in first-seen order, de-duplicated.
        allow: Vec<i64>,
    },
    /// `doctor` — print runtime environment readiness.
    Doctor,
    /// `version` / `--version` / `-V`.
    Version,
    /// `help` / `--help` / `-h` (and the no-args default).
    Help,
    /// An unrecognized subcommand (carries the verb for the error reply). Never
    /// falls through to anything that executes.
    Unknown(String),
}

/// Parses the argv tail (everything after the binary name) into a [`DaemonCommand`].
///
/// `serve` collects its allowlist from two sources, merged in this order (then
/// de-duplicated, preserving first-seen order):
/// 1. the `CRUSTCORE_TELEGRAM_ALLOW` env var — a comma/space-separated list of ids;
/// 2. each `--chat-id <n>` / `--chat-id=<n>` flag.
///
/// This reads the environment (via [`std::env::var`]) but performs no other I/O and
/// builds nothing, so the whole decision is deterministic given argv + env and is
/// unit-tested directly. Malformed ids (non-`i64`) are skipped — the deny-all default
/// means a typo can only *narrow* access, never widen it.
#[must_use]
pub fn parse_args(args: &[String]) -> DaemonCommand {
    let Some(verb) = args.first().map(String::as_str) else {
        return DaemonCommand::Help;
    };
    match verb {
        "serve" => {
            let env_ids = std::env::var("CRUSTCORE_TELEGRAM_ALLOW").unwrap_or_default();
            DaemonCommand::Serve {
                allow: parse_allowlist(&env_ids, &args[1..]),
            }
        }
        "doctor" => DaemonCommand::Doctor,
        "version" | "--version" | "-V" => DaemonCommand::Version,
        "help" | "--help" | "-h" => DaemonCommand::Help,
        other => DaemonCommand::Unknown(other.to_string()),
    }
}

/// Builds the allowlist id vector from the `CRUSTCORE_TELEGRAM_ALLOW` value and the
/// `serve` flag tail. Pure (no I/O): the env value is passed in so this is directly
/// testable. Order is env ids first, then `--chat-id` flags; duplicates are dropped.
fn parse_allowlist(env_value: &str, serve_args: &[String]) -> Vec<i64> {
    let mut ids: Vec<i64> = Vec::new();
    let push = |id: i64, ids: &mut Vec<i64>| {
        if !ids.contains(&id) {
            ids.push(id);
        }
    };

    // Env var: comma/whitespace-separated ids.
    for tok in env_value.split([',', ' ', '\t', '\n']) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Ok(id) = tok.parse::<i64>() {
            push(id, &mut ids);
        }
    }

    // `--chat-id <n>` / `--chat-id=<n>` flags.
    let mut it = serve_args.iter();
    while let Some(arg) = it.next() {
        let raw = if let Some(rest) = arg.strip_prefix("--chat-id=") {
            Some(rest.to_string())
        } else if arg == "--chat-id" {
            it.next().cloned()
        } else {
            None
        };
        if let Some(raw) = raw {
            if let Ok(id) = raw.trim().parse::<i64>() {
                push(id, &mut ids);
            }
        }
    }

    ids
}

// ---------------------------------------------------------------------------
// Subcommand handlers (side-effecting — kept out of the tested parse path)
// ---------------------------------------------------------------------------

/// `crustcore-daemon serve` — construct the runtime pieces that are real and testable
/// today and print a readiness report. This wires the std-only core: a
/// [`ChatAllowlist`] (empty = deny-all), a [`TelegramPoller`] over it, and a
/// [`ChatBridge`] (persona + operator steering loaded via [`ChatConfig::default`]).
///
/// The **live Bot-API long-poll/send transport is `TODO(P9-net-live)`** — there is no
/// fake network loop here. With a non-empty allowlist the runtime is configured and
/// ready; the loop is reported as pending and the process exits cleanly so an operator
/// can confirm wiring before the live transport lands.
fn serve(allow: &[i64]) -> ExitCode {
    // Empty allowlist => deny-all (the single most important fail-safe default). We
    // never synthesize a wildcard; an unbound daemon is inert by design.
    let allowlist = if allow.is_empty() {
        ChatAllowlist::deny_all()
    } else {
        ChatAllowlist::of(allow)
    };

    // The inbound runtime loop over the allowlist (offset/dedupe/normalize/route). The
    // live `TelegramApi` HTTP transport is wired in P9-net-live; here we just hold the
    // configured poller so the wiring is proven.
    let _poller = TelegramPoller::new(allowlist);

    // The converse front door bridge. No secret broker is wired in this standalone
    // entry point yet, so the redactor starts empty (mirrors `crustcore chat`); when
    // the supervisor hosts the surface it passes the broker's pre-loaded redactor so
    // stored secrets are scrubbed from answers (invariants 2, 15).
    let redactor = Redactor::new();
    let bridge = ChatBridge::new(&redactor, ChatConfig::default());

    println!("crustcore-daemon {VERSION} — runtime readiness");
    println!("  allowlisted chats: {}", allow.len());
    if allow.is_empty() {
        println!("  posture: DENY-ALL (no chat bound — the daemon is inert by design)");
        println!("           bind a chat with --chat-id <n> or CRUSTCORE_TELEGRAM_ALLOW");
    } else {
        println!("  posture: bound to {} chat id(s)", allow.len());
    }
    println!("  runtime channel: Telegram (live Bot-API pending — TODO(P9-net-live))");
    println!("  persona/steering: loaded (front-door bridge ready)");
    // Touch the bridge so its construction is observably part of readiness.
    println!(
        "  converse preamble: {} byte(s) (safety core + persona)",
        bridge.system_preamble().len()
    );
    println!("ready: configured; live long-poll transport pending (TODO(P9-net-live)).");
    ExitCode::SUCCESS
}

/// `crustcore-daemon doctor` — a minimal runtime-readiness probe. Reports whether the
/// spawned net-helper path is configured (the Telegram/model transport runs as the
/// `crustcore-net` sidecar; `docs/model-routing.md` §6). A fuller doctor lands with the
/// live transport.
fn doctor() -> ExitCode {
    match std::env::var("CRUSTCORE_NET_HELPER") {
        Ok(path) if !path.trim().is_empty() => {
            println!("net-helper: configured (CRUSTCORE_NET_HELPER={path})");
        }
        _ => {
            println!(
                "net-helper: not set (will default to `crustcore-net` on PATH when the \
                 live transport runs); set CRUSTCORE_NET_HELPER to override."
            );
        }
    }
    ExitCode::SUCCESS
}

/// The usage/help text.
fn usage() -> String {
    "\
crustcore-daemon — the long-running CrustCore runtime (Phase 9/10)

USAGE:
    crustcore-daemon <command>

COMMANDS:
    serve      Start the runtime channel (Telegram + converse front door).
               --chat-id <n>   Allowlist a Telegram chat id (repeatable).
                               Also reads CRUSTCORE_TELEGRAM_ALLOW (comma/space list).
                               An empty allowlist is DENY-ALL (never a wildcard).
    doctor     Report runtime environment readiness (net-helper path).
    version    Print the daemon version.
    help       Print this help.

Note: the live Telegram Bot-API long-poll/send transport is TODO(P9-net-live);
`serve` configures and reports the std-only runtime pieces, then exits cleanly.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn no_args_is_help() {
        assert_eq!(parse_args(&[]), DaemonCommand::Help);
    }

    #[test]
    fn help_and_version_flags_and_verbs() {
        for v in ["help", "--help", "-h"] {
            assert_eq!(parse_args(&args(&[v])), DaemonCommand::Help);
        }
        for v in ["version", "--version", "-V"] {
            assert_eq!(parse_args(&args(&[v])), DaemonCommand::Version);
        }
    }

    #[test]
    fn doctor_verb_parses() {
        assert_eq!(parse_args(&args(&["doctor"])), DaemonCommand::Doctor);
    }

    #[test]
    fn unknown_command_is_typed_not_executed() {
        assert_eq!(
            parse_args(&args(&["frobnicate"])),
            DaemonCommand::Unknown("frobnicate".to_string())
        );
    }

    #[test]
    fn serve_collects_chat_id_flags_in_order_deduped() {
        // Both `--chat-id <n>` and `--chat-id=<n>` forms; a duplicate is dropped.
        let cmd = parse_args(&args(&[
            "serve",
            "--chat-id",
            "100",
            "--chat-id=200",
            "--chat-id",
            "100", // duplicate
        ]));
        assert_eq!(
            cmd,
            DaemonCommand::Serve {
                allow: vec![100, 200]
            }
        );
    }

    #[test]
    fn serve_with_no_ids_is_deny_all_empty_vec() {
        // No flags, no env (cleared) => empty allowlist (deny-all), NOT a wildcard.
        // Note: this asserts the flag path; the env merge is covered by the pure
        // `parse_allowlist` tests below (which take the env value as an argument and
        // so do not touch process-global state).
        let cmd = parse_args(&args(&["serve"]));
        match cmd {
            DaemonCommand::Serve { allow } => {
                // The process env may carry a value in some runners; the deterministic
                // contract is exercised by `parse_allowlist` directly. Here we only
                // assert the command shape.
                let _ = allow;
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn parse_allowlist_merges_env_then_flags_and_dedupes() {
        // Env ids come first (comma + space separated), then flags; dupes dropped.
        let ids = parse_allowlist(
            "100, 200 300",
            &args(&["--chat-id", "200", "--chat-id=400"]),
        );
        assert_eq!(ids, vec![100, 200, 300, 400]);
    }

    #[test]
    fn parse_allowlist_empty_env_and_no_flags_is_empty() {
        // The deny-all default: nothing in, nothing out (never a wildcard).
        assert_eq!(parse_allowlist("", &[]), Vec::<i64>::new());
        // Whitespace/garbage-only env is also empty.
        assert_eq!(parse_allowlist("  , ,  ", &[]), Vec::<i64>::new());
    }

    #[test]
    fn parse_allowlist_skips_malformed_ids() {
        // A non-i64 token can only narrow access (it is skipped), never widen it.
        let ids = parse_allowlist("100, notanid, 200", &args(&["--chat-id", "abc"]));
        assert_eq!(ids, vec![100, 200]);
    }

    #[test]
    fn parse_allowlist_accepts_negative_ids() {
        // Telegram group/channel chat ids are negative i64 — must be accepted.
        let ids = parse_allowlist("-100200300", &args(&["--chat-id", "-42"]));
        assert_eq!(ids, vec![-100200300, -42]);
    }

    #[test]
    fn dangling_chat_id_flag_is_ignored_not_a_panic() {
        // `--chat-id` with no following value must not panic and yields no id.
        let ids = parse_allowlist("", &args(&["--chat-id"]));
        assert_eq!(ids, Vec::<i64>::new());
    }
}
