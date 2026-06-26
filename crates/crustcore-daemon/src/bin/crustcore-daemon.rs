// SPDX-License-Identifier: Apache-2.0
//! The `crustcore-daemon` runtime entry point (`ROADMAP.md` §2.3, Phase 9/10;
//! `docs/chat.md`, `docs/telegram.md`).
//!
//! The long-running runtime binary. `serve` runs the live Telegram bot loop
//! (long-poll → dispatch → reply, launching verified tasks from chat); `serve --pair`
//! discovers your chat id. The live transport is gated on the `live` cargo feature; a
//! base build prints a readiness report and the rebuild hint. It is a non-nano pack
//! (invariants 19, 20): nano links no part of this stack.
//!
//! The CLI is a tiny hand-rolled parser (no `clap`). The arg-parsing is factored into
//! the pure [`parse_args`] / [`parse_serve_opts`] functions so it is unit-tested without
//! any I/O.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use crustcore_daemon::telegram::ChatAllowlist;

/// The daemon version (from the crate manifest).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The env var carrying the BotFather token (a credential — never an arg, never logged).
const TOKEN_ENV: &str = "CRUSTCORE_TELEGRAM_TOKEN";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        DaemonCommand::Serve(opts) => serve(&opts),
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

/// Options for `serve`, parsed purely from argv + env (no side effects, so fully
/// unit-testable). The bot **token is not here** — it is a credential read from the
/// environment at serve time, kept out of the parsed/logged struct.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServeOpts {
    /// Allowlisted Telegram chat ids (first-seen order, de-duplicated). Empty = deny-all.
    pub allow: Vec<i64>,
    /// `--pair`: run chat-id discovery instead of the bot loop.
    pub pair: bool,
    /// `--dir <repo>`: the repo a chat-launched task runs against.
    pub dir: Option<String>,
    /// `--verify <cmd>`: the verify command (split, no shell); empty = detect.
    pub verify: Option<String>,
    /// `--backend native|codex|claude`: the coding backend for chat-launched tasks.
    pub backend: Option<String>,
    /// `--helper <path>`: the `crustcore-net` helper to spawn for model calls.
    pub helper: Option<String>,
    /// `--open-pr`: when a chat task verifies, open a **draft** PR (each launch is gated
    /// on a human approval). Requires `--repo`.
    pub open_pr: bool,
    /// `--repo <owner/name>`: the repository draft PRs target.
    pub repo: Option<String>,
    /// `--base <branch>`: the base branch a draft PR targets (default `main`).
    pub base: Option<String>,
    /// `--branch-prefix <prefix>`: the prefix the PR head branch is confined under
    /// (default `crustcore`).
    pub branch_prefix: Option<String>,
}

/// A parsed daemon subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonCommand {
    /// `serve` — start the runtime (or `--pair`).
    Serve(ServeOpts),
    /// `doctor` — print runtime environment readiness.
    Doctor,
    /// `version` / `--version` / `-V`.
    Version,
    /// `help` / `--help` / `-h` (and the no-args default).
    Help,
    /// An unrecognized subcommand (carries the verb for the error reply).
    Unknown(String),
}

/// Parses the argv tail into a [`DaemonCommand`]. Reads `CRUSTCORE_TELEGRAM_ALLOW` for
/// the `serve` allowlist (merged before `--chat-id` flags) but performs no other I/O.
#[must_use]
pub fn parse_args(args: &[String]) -> DaemonCommand {
    let Some(verb) = args.first().map(String::as_str) else {
        return DaemonCommand::Help;
    };
    match verb {
        "serve" => {
            let env_ids = std::env::var("CRUSTCORE_TELEGRAM_ALLOW").unwrap_or_default();
            DaemonCommand::Serve(parse_serve_opts(&env_ids, &args[1..]))
        }
        "doctor" => DaemonCommand::Doctor,
        "version" | "--version" | "-V" => DaemonCommand::Version,
        "help" | "--help" | "-h" => DaemonCommand::Help,
        other => DaemonCommand::Unknown(other.to_string()),
    }
}

/// Builds [`ServeOpts`] from the `CRUSTCORE_TELEGRAM_ALLOW` value and the `serve` flag
/// tail. Pure (env value passed in) so it is directly testable. Both `--flag <v>` and
/// `--flag=<v>` are accepted; an unknown flag is ignored.
#[must_use]
pub fn parse_serve_opts(env_allow: &str, serve_args: &[String]) -> ServeOpts {
    let mut opts = ServeOpts {
        allow: parse_allowlist(env_allow, serve_args),
        ..ServeOpts::default()
    };
    let mut it = serve_args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--pair" => opts.pair = true,
            a if a.starts_with("--dir") => opts.dir = flag_value(a, "--dir", &mut it),
            a if a.starts_with("--verify") => opts.verify = flag_value(a, "--verify", &mut it),
            a if a.starts_with("--backend") => opts.backend = flag_value(a, "--backend", &mut it),
            a if a.starts_with("--helper") => opts.helper = flag_value(a, "--helper", &mut it),
            "--open-pr" => opts.open_pr = true,
            a if a.starts_with("--repo") => opts.repo = flag_value(a, "--repo", &mut it),
            a if a.starts_with("--base") => opts.base = flag_value(a, "--base", &mut it),
            a if a.starts_with("--branch-prefix") => {
                opts.branch_prefix = flag_value(a, "--branch-prefix", &mut it)
            }
            _ => {}
        }
    }
    opts
}

/// Resolves a `--name=value` (inline) or `--name value` (next-token) flag value.
fn flag_value(arg: &str, name: &str, it: &mut std::slice::Iter<'_, String>) -> Option<String> {
    if let Some(inline) = arg.strip_prefix(&format!("{name}=")) {
        Some(inline.to_string())
    } else if arg == name {
        it.next().cloned()
    } else {
        None
    }
}

/// Builds the allowlist id vector from `CRUSTCORE_TELEGRAM_ALLOW` and the `--chat-id`
/// flags. Pure. Env ids first, then flags; duplicates dropped; malformed ids skipped.
fn parse_allowlist(env_value: &str, serve_args: &[String]) -> Vec<i64> {
    let mut ids: Vec<i64> = Vec::new();
    let mut push = |id: i64| {
        if !ids.contains(&id) {
            ids.push(id);
        }
    };
    for tok in env_value.split([',', ' ', '\t', '\n']) {
        if let Ok(id) = tok.trim().parse::<i64>() {
            push(id);
        }
    }
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
                push(id);
            }
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Subcommand handlers (side-effecting — kept out of the tested parse path)
// ---------------------------------------------------------------------------

/// `crustcore-daemon serve` — run the runtime. With the `live` feature and a bot token,
/// this is the **actual running bot**: it long-polls Telegram, answers/steers/launches
/// tasks from the allowlisted chat, and gates irreversible actions on `/approve`. Without
/// a token it prints the setup hint; without the `live` feature, a readiness report.
fn serve(opts: &ServeOpts) -> ExitCode {
    let allowlist = if opts.allow.is_empty() {
        ChatAllowlist::deny_all()
    } else {
        ChatAllowlist::of(&opts.allow)
    };
    let token = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.trim().is_empty());

    #[cfg(feature = "live")]
    {
        match token {
            Some(token) => serve_live(opts, allowlist, token),
            None => {
                eprintln!(
                    "crustcore-daemon serve: no bot token. Create one with @BotFather, then:"
                );
                eprintln!("  export {TOKEN_ENV}=<token>");
                eprintln!("  crustcore-daemon serve --pair            # discover your chat id");
                eprintln!("  crustcore-daemon serve --chat-id <id> --dir <repo> --verify '<cmd>'");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = token;
        readiness_report(opts, &allowlist);
        ExitCode::SUCCESS
    }
}

#[cfg(feature = "live")]
fn serve_live(opts: &ServeOpts, allowlist: ChatAllowlist, token: String) -> ExitCode {
    use crustcore_chat::{OperatorSteering, Persona};
    use crustcore_daemon::runtime::{run_pair_discovery, run_serve_loop, ServeConfig};

    if opts.pair {
        return match run_pair_discovery(&token, 1000) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("crustcore-daemon serve --pair: {e}");
                ExitCode::from(1)
            }
        };
    }

    if opts.allow.is_empty() {
        eprintln!("crustcore-daemon serve: DENY-ALL (no --chat-id bound) — the bot will ignore");
        eprintln!("  every message. Run `serve --pair` to find your id, then bind it.");
    }

    let helper = opts
        .helper
        .clone()
        .or_else(|| std::env::var("CRUSTCORE_NET_HELPER").ok())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "crustcore-net".to_string());

    // Persona + operator steering from the trusted project root (both optional, tone/
    // guidance only — scoped below the fixed safety preamble).
    let persona = std::fs::read_to_string("persona.md")
        .map(|s| Persona::from_markdown(&s))
        .unwrap_or_default();
    let steering = ["CRUSTCORE.md", "AGENTS.md"]
        .iter()
        .find_map(|f| std::fs::read_to_string(f).ok())
        .map(|s| OperatorSteering::from_content(&s))
        .unwrap_or_default();

    let task = build_task_spec(opts);
    if task.is_none() {
        eprintln!(
            "crustcore-daemon serve: no --dir given — I'll chat, but task execution is off \
             (add --dir <repo> --verify '<cmd>' to enable it)."
        );
    }

    let config = ServeConfig {
        allowlist,
        bot_token: token,
        helper_program: helper,
        persona,
        steering,
        task,
        poll_backoff_ms: 1000,
    };
    match run_serve_loop(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("crustcore-daemon serve: {e}");
            eprintln!("  (the model transport runs as the spawned `crustcore-net` helper; set");
            eprintln!("   CRUSTCORE_NET_HELPER or put a `live`-built crustcore-net on PATH.)");
            ExitCode::from(1)
        }
    }
}

/// Build the chat-launched task target from `--dir`/`--verify`/`--backend`, or `None`
/// when `--dir` is absent (chat still works; execution is off).
#[cfg(feature = "live")]
fn build_task_spec(opts: &ServeOpts) -> Option<crustcore_daemon::task::TaskSpec> {
    use crustcore_daemon::task::{PrTarget, TaskBackend, TaskSpec};
    let dir = opts.dir.as_deref()?;
    let repo_root = std::fs::canonicalize(dir).ok()?;
    let verify = opts
        .verify
        .as_deref()
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let backend = match opts.backend.as_deref() {
        Some("codex") => TaskBackend::Codex,
        Some("claude") => TaskBackend::ClaudeCode,
        // `native` (default) verifies the worktree as-is; `cmd` needs a worker command
        // this minimal entry does not yet take, so it degrades to native.
        _ => TaskBackend::Native,
    };
    // PR mode is opt-in (`--open-pr --repo owner/name`): a verified task opens a *draft*
    // PR, gated on a per-launch human approval. Without `--repo` it stays off (no PR).
    let pr = if opts.open_pr {
        opts.repo.as_deref().map(|repo| PrTarget {
            repo: repo.to_string(),
            base_branch: opts.base.clone().unwrap_or_else(|| "main".to_string()),
            branch_prefix: opts
                .branch_prefix
                .clone()
                .unwrap_or_else(|| "crustcore".to_string()),
        })
    } else {
        None
    };
    Some(TaskSpec {
        repo_root,
        verify,
        backend,
        pr,
    })
}

/// The readiness report printed by a non-`live` build (the std-only pieces are wired and
/// tested; only the HTTP transport is feature-gated).
#[cfg(not(feature = "live"))]
fn readiness_report(opts: &ServeOpts, _allowlist: &ChatAllowlist) {
    println!("crustcore-daemon {VERSION} — runtime readiness (base build)");
    println!("  allowlisted chats: {}", opts.allow.len());
    if opts.allow.is_empty() {
        println!("  posture: DENY-ALL (no chat bound — inert by design)");
    } else {
        println!("  posture: bound to {} chat id(s)", opts.allow.len());
    }
    println!("  runtime channel: Telegram — rebuild with `--features live` to run the bot.");
    println!("ready: std-only pieces wired; live transport is feature-gated.");
}

/// `crustcore-daemon doctor` — a minimal readiness probe.
fn doctor() -> ExitCode {
    match std::env::var("CRUSTCORE_NET_HELPER") {
        Ok(path) if !path.trim().is_empty() => {
            println!("net-helper: configured (CRUSTCORE_NET_HELPER={path})");
        }
        _ => println!(
            "net-helper: not set (defaults to `crustcore-net` on PATH); set \
             CRUSTCORE_NET_HELPER to override."
        ),
    }
    match std::env::var(TOKEN_ENV) {
        Ok(t) if !t.trim().is_empty() => println!("bot-token: set ({TOKEN_ENV})"),
        _ => {
            println!("bot-token: not set — `export {TOKEN_ENV}=<BotFather token>` to run the bot.")
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
    serve      Run the Telegram bot (long-poll → answer/steer/launch tasks).
               --pair             Discover your chat id (message the bot; it prints it).
               --chat-id <n>      Allowlist a chat id (repeatable). Empty = DENY-ALL.
                                  Also reads CRUSTCORE_TELEGRAM_ALLOW (comma/space list).
               --dir <repo>       Repo a chat-launched task runs against.
               --verify <cmd>     Verify command (split, no shell); empty = auto-detect.
               --backend <b>      native|codex|claude (default native).
               --helper <path>    crustcore-net helper to spawn (or CRUSTCORE_NET_HELPER).
               --open-pr          On a verified task, open a DRAFT PR (each launch is
                                  gated on your approval). Requires --repo.
               --repo <o/n>       Repository draft PRs target (owner/name).
               --base <branch>    Base branch a draft PR targets (default main).
               --branch-prefix <p>  Head-branch prefix (default crustcore).
               Requires CRUSTCORE_TELEGRAM_TOKEN=<BotFather token> and a `live` build.
    doctor     Report runtime environment readiness.
    version    Print the daemon version.
    help       Print this help.

SETUP:
    1. @BotFather → create a bot → copy the token.
    2. export CRUSTCORE_TELEGRAM_TOKEN=<token>
    3. crustcore-daemon serve --pair          (message the bot; note your chat id)
    4. crustcore-daemon serve --chat-id <id> --dir . --verify 'cargo test'
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
        let opts = parse_serve_opts(
            "",
            &args(&["--chat-id", "100", "--chat-id=200", "--chat-id", "100"]),
        );
        assert_eq!(opts.allow, vec![100, 200]);
        assert!(!opts.pair);
    }

    #[test]
    fn serve_parses_pair_dir_verify_backend_helper() {
        let opts = parse_serve_opts(
            "",
            &args(&[
                "--pair",
                "--dir",
                "/repo",
                "--verify=cargo test",
                "--backend",
                "codex",
                "--helper=/bin/crustcore-net",
            ]),
        );
        assert!(opts.pair);
        assert_eq!(opts.dir.as_deref(), Some("/repo"));
        assert_eq!(opts.verify.as_deref(), Some("cargo test"));
        assert_eq!(opts.backend.as_deref(), Some("codex"));
        assert_eq!(opts.helper.as_deref(), Some("/bin/crustcore-net"));
    }

    #[test]
    fn serve_parses_pr_flags() {
        let opts = parse_serve_opts(
            "",
            &args(&[
                "--open-pr",
                "--repo",
                "owner/name",
                "--base=develop",
                "--branch-prefix",
                "bots",
            ]),
        );
        assert!(opts.open_pr);
        assert_eq!(opts.repo.as_deref(), Some("owner/name"));
        assert_eq!(opts.base.as_deref(), Some("develop"));
        assert_eq!(opts.branch_prefix.as_deref(), Some("bots"));
        // Off by default (no --open-pr → no PR mode even if --repo is given).
        let off = parse_serve_opts("", &args(&["--repo", "owner/name"]));
        assert!(!off.open_pr);
    }

    #[test]
    fn parse_allowlist_merges_env_then_flags_and_dedupes() {
        let ids = parse_allowlist(
            "100, 200 300",
            &args(&["--chat-id", "200", "--chat-id=400"]),
        );
        assert_eq!(ids, vec![100, 200, 300, 400]);
    }

    #[test]
    fn parse_allowlist_empty_is_deny_all() {
        assert_eq!(parse_allowlist("", &[]), Vec::<i64>::new());
        assert_eq!(parse_allowlist("  , ,  ", &[]), Vec::<i64>::new());
    }

    #[test]
    fn parse_allowlist_skips_malformed_and_accepts_negative() {
        assert_eq!(
            parse_allowlist("100, notanid, 200", &args(&["--chat-id", "abc"])),
            vec![100, 200]
        );
        assert_eq!(
            parse_allowlist("-100200300", &args(&["--chat-id", "-42"])),
            vec![-100200300, -42]
        );
    }

    #[test]
    fn dangling_chat_id_flag_is_ignored_not_a_panic() {
        assert_eq!(
            parse_allowlist("", &args(&["--chat-id"])),
            Vec::<i64>::new()
        );
    }
}
