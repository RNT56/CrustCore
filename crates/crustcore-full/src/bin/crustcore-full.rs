// SPDX-License-Identifier: Apache-2.0
//! `crustcore-full` — the **single-binary, casual-user** front door.
//!
//! The architecture is multi-binary by design (a sub-800kB trusted `crustcore` that
//! *spawns* a `crustcore-net` model helper and an optional `crustcore-daemon` bot). That is
//! the right shape for the trusted core, but it is three artifacts + PATH + env wiring — too
//! much for a casual default. This binary is the convenience all-in-one: **one download**
//! that bundles the chat front door, the Telegram bot, and the model helper, and **spawns
//! itself** as that helper (busybox-style), so there is nothing to put on PATH.
//!
//! ```text
//!   crustcore-full chat                 # terminal conversational agent
//!   crustcore-full serve --pair         # discover your Telegram chat id
//!   crustcore-full serve --chat-id <id> --dir . --verify 'cargo test'
//!   crustcore-full setup                # write a config-file template
//! ```
//!
//! It reads a simple `KEY=VALUE` config file (model keys, bot token, an optional provider
//! config) so a casual user never juggles shell env vars. It is **never** the flagship size
//! claim (nano is) and links none of the heavy stacks into nano — it is a separate package
//! built with `--features all`. The trusted boundary is unchanged: this binary only *wires*
//! the existing, tested entry points (`crustcore_chat::run_terminal`,
//! `crustcore_daemon::runtime::run_serve_loop`, the `crustcore_net` helper engine) together;
//! every safety property (redaction, allowlist, sandbox, verifier-owned completion) lives in
//! those, not here.
//!
//! ## Self-spawn
//!
//! On startup the binary checks `CRUSTCORE_FULL_HELPER`: if set, it *is* the spawned model
//! helper and runs the helper loop (live if a provider config is configured, else mock). A
//! normal launch sets that marker + points `CRUSTCORE_NET_HELPER` at its own executable, so
//! when the chat/serve loops spawn "the helper" they re-launch this same binary in helper
//! mode. No change to the spawn protocol is needed.
#![forbid(unsafe_code)]

use std::process::ExitCode;

// The env-var names below are used only by the `all`-gated runtime glue; gate them so the
// default (no-`all`) build of this bin has no dead constants under `-D warnings`.
/// The marker env var that puts a re-launched instance into model-helper mode (see module
/// docs). Checked before anything else; set by a normal launch for its children.
#[cfg(feature = "all")]
const ENV_HELPER_MODE: &str = "CRUSTCORE_FULL_HELPER";
/// The helper path the chat/serve loops spawn. A normal launch sets it to this executable.
#[cfg(feature = "all")]
const ENV_NET_HELPER: &str = "CRUSTCORE_NET_HELPER";
/// Path to a provider config (JSON, the `crustcore-net` format). Present ⇒ helper goes live.
#[cfg(feature = "all")]
const ENV_PROVIDERS: &str = "CRUSTCORE_NET_PROVIDERS";
/// The Telegram bot token (BotFather). Never an argv; never logged.
#[cfg(feature = "all")]
const ENV_TOKEN: &str = "CRUSTCORE_TELEGRAM_TOKEN";
/// Allowlisted Telegram chat ids (comma/space list), merged with `--chat-id` flags.
#[cfg(feature = "all")]
const ENV_ALLOW: &str = "CRUSTCORE_TELEGRAM_ALLOW";
/// An explicit config-file path (overrides the default search).
#[cfg(feature = "all")]
const ENV_CONFIG: &str = "CRUSTCORE_CONFIG";

// ---------------------------------------------------------------------------
// Pure, always-compiled, CI-tested: config-file + command parsing.
// ---------------------------------------------------------------------------

/// Parse a `KEY=VALUE` config file into `(key, value)` pairs. Blank lines and `#` comments
/// are skipped; the split is on the **first** `=`; surrounding ASCII whitespace and one pair
/// of matching single/double quotes around the value are stripped. A line without `=` is
/// ignored. Pure and bounded — this is the casual-user alternative to exporting shell vars.
#[must_use]
pub fn parse_config(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = v.trim();
        // Strip one matching pair of surrounding quotes.
        for q in ['"', '\''] {
            if val.len() >= 2 && val.starts_with(q) && val.ends_with(q) {
                val = &val[1..val.len() - 1];
                break;
            }
        }
        out.push((key.to_string(), val.to_string()));
    }
    out
}

/// The subcommand a user invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    /// `chat` — the terminal conversational front door.
    Chat,
    /// `serve <flags…>` — the Telegram bot (carries the remaining args).
    Serve(Vec<String>),
    /// `doctor` — environment readiness.
    Doctor,
    /// `setup` — write a config-file template.
    Setup,
    /// `version`.
    Version,
    /// `help` / no args / unknown.
    Help,
    /// The hidden model-helper mode (also reached via the `CRUSTCORE_FULL_HELPER` env marker).
    NetHelper,
}

/// Classify argv (after the program name) into a [`Cmd`]. Pure + testable.
#[must_use]
pub fn parse_cmd(args: &[String]) -> Cmd {
    match args.first().map(String::as_str) {
        Some("chat") => Cmd::Chat,
        Some("serve") => Cmd::Serve(args[1..].to_vec()),
        Some("doctor") => Cmd::Doctor,
        Some("setup") => Cmd::Setup,
        Some("version" | "--version" | "-V") => Cmd::Version,
        // Hidden: the self-spawned helper mode.
        Some("net-helper" | "__net-helper") => Cmd::NetHelper,
        _ => Cmd::Help,
    }
}

/// The default config-file path: `$CRUSTCORE_CONFIG`, else `$HOME/.config/crustcore/config`,
/// else `./crustcore.conf`. Pure given the two env inputs (passed in for testability).
#[must_use]
pub fn config_path(explicit: Option<&str>, home: Option<&str>) -> String {
    if let Some(p) = explicit {
        return p.to_string();
    }
    if let Some(h) = home {
        return format!("{h}/.config/crustcore/config");
    }
    "crustcore.conf".to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    #[cfg(feature = "all")]
    {
        full::run(args)
    }
    #[cfg(not(feature = "all"))]
    {
        let _ = args;
        eprintln!(
            "crustcore-full: this binary bundles the full runtime (chat + Telegram bot + \
             model helper).\nRebuild it with the all-in-one features:\n  \
             cargo build --release -p crustcore-full --features all"
        );
        ExitCode::from(2)
    }
}

// ---------------------------------------------------------------------------
// The runtime glue — only with `--features all` (links chat + daemon + net live).
// ---------------------------------------------------------------------------
#[cfg(feature = "all")]
mod full {
    use std::process::ExitCode;

    use super::{
        config_path, parse_cmd, parse_config, Cmd, ENV_ALLOW, ENV_CONFIG, ENV_HELPER_MODE,
        ENV_NET_HELPER, ENV_PROVIDERS, ENV_TOKEN,
    };

    pub fn run(args: Vec<String>) -> ExitCode {
        // 1. Helper mode FIRST — before we set the marker for children. A re-launched
        //    instance (or an explicit `net-helper`) becomes the spawned model transport.
        if std::env::var(ENV_HELPER_MODE).is_ok() || parse_cmd(&args) == Cmd::NetHelper {
            return run_net_helper();
        }
        // 2. Load the config file into the environment (real env wins; file fills the gaps).
        load_config_into_env();
        // 3. Become self-contained: point the helper at THIS executable + arm helper mode so
        //    the chat/serve loops spawn us in helper mode (busybox-style self-spawn).
        if let Ok(exe) = std::env::current_exe() {
            std::env::set_var(ENV_NET_HELPER, exe);
        }
        std::env::set_var(ENV_HELPER_MODE, "1");
        // 4. Dispatch.
        match parse_cmd(&args) {
            Cmd::Chat => chat(),
            Cmd::Serve(rest) => serve(&rest),
            Cmd::Doctor => doctor(),
            Cmd::Setup => setup(),
            Cmd::Version => {
                println!("crustcore-full {}", crustcore_full::VERSION);
                ExitCode::SUCCESS
            }
            Cmd::NetHelper => run_net_helper(),
            Cmd::Help => {
                print!("{}", usage());
                ExitCode::SUCCESS
            }
        }
    }

    /// Load the config file's `KEY=VALUE` pairs into the process environment — but only for
    /// keys not already set, so a real shell env var always wins over the file.
    fn load_config_into_env() {
        let explicit = std::env::var(ENV_CONFIG).ok();
        let home = std::env::var("HOME").ok();
        let path = config_path(explicit.as_deref(), home.as_deref());
        if let Ok(content) = std::fs::read_to_string(&path) {
            for (k, v) in parse_config(&content) {
                if std::env::var(&k).is_err() {
                    std::env::set_var(&k, &v);
                }
            }
        }
    }

    /// The bundled model-helper loop: serve the routing engine over stdin/stdout (the
    /// std-only `crustcore-netproto`). Live if a provider config is configured, else the
    /// deterministic mock — identical loop to the standalone `crustcore-net` helper.
    fn run_net_helper() -> ExitCode {
        let mut engine = match std::env::var(ENV_PROVIDERS) {
            Ok(path) => match build_live_engine(&path) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("crustcore-full helper: {e}");
                    return ExitCode::from(2);
                }
            },
            Err(_) => crustcore_net::default_mock_multimodal_engine(),
        };
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        match engine.serve(&mut reader, &mut writer) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("crustcore-full helper: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Build a live multi-modal engine from a provider config (JSON). Credentials are
    /// resolved per provider from `CRUSTCORE_NET_KEY_<LABEL>` at call time — never inlined in
    /// the config, never handed to a model (invariant 1). Mirrors the standalone helper.
    fn build_live_engine(path: &str) -> Result<crustcore_net::MultiModalEngine, String> {
        use std::rc::Rc;
        let json = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        let configs = crustcore_net::config::parse_providers(&json)?;
        let mut creds = crustcore_net::credsource::StaticCredentials::new();
        for cfg in &configs {
            if let Some(label) = &cfg.secret_label {
                let var = format!(
                    "CRUSTCORE_NET_KEY_{}",
                    label.to_ascii_uppercase().replace('-', "_")
                );
                if let Ok(key) = std::env::var(&var) {
                    creds = creds.with(label, &key);
                }
            }
        }
        Ok(crustcore_net::live_multimodal_engine(
            &configs,
            Rc::new(creds) as Rc<dyn crustcore_net::credsource::CredentialSource>,
        ))
    }

    /// Persona + operator steering from the trusted project root (both optional; tone only,
    /// scoped below the fixed safety preamble). Shared by `chat` and `serve`.
    fn load_persona_steering() -> (crustcore_chat::Persona, crustcore_chat::OperatorSteering) {
        use crustcore_chat::{OperatorSteering, Persona};
        let persona = std::fs::read_to_string("persona.md")
            .map(|s| Persona::from_markdown(&s))
            .unwrap_or_default();
        let steering = ["CRUSTCORE.md", "AGENTS.md"]
            .iter()
            .find_map(|f| std::fs::read_to_string(f).ok())
            .map(|s| OperatorSteering::from_content(&s))
            .unwrap_or_default();
        (persona, steering)
    }

    /// The terminal conversational front door — reuses `crustcore_chat::run_terminal`, with
    /// the model helper resolved to this very binary (helper mode).
    fn chat() -> ExitCode {
        use crustcore_chat::{run_terminal, ChatConfig};
        use crustcore_secrets::Redactor;

        let helper = std::env::var(ENV_NET_HELPER).unwrap_or_else(|_| "crustcore-net".into());
        let (persona, steering) = load_persona_steering();
        let config = ChatConfig {
            persona,
            steering,
            ..ChatConfig::default()
        };
        let redactor = Redactor::new();
        println!(
            "crustcore-full chat — type a message; `!text` steers, `/cancel` aborts, Ctrl-D exits."
        );
        match run_terminal(&helper, &[], &redactor, config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("crustcore-full chat: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// The Telegram bot — reuses `crustcore_daemon::runtime::run_serve_loop` /
    /// `run_pair_discovery`, with this binary as the bundled model helper. Minimal flags:
    /// `--pair`, `--chat-id <id>` (repeatable), `--dir <repo>`, `--verify <cmd>`.
    fn serve(args: &[String]) -> ExitCode {
        use crustcore_daemon::runtime::{run_pair_discovery, run_serve_loop, ServeConfig};
        use crustcore_daemon::task::{TaskBackend, TaskSpec};
        use crustcore_daemon::telegram::ChatAllowlist;

        let mut pair = false;
        let mut ids: Vec<i64> = Vec::new();
        let mut dir: Option<String> = None;
        let mut verify: Option<String> = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--pair" => pair = true,
                "--chat-id" => {
                    if let Some(v) = it.next() {
                        if let Ok(n) = v.trim().parse() {
                            ids.push(n);
                        }
                    }
                }
                "--dir" => dir = it.next().cloned(),
                "--verify" => verify = it.next().cloned(),
                _ => {}
            }
        }
        // Merge the env allowlist (comma/space list) with the --chat-id flags.
        if let Ok(env_ids) = std::env::var(ENV_ALLOW) {
            for tok in env_ids.split([',', ' ', '\t']) {
                if let Ok(n) = tok.trim().parse() {
                    if !ids.contains(&n) {
                        ids.push(n);
                    }
                }
            }
        }

        let token = match std::env::var(ENV_TOKEN) {
            Ok(t) if !t.trim().is_empty() => t,
            _ => {
                eprintln!(
                    "crustcore-full serve: no Telegram bot token.\n  Create one with \
                     @BotFather, then add it to your config file or:\n  export \
                     {ENV_TOKEN}=<token>   (then `serve --pair` to find your chat id)"
                );
                return ExitCode::from(2);
            }
        };

        if pair {
            return match run_pair_discovery(&token, 1000) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("crustcore-full serve --pair: {e}");
                    ExitCode::from(1)
                }
            };
        }

        let helper = std::env::var(ENV_NET_HELPER).unwrap_or_else(|_| "crustcore-net".into());
        let (persona, steering) = load_persona_steering();
        let task = dir.as_deref().and_then(|d| {
            std::fs::canonicalize(d).ok().map(|repo_root| TaskSpec {
                repo_root,
                verify: verify
                    .as_deref()
                    .map(|v| v.split_whitespace().map(str::to_string).collect())
                    .unwrap_or_default(),
                backend: TaskBackend::Native,
                pr: None,
            })
        });
        if dir.is_some() && task.is_none() {
            eprintln!("crustcore-full serve: --dir path not found; running chat-only.");
        }

        let config = ServeConfig {
            allowlist: ChatAllowlist::of(&ids),
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
                eprintln!("crustcore-full serve: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Environment readiness for a casual user.
    fn doctor() -> ExitCode {
        println!("crustcore-full {} — readiness", crustcore_full::VERSION);
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into());
        println!("  self (bundled model helper): {exe}");
        let have = |k: &str| {
            if std::env::var(k)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                "set"
            } else {
                "unset"
            }
        };
        println!("  {ENV_TOKEN}: {} (Telegram bot)", have(ENV_TOKEN));
        println!(
            "  {ENV_PROVIDERS}: {} (live models if set, else mock)",
            have(ENV_PROVIDERS)
        );
        let home = std::env::var("HOME").ok();
        let cfg = config_path(std::env::var(ENV_CONFIG).ok().as_deref(), home.as_deref());
        let cfg_state = if std::path::Path::new(&cfg).exists() {
            "present"
        } else {
            "absent (run `crustcore-full setup`)"
        };
        println!("  config file: {cfg} — {cfg_state}");
        ExitCode::SUCCESS
    }

    /// Write a starter config file (it does not overwrite an existing one).
    fn setup() -> ExitCode {
        let home = std::env::var("HOME").ok();
        let path = config_path(std::env::var(ENV_CONFIG).ok().as_deref(), home.as_deref());
        if std::path::Path::new(&path).exists() {
            println!("crustcore-full: config already exists at {path} (left unchanged).");
            return ExitCode::SUCCESS;
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let template = "\
# crustcore-full config — KEY=VALUE, '#' comments. A real shell env var overrides a line here.
# Telegram bot token from @BotFather (for `crustcore-full serve`):
# CRUSTCORE_TELEGRAM_TOKEN=123456:ABC-DEF...
# Allowlisted Telegram chat ids (comma/space list), or pass --chat-id:
# CRUSTCORE_TELEGRAM_ALLOW=
# Live model providers: a path to a crustcore-net provider config (JSON). Omit for mock.
# CRUSTCORE_NET_PROVIDERS=~/.config/crustcore/providers.json
# Per-provider keys (one per provider label in that config):
# CRUSTCORE_NET_KEY_ANTHROPIC=sk-ant-...
";
        match std::fs::write(&path, template) {
            Ok(()) => {
                println!("crustcore-full: wrote a config template to {path}");
                println!(
                    "  edit it, then run `crustcore-full chat` or `crustcore-full serve --pair`."
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("crustcore-full setup: cannot write {path}: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn usage() -> String {
        "\
crustcore-full — the single-binary CrustCore (chat + Telegram bot + bundled model helper)

USAGE:
    crustcore-full <command>

COMMANDS:
    chat                 Terminal conversational agent.
    serve --pair         Discover your Telegram chat id (message the bot).
    serve --chat-id <id> --dir <repo> --verify '<cmd>'
                         Run the Telegram bot, bound to a chat + repo.
    setup                Write a config-file template (token + model keys).
    doctor               Report readiness.
    version              Print the version.
    help                 This listing.

The model helper is bundled — this binary spawns itself; nothing to put on PATH. Set live
model providers via CRUSTCORE_NET_PROVIDERS (else deterministic mock). Config file:
$CRUSTCORE_CONFIG, else $HOME/.config/crustcore/config.
"
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_reads_pairs_skips_comments_and_strips_quotes() {
        let cfg = "\
# a comment
CRUSTCORE_TELEGRAM_TOKEN = 123:abc

CRUSTCORE_NET_KEY_ANTHROPIC=\"sk-ant-xyz\"
CRUSTCORE_NET_PROVIDERS='/p/providers.json'
malformed line without equals
=novalue
KEY=a=b=c
";
        let got = parse_config(cfg);
        assert_eq!(
            got,
            vec![
                ("CRUSTCORE_TELEGRAM_TOKEN".into(), "123:abc".into()),
                ("CRUSTCORE_NET_KEY_ANTHROPIC".into(), "sk-ant-xyz".into()),
                ("CRUSTCORE_NET_PROVIDERS".into(), "/p/providers.json".into()),
                // split on FIRST '='; the rest of the value is kept verbatim.
                ("KEY".into(), "a=b=c".into()),
            ]
        );
    }

    #[test]
    fn parse_cmd_classifies_subcommands() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_cmd(&v(&["chat"])), Cmd::Chat);
        assert_eq!(parse_cmd(&v(&["doctor"])), Cmd::Doctor);
        assert_eq!(parse_cmd(&v(&["setup"])), Cmd::Setup);
        assert_eq!(parse_cmd(&v(&["version"])), Cmd::Version);
        assert_eq!(parse_cmd(&v(&["net-helper"])), Cmd::NetHelper);
        assert_eq!(parse_cmd(&v(&["__net-helper"])), Cmd::NetHelper);
        assert_eq!(
            parse_cmd(&v(&["serve", "--pair"])),
            Cmd::Serve(vec!["--pair".into()])
        );
        assert_eq!(parse_cmd(&v(&[])), Cmd::Help);
        assert_eq!(parse_cmd(&v(&["bogus"])), Cmd::Help);
    }

    #[test]
    fn config_path_prefers_explicit_then_home_then_cwd() {
        assert_eq!(config_path(Some("/x/cfg"), Some("/home/u")), "/x/cfg");
        assert_eq!(
            config_path(None, Some("/home/u")),
            "/home/u/.config/crustcore/config"
        );
        assert_eq!(config_path(None, None), "crustcore.conf");
    }
}
