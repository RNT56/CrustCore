// SPDX-License-Identifier: Apache-2.0
//! OS keychain secret loaders (P8-store): macOS Keychain + Linux Secret Service.
//!
//! Behind the `macos-keychain` / `linux-keyring` cargo features; **never in nano**
//! (the `forbidden-deps` gate proves nano links neither). Like the encrypted-file
//! vault ([`crate::store`]), a keychain backend is a **loader** that fetches secrets
//! *into* an [`InMemoryStore`] the broker reads — it does not implement the
//! borrow-returning [`SecretStore`](crate::SecretStore) trait per call (the OS tool
//! returns owned bytes per lookup, not a stored reference).
//!
//! The only OS-specific part is the **argv** for the system tool (`security` on macOS,
//! `secret-tool` on Linux). All the command-building, output-parsing, and
//! store-population logic is dependency-free and unit-tested over a [`MockRunner`]; the
//! real shell-out ([`SystemCommandRunner`]) is exercised only by `#[ignore]`d
//! integration tests (it needs a real keychain session — `TODO(P8-store-live)`).

use crate::InMemoryStore;
use crustcore_types::SecretId;

/// Which OS keychain tool to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainKind {
    /// macOS Keychain via the `security find-generic-password` CLI.
    MacOs,
    /// Linux Secret Service (libsecret) via the `secret-tool lookup` CLI.
    LinuxSecretService,
}

/// One secret to fetch from the keychain. `label` is the model-visible
/// [`SecretHandle`](crate::SecretHandle) label (never the value); `service`/`account`
/// are the keychain lookup attributes.
#[derive(Debug, Clone)]
pub struct KeychainEntry {
    /// The store id to insert under.
    pub id: SecretId,
    /// The non-sensitive label.
    pub label: String,
    /// The keychain service attribute.
    pub service: String,
    /// The keychain account attribute.
    pub account: String,
}

/// Why a keychain load failed (no secret bytes ever appear in these — only labels and
/// tool/status strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// The tool ran but found no secret for this label.
    NotFound(String),
    /// The tool could not be run, or exited non-zero.
    Tool(String),
}

impl core::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeychainError::NotFound(l) => write!(f, "keychain: no secret for '{l}'"),
            KeychainError::Tool(e) => write!(f, "keychain tool error: {e}"),
        }
    }
}

impl std::error::Error for KeychainError {}

/// Abstracts running the keychain CLI so the loader logic is testable without the OS
/// tool. A real implementation shells out ([`SystemCommandRunner`]); tests use a
/// [`MockRunner`].
pub trait CommandRunner {
    /// Run `program args…`, returning the stdout bytes on success (exit 0), or a typed
    /// error. The implementation must not inherit ambient env that could leak.
    ///
    /// # Errors
    /// [`KeychainError::Tool`] if the program cannot be run or exits non-zero.
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, KeychainError>;
}

impl KeychainKind {
    /// The `(program, argv)` to print one secret's raw value to stdout.
    fn fetch_argv(self, service: &str, account: &str) -> (&'static str, Vec<String>) {
        match self {
            // `-w` prints just the password to stdout (with a trailing newline).
            KeychainKind::MacOs => (
                "security",
                vec![
                    "find-generic-password".to_string(),
                    "-s".to_string(),
                    service.to_string(),
                    "-a".to_string(),
                    account.to_string(),
                    "-w".to_string(),
                ],
            ),
            // `secret-tool lookup attr value …` prints the value with no trailing newline.
            KeychainKind::LinuxSecretService => (
                "secret-tool",
                vec![
                    "lookup".to_string(),
                    "service".to_string(),
                    service.to_string(),
                    "account".to_string(),
                    account.to_string(),
                ],
            ),
        }
    }
}

/// Fetch one secret's bytes via `runner`. macOS `security -w` appends a single trailing
/// newline (stripped here); `secret-tool` does not. An empty result is treated as
/// not-found (fail-closed).
///
/// # Errors
/// [`KeychainError`] if the tool failed or no secret was found.
pub fn fetch_secret(
    kind: KeychainKind,
    entry: &KeychainEntry,
    runner: &dyn CommandRunner,
) -> Result<Vec<u8>, KeychainError> {
    let (program, args) = kind.fetch_argv(&entry.service, &entry.account);
    let argref: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut out = runner.run(program, &argref)?;
    if kind == KeychainKind::MacOs && out.last() == Some(&b'\n') {
        out.pop();
    }
    if out.is_empty() {
        return Err(KeychainError::NotFound(entry.label.clone()));
    }
    Ok(out)
}

/// Load every entry into a fresh [`InMemoryStore`] (the decrypt-into pattern the broker
/// reads, mirroring the vault). **Fail-closed:** a single missing/failed entry fails the
/// whole load, so a broker never silently runs with a half-populated secret set.
///
/// # Errors
/// [`KeychainError`] for the first entry that cannot be fetched.
pub fn load_keychain_store(
    kind: KeychainKind,
    entries: &[KeychainEntry],
    runner: &dyn CommandRunner,
) -> Result<InMemoryStore, KeychainError> {
    let mut store = InMemoryStore::new();
    for entry in entries {
        let bytes = fetch_secret(kind, entry, runner)?;
        store.insert(entry.id, &entry.label, bytes);
    }
    Ok(store)
}

/// The real runner: shells out to the OS keychain tool. It clears the child env (the
/// tool needs none of ours, and we never want to forward ambient secrets) and captures
/// stdout. Only built when a keychain feature is enabled.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, KeychainError> {
        let output = std::process::Command::new(program)
            .args(args)
            .env_clear()
            .output()
            .map_err(|e| KeychainError::Tool(format!("{program}: {e}")))?;
        if !output.status.success() {
            return Err(KeychainError::Tool(format!(
                "{program} exited with status {:?}",
                output.status.code()
            )));
        }
        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic runner: maps a `program arg0 arg1 …` key to a canned result.
    #[derive(Default)]
    struct MockRunner {
        responses: HashMap<String, Result<Vec<u8>, KeychainError>>,
    }

    impl MockRunner {
        fn key(program: &str, args: &[&str]) -> String {
            let mut k = program.to_string();
            for a in args {
                k.push(' ');
                k.push_str(a);
            }
            k
        }
        fn ok(mut self, program: &str, args: &[&str], out: &[u8]) -> Self {
            self.responses
                .insert(Self::key(program, args), Ok(out.to_vec()));
            self
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, KeychainError> {
            self.responses
                .get(&Self::key(program, args))
                .cloned()
                .unwrap_or_else(|| Err(KeychainError::Tool("no canned response".into())))
        }
    }

    fn entry(id: u32, label: &str) -> KeychainEntry {
        KeychainEntry {
            id: SecretId(id),
            label: label.to_string(),
            service: "crustcore".to_string(),
            account: label.to_string(),
        }
    }

    #[test]
    fn macos_argv_is_find_generic_password_w() {
        let (prog, args) = KeychainKind::MacOs.fetch_argv("crustcore", "model-key");
        assert_eq!(prog, "security");
        assert_eq!(args[0], "find-generic-password");
        assert!(args.contains(&"-w".to_string()));
        assert!(args.contains(&"crustcore".to_string()));
        assert!(args.contains(&"model-key".to_string()));
    }

    #[test]
    fn linux_argv_is_secret_tool_lookup() {
        let (prog, args) = KeychainKind::LinuxSecretService.fetch_argv("crustcore", "model-key");
        assert_eq!(prog, "secret-tool");
        assert_eq!(args[0], "lookup");
        assert!(args.contains(&"service".to_string()));
    }

    #[test]
    fn macos_strips_one_trailing_newline() {
        let (prog, args) = KeychainKind::MacOs.fetch_argv("crustcore", "model-key");
        let argref: Vec<&str> = args.iter().map(String::as_str).collect();
        let runner = MockRunner::default().ok(prog, &argref, b"sk-SECRET\n");
        let bytes = fetch_secret(KeychainKind::MacOs, &entry(1, "model-key"), &runner).unwrap();
        assert_eq!(bytes, b"sk-SECRET");
    }

    #[test]
    fn linux_keeps_the_value_verbatim() {
        let (prog, args) = KeychainKind::LinuxSecretService.fetch_argv("crustcore", "model-key");
        let argref: Vec<&str> = args.iter().map(String::as_str).collect();
        let runner = MockRunner::default().ok(prog, &argref, b"sk-SECRET");
        let bytes = fetch_secret(
            KeychainKind::LinuxSecretService,
            &entry(1, "model-key"),
            &runner,
        )
        .unwrap();
        assert_eq!(bytes, b"sk-SECRET");
    }

    #[test]
    fn empty_result_is_not_found() {
        let (prog, args) = KeychainKind::MacOs.fetch_argv("crustcore", "model-key");
        let argref: Vec<&str> = args.iter().map(String::as_str).collect();
        let runner = MockRunner::default().ok(prog, &argref, b"\n");
        let err = fetch_secret(KeychainKind::MacOs, &entry(1, "model-key"), &runner).unwrap_err();
        assert!(matches!(err, KeychainError::NotFound(_)));
    }

    #[test]
    fn load_populates_the_store_and_broker_reads_it() {
        use crate::{SecretAvailability, SecretBroker};
        let (prog, args) = KeychainKind::MacOs.fetch_argv("crustcore", "model-key");
        let argref: Vec<&str> = args.iter().map(String::as_str).collect();
        let runner = MockRunner::default().ok(prog, &argref, b"sk-SENTINEL\n");
        let store =
            load_keychain_store(KeychainKind::MacOs, &[entry(7, "model-key")], &runner).unwrap();
        // The broker reads it exactly like any other store, and its redactor now scrubs
        // the loaded value.
        let broker = SecretBroker::new(store);
        assert_eq!(
            broker.availability(SecretId(7)),
            SecretAvailability::Available
        );
        assert!(broker.redactor().would_leak("using sk-SENTINEL now"));
        assert!(!broker
            .redactor()
            .redact("using sk-SENTINEL now")
            .contains("SENTINEL"));
    }

    #[test]
    fn one_failed_entry_fails_the_whole_load() {
        // Only the first entry has a canned response; the second fails -> whole load fails
        // (fail-closed, no half-populated broker).
        let (prog, args) = KeychainKind::MacOs.fetch_argv("crustcore", "a");
        let argref: Vec<&str> = args.iter().map(String::as_str).collect();
        let runner = MockRunner::default().ok(prog, &argref, b"v\n");
        // `InMemoryStore` is intentionally not `Debug` (it holds secrets), so we match
        // rather than `.unwrap_err()` (which would require Debug on the Ok type).
        let result = load_keychain_store(
            KeychainKind::MacOs,
            &[entry(1, "a"), entry(2, "b")],
            &runner,
        );
        assert!(matches!(result, Err(KeychainError::Tool(_))));
    }
}
