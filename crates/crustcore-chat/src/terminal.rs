// SPDX-License-Identifier: Apache-2.0
//! The **terminal** front door — a local `crustcore chat` REPL.
//!
//! This is the NilCore `nilcore chat` analog for the terminal: read a line, route it
//! (converse vs start-a-task), and print a redacted answer. The local operator at the
//! terminal is, by definition, an authorized [`Principal`](crate::Principal) (the CLI
//! is the trusted setup/admin path, invariant 16) — so their input becomes a real user
//! turn while model/tool/file content never can.
//!
//! Design split so the loop is testable without a live model:
//! - [`run_repl`] is generic over the input/output streams **and** the model consult,
//!   so a CI test drives it with canned input + a canned model (no process, no
//!   network).
//! - [`complete_text`] adapts a [`NetHelper`] into the session's consult shape and is
//!   CI-tested over an in-memory [`NetHelper`] fed a canned `Final`.
//! - [`run_terminal`] is the thin live entry: it spawns the `crustcore-net` helper and
//!   wires real stdio into [`run_repl`]. Only this function touches a real process; it
//!   is exercised by an `#[ignore]`d smoke test, never CI.

use std::io::{BufRead, Write};

use crustcore_netproto::{CompleteRequest, NetHelper, SpawnedHelper};
use crustcore_secrets::Redactor;

use crate::session::{ChatConfig, ChatSession, ConsultFn, Turn};
use crate::steer::Disposition;
use crate::{accept, Principal};

/// Run one completion through a [`NetHelper`] and return the model's full text (the
/// consult shape the session expects). Chunks are discarded here; the answer is
/// redacted+bounded by the session's [`ConverseRenderer`](crate::ConverseRenderer)
/// before the user sees it, so streaming raw chunks straight to the terminal (which
/// would bypass redaction across a chunk boundary) is deliberately *not* done.
pub fn complete_text<W: Write, R: BufRead>(
    helper: &mut NetHelper<W, R>,
    req: &CompleteRequest,
) -> Option<String> {
    match helper.complete(req, |_chunk| {}) {
        Ok(fin) => Some(fin.text.as_str().to_string()),
        Err(_) => None,
    }
}

/// The conversational REPL. Generic over input/output and the model consult so it runs
/// in CI with no process or network. Reads lines until EOF; each line from the
/// authorized local operator is routed and answered.
///
/// # Errors
/// [`std::io::Error`] on a read/write failure of the provided streams.
pub fn run_repl<In: BufRead, Out: Write>(
    redactor: &Redactor,
    config: ChatConfig,
    input: &mut In,
    output: &mut Out,
    model: &mut ConsultFn<'_>,
) -> std::io::Result<()> {
    let mut session = ChatSession::new(redactor, config);
    let mut line = String::new();
    loop {
        write!(output, "you> ")?;
        output.flush()?;
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break; // EOF
        }
        // The local operator is an authorized principal; bound + trim the input.
        let Some(msg) = accept(Principal::Authorized, &line) else {
            continue;
        };
        if msg.is_empty() {
            continue;
        }
        match session.submit(&msg) {
            Disposition::Cancel => {
                session.cancel();
                writeln!(output, "(run cancelled)")?;
                continue;
            }
            Disposition::Command => {
                writeln!(
                    output,
                    "(commands apply during a running task: plain text queues a turn, \
                     `!text` steers, `/cancel` aborts)"
                )?;
                continue;
            }
            Disposition::DroppedFull => {
                writeln!(output, "(queue full — message dropped)")?;
                continue;
            }
            // Queued / SteerCancelModel / SteerBuffered: drain below.
            _ => {}
        }
        while let Some(turn_text) = session.next_turn() {
            match session.handle(&turn_text, &mut *model) {
                Turn::Answer(a) => writeln!(output, "crustcore> {}", a.as_str())?,
                Turn::Notice(n) => writeln!(output, "crustcore: {}", n.as_str())?,
                Turn::StartTask { route, prompt } => writeln!(
                    output,
                    "[route: {} — hand off to the kernel task flow: {}]",
                    route.as_str(),
                    prompt
                )?,
            }
        }
    }
    Ok(())
}

/// Spawn the `crustcore-net` helper at `program args…` and run the terminal REPL over
/// real stdin/stdout. This is the only function here that touches a process; it is the
/// `crustcore chat` entry the binary calls. Exercised by an `#[ignore]`d smoke test
/// (needs a real helper binary), never in CI.
///
/// # Errors
/// [`std::io::Error`] if the helper cannot be spawned or stdio fails.
pub fn run_terminal(
    program: &str,
    args: &[&str],
    redactor: &Redactor,
    config: ChatConfig,
) -> std::io::Result<()> {
    let mut spawned = SpawnedHelper::spawn(program, args)?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let mut model = |req: &CompleteRequest| complete_text(spawned.helper(), req);
    run_repl(redactor, config, &mut input, &mut output, &mut model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_netproto::{
        encode_response, BoundedText, Final, Require, Response, Role, Usage, MAX_TEXT_BYTES,
    };
    use crustcore_secrets::{InMemoryStore, SecretBroker};
    use crustcore_types::SecretId;
    use std::io::{BufReader, Cursor};

    fn req() -> CompleteRequest {
        CompleteRequest {
            role: Role::Research,
            system: BoundedText::truncated("", MAX_TEXT_BYTES),
            prompt: BoundedText::truncated("hi", MAX_TEXT_BYTES),
            max_tokens: 64,
            stream: false,
            max_cost_micros: 0,
            require: Require::default(),
        }
    }

    #[test]
    fn complete_text_reads_the_final_over_an_in_memory_helper() {
        // Stage a canned Final response and adapt it through complete_text — the
        // consult adapter, exercised without spawning a process.
        let fin = Final {
            text: BoundedText::truncated("a verifier kernel", MAX_TEXT_BYTES),
            provider: "p".into(),
            model: "m".into(),
            usage: Usage::default(),
            fallbacks: vec![],
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(encode_response(&Response::Final(fin)).as_bytes());
        bytes.push(b'\n');
        let mut helper = NetHelper::new(Vec::new(), BufReader::new(Cursor::new(bytes)));
        assert_eq!(
            complete_text(&mut helper, &req()).as_deref(),
            Some("a verifier kernel")
        );
    }

    #[test]
    fn complete_text_returns_none_on_error_response() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(encode_response(&Response::Error("boom".into())).as_bytes());
        bytes.push(b'\n');
        let mut helper = NetHelper::new(Vec::new(), BufReader::new(Cursor::new(bytes)));
        assert_eq!(complete_text(&mut helper, &req()), None);
    }

    #[test]
    fn repl_answers_a_question_and_starts_a_task_and_cancels() {
        // Canned operator session: a question (converse), a small ask (quick-fix task),
        // and a /cancel. A canned model returns a fixed answer for converse turns.
        let broker = SecretBroker::new(InMemoryStore::new());
        let input_text = "what is this repo?\nrename the foo variable\n/cancel\n";
        let mut input = BufReader::new(Cursor::new(input_text.as_bytes().to_vec()));
        let mut output: Vec<u8> = Vec::new();
        let mut model = |_req: &CompleteRequest| Some("A sub-800kB verifier kernel.".to_string());

        run_repl(
            broker.redactor(),
            ChatConfig::default(),
            &mut input,
            &mut output,
            &mut model,
        )
        .unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(out.contains("crustcore> A sub-800kB verifier kernel."));
        assert!(out.contains("hand off to the kernel task flow: rename the foo variable"));
        assert!(out.contains("(run cancelled)"));
    }

    #[test]
    fn repl_redacts_a_secret_in_a_converse_answer() {
        // RED-TEAM through the whole REPL: the model's answer echoes a secret; the user
        // must see it redacted (the converse renderer's redact-then-bound boundary).
        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "model-key", b"sk-REPLSENTINEL".to_vec());
        let broker = SecretBroker::new(store);
        let input_text = "what's the key?\n";
        let mut input = BufReader::new(Cursor::new(input_text.as_bytes().to_vec()));
        let mut output: Vec<u8> = Vec::new();
        let mut model = |_req: &CompleteRequest| Some("The key is sk-REPLSENTINEL.".to_string());

        run_repl(
            broker.redactor(),
            ChatConfig::default(),
            &mut input,
            &mut output,
            &mut model,
        )
        .unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(!out.contains("sk-REPLSENTINEL"));
        assert!(out.contains("[REDACTED:model-key]"));
    }
}
