// SPDX-License-Identifier: Apache-2.0
//! `crustcore-toolkit` — std-only runtime support for `#[crust_tool]`-authored
//! capability-pack tools (C2-toolmacro; `docs/roadmap-v0.2.md` §C2).
//!
//! This crate holds the **real safety logic** that `#[crust_tool]` generates calls
//! into, kept here (not inlined in the macro) so it is unit-testable WITHOUT the
//! proc-macro and so the macro stays a thin, auditable wiring layer. The macro
//! never re-implements any of this; it consumes the policy/secrets/receipts/types
//! contracts UNCHANGED through this surface.
//!
//! ## The trust story, made structural
//!
//! - **No model-visible string can skip the redactor.** A tool's only model-visible
//!   channel is [`ToolOutcome::visible`], typed [`ModelVisibleText`], whose *sole*
//!   constructor is [`crustcore_secrets::Redactor::to_model_visible`]. A tool
//!   cannot return un-redacted visible text — there is no API on `ToolOutcome` that
//!   accepts a raw `String` for the model (invariants 2, 10).
//! - **Redact precedes bound precedes receipt.** [`finalize`] runs the fixed order
//!   *redact → bound (refuse-on-overrun) → mint receipt over the EXACT redacted +
//!   bounded bytes*, so the receipt's `result_hash` binds the post-redaction bytes
//!   shown to the model, and a secret tail cannot reappear after truncation
//!   (invariants 10, 11).
//! - **Generated code holds no key and self-authorizes nothing.** The trusted HOST
//!   owns the [`crustcore_receipts::MacKey`]/[`crustcore_receipts::ReceiptChain`];
//!   [`finalize`] takes the chain by `&mut` reference. Generated code calls
//!   `finalize`; it never holds a `MacKey`, never calls `ReceiptChain::mint`, and
//!   never references `Approved<T>`/`AuthorizedUser::approve` (invariants 4, 8).
//! - **Fail-safe risk default.** [`CrustTool::default_reversibility`] returns
//!   [`Reversibility::Destructive`] unless an author *explicitly* downgrades, which
//!   [`crustcore_policy::PolicySnapshot::classify`] maps to `RequireApproval` (or
//!   `Deny` under `ReadOnly`) — a forgotten classification fails closed (invariant
//!   14). Risk classification always flows through `classify`; the toolkit never
//!   embeds an allow/deny decision and the host alone selects the `RiskProfile`.
#![forbid(unsafe_code)]

use crustcore_policy::{PolicyDecision, PolicySnapshot};
use crustcore_receipts::{ReceiptChain, ReceiptParams, ToolReceipt};
use crustcore_secrets::{ModelVisibleText, Redactor};
use crustcore_types::{ArtifactId, EventSeq, JobId, TaskId, ToolCallId};

// Re-export the contract types tools name most often, so authors (and the macro's
// generated code) can reach them through one stable surface. These are the SAME
// types from the contract crates — re-exported, never redefined.
pub use crustcore_types::{BoundedText, Reversibility};

/// Default cap on the bytes of a tool's serialized arguments (mirrors
/// [`BoundedText::DEFAULT_MAX`], 64 KiB). Bounded everything (CLAUDE.md §6.5,
/// invariant 11).
pub const MAX_ARGS_BYTES: usize = BoundedText::DEFAULT_MAX;

/// Default cap on the bytes of a tool's model-visible result (mirrors
/// [`BoundedText::DEFAULT_MAX`], 64 KiB). The redacted result is refused — not
/// silently truncated — if it exceeds this, so a tool can never read an unbounded
/// blob into model context (invariant 11).
pub const MAX_RESULT_BYTES: usize = BoundedText::DEFAULT_MAX;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// The JSON-Schema-shaped type of one tool parameter or the tool's result.
///
/// `#[crust_tool]` derives these from the Rust signature; an **unsupported** Rust
/// type is a hard compile error in the macro, never a permissive `Any` here — so
/// the accepted-input surface is exactly the declared types (invariant 7, dimension
/// f). `Any` exists only for hand-written tools that genuinely have no typed shape;
/// the macro never emits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaType {
    /// A UTF-8 string (`String`).
    String,
    /// A signed/unsigned integer (any of the Rust integer widths).
    Integer,
    /// A boolean.
    Boolean,
    /// An optional value: present or absent.
    Optional(Box<SchemaType>),
    /// A homogeneous array of values.
    Array(Box<SchemaType>),
    /// Escape hatch for hand-written tools only — the macro NEVER emits this.
    Any,
}

impl SchemaType {
    /// The JSON-Schema `"type"` keyword for this type (top level).
    #[must_use]
    pub fn json_type(&self) -> &'static str {
        match self {
            SchemaType::String => "string",
            SchemaType::Integer => "integer",
            SchemaType::Boolean => "boolean",
            SchemaType::Array(_) => "array",
            // An optional value's JSON type is that of its inner type; absence is
            // expressed by the param not being `required`.
            SchemaType::Optional(inner) => inner.json_type(),
            SchemaType::Any => "any",
        }
    }
}

/// One named parameter of a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSchema {
    /// The parameter name (matches the Rust argument name).
    pub name: String,
    /// The parameter's type.
    pub ty: SchemaType,
    /// Whether the parameter must be supplied. An [`SchemaType::Optional`] param is
    /// not required; everything else is.
    pub required: bool,
}

/// A tool's full schema: its name, an ordered list of typed params, and its result
/// type. Derived mechanically from the Rust signature by `#[crust_tool]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchema {
    /// The tool's name (model-visible identifier).
    pub name: String,
    /// The tool's typed parameters, in declaration order.
    pub params: Vec<ParamSchema>,
    /// The tool's result type.
    pub result: SchemaType,
}

impl ToolSchema {
    /// Whether the schema is well-formed: a non-empty name, no duplicate param
    /// names, and no `Any` anywhere (a macro-derived schema is never permissive;
    /// this check lets a test assert it). Hand-written tools may opt into `Any`,
    /// in which case [`ToolSchema::is_concrete`] is the weaker check.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if self.name.is_empty() {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        self.params.iter().all(|p| seen.insert(p.name.as_str()))
    }

    /// Whether the schema contains no [`SchemaType::Any`] — i.e. it is fully
    /// concrete, the property every macro-derived schema must hold (dimension f).
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        fn concrete(t: &SchemaType) -> bool {
            match t {
                SchemaType::Any => false,
                SchemaType::Optional(i) | SchemaType::Array(i) => concrete(i),
                _ => true,
            }
        }
        self.params.iter().all(|p| concrete(&p.ty)) && concrete(&self.result)
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Bounded, opaque tool inputs handed to [`CrustTool::invoke`].
///
/// The raw argument bytes are bounded at construction ([`ToolArgs::new`] refuses
/// anything over [`MAX_ARGS_BYTES`]) so a tool can never receive an unbounded blob
/// (invariant 11). The bytes are *untrusted data* (invariant 7): a tool parses them
/// but must never treat them as instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolArgs {
    raw: Vec<u8>,
}

impl ToolArgs {
    /// Wraps already-canonicalized argument bytes, refusing an oversize input.
    ///
    /// # Errors
    /// [`ToolError::InputTooLarge`] if `raw` exceeds [`MAX_ARGS_BYTES`].
    pub fn new(raw: Vec<u8>) -> Result<Self, ToolError> {
        Self::with_max(raw, MAX_ARGS_BYTES)
    }

    /// Wraps argument bytes with an explicit cap (for tighter per-tool bounds).
    ///
    /// # Errors
    /// [`ToolError::InputTooLarge`] if `raw` exceeds `max`.
    pub fn with_max(raw: Vec<u8>, max: usize) -> Result<Self, ToolError> {
        if raw.len() > max {
            return Err(ToolError::InputTooLarge {
                len: raw.len(),
                max,
            });
        }
        Ok(ToolArgs { raw })
    }

    /// The raw argument bytes (untrusted data).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The argument bytes as `&str` if valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.raw).ok()
    }
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// An opaque, content-addressed reference to an artifact a tool produced (a diff,
/// a log, a transcript). Carries the kernel [`ArtifactId`] hash only — never the
/// bytes — so contents stay out of model-visible projections (invariant 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactRef(pub ArtifactId);

/// The result of invoking a tool.
///
/// `visible` is the **only** model-visible channel and is typed [`ModelVisibleText`]
/// — whose sole constructor is [`Redactor::to_model_visible`] — so there is no path
/// by which a tool returns model-visible text that skipped the redactor (invariant
/// 2, dimension a). Build one with [`finalize`], which also mints the receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutcome {
    /// The redacted, bounded, model-visible result.
    pub visible: ModelVisibleText,
    /// Opaque handles to any artifacts produced (contents never inlined).
    pub artifacts: Vec<ArtifactRef>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a tool invocation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// The serialized arguments exceeded the input cap (refused, not truncated).
    InputTooLarge {
        /// The rejected length, in bytes.
        len: usize,
        /// The cap that was exceeded, in bytes.
        max: usize,
    },
    /// The redacted result exceeded the output cap (refused, not truncated — so a
    /// tail cannot leak past the bound; invariant 11).
    OutputTooLarge {
        /// The rejected length, in bytes.
        len: usize,
        /// The cap that was exceeded, in bytes.
        max: usize,
    },
    /// The tool's arguments could not be parsed / validated.
    InvalidArgs(String),
    /// Policy denied or gated the operation; carries the non-sensitive reason from
    /// [`PolicyDecision`]. A tool that needs approval surfaces this rather than
    /// proceeding (invariants 8, 14).
    PolicyRefused(String),
    /// The tool ran but failed; carries a non-sensitive message.
    Failed(String),
}

impl core::fmt::Display for ToolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ToolError::InputTooLarge { len, max } => {
                write!(f, "tool input of {len} bytes exceeds cap of {max} bytes")
            }
            ToolError::OutputTooLarge { len, max } => {
                write!(f, "tool output of {len} bytes exceeds cap of {max} bytes")
            }
            ToolError::InvalidArgs(e) => write!(f, "invalid tool arguments: {e}"),
            ToolError::PolicyRefused(e) => write!(f, "policy refused: {e}"),
            ToolError::Failed(e) => write!(f, "tool failed: {e}"),
        }
    }
}

impl std::error::Error for ToolError {}

// ---------------------------------------------------------------------------
// The trait the macro targets
// ---------------------------------------------------------------------------

/// A capability-pack tool: a typed, schema-described, bounded, redacted, receipted
/// unit of work. `#[crust_tool]` generates an implementation of this trait; a tool
/// may also implement it by hand (the toolkit's own tests do both, proving parity).
///
/// The trust guarantees are carried by the *types*, not by the implementer's care:
/// `invoke` can only return a [`ToolOutcome`] whose `visible` is [`ModelVisibleText`]
/// (redactor-sealed), and the only ergonomic way to build that is [`finalize`],
/// which redacts, bounds, and mints the host receipt in the fixed order.
pub trait CrustTool {
    /// The tool's JSON-Schema-shaped description, derived from its typed signature.
    fn schema(&self) -> ToolSchema;

    /// The most restrictive reversibility that still lets this tool run as intended.
    /// The macro defaults this to [`Reversibility::Destructive`] (fail-safe) unless
    /// the author explicitly downgrades; this drives [`PolicySnapshot::classify`].
    fn default_reversibility() -> Reversibility
    where
        Self: Sized;

    /// Performs the work over bounded, untrusted [`ToolArgs`] and returns a redacted,
    /// bounded, receipted [`ToolOutcome`] — or a [`ToolError`].
    ///
    /// # Errors
    /// Any [`ToolError`] the tool surfaces (bad input, policy refusal, failure, or
    /// an output that exceeds the cap).
    fn invoke(&self, args: &ToolArgs) -> Result<ToolOutcome, ToolError>;
}

/// Classifies a tool's reversibility under a host-selected policy snapshot. This is
/// the single chokepoint generated code calls for the risk decision — the toolkit
/// never inlines an allow/deny, never constructs an `Approved<T>`, and never selects
/// the `RiskProfile` (that is host config). A tool whose `default_reversibility` is
/// `Destructive` (the fail-safe default) is gated `RequireApproval`/`Deny` here
/// (invariants 4, 8, 14).
#[must_use]
pub fn classify_tool<T: CrustTool>(policy: &PolicySnapshot) -> PolicyDecision {
    policy.classify(T::default_reversibility())
}

// ---------------------------------------------------------------------------
// The host-side finalize helper: redact -> bound -> mint
// ---------------------------------------------------------------------------

/// The committed call-site metadata a [`finalize`] receipt anchors to. The trusted
/// host fills these in from the kernel; generated code threads them through.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptContext {
    /// Task the call ran under.
    pub task_id: TaskId,
    /// Job the call ran under.
    pub job_id: JobId,
    /// The specific tool call.
    pub tool_call_id: ToolCallId,
    /// The event-log seq this receipt anchors to.
    pub event_seq: EventSeq,
}

/// The fixed-order safe finalizer every `#[crust_tool]` result flows through.
///
/// Order is **redact → bound → mint** and is not optional:
/// 1. **Redact** `raw_result` through the host [`Redactor`] into [`ModelVisibleText`]
///    — the sole way to obtain that type, so the model never sees un-redacted bytes
///    (invariants 2, 10).
/// 2. **Bound** the redacted text against [`MAX_RESULT_BYTES`], *refusing* (not
///    truncating) on overrun — so a secret tail cannot reappear past a truncation
///    boundary and nothing unbounded enters model context (invariant 11, dimension
///    d).
/// 3. **Mint** a [`ToolReceipt`] over the **exact** redacted-and-bounded bytes shown
///    to the model, using the HOST's [`ReceiptChain`]/[`MacKey`] (passed by `&mut`).
///    The `result` hashed is byte-identical to `outcome.visible`, so the receipt's
///    `result_hash` binds the post-redaction bytes (invariant 10, dimension e).
///
/// Generated code calls this; it never holds a `MacKey` and never calls
/// `ReceiptChain::mint` itself.
///
/// `tool_name` and `args` are the raw committed bytes for the receipt's name/args
/// hashes (already canonicalized by the caller); they are hashed, never stored.
///
/// # Errors
/// [`ToolError::OutputTooLarge`] if the redacted result exceeds [`MAX_RESULT_BYTES`].
pub fn finalize(
    redactor: &Redactor,
    chain: &mut ReceiptChain,
    ctx: &ReceiptContext,
    tool_name: &str,
    args: &[u8],
    raw_result: &str,
    artifacts: &[ArtifactRef],
) -> Result<(ToolOutcome, ToolReceipt), ToolError> {
    finalize_with(
        redactor,
        chain,
        ctx,
        tool_name,
        args,
        raw_result,
        artifacts,
        MAX_RESULT_BYTES,
    )
}

/// [`finalize`] with an explicit result cap (for tighter per-tool bounds). Same
/// fixed order and the same refuse-on-overrun guarantee.
///
/// # Errors
/// [`ToolError::OutputTooLarge`] if the redacted result exceeds `max_result`.
#[allow(clippy::too_many_arguments)]
pub fn finalize_with(
    redactor: &Redactor,
    chain: &mut ReceiptChain,
    ctx: &ReceiptContext,
    tool_name: &str,
    args: &[u8],
    raw_result: &str,
    artifacts: &[ArtifactRef],
    max_result: usize,
) -> Result<(ToolOutcome, ToolReceipt), ToolError> {
    // 1. REDACT first — the only constructor of ModelVisibleText.
    let visible = redactor.to_model_visible(raw_result);

    // 2. BOUND the *redacted* bytes. Refuse on overrun (do not truncate): a
    //    truncation could drop the closing marker of a redaction span, and a
    //    refuse-on-overrun policy is the only one that cannot leak a tail.
    let shown = visible.as_str();
    if shown.len() > max_result {
        return Err(ToolError::OutputTooLarge {
            len: shown.len(),
            max: max_result,
        });
    }

    // 3. MINT the receipt over the EXACT redacted+bounded bytes shown to the model,
    //    using the host's chain/key. The artifact hashes are committed too.
    let artifact_ids: Vec<ArtifactId> = artifacts.iter().map(|a| a.0).collect();
    let receipt = chain.mint(&ReceiptParams {
        task_id: ctx.task_id,
        job_id: ctx.job_id,
        tool_call_id: ctx.tool_call_id,
        tool_name: tool_name.as_bytes(),
        args,
        result: shown.as_bytes(),
        artifacts: &artifact_ids,
        event_seq: ctx.event_seq,
    });

    Ok((
        ToolOutcome {
            visible,
            artifacts: artifacts.to_vec(),
        },
        receipt,
    ))
}

// ---------------------------------------------------------------------------
// The host handle generated code threads through
// ---------------------------------------------------------------------------

/// The trusted-host handle a `#[crust_tool]` body receives as its first argument.
///
/// It bundles the host's [`Redactor`], the host's [`ReceiptChain`] (which owns the
/// [`MacKey`]), and the [`ReceiptContext`] for this call. A tool body calls
/// [`HostTool::emit`] to turn a raw result `String` into a redacted, bounded,
/// receipted [`ToolOutcome`]; it never touches the key or the chain directly.
///
/// Because the chain and redactor are *borrowed from the host*, the generated tool
/// has no way to construct one, hold a `MacKey`, or mint a receipt over different
/// bytes than the ones [`emit`](HostTool::emit) shows the model (dimension e).
pub struct HostTool<'h> {
    redactor: &'h Redactor,
    chain: &'h mut ReceiptChain,
    ctx: ReceiptContext,
}

impl<'h> HostTool<'h> {
    /// Builds a host handle from the trusted host's redactor + receipt chain and the
    /// call context. Only the trusted host (which owns the [`MacKey`] inside the
    /// chain) can call this.
    #[must_use]
    pub fn new(redactor: &'h Redactor, chain: &'h mut ReceiptChain, ctx: ReceiptContext) -> Self {
        HostTool {
            redactor,
            chain,
            ctx,
        }
    }

    /// The host redactor (for a tool that needs to pre-scrub before composing a
    /// result; [`emit`](Self::emit) re-redacts regardless, so this never weakens the
    /// boundary).
    #[must_use]
    pub fn redactor(&self) -> &Redactor {
        self.redactor
    }

    /// Turns a raw result string into a redacted, bounded, receipted outcome via the
    /// fixed-order [`finalize`] path. Generated code calls exactly this. The returned
    /// receipt is minted over the **exact** bytes in `outcome.visible`.
    ///
    /// # Errors
    /// [`ToolError::OutputTooLarge`] if the redacted result exceeds [`MAX_RESULT_BYTES`].
    pub fn emit(
        &mut self,
        tool_name: &str,
        args: &[u8],
        raw_result: &str,
        artifacts: &[ArtifactRef],
    ) -> Result<(ToolOutcome, ToolReceipt), ToolError> {
        finalize(
            self.redactor,
            self.chain,
            &self.ctx,
            tool_name,
            args,
            raw_result,
            artifacts,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_well_formed_and_concrete() {
        let s = ToolSchema {
            name: "echo".to_string(),
            params: vec![ParamSchema {
                name: "msg".to_string(),
                ty: SchemaType::String,
                required: true,
            }],
            result: SchemaType::String,
        };
        assert!(s.is_well_formed());
        assert!(s.is_concrete());
    }

    #[test]
    fn schema_with_any_is_not_concrete() {
        let s = ToolSchema {
            name: "x".to_string(),
            params: vec![ParamSchema {
                name: "v".to_string(),
                ty: SchemaType::Any,
                required: true,
            }],
            result: SchemaType::String,
        };
        assert!(s.is_well_formed());
        assert!(!s.is_concrete(), "Any must not count as concrete");
    }

    #[test]
    fn duplicate_param_names_are_not_well_formed() {
        let s = ToolSchema {
            name: "x".to_string(),
            params: vec![
                ParamSchema {
                    name: "a".to_string(),
                    ty: SchemaType::String,
                    required: true,
                },
                ParamSchema {
                    name: "a".to_string(),
                    ty: SchemaType::Integer,
                    required: true,
                },
            ],
            result: SchemaType::Boolean,
        };
        assert!(!s.is_well_formed());
    }

    #[test]
    fn args_refuse_oversize_input() {
        let big = vec![b'x'; MAX_ARGS_BYTES + 1];
        assert!(matches!(
            ToolArgs::new(big),
            Err(ToolError::InputTooLarge { .. })
        ));
        // At the cap is fine.
        assert!(ToolArgs::new(vec![b'x'; MAX_ARGS_BYTES]).is_ok());
    }
}
