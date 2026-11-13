//! The signer's command line (SG-01, SG-02, SG-08), as a function from arguments and stdin bytes
//! to one output line and an exit code, so everything it does is testable without a process.
//!
//! Invariants: exactly one JCS line per run (the entry point adds the closing LF), exit codes 0 to
//! 5 only, stdout never carries a render. `version` shows no prompt and reads no stdin. Every other
//! command reads at most one object from stdin through the canonical subset recognizer, bounded by
//! MAX_INPUT (SG-01).
//! Failure modes: every failure is `{"error":code}` with the exit code of SG-08; an error nobody
//! listed is `internal`, exit 5, never a made-up code and never exit 0.
//!
//! `run_conformance` is the entry point of `handsal-sign-conformance` (CF-04). It is the same core
//! with the CF-03 form of `render` and the shipped `emit`: it holds no key, shows no prompt and
//! reads neither the clock nor a random source, because every value its output depends on is in
//! its input.

use crate::commands;
use crate::emit;
use crate::json;
use crate::limits::max_input;
use crate::profiles::Profiles;
use crate::render::RenderInput;
use crate::render_attach;
use crate::subset;
use crate::value::{Checked, JValue, Refusal};
use std::time::{SystemTime, UNIX_EPOCH};

/// The person and key a signer is bound to at keygen (SG-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub performer: String,
    pub kid: String,
}

/// What the signer owns and a caller never supplies: who it signs as, its clock, its randomness.
pub struct Environment {
    /// Bound at keygen. `None` until a key exists, and then `render` and `sign` answer `key_unavailable`.
    pub identity: Option<Identity>,
    now: Box<dyn Fn() -> i64>,
    nonce: Box<dyn Fn() -> Checked<String>>,
}

impl Environment {
    pub fn new(identity: Option<Identity>, now: Box<dyn Fn() -> i64>, nonce: Box<dyn Fn() -> Checked<String>>) -> Environment {
        Environment { identity, now, nonce }
    }

    /// A fixed clock and nonce, for tests and for any caller that must be deterministic.
    pub fn fixed(identity: Option<Identity>, now: i64, nonce: String) -> Environment {
        Environment::new(identity, Box::new(move || now), Box::new(move || Ok(nonce.clone())))
    }

    /// No key and no entropy source: this core ships none. The key backend (T6.6) supplies the
    /// identity and a CSPRNG; until then `render` stops at `key_unavailable` before any nonce is
    /// drawn, and a draw would be `internal`, never a made-up value.
    pub fn unbound() -> Environment {
        let clock = || SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        Environment::new(None, Box::new(clock), Box::new(|| Err(Refusal::new("internal"))))
    }

    pub fn now(&self) -> i64 {
        (self.now)()
    }

    pub fn nonce(&self) -> Checked<String> {
        (self.nonce)()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit: i32,
    pub line: Vec<u8>,
}

/// stdin, read once and only when the command needs it. A failed read is `internal`.
pub type ReadStdin<'a> = &'a mut dyn FnMut() -> Checked<Vec<u8>>;

const REFUSED_INPUT: [&str; 8] = [
    "schema_refused",
    "render_refused",
    "attachment_missing",
    "attachment_mismatch",
    "unsupported_method",
    "unsupported_command",
    "identity_mismatch",
    "key_exists",
];

/// Codes the checker-form renderer and the validators use; the signer says `schema_refused`.
const SCHEMA_LIKE: [&str; 7] =
    ["schema", "body_schema", "malformed_input", "genesis_schema", "payload_not_canonical_subset", "payload_too_large", "jws_shape"];

fn error_line(code: &str) -> Vec<u8> {
    format!("{{\"error\":\"{}\"}}", code).into_bytes()
}

fn error(code: &str, exit: i32) -> Outcome {
    Outcome { exit, line: error_line(code) }
}

/// SG-08: the exit code of a refusal. A code nobody listed is `internal`, exit 5.
pub fn outcome_for(refusal: Refusal) -> Outcome {
    let code = refusal.code;
    if REFUSED_INPUT.contains(&code) {
        return error(code, 2);
    }
    if SCHEMA_LIKE.contains(&code) {
        return error("schema_refused", 2);
    }
    match code {
        "method_unknown" => error("unsupported_method", 2),
        "user_cancel" => error(code, 1),
        "key_unavailable" => error(code, 3),
        "no_display" | "prompt_refused" => error(code, 4),
        _ => error("internal", 5),
    }
}

fn finish(result: Checked<JValue>) -> Outcome {
    match result {
        Ok(value) => Outcome { exit: 0, line: emit::result_line(&value) },
        Err(refusal) => outcome_for(refusal),
    }
}

/// One object from stdin: at most MAX_INPUT bytes, one trailing LF of framing removed, read
/// through the canonical subset recognizer.
fn read_object(bytes: &[u8]) -> Checked<JValue> {
    let refused = || Refusal::new("schema_refused");
    if bytes.len() > max_input() {
        return Err(refused());
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    subset::parse(body, max_input()).map_err(|_| refused())
}

fn version() -> JValue {
    JValue::Object(
        [
            ("class".to_string(), JValue::string("win-hello-hw")),
            ("impl".to_string(), JValue::string("handsal-sign-rust")),
            ("spec".to_string(), JValue::string(&Profiles::standard().production)),
        ]
        .into(),
    )
}

fn unsupported_command() -> Outcome {
    outcome_for(Refusal::new("unsupported_command"))
}

pub fn run(args: &[String], read_stdin: ReadStdin, environment: &Environment) -> Outcome {
    let [command] = args else { return unsupported_command() };
    let mut input = || read_stdin().and_then(|bytes| read_object(&bytes));
    match command.as_str() {
        "version" => finish(Ok(version())),
        "emit" => finish(input().and_then(|v| commands::emit(&v))),
        "render" => finish(input().and_then(|v| commands::render(&v, environment))),
        // The key backend is a later task (T6.6); until it exists these cannot do their work.
        "keygen" | "pubkey" | "sign" => outcome_for(Refusal::new("internal")),
        _ => unsupported_command(),
    }
}

// The conformance entry point

fn checker_error(code: &str) -> Outcome {
    Outcome { exit: 0, line: error_line(code) }
}

/// The CF-03 `render`: `{attachments, kid, method, payload}`. Input that is not I-JSON within the
/// bound is `unparseable_input`, a mistyped input is `malformed_input`, a rule of the profile
/// saying no is `{"error": code}`; every result exits 0.
fn conformance_render(stdin: &[u8]) -> Outcome {
    if stdin.len() > max_input() {
        return checker_error("unparseable_input");
    }
    let Ok(value) = json::parse(stdin) else { return checker_error("unparseable_input") };
    let shape = value.dict().filter(|m| m.len() == 4).and_then(|m| {
        Some(RenderInput {
            attachments: m.get("attachments").filter(|a| a.dict().is_some())?.clone(),
            kid: m.get("kid")?.str()?.to_string(),
            method: m.get("method")?.str()?.to_string(),
            payload: m.get("payload").filter(|p| p.dict().is_some())?.clone(),
        })
    });
    let Some(input) = shape else { return checker_error("malformed_input") };
    match render_attach::render(&input) {
        Ok(rendered) => {
            let result = JValue::Object(
                [("first_line".to_string(), JValue::String(rendered.first_line)), ("text".to_string(), JValue::String(rendered.text))].into(),
            );
            Outcome { exit: 0, line: emit::result_line(&result) }
        }
        Err(refusal) => checker_error(refusal.code),
    }
}

pub fn run_conformance(args: &[String], read_stdin: ReadStdin) -> Outcome {
    let [command] = args else { return unsupported_command() };
    match command.as_str() {
        "render" => match read_stdin() {
            Ok(bytes) => conformance_render(&bytes),
            Err(refusal) => outcome_for(refusal),
        },
        "emit" => finish(read_stdin().and_then(|bytes| read_object(&bytes)).and_then(|v| commands::emit(&v))),
        _ => unsupported_command(),
    }
}
