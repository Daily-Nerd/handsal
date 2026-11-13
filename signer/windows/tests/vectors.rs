//! Conformance vectors a signer answers (CF-04): `render` and `emit` through the conformance
//! entry point, plus the `subset` rows (`jcs/*`) through the recognizer (T6.2).
//! The vector files are the oracle; nothing here derives an expectation from the code under test.

use handsal_core::cli;
use handsal_core::emit;
use handsal_core::json;
use handsal_core::limits::max_input;
use handsal_core::subset::{self, SubsetFailure};
use handsal_core::value::JValue;
use std::path::PathBuf;

enum Input {
    Json(JValue),
    Bytes(Vec<u8>),
}

struct Vector {
    name: String,
    command: String,
    anchor: String,
    input: Input,
    pad: Option<Vec<JValue>>,
    exit: i32,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors")
}

fn hex_decode(text: &str) -> Vec<u8> {
    let digits = text.as_bytes();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn load_all() -> Vec<Vector> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(vectors_dir())
        .expect("vectors directory")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().map_or(false, |e| e == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        let doc = json::parse(&bytes).unwrap_or_else(|e| panic!("{}: {:?}", file.display(), e));
        let top = doc.dict().expect("vector is an object");
        let text = |key: &str| top.get(key).and_then(JValue::str).map(str::to_string);
        let input = if let Some(value) = top.get("input") {
            Input::Json(value.clone())
        } else if let Some(raw) = text("input_raw") {
            Input::Bytes(raw.into_bytes())
        } else if let Some(hex) = text("input_hex") {
            Input::Bytes(hex_decode(&hex))
        } else {
            panic!("{}: no input", file.display());
        };
        let exit = match top.get("exit") {
            Some(JValue::Number(n)) => n.parse().unwrap(),
            _ => 0,
        };
        out.push(Vector {
            name: text("name").unwrap(),
            command: text("command").unwrap(),
            anchor: text("anchor").unwrap(),
            input,
            pad: top.get("pad").and_then(JValue::list).map(|l| l.to_vec()),
            exit,
        });
    }
    out
}

fn with_command(command: &str) -> Vec<Vector> {
    load_all().into_iter().filter(|v| v.command == command).collect()
}

/// The stdin the harness sends (conformance/run.py `build_stdin`): compact JSON and one LF, the
/// raw bytes as they are, or a value grown with "a" until the whole input is MAX_INPUT + 1 bytes.
fn stdin_of(vector: &Vector) -> Vec<u8> {
    match &vector.input {
        Input::Bytes(bytes) => bytes.clone(),
        Input::Json(value) => {
            let mut value = value.clone();
            if let Some(path) = &vector.pad {
                let base = framed(&value);
                let extra = max_input() + 1 - base.len();
                let mut slot = &mut value;
                for step in path {
                    slot = match (slot, step) {
                        (JValue::Object(members), JValue::String(key)) => members.get_mut(key).unwrap(),
                        (JValue::Array(items), JValue::Number(n)) => &mut items[n.parse::<usize>().unwrap()],
                        _ => panic!("{}: bad pad path", vector.name),
                    };
                }
                match slot {
                    JValue::String(text) => text.push_str(&"a".repeat(extra)),
                    _ => panic!("{}: pad slot is not a string", vector.name),
                }
            }
            framed(&value)
        }
    }
}

fn framed(value: &JValue) -> Vec<u8> {
    let mut out = emit::result_line(value);
    out.push(b'\n');
    out
}

#[test]
fn vector_files_load() {
    assert_eq!(with_command("subset").len(), 39);
    assert_eq!(with_command("render").len(), 98, "96 rnd rows and the two cli/stdin-nesting rows");
}

#[test]
fn subset_rows() {
    let rows = with_command("subset");
    assert!(!rows.is_empty());
    let mut failed = Vec::new();
    for row in &rows {
        let Input::Bytes(bytes) = &row.input else {
            failed.push(format!("{}: subset needs raw bytes", row.name));
            continue;
        };
        let line = match subset::parse(bytes, 16_384) {
            Ok(_) => r#"{"canonical":true,"reason":"ok"}"#,
            Err(SubsetFailure::TooLarge) => r#"{"canonical":false,"reason":"payload_too_large"}"#,
            Err(SubsetFailure::NotCanonical) => r#"{"canonical":false,"reason":"payload_not_canonical_subset"}"#,
        };
        if line != row.anchor {
            failed.push(format!("{}: {} != {}", row.name, line, row.anchor));
        }
    }
    assert!(failed.is_empty(), "{} subset rows failed:\n{}", failed.len(), failed.join("\n"));
}

fn run_rows(command: &str) -> Vec<String> {
    let mut failed = Vec::new();
    for row in with_command(command) {
        let outcome = cli::run_conformance(&[command.to_string()], &mut || Ok(stdin_of(&row)));
        let line = String::from_utf8_lossy(&outcome.line).to_string();
        if line != row.anchor || outcome.exit != row.exit {
            failed.push(format!("{}: exit {} {:.200} != exit {} {:.200}", row.name, outcome.exit, line, row.exit, row.anchor));
        }
    }
    failed
}

#[test]
fn render_rows() {
    let failed = run_rows("render");
    assert!(failed.is_empty(), "{} render rows failed:\n{}", failed.len(), failed.join("\n"));
}

/// The `emit` vectors written by the generator: all of them, and there must be some.
#[test]
fn emit_rows() {
    assert!(!with_command("emit").is_empty(), "no emit vectors on disk");
    let failed = run_rows("emit");
    assert!(failed.is_empty(), "{} emit rows failed:\n{}", failed.len(), failed.join("\n"));
}
