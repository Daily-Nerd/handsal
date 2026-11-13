//! Process plumbing shared by both executables: arguments and stdin bytes in, one line and the
//! closing LF on stdout, the exit code out. Every decision is in `cli`, which tests call without a
//! process; this file only moves bytes.
//!
//! Invariants: stdout is written as raw bytes (the Rust standard library does no newline
//! translation, on Windows either), stdin is read as raw bytes and never more than one byte past
//! MAX_INPUT, so the core can refuse an oversize input without buffering it.
//! Failure mode: a failed read is `internal` (reported by the core); a failed write of the result
//! cannot be reported anywhere, so the process exits 5.

use crate::cli::{Outcome, ReadStdin};
use crate::limits::MAX_INPUT;
use crate::value::Refusal;
use std::io::{Read, Write};

fn read_stdin_bounded() -> Result<Vec<u8>, Refusal> {
    let mut data = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut data)
        .map(|_| data)
        .map_err(|_| Refusal::new("internal"))
}

pub fn run_process(command_line: impl FnOnce(&[String], ReadStdin) -> Outcome) -> ! {
    // An argument that is not UTF-8 can match no command; it becomes one that never does.
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.into_string().unwrap_or_else(|_| "\u{fffd}".to_string())).collect();
    let outcome = command_line(&args, &mut read_stdin_bounded);
    let mut line = outcome.line;
    line.push(b'\n');
    let mut out = std::io::stdout().lock();
    if out.write_all(&line).and_then(|_| out.flush()).is_err() {
        std::process::exit(5);
    }
    std::process::exit(outcome.exit)
}
