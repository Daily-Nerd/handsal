//! `handsal-sign`: the shipped signer. Plumbing only; the commands are in `handsal_core::cli`.
//! The key backend (Windows, T6.6) is not built yet, so `render` stops at `key_unavailable` and
//! `keygen`, `pubkey` and `sign` fail closed.

use handsal_core::cli::{self, Environment};
use handsal_core::process;

fn main() {
    process::run_process(|args, stdin| cli::run(args, stdin, &Environment::unbound()))
}
