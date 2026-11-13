//! `handsal-sign-conformance` (CF-04): the executable that runs the `render` and `emit` vectors.
//! The same core as `handsal-sign`, a separate entry point, never a flag of it. It holds no key,
//! shows no prompt and reads neither the clock nor a random source. It is never installed at an
//! administrator path and is not part of the signer's distribution.

use handsal_core::cli;
use handsal_core::process;

fn main() {
    process::run_process(cli::run_conformance)
}
