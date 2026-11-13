//! The byte-stream contract of both executables (SG-01, SG-02, SG-08, CF-04, T6.5): raw bytes in
//! and out through a real process, so what is tested is what a caller sees.

use handsal_core::encoding;
use handsal_core::profiles::Profiles;
use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

const SIGNER: &str = env!("CARGO_BIN_EXE_handsal-sign");
const CONFORMANCE: &str = env!("CARGO_BIN_EXE_handsal-sign-conformance");
const KID: &str = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI";
const OTHER_KID: &str = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY";

struct Run {
    exit: i32,
    stdout: Vec<u8>,
}

fn run_args(exe: &str, args: &[&OsStr], stdin: &[u8]) -> Run {
    let mut child =
        Command::new(exe).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let mut pipe = child.stdin.take().unwrap();
    let input = stdin.to_vec();
    // A writer thread, so a large input cannot deadlock against a full stdout pipe; the process may
    // stop reading early (an oversize input), so a broken pipe is not a failure.
    let writer = std::thread::spawn(move || {
        let _ = pipe.write_all(&input);
    });
    let out = child.wait_with_output().expect("wait");
    writer.join().unwrap();
    Run { exit: out.status.code().expect("exit code"), stdout: out.stdout }
}

fn run(exe: &str, args: &[&str], stdin: &[u8]) -> Run {
    let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    run_args(exe, &os, stdin)
}

fn text(run: &Run) -> String {
    String::from_utf8(run.stdout.clone()).unwrap()
}

fn hs(seed: &str) -> String {
    encoding::hashstr(seed.as_bytes())
}

fn emit_input() -> String {
    format!(
        concat!(
            r#"{{"attachments":{{}},"draft":{{"body":{{"kid":"{}","person":"carol"}},"method":"local:handsal.device.remove","#,
            r#""org":"{}","parent":{{"id":"{}","performer":"bob"}}}},"#,
            r#""fixed":{{"kid":"{}","nonce":"{}","performer":"alice","ts":"2026-11-08T11:59:00Z"}}}}"#
        ),
        OTHER_KID,
        hs("org"),
        hs("p"),
        KID,
        hs("nonce")
    )
}

#[test]
fn version_is_one_jcs_line_and_reads_no_stdin() {
    let r = run(SIGNER, &["version"], b"");
    assert_eq!(r.exit, 0);
    let want = format!(r#"{{"class":"win-hello-hw","impl":"handsal-sign-rust","spec":"{}"}}"#, Profiles::standard().production);
    assert_eq!(text(&r), format!("{}\n", want));
    // Anything on stdin is ignored by version.
    assert_eq!(run(SIGNER, &["version"], b"{not json").stdout, r.stdout);
}

#[test]
fn output_is_utf8_without_bom_lf_only_and_exactly_one_line() {
    for (args, stdin) in [(vec!["version"], emit_input()), (vec!["emit"], emit_input()), (vec!["bogus"], String::new())] {
        let r = run(SIGNER, &args, stdin.as_bytes());
        assert!(std::str::from_utf8(&r.stdout).is_ok());
        assert!(!r.stdout.starts_with(&[0xef, 0xbb, 0xbf]), "no BOM");
        assert!(!r.stdout.contains(&b'\r'), "no CR");
        assert_eq!(r.stdout.iter().filter(|&&b| b == b'\n').count(), 1, "one LF");
        assert_eq!(r.stdout.last(), Some(&b'\n'), "the LF closes the line");
    }
}

#[test]
fn any_command_but_the_listed_ones_is_unsupported_command() {
    let want = "{\"error\":\"unsupported_command\"}\n";
    for args in [vec![], vec!["info"], vec!["Version"], vec![""], vec!["version", "extra"], vec!["emit", "emit"], vec!["pin-read"], vec!["build"]] {
        let r = run(SIGNER, &args, b"");
        assert_eq!((r.exit, text(&r).as_str()), (2, want), "{:?}", args);
    }
    let bad = run_args(SIGNER, &[OsStr::new("\u{fffd}")], b"");
    assert_eq!((bad.exit, text(&bad).as_str()), (2, want));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let raw = run_args(SIGNER, &[OsStr::from_bytes(&[0xff, 0xfe])], b"");
        assert_eq!((raw.exit, text(&raw).as_str()), (2, want), "an argument that is not UTF-8");
    }
}

#[test]
fn emit_takes_one_object_with_one_framing_lf_and_nothing_else() {
    let input = emit_input();
    let bare = run(SIGNER, &["emit"], input.as_bytes());
    assert_eq!(bare.exit, 0, "{}", text(&bare));
    assert!(text(&bare).starts_with("{\"payload_hex\":\""));
    let framed = run(SIGNER, &["emit"], format!("{}\n", input).as_bytes());
    assert_eq!(framed.stdout, bare.stdout, "one trailing LF is framing");
    let refused = "{\"error\":\"schema_refused\"}\n";
    for stdin in [format!("{}\n\n", input), format!("{}\r\n", input), format!("\u{feff}{}", input), format!("{} ", input), String::new()] {
        let r = run(SIGNER, &["emit"], stdin.as_bytes());
        assert_eq!((r.exit, text(&r).as_str()), (2, refused), "{:?}", &stdin[..stdin.len().min(12)]);
    }
    let dup = r#"{"attachments":{},"attachments":{},"draft":{},"fixed":{}}"#;
    assert_eq!(text(&run(SIGNER, &["emit"], dup.as_bytes())), refused, "a duplicate key");
}

#[test]
fn stdin_over_max_input_is_refused_without_reading_it_all() {
    let big = vec![b'a'; 16_777_217];
    let r = run(SIGNER, &["emit"], &big);
    assert_eq!((r.exit, text(&r).as_str()), (2, "{\"error\":\"schema_refused\"}\n"));
}

#[test]
fn render_and_the_key_commands_fail_closed_with_the_documented_codes() {
    let draft_input = format!(
        r#"{{"attachments":{{}},"draft":{{"body":{{"kid":"{}","person":"carol"}},"method":"local:handsal.device.remove","org":"{}","parent":{{"id":"{}","performer":"bob"}}}}}}"#,
        OTHER_KID,
        hs("org"),
        hs("p")
    );
    let r = run(SIGNER, &["render"], draft_input.as_bytes());
    assert_eq!((r.exit, text(&r).as_str()), (3, "{\"error\":\"key_unavailable\"}\n"), "no key is bound");
    for command in ["keygen", "pubkey", "sign"] {
        let r = run(SIGNER, &[command], b"{}");
        assert_eq!((r.exit, text(&r).as_str()), (5, "{\"error\":\"internal\"}\n"), "{}", command);
    }
    // The CF-03 form of render is not the signer's render.
    let checker_form = r#"{"attachments":{},"kid":"k","method":"m","payload":{}}"#;
    let r = run(SIGNER, &["render"], checker_form.as_bytes());
    assert_eq!((r.exit, text(&r).as_str()), (2, "{\"error\":\"schema_refused\"}\n"));
}

#[test]
fn the_conformance_executable_has_render_and_emit_only() {
    for args in [vec![], vec!["version"], vec!["keygen"], vec!["sign"], vec!["render", "x"]] {
        let r = run(CONFORMANCE, &args, b"{}");
        assert_eq!((r.exit, text(&r).as_str()), (2, "{\"error\":\"unsupported_command\"}\n"), "{:?}", args);
    }
    let shipped = run(SIGNER, &["emit"], emit_input().as_bytes());
    let conformance = run(CONFORMANCE, &["emit"], emit_input().as_bytes());
    assert_eq!((conformance.exit, &conformance.stdout), (shipped.exit, &shipped.stdout), "the same emit");
    let refused = run(CONFORMANCE, &["emit"], b"{}");
    assert_eq!((refused.exit, text(&refused).as_str()), (2, "{\"error\":\"schema_refused\"}\n"));
}

#[test]
fn conformance_render_exits_zero_for_every_result() {
    for (stdin, want) in [
        ("not json".to_string(), "unparseable_input"),
        (r#"{"a":1,"a":2}"#.to_string(), "unparseable_input"),
        ("{}".to_string(), "malformed_input"),
        (r#"{"attachments":[],"kid":"k","method":"m","payload":{}}"#.to_string(), "malformed_input"),
        (r#"{"attachments":{},"kid":"k","method":"m","payload":{},"x":null}"#.to_string(), "malformed_input"),
        (r#"{"attachments":{},"kid":"k","method":"m","payload":{}}"#.to_string(), "schema"),
    ] {
        let r = run(CONFORMANCE, &["render"], format!("{}\n", stdin).as_bytes());
        assert_eq!((r.exit, text(&r)), (0, format!("{{\"error\":\"{}\"}}\n", want)), "{}", stdin);
    }
    let big = vec![b' '; 16_777_217];
    let r = run(CONFORMANCE, &["render"], &big);
    assert_eq!((r.exit, text(&r).as_str()), (0, "{\"error\":\"unparseable_input\"}\n"));
}

/// CF-03 through the conformance executable: 64 levels reach the command (`malformed_input`), 65 are
/// `unparseable_input`, both with exit 0 (cli/stdin-nesting-*).
#[test]
fn conformance_render_nesting_bound_is_exactly_max_nesting() {
    let arrays = |n: usize| format!("{}{}\n", "[".repeat(n), "]".repeat(n));
    for (levels, want) in [(63, "malformed_input"), (64, "malformed_input"), (65, "unparseable_input")] {
        let r = run(CONFORMANCE, &["render"], arrays(levels).as_bytes());
        assert_eq!((r.exit, text(&r)), (0, format!("{{\"error\":\"{}\"}}\n", want)), "{} levels", levels);
    }
}

/// SG-08, SG-10: a refused prompt is exit 4, `prompt_refused`.
#[test]
fn prompt_refused_is_exit_4() {
    let out = handsal_core::cli::outcome_for(handsal_core::value::Refusal::new("prompt_refused"));
    assert_eq!((out.exit, out.line.as_slice()), (4, br#"{"error":"prompt_refused"}"#.as_slice()));
}
