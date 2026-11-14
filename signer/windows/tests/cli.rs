//! The byte-stream contract of both executables (SG-01, SG-02, SG-08, CF-04, T6.5): raw bytes in
//! and out through a real process, so what is tested is what a caller sees.

use handsal_core::cli::{self, Environment};
use handsal_core::encoding;
use handsal_core::profiles::Profiles;
use handsal_core::value::Refusal;
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

/// SG-02: `class` is the registry id of the key class the build produces, and the key backend is the one owner
/// of it. This core ships no backend (T6.6), so the shipped binary has no class to name and `version` is `internal`
/// rather than a hand-written class that the registry may not hold.
#[test]
fn version_of_a_build_without_a_key_backend_is_internal_not_a_made_up_class() {
    let r = run(SIGNER, &["version"], b"");
    assert_eq!((r.exit, text(&r)), (5, "{\"error\":\"internal\"}\n".to_string()));
    assert_eq!(run(SIGNER, &["version"], b"{not json").stdout, r.stdout);
}

fn version_in_process(environment: &Environment) -> (i32, String) {
    let mut stdin = || -> Result<Vec<u8>, Refusal> { panic!("version reads no stdin") };
    let out = cli::run(&["version".to_string()], &mut stdin, environment);
    (out.exit, String::from_utf8(out.line).unwrap())
}

#[test]
fn version_is_one_jcs_line_with_the_class_of_the_backend_and_reads_no_stdin() {
    let environment = Environment::fixed(None, 0, hs("nonce")).with_key_class("apple-se-bio");
    let want = format!(r#"{{"class":"apple-se-bio","impl":"handsal-sign-rust","spec":"{}"}}"#, Profiles::standard().production);
    assert_eq!(version_in_process(&environment), (0, want));
}

#[test]
#[should_panic(expected = "not in the registry")]
fn an_environment_cannot_name_a_class_the_registry_does_not_hold() {
    let _ = Environment::fixed(None, 0, hs("nonce")).with_key_class("win-hello-hw");
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

/// SG-16: the shipped binary has no key backend yet, so `agree` has no key: a well-formed input is `key_unavailable`
/// (the same code `render` gives before a key exists), a malformed one is `schema_refused` first (SG-08 order).
#[test]
fn agree_in_a_build_without_a_key_backend_is_key_unavailable_after_the_form() {
    let point = r#"{"x":"lUPCNEHvuafONehP-i-tr0JapbPS5kgZ4WaJ5lh3HV4","y":"jfz8J-2vz7ErGwS7MHsMN0OFDa7KtIQlwW0IqdQRbMQ"}"#;
    let good = format!(r#"{{"context":"mail/v1","peer":{}}}"#, point);
    let r = run(SIGNER, &["agree"], good.as_bytes());
    assert_eq!((r.exit, text(&r).as_str()), (3, "{\"error\":\"key_unavailable\"}\n"));
    let r = run(SIGNER, &["agree"], b"{\"context\":\"mail/v1\"}");
    assert_eq!((r.exit, text(&r).as_str()), (2, "{\"error\":\"schema_refused\"}\n"));
    // the conformance executable holds no key and has no agree command (CF-04)
    let r = run(CONFORMANCE, &["agree"], good.as_bytes());
    assert_eq!((r.exit, text(&r).as_str()), (2, "{\"error\":\"unsupported_command\"}\n"));
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

/// SG-08: a sensor that cannot verify now is exit 4, `biometric_unavailable`.
#[test]
fn biometric_unavailable_is_exit_4() {
    let out = handsal_core::cli::outcome_for(handsal_core::value::Refusal::new("biometric_unavailable"));
    assert_eq!((out.exit, out.line.as_slice()), (4, br#"{"error":"biometric_unavailable"}"#.as_slice()));
}
