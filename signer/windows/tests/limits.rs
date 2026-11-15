//! SG-01, section 2.3: the limits have one owner, `spec/registry.json`. `core/limits.rs` reads them
//! from the registry the binary embeds and holds no number of its own, so a change to the file is a
//! change to every limit and the profile hash together.

use handsal_core::limits;
use handsal_core::registry::Registry;
use std::path::PathBuf;

#[test]
fn every_limit_is_the_registry_number() {
    let registry = Registry::standard();
    assert_eq!(limits::max_payload() as i64, registry.number("MAX_PAYLOAD"));
    assert_eq!(limits::max_depth() as i64, registry.number("MAX_DEPTH"));
    assert_eq!(limits::max_input() as i64, registry.number("MAX_INPUT"));
    assert_eq!(limits::line_max() as i64, registry.number("render_line.max"));
    assert_eq!(limits::wrap_segment() as i64, registry.number("render_line.wrap_segment_max"));
    assert_eq!(limits::max_lines() as i64, registry.number("render_length.max"));
    assert_eq!(limits::block_max_bytes() as i64, registry.number("content_block.max_source_bytes"));
    assert_eq!(limits::block_max_lines() as i64, registry.number("content_block.max_block_lines"));
    assert_eq!(limits::block_line_bytes() as i64, registry.number("content_block.max_escaped_bytes_per_line"));
}

/// CF-11 and GP-02: the admission reserve and the `relays` bounds are registry rows, and two reserves
/// leave the 14 MiB the pool keeps for acts.
#[test]
fn the_admit_reserve_and_relays_bounds_are_registry_rows() {
    let registry = Registry::standard();
    assert_eq!(registry.number("ADMIT_RESERVE"), 1_048_576);
    assert_eq!(registry.number("relays.min"), 0);
    assert_eq!(registry.number("relays.max"), 2);
    assert_eq!(registry.number("MAX_INPUT") - 2 * registry.number("ADMIT_RESERVE"), 14 * 1_048_576);
}

/// The tripwire for the way this drifted: a literal typed into `limits.rs` is a second copy.
#[test]
fn limits_hold_no_number_literal() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core/limits.rs");
    let source = std::fs::read_to_string(path).unwrap();
    let mut code = String::new();
    let mut in_string = false;
    for line in source.lines() {
        let line = line.split("//").next().unwrap_or("");
        for c in line.chars() {
            if c == '"' {
                in_string = !in_string;
            } else if !in_string {
                code.push(c);
            }
        }
        code.push('\n');
    }
    let digits: Vec<&str> = code.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).collect();
    assert!(digits.is_empty(), "limits.rs holds the numbers {:?}", digits);
}
