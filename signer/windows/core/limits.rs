//! The constants of section 2.3, read from the registry. `spec/registry.json` is the one owner:
//! the binary embeds it (`registry.rs`) and every limit here is looked up in it, so no number is
//! written twice. The expiry bound `MAX_EXPIRES_IN_S` is read where it is used (`draft.rs`).

use crate::registry::Registry;

fn limit(path: &str) -> usize {
    Registry::standard().number(path) as usize
}

/// Every signed or hashed value: payload, header, genesis document.
pub fn max_payload() -> usize {
    limit("MAX_PAYLOAD")
}

pub fn max_depth() -> usize {
    limit("MAX_DEPTH")
}

/// The bytes a signer reads from its input channel.
pub fn max_input() -> usize {
    limit("MAX_INPUT")
}

pub fn line_max() -> usize {
    limit("render_line.max")
}

pub fn wrap_segment() -> usize {
    limit("render_line.wrap_segment_max")
}

pub fn max_lines() -> usize {
    limit("render_length.max")
}

pub fn block_max_bytes() -> usize {
    limit("content_block.max_source_bytes")
}

pub fn block_max_lines() -> usize {
    limit("content_block.max_block_lines")
}

pub fn block_line_bytes() -> usize {
    limit("content_block.max_escaped_bytes_per_line")
}
