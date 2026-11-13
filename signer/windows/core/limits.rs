//! The constants of section 2.3. One owner, so no number is repeated.

/// Every signed or hashed value: payload, header, genesis document.
pub const MAX_PAYLOAD: usize = 16_384;
pub const MAX_DEPTH: usize = 8;
/// The bytes a signer reads from its input channel.
pub const MAX_INPUT: usize = 16_777_216;
pub const MAX_EXPIRES_IN_S: i64 = 2_592_000;
pub const LINE_MAX: usize = 100;
pub const WRAP_SEGMENT: usize = 98;
pub const MAX_LINES: usize = 72;
pub const BLOCK_MAX_BYTES: usize = 2048;
pub const BLOCK_MAX_LINES: usize = 32;
pub const BLOCK_LINE_BYTES: usize = 96;
