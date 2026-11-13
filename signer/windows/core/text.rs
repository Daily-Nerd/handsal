//! Byte classes of the signed alphabet (ACT-04, ACT-10). One owner.

/// One byte of a signed string: 0x20 to 0x7E except `"` and `\`.
pub fn is_plain_byte(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) && byte != 0x22 && byte != 0x5C
}

pub fn is_plain(text: &str) -> bool {
    text.bytes().all(is_plain_byte)
}
