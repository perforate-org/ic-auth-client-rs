//! Standard base64, as the JavaScript library writes it.
//!
//! Port of upstream `src/client/base64.ts`. Upstream uses `btoa`/`atob`
//! semantics --- standard alphabet, padded --- and not base64url.

use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD, Engine as _};

/// Encodes bytes as standard base64, padded.
pub fn to_base64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

/// Decodes standard base64 into bytes.
pub fn from_base64(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(encoded)
}

/// Encodes bytes as base64url without padding, the form URLs and fragments use.
pub fn base64_url_no_pad(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
pub fn from_base64_url_no_pad(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_SAFE_NO_PAD.decode(encoded)
}

/// Decodes standard base64 into bytes, reporting nothing where the text is not
/// base64.
///
/// Used where a stored value is advisory: a journal entry that cannot be decoded
/// means "this flow did not start here", which is not an error.
pub fn from_base64_opt(encoded: &str) -> Option<Vec<u8>> {
    from_base64(encoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for bytes in [&b""[..], b"a", b"ab", b"abc", &[0u8, 255, 128, 1][..]] {
            let encoded = to_base64(bytes);
            assert_eq!(from_base64(&encoded).unwrap(), bytes);
        }
    }

    #[test]
    fn is_padded_standard_alphabet() {
        assert_eq!(to_base64(b"ab"), "YWI=");
        assert_eq!(to_base64(&[0xfb, 0xff]), "+/8=");
    }
}
