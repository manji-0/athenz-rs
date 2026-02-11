use crate::error::Error;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;

pub(crate) fn decode(input: &str) -> Result<Vec<u8>, Error> {
    let len = input.len();
    if !len.is_multiple_of(4) {
        return Err(ybase64_error("invalid length"));
    }

    let bytes = input.as_bytes();
    let mut padding = 0usize;
    for &b in bytes.iter().rev() {
        if b == b'-' {
            padding += 1;
        } else {
            break;
        }
    }
    if padding > 2 {
        return Err(ybase64_error("too much padding"));
    }

    let data_len = len - padding;
    if bytes[..data_len].contains(&b'-') {
        return Err(ybase64_error("padding must be trailing"));
    }

    for (idx, &b) in bytes[..data_len].iter().enumerate() {
        if ybase64_value(b).is_none() {
            return Err(ybase64_error(&format!("invalid character at index {idx}")));
        }
    }

    if padding == 1 {
        let value = ybase64_value(bytes[len - 2])
            .ok_or_else(|| ybase64_error("invalid character before padding"))?;
        if (value & 0x03) != 0 {
            return Err(ybase64_error("invalid padding bits"));
        }
    } else if padding == 2 {
        let value = ybase64_value(bytes[len - 3])
            .ok_or_else(|| ybase64_error("invalid character before padding"))?;
        if (value & 0x0f) != 0 {
            return Err(ybase64_error("invalid padding bits"));
        }
    }

    let mut normalized = String::with_capacity(len);
    for &b in bytes {
        let ch = match b {
            b'.' => '+',
            b'_' => '/',
            b'-' => '=',
            _ => b as char,
        };
        normalized.push(ch);
    }

    BASE64_STD
        .decode(normalized.as_bytes())
        .map_err(|e| Error::Crypto(format!("ybase64 decode error: {e}")))
}

fn ybase64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'.' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn ybase64_error(message: &str) -> Error {
    Error::Crypto(format!("ybase64 decode error: {message}"))
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decode_accepts_valid_values() {
        let encoded = "dGVzdE1lc3NhZ2U-";
        let decoded = decode(encoded).expect("decode should succeed");
        assert_eq!(decoded, b"testMessage");
    }

    #[test]
    fn decode_rejects_invalid_chars() {
        let err = decode("abcd+efg").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn decode_rejects_non_trailing_padding() {
        let err = decode("ab-c").unwrap_err();
        assert!(err.to_string().contains("padding must be trailing"));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let err = decode("abc").unwrap_err();
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn decode_rejects_invalid_padding_bits_single() {
        let err = decode("AAB-").unwrap_err();
        assert!(err.to_string().contains("invalid padding bits"));
    }

    #[test]
    fn decode_rejects_invalid_padding_bits_double() {
        let err = decode("AB--").unwrap_err();
        assert!(err.to_string().contains("invalid padding bits"));
    }

    #[test]
    fn decode_rejects_too_much_padding() {
        let err = decode("A---").unwrap_err();
        assert!(err.to_string().contains("too much padding"));
    }
}
