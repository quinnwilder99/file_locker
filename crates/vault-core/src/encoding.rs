//! Crockford base32: unambiguous for humans (no I, L, O, U) and safe for
//! case-insensitive filesystems. Used for recovery keys and storage paths.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) fn crockford_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes Crockford base32. Accepts lower case and the usual confusables
/// (O for 0, I and L for 1). Returns `None` on an invalid character or
/// non-zero padding bits.
pub(crate) fn crockford_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.chars() {
        acc = (acc << 5) | crockford_value(c)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

/// Maps a character to its canonical alphabet character, if it has one.
pub(crate) fn crockford_normalize(c: char) -> Option<char> {
    crockford_value(c).map(|v| ALPHABET[v as usize] as char)
}

fn crockford_value(c: char) -> Option<u32> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_lengths() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(crockford_decode(&crockford_encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn accepts_confusables_and_lower_case() {
        let encoded = crockford_encode(&[0x00, 0x42, 0xff]);
        let sloppy = encoded.to_lowercase().replace('0', "o").replace('1', "l");
        assert_eq!(crockford_decode(&sloppy).unwrap(), [0x00, 0x42, 0xff]);
    }

    #[test]
    fn rejects_bad_characters() {
        assert!(crockford_decode("AB!D").is_none());
        assert!(crockford_decode("U").is_none());
    }
}
