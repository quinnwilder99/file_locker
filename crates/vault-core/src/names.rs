//! File and folder names: AES-SIV with the parent folder's ID as associated
//! data, so equal names in different folders encrypt differently and entries
//! cannot be moved between folders undetected.

use std::path::PathBuf;

use aes_siv::siv::Aes256Siv;
use aes_siv::KeyInit;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::encoding::crockford_encode;
use crate::{Error, Result};

pub(crate) const ENTRY_SUFFIX: &str = ".flk";
pub(crate) const SHORTENED_SUFFIX: &str = ".flks";
/// Longest stored name kept as is; keeps paths well under NTFS's 255-character
/// component limit. Longer encrypted names are shortened.
const MAX_STORED_LEN: usize = 220;
/// Windows' limit for one path component, in UTF-16 code units.
const MAX_NAME_UTF16: usize = 255;

/// How an encrypted name is stored in its parent's storage folder.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoredName {
    /// `<encrypted>.flk`, used directly as the entry name.
    Plain(String),
    /// `<hash>.flks`: a folder whose `name.flk` file holds `full`.
    Shortened { short: String, full: String },
}

pub(crate) fn encrypt_name(key: &[u8; 64], dir_id: &str, name: &str) -> Result<StoredName> {
    validate_name(name)?;
    let sealed = Aes256Siv::new_from_slice(key)
        .expect("64-byte key")
        .encrypt([dir_id.as_bytes()], name.as_bytes())
        .expect("AES-SIV encryption cannot fail");
    let full = URL_SAFE_NO_PAD.encode(sealed) + ENTRY_SUFFIX;
    Ok(if full.len() <= MAX_STORED_LEN {
        StoredName::Plain(full)
    } else {
        StoredName::Shortened {
            short: shorten(&full),
            full,
        }
    })
}

/// Decrypts a full stored name (`<encrypted>.flk`).
pub(crate) fn decrypt_name(key: &[u8; 64], dir_id: &str, full: &str) -> Result<String> {
    let encoded = full
        .strip_suffix(ENTRY_SUFFIX)
        .ok_or_else(|| Error::Corrupt(format!("unexpected entry {full}")))?;
    let sealed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Corrupt(format!("undecodable entry name {full}")))?;
    let plain = Aes256Siv::new_from_slice(key)
        .expect("64-byte key")
        .decrypt([dir_id.as_bytes()], &sealed)
        .map_err(|_| Error::Integrity(format!("entry name {full}")))?;
    let name = String::from_utf8(plain)
        .map_err(|_| Error::Corrupt(format!("entry name {full} is not UTF-8")))?;
    validate_name(&name)?;
    Ok(name)
}

/// The stand-in stored for a long encrypted name: a hash of it, so lookups can
/// find it without reading every `name.flk`.
pub(crate) fn shorten(full: &str) -> String {
    crockford_encode(&Sha256::digest(full.as_bytes())[..20]) + SHORTENED_SUFFIX
}

/// Rejects names that could escape their folder when exported, and names
/// longer than Windows allows.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(Error::InvalidName(name.into()));
    }
    if name.encode_utf16().count() > MAX_NAME_UTF16 {
        return Err(Error::NameTooLong(name.into()));
    }
    Ok(())
}

/// Storage folder for a vault folder ID, relative to the vault root:
/// `d/<2 chars>/<30 chars>`, from a keyed hash so the tree shape is not linkable to IDs.
pub(crate) fn dir_storage_path(key: &[u8; 32], dir_id: &str) -> PathBuf {
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(dir_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    let encoded = crockford_encode(&digest[..20]);
    PathBuf::from("d").join(&encoded[..2]).join(&encoded[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(stored: StoredName) -> String {
        match stored {
            StoredName::Plain(full) | StoredName::Shortened { full, .. } => full,
        }
    }

    #[test]
    fn names_round_trip_and_depend_on_folder() {
        let key = [9u8; 64];
        let a = full(encrypt_name(&key, "dir-a", "Résumé 2026.docx").unwrap());
        let b = full(encrypt_name(&key, "dir-b", "Résumé 2026.docx").unwrap());
        assert_ne!(a, b);
        assert_eq!(
            a,
            full(encrypt_name(&key, "dir-a", "Résumé 2026.docx").unwrap())
        );
        assert_eq!(decrypt_name(&key, "dir-a", &a).unwrap(), "Résumé 2026.docx");
        assert!(matches!(
            decrypt_name(&key, "dir-b", &a),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn long_names_are_shortened() {
        let key = [9u8; 64];
        let long = "x".repeat(200);
        let StoredName::Shortened { short, full } = encrypt_name(&key, "", &long).unwrap() else {
            panic!("expected a shortened name");
        };
        assert_eq!(short, shorten(&full));
        assert_eq!(short.len(), 32 + SHORTENED_SUFFIX.len());
        assert_eq!(decrypt_name(&key, "", &full).unwrap(), long);
        assert!(matches!(
            encrypt_name(&key, "", "short").unwrap(),
            StoredName::Plain(_)
        ));
    }

    #[test]
    fn rejects_escaping_and_oversized_names() {
        for bad in ["", ".", "..", "a/b", "a\\b", "nul\0"] {
            assert!(
                matches!(encrypt_name(&[0; 64], "", bad), Err(Error::InvalidName(_))),
                "{bad:?}"
            );
        }
        assert!(validate_name(&"é".repeat(255)).is_ok());
        assert!(matches!(
            validate_name(&"é".repeat(256)),
            Err(Error::NameTooLong(_))
        ));
    }

    #[test]
    fn storage_path_shape() {
        let p = dir_storage_path(&[3; 32], "");
        let parts: Vec<_> = p.iter().map(|s| s.to_str().unwrap().len()).collect();
        assert_eq!(parts, [1, 2, 30]);
    }
}
