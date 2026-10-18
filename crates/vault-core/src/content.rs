//! File contents: a header holding a random per-file key wrapped by the vault
//! content key, then 64 KiB chunks sealed with AES-256-GCM.
//!
//! ```text
//! header  = "FLKF" | version (1) | header nonce (12) | wrapped file key (32 + 16 tag)
//! chunk   = nonce (12) | ciphertext (≤ 64 KiB) | tag (16)
//! aad     = header nonce | chunk index (u64 BE) | is-last (u8)
//! ```
//!
//! Every chunk gets a fresh random nonce, so rewriting a chunk never reuses one.
//! The final chunk is always shorter than a full chunk (possibly empty), and the
//! AAD marks it as last, so truncation, reordering and appending are detected.

use std::io::{self, Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::{random_fill, Error, Result};

pub(crate) const CHUNK_LEN: usize = 64 * 1024;
const MAGIC: &[u8; 4] = b"FLKF";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FILE_KEY_LEN: usize = 32;
pub(crate) const HEADER_LEN: usize = MAGIC.len() + 1 + NONCE_LEN + FILE_KEY_LEN + TAG_LEN;
const CHUNK_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub(crate) const SEALED_CHUNK_LEN: usize = CHUNK_LEN + CHUNK_OVERHEAD;

/// Plaintext size of an encrypted file of `sealed_len` bytes, or `None` if no
/// valid file has that size.
pub(crate) fn plaintext_len(sealed_len: u64) -> Option<u64> {
    let body = sealed_len.checked_sub(HEADER_LEN as u64)?;
    let full_chunks = body / SEALED_CHUNK_LEN as u64;
    let last = (body % SEALED_CHUNK_LEN as u64).checked_sub(CHUNK_OVERHEAD as u64)?;
    Some(full_chunks * CHUNK_LEN as u64 + last)
}

/// Encrypts `input` to `output`. Returns the number of plaintext bytes.
pub(crate) fn encrypt(
    content_key: &[u8; 32],
    mut input: impl Read,
    mut output: impl Write,
) -> Result<u64> {
    let mut file_key = Zeroizing::new([0u8; FILE_KEY_LEN]);
    random_fill(&mut *file_key)?;
    let mut header_nonce = [0u8; NONCE_LEN];
    random_fill(&mut header_nonce)?;
    let wrapped = cipher(content_key)
        .encrypt(
            &Nonce::from(header_nonce),
            Payload {
                msg: &file_key[..],
                aad: &header_aad(),
            },
        )
        .expect("AES-GCM encryption of a key cannot fail");
    output.write_all(MAGIC)?;
    output.write_all(&[VERSION])?;
    output.write_all(&header_nonce)?;
    output.write_all(&wrapped)?;

    let chunk_cipher = cipher(&file_key);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_LEN]);
    let mut total = 0u64;
    for index in 0u64.. {
        let len = read_full(&mut input, &mut buf)?;
        let last = len < CHUNK_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        random_fill(&mut nonce)?;
        let sealed = chunk_cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &buf[..len],
                    aad: &chunk_aad(&header_nonce, index, last),
                },
            )
            .expect("AES-GCM encryption of a 64 KiB chunk cannot fail");
        output.write_all(&nonce)?;
        output.write_all(&sealed)?;
        total += len as u64;
        if last {
            break;
        }
    }
    output.flush()?;
    Ok(total)
}

/// Decrypts `input` to `output`. Returns the number of plaintext bytes.
///
/// Plaintext is streamed out chunk by chunk as each chunk authenticates; on an
/// error, `output` may hold a verified prefix and must be discarded.
pub(crate) fn decrypt(
    content_key: &[u8; 32],
    mut input: impl Read,
    mut output: impl Write,
) -> Result<u64> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut input, &mut header)? != HEADER_LEN {
        return Err(Error::Corrupt("file is shorter than its header".into()));
    }
    if &header[..4] != MAGIC {
        return Err(Error::Corrupt("not a file_locker file".into()));
    }
    if header[4] != VERSION {
        return Err(Error::UnsupportedVersion(header[4].into()));
    }
    let header_nonce: [u8; NONCE_LEN] = header[5..5 + NONCE_LEN].try_into().expect("fixed slice");
    let file_key = Zeroizing::new(
        cipher(content_key)
            .decrypt(
                &Nonce::from(header_nonce),
                Payload {
                    msg: &header[5 + NONCE_LEN..],
                    aad: &header_aad(),
                },
            )
            .map_err(|_| Error::Integrity("file header".into()))?,
    );
    let chunk_cipher = Aes256Gcm::new_from_slice(&file_key).expect("unwrapped key is 32 bytes");

    let mut buf = vec![0u8; SEALED_CHUNK_LEN];
    let mut total = 0u64;
    for index in 0u64.. {
        let len = read_full(&mut input, &mut buf)?;
        if len < CHUNK_OVERHEAD {
            return Err(Error::Integrity("file is truncated".into()));
        }
        let last = len < SEALED_CHUNK_LEN;
        let (nonce, sealed) = buf[..len].split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let plain = Zeroizing::new(
            chunk_cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: sealed,
                        aad: &chunk_aad(&header_nonce, index, last),
                    },
                )
                .map_err(|_| Error::Integrity(format!("chunk {index}")))?,
        );
        output.write_all(&plain)?;
        total += plain.len() as u64;
        if last {
            if read_full(&mut input, &mut [0u8; 1])? != 0 {
                return Err(Error::Integrity("data after the final chunk".into()));
            }
            break;
        }
    }
    output.flush()?;
    Ok(total)
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

fn header_aad() -> [u8; 5] {
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION]
}

fn chunk_aad(header_nonce: &[u8; NONCE_LEN], index: u64, last: bool) -> [u8; NONCE_LEN + 9] {
    let mut aad = [0u8; NONCE_LEN + 9];
    aad[..NONCE_LEN].copy_from_slice(header_nonce);
    aad[NONCE_LEN..NONCE_LEN + 8].copy_from_slice(&index.to_be_bytes());
    aad[NONCE_LEN + 8] = u8::from(last);
    aad
}

/// Reads until `buf` is full or the input ends. Returns the bytes read.
fn read_full(input: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn seal(data: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        encrypt(&KEY, data, &mut sealed).unwrap();
        sealed
    }

    fn open(sealed: &[u8]) -> Result<Vec<u8>> {
        let mut plain = Vec::new();
        decrypt(&KEY, sealed, &mut plain)?;
        Ok(plain)
    }

    #[test]
    fn round_trips_boundary_sizes() {
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 17,
        ] {
            let data = sample(len);
            let sealed = seal(&data);
            assert_eq!(
                plaintext_len(sealed.len() as u64),
                Some(len as u64),
                "len {len}"
            );
            assert_eq!(open(&sealed).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn same_plaintext_encrypts_differently() {
        assert_ne!(seal(b"hello"), seal(b"hello"));
    }

    #[test]
    fn detects_tampering() {
        let sealed = seal(&sample(2 * CHUNK_LEN + 500));
        let integrity = |data: &[u8]| matches!(open(data), Err(Error::Integrity(_)));

        let mut flipped = sealed.clone();
        flipped[HEADER_LEN + 100] ^= 1;
        assert!(integrity(&flipped), "bit flip");

        assert!(integrity(&sealed[..sealed.len() - 5]), "short final chunk");
        assert!(
            integrity(&sealed[..HEADER_LEN + 2 * SEALED_CHUNK_LEN]),
            "final chunk removed"
        );

        let mut swapped = sealed.clone();
        let (a, b) = (HEADER_LEN, HEADER_LEN + SEALED_CHUNK_LEN);
        let first = swapped[a..b].to_vec();
        swapped.copy_within(b..b + SEALED_CHUNK_LEN, a);
        swapped[b..b + SEALED_CHUNK_LEN].copy_from_slice(&first);
        assert!(integrity(&swapped), "chunks swapped");

        let mut extended = sealed.clone();
        extended.push(0);
        assert!(integrity(&extended), "byte appended");

        let mut wrong_key = Vec::new();
        assert!(matches!(
            decrypt(&[8; 32], &sealed[..], &mut wrong_key),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn rejects_foreign_files() {
        assert!(matches!(
            open(b"not a vault file at all, just some text here.........................."),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(open(b"FLK"), Err(Error::Corrupt(_))));
    }
}
