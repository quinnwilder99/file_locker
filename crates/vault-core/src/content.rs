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

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::fs_util::temp_path_beside;
use crate::secret::SecretBytes;

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
    let (header, header_nonce, file_key) = new_header(content_key)?;
    output.write_all(&header)?;

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
    let (header_nonce, file_key) = open_header(content_key, &header)?;
    let chunk_cipher = cipher(&file_key);

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

/// A header for a new file with a random file key. Returns `(header bytes,
/// header nonce, file key)`.
fn new_header(
    content_key: &[u8; 32],
) -> Result<([u8; HEADER_LEN], [u8; NONCE_LEN], SecretBytes<FILE_KEY_LEN>)> {
    let mut file_key = SecretBytes::<FILE_KEY_LEN>::zeroed();
    random_fill(&mut file_key[..])?;
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
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5..5 + NONCE_LEN].copy_from_slice(&header_nonce);
    header[5 + NONCE_LEN..].copy_from_slice(&wrapped);
    Ok((header, header_nonce, file_key))
}

/// Checks a file header and unwraps its file key. Returns `(header nonce, file key)`.
fn open_header(
    content_key: &[u8; 32],
    header: &[u8; HEADER_LEN],
) -> Result<([u8; NONCE_LEN], SecretBytes<FILE_KEY_LEN>)> {
    if &header[..4] != MAGIC {
        return Err(Error::Corrupt("not a file_locker file".into()));
    }
    if header[4] != VERSION {
        return Err(Error::UnsupportedVersion(header[4].into()));
    }
    let header_nonce: [u8; NONCE_LEN] = header[5..5 + NONCE_LEN].try_into().expect("fixed slice");
    let unwrapped = Zeroizing::new(
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
    let file_key = SecretBytes::<FILE_KEY_LEN>::from_slice(&unwrapped)
        .ok_or_else(|| Error::Corrupt("file key has the wrong length".into()))?;
    Ok((header_nonce, file_key))
}

/// Size on disk of an encrypted file holding `len` plaintext bytes.
fn sealed_len(len: u64) -> u64 {
    let chunk = CHUNK_LEN as u64;
    HEADER_LEN as u64
        + (len / chunk) * SEALED_CHUNK_LEN as u64
        + CHUNK_OVERHEAD as u64
        + len % chunk
}

fn chunk_offset(index: u64) -> u64 {
    HEADER_LEN as u64 + index * SEALED_CHUNK_LEN as u64
}

/// An encrypted file opened for reads and writes at any offset, as a mounted
/// drive needs. A write re-encrypts only the chunks it touches, each with a
/// fresh nonce, and keeps the final-chunk rule, so the file is always valid
/// for whole-file decryption too.
///
/// Not crash-atomic: if a chunk rewrite is interrupted, that chunk fails
/// authentication afterwards while the rest of the file stays readable.
pub struct VaultFile {
    file: File,
    header_nonce: [u8; NONCE_LEN],
    cipher: Aes256Gcm,
    len: u64,
}

impl VaultFile {
    /// Creates an empty encrypted file at `path` and keeps it open.
    ///
    /// Written under a temporary name and renamed into place, so `path` never
    /// holds a partial header. Not synced to disk: an empty new file is not
    /// worth a flush, and callers that need durability call [`sync`](Self::sync).
    /// Keeping the handle also avoids a reopen, which antivirus scanners make
    /// slow for new, random-looking files.
    pub(crate) fn create(content_key: &[u8; 32], path: &Path) -> Result<Self> {
        let tmp = temp_path_beside(path)?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let (header, header_nonce, file_key) = new_header(content_key)?;
            file.write_all(&header)?;
            let mut created = Self {
                file,
                header_nonce,
                cipher: cipher(&file_key),
                len: 0,
            };
            created.write_chunk(0, &[], true)?;
            // The handle stays valid across the rename (std opens files with
            // delete sharing).
            std::fs::rename(&tmp, path)?;
            Ok(created)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    pub(crate) fn open(content_key: &[u8; 32], path: &Path) -> Result<Self> {
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            // A read-only vault (e.g. on write-protected media) still opens for reading.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => File::open(path)?,
            Err(e) => return Err(e.into()),
        };
        let len = plaintext_len(file.metadata()?.len())
            .ok_or_else(|| Error::Corrupt("file has an impossible size".into()))?;
        let mut header = [0u8; HEADER_LEN];
        file.read_exact(&mut header)?;
        let (header_nonce, file_key) = open_header(content_key, &header)?;
        Ok(Self {
            file,
            header_nonce,
            cipher: cipher(&file_key),
            len,
        })
    }

    /// Plaintext length.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads up to `buf.len()` bytes at `offset`; returns 0 at or past the end.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let end = self.len.min(offset + buf.len() as u64);
        let chunk = CHUNK_LEN as u64;
        let mut pos = offset;
        while pos < end {
            let index = pos / chunk;
            let chunk_start = index * chunk;
            let plain = self.read_chunk(index, self.len)?;
            let from = (pos - chunk_start) as usize;
            let to = ((end - chunk_start) as usize).min(plain.len());
            let at = (pos - offset) as usize;
            buf[at..at + (to - from)].copy_from_slice(&plain[from..to]);
            pos = chunk_start + to as u64;
        }
        Ok((end - offset) as usize)
    }

    /// Writes `data` at `offset`, extending the file (with zeros for any gap) if needed.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::NotAllowed(
                "write past the largest possible file size",
            ))?;
        self.update(offset, data, self.len.max(end))
    }

    /// Truncates or zero-extends the file to `new_len` bytes.
    pub fn set_len(&mut self, new_len: u64) -> Result<()> {
        if new_len == self.len {
            return Ok(());
        }
        self.update(new_len.min(self.len), &[], new_len)
    }

    pub fn sync(&mut self) -> Result<()> {
        Ok(self.file.sync_data()?)
    }

    /// Writes `data` at `offset` and makes the file `new_len` bytes long
    /// (`new_len >= offset + data.len()`), re-encrypting only affected chunks.
    fn update(&mut self, offset: u64, data: &[u8], new_len: u64) -> Result<()> {
        let old_len = self.len;
        let chunk = CHUNK_LEN as u64;
        let data_end = offset + data.len() as u64;
        // From the first chunk that changes, through the new final chunk if
        // the length changes (the old final chunk stops being final, or a
        // truncated chunk becomes final), else through the last chunk written.
        let first = offset.min(old_len).min(new_len) / chunk;
        let last = if new_len != old_len {
            new_len / chunk
        } else if data.is_empty() {
            return Ok(());
        } else {
            (data_end - 1) / chunk
        };
        for index in first..=last {
            let chunk_start = index * chunk;
            let chunk_len = (new_len - chunk_start).min(chunk) as usize;
            let mut plain = if index <= old_len / chunk {
                self.read_chunk(index, old_len)?
            } else {
                Zeroizing::new(Vec::with_capacity(CHUNK_LEN))
            };
            plain.resize(chunk_len, 0);
            let lo = offset.max(chunk_start);
            let hi = data_end.min(chunk_start + chunk_len as u64);
            if lo < hi {
                plain[(lo - chunk_start) as usize..(hi - chunk_start) as usize]
                    .copy_from_slice(&data[(lo - offset) as usize..(hi - offset) as usize]);
            }
            self.write_chunk(index, &plain, index == new_len / chunk)?;
        }
        self.file.set_len(sealed_len(new_len))?;
        self.len = new_len;
        Ok(())
    }

    /// Decrypts chunk `index` of a file that is `len` plaintext bytes long.
    fn read_chunk(&mut self, index: u64, len: u64) -> Result<Zeroizing<Vec<u8>>> {
        let chunk = CHUNK_LEN as u64;
        let last = index == len / chunk;
        let plain_len = if last {
            (len % chunk) as usize
        } else {
            CHUNK_LEN
        };
        let mut sealed = vec![0u8; plain_len + CHUNK_OVERHEAD];
        self.file.seek(SeekFrom::Start(chunk_offset(index)))?;
        self.file
            .read_exact(&mut sealed)
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => Error::Integrity("file is truncated".into()),
                _ => e.into(),
            })?;
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let decrypted = Zeroizing::new(
            self.cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: body,
                        aad: &chunk_aad(&self.header_nonce, index, last),
                    },
                )
                .map_err(|_| Error::Integrity(format!("chunk {index}")))?,
        );
        // Full capacity up front, so resizing later never reallocates and
        // leaves an unwiped copy behind.
        let mut plain = Zeroizing::new(Vec::with_capacity(CHUNK_LEN));
        plain.extend_from_slice(&decrypted);
        Ok(plain)
    }

    fn write_chunk(&mut self, index: u64, plain: &[u8], last: bool) -> Result<()> {
        let mut nonce = [0u8; NONCE_LEN];
        random_fill(&mut nonce)?;
        let sealed = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: &chunk_aad(&self.header_nonce, index, last),
                },
            )
            .expect("AES-GCM encryption of a 64 KiB chunk cannot fail");
        let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        self.file.seek(SeekFrom::Start(chunk_offset(index)))?;
        self.file.write_all(&out)?;
        Ok(())
    }
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

    /// Deterministic xorshift, so failures reproduce.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        /// Offsets clustered around chunk boundaries, where bugs live.
        fn offset(&mut self, len: u64) -> u64 {
            let chunk = CHUNK_LEN as u64;
            match self.below(3) {
                0 => self.below(len + chunk),
                1 => (self.below(len / chunk + 2) * chunk).saturating_sub(self.below(3)),
                _ => self.below(len / chunk + 2) * chunk + self.below(3),
            }
        }
    }

    fn new_vault_file(dir: &Path, initial: &[u8]) -> (std::path::PathBuf, VaultFile) {
        let path = dir.join("file.flk");
        let mut sealed = Vec::new();
        encrypt(&KEY, initial, &mut sealed).unwrap();
        std::fs::write(&path, sealed).unwrap();
        let file = VaultFile::open(&KEY, &path).unwrap();
        (path, file)
    }

    fn assert_matches_model(path: &Path, file: &mut VaultFile, model: &[u8]) {
        assert_eq!(file.len(), model.len() as u64);
        let mut all = vec![0u8; model.len() + 10];
        assert_eq!(file.read_at(0, &mut all).unwrap(), model.len());
        assert_eq!(&all[..model.len()], model);
        // The file on disk must stay valid for whole-file decryption.
        assert_eq!(open(&std::fs::read(path).unwrap()).unwrap(), model);
    }

    #[test]
    fn random_access_matches_a_plain_model() {
        let tmp = tempfile::tempdir().unwrap();
        let initial = sample(CHUNK_LEN + 300);
        let (path, mut file) = new_vault_file(tmp.path(), &initial);
        let mut model = initial;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

        for step in 0..400 {
            let len = model.len() as u64;
            match rng.below(10) {
                0..=4 => {
                    let offset = rng.offset(len);
                    let size = match rng.below(4) {
                        0 => rng.below(16),
                        1 => CHUNK_LEN as u64,
                        _ => rng.below(3 * CHUNK_LEN as u64),
                    } as usize;
                    let data: Vec<u8> = (0..size).map(|_| rng.next() as u8).collect();
                    file.write_at(offset, &data).unwrap();
                    // A zero-length write is a no-op, even past the end.
                    if !data.is_empty() {
                        let end = offset as usize + size;
                        if model.len() < end {
                            model.resize(end, 0);
                        }
                        model[offset as usize..end].copy_from_slice(&data);
                    }
                }
                5 | 6 => {
                    let new_len = rng.offset(len).min(5 * CHUNK_LEN as u64);
                    file.set_len(new_len).unwrap();
                    model.resize(new_len as usize, 0);
                }
                _ => {
                    let offset = rng.offset(len);
                    let mut buf = vec![0xEEu8; rng.below(2 * CHUNK_LEN as u64) as usize];
                    let n = file.read_at(offset, &mut buf).unwrap();
                    let expected = model.get(offset as usize..).unwrap_or(&[]);
                    let expected = &expected[..expected.len().min(buf.len())];
                    assert_eq!(&buf[..n], expected, "step {step}: read at {offset}");
                }
            }
            if step % 25 == 0 {
                assert_matches_model(&path, &mut file, &model);
            }
        }
        assert_matches_model(&path, &mut file, &model);

        // Reopening sees the same contents.
        let mut reopened = VaultFile::open(&KEY, &path).unwrap();
        assert_matches_model(&path, &mut reopened, &model);
    }

    #[test]
    fn random_access_edge_cases() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, mut file) = new_vault_file(tmp.path(), b"");
        let chunk = CHUNK_LEN as u64;

        // Grow to exactly one chunk: the final chunk becomes an empty one.
        file.set_len(chunk).unwrap();
        assert_matches_model(&path, &mut file, &vec![0; CHUNK_LEN]);
        // Write far past the end: the gap reads as zeros.
        file.write_at(3 * chunk + 5, b"tail").unwrap();
        let mut model = vec![0u8; 3 * CHUNK_LEN + 9];
        model[3 * CHUNK_LEN + 5..].copy_from_slice(b"tail");
        assert_matches_model(&path, &mut file, &model);
        // Shrink to a chunk boundary, then to nothing.
        file.set_len(2 * chunk).unwrap();
        assert_matches_model(&path, &mut file, &vec![0; 2 * CHUNK_LEN]);
        file.set_len(0).unwrap();
        assert_matches_model(&path, &mut file, &[]);
        assert_eq!(file.read_at(0, &mut [0; 8]).unwrap(), 0);
        assert_eq!(file.read_at(100, &mut [0; 8]).unwrap(), 0);
    }

    #[test]
    fn random_access_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _) = new_vault_file(tmp.path(), &sample(3 * CHUNK_LEN));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN + SEALED_CHUNK_LEN + 40] ^= 1;
        std::fs::write(&path, bytes).unwrap();

        let mut file = VaultFile::open(&KEY, &path).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(file.read_at(0, &mut buf).unwrap(), 16);
        assert!(matches!(
            file.read_at(CHUNK_LEN as u64 + 1, &mut buf),
            Err(Error::Integrity(_))
        ));
        assert!(matches!(
            file.write_at(CHUNK_LEN as u64 + 1, b"x"),
            Err(Error::Integrity(_))
        ));
    }
}
