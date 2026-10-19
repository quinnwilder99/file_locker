//! Key hierarchy: password or recovery key → key-encryption key (KEK) →
//! wrapped master key → per-purpose subkeys.

use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{crockford_decode, crockford_encode, crockford_normalize};
use crate::secret::SecretBytes;
use crate::{random_fill, Error, Result};

/// Cap for calibration, well inside `validate`'s bound of 64, so a slow
/// timer reading cannot produce a vault that takes minutes to open.
const MAX_CALIBRATED_ITERATIONS: u32 = 32;
pub(crate) const MASTER_KEY_LEN: usize = 64;
pub(crate) const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEK_LEN: usize = 32;

/// Argon2id cost parameters, stored in `vault.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Default for new vaults: 256 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Returns `self` with `iterations` raised so that one derivation takes
    /// about `target` on this machine. Never weaker than `self`.
    pub fn calibrate(self, target: Duration) -> Result<KdfParams> {
        self.validate()?;
        let mut salt = [0u8; SALT_LEN];
        random_fill(&mut salt)?;
        let start = Instant::now();
        password_kek(b"calibration", &salt, &self)?;
        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        // Argon2 time grows linearly with passes. `as` saturates on overflow.
        let scaled = (f64::from(self.iterations) * target.as_secs_f64() / elapsed).round() as u32;
        let iterations = scaled.clamp(
            self.iterations,
            MAX_CALIBRATED_ITERATIONS.max(self.iterations),
        );
        Ok(KdfParams { iterations, ..self })
    }

    /// Bounds accepted when opening a vault, so a crafted `vault.json` cannot
    /// demand absurd memory or time.
    pub(crate) fn validate(&self) -> Result<()> {
        let ok = (1..=16).contains(&self.parallelism)
            && (1..=64).contains(&self.iterations)
            && self.memory_kib >= 8 * self.parallelism
            && self.memory_kib <= 4 * 1024 * 1024;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidKdf(*self))
        }
    }
}

pub(crate) struct MasterKey(SecretBytes<MASTER_KEY_LEN>);

impl MasterKey {
    pub(crate) fn generate() -> Result<Self> {
        let mut key = SecretBytes::zeroed();
        random_fill(&mut key[..])?;
        Ok(Self(key))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Independent subkeys derived from the master key with HKDF-SHA-256.
pub(crate) struct VaultKeys {
    /// Wraps each file's random content key.
    pub(crate) content: SecretBytes<32>,
    /// AES-SIV-256 key for file and folder names.
    pub(crate) names: SecretBytes<64>,
    /// HMAC key that maps folder IDs to storage paths.
    pub(crate) dir_hash: SecretBytes<32>,
}

impl VaultKeys {
    pub(crate) fn derive(master: &MasterKey) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"file_locker vault v1"), master.as_bytes());
        let mut keys = VaultKeys {
            content: SecretBytes::zeroed(),
            names: SecretBytes::zeroed(),
            dir_hash: SecretBytes::zeroed(),
        };
        // Output lengths are far below HKDF's 255 * 32 byte limit.
        hk.expand(b"content", &mut keys.content[..])
            .expect("valid HKDF length");
        hk.expand(b"names", &mut keys.names[..])
            .expect("valid HKDF length");
        hk.expand(b"dir-hash", &mut keys.dir_hash[..])
            .expect("valid HKDF length");
        keys
    }
}

pub(crate) fn password_kek(
    password: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<SecretBytes<KEK_LEN>> {
    kdf.validate()?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEK_LEN),
    )
    .map_err(|_| Error::InvalidKdf(*kdf))?;
    let mut kek = SecretBytes::zeroed();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut kek[..])
        .map_err(|_| Error::InvalidKdf(*kdf))?;
    Ok(kek)
}

/// The recovery key is 256 random bits, so a fast KDF is enough.
pub(crate) fn recovery_kek(recovery: &RecoveryKey, salt: &[u8]) -> SecretBytes<KEK_LEN> {
    let mut kek = SecretBytes::zeroed();
    Hkdf::<Sha256>::new(Some(salt), &recovery.0[..])
        .expand(b"file_locker recovery slot v1", &mut kek[..])
        .expect("valid HKDF length");
    kek
}

/// Wraps the master key under `kek`. Returns `(nonce, ciphertext)`.
pub(crate) fn wrap_master(
    kek: &[u8; KEK_LEN],
    master: &MasterKey,
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    random_fill(&mut nonce)?;
    let wrapped = Aes256Gcm::new_from_slice(kek)
        .expect("32-byte key")
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: master.as_bytes(),
                aad,
            },
        )
        .expect("AES-GCM encryption of a 64-byte buffer cannot fail");
    Ok((nonce.to_vec(), wrapped))
}

/// Returns `None` if the KEK is wrong or the slot was altered.
pub(crate) fn unwrap_master(
    kek: &[u8; KEK_LEN],
    nonce: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Option<MasterKey> {
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(kek)
            .expect("32-byte key")
            .decrypt(&Nonce::from(nonce), Payload { msg: wrapped, aad })
            .ok()?,
    );
    SecretBytes::from_slice(&plain).map(MasterKey)
}

/// A 256-bit recovery key, shown to the user once when the vault is created.
///
/// Display form: 52 Crockford base32 characters of key plus a 4-character
/// checksum, in 14 groups of 4 separated by dashes. The checksum lets typos be
/// reported as typos instead of as a wrong key.
pub struct RecoveryKey(SecretBytes<32>);

const RECOVERY_BODY_CHARS: usize = 52;
const RECOVERY_CHECK_CHARS: usize = 4;

impl RecoveryKey {
    pub(crate) fn generate() -> Result<Self> {
        let mut key = SecretBytes::zeroed();
        random_fill(&mut key[..])?;
        Ok(Self(key))
    }

    pub fn to_display_string(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(crockford_encode(&self.0[..]));
        chars.push_str(&checksum(&self.0));
        let groups: Vec<&str> = chars
            .as_bytes()
            .chunks(4)
            .map(|g| std::str::from_utf8(g).expect("base32 is ASCII"))
            .collect();
        Zeroizing::new(groups.join("-"))
    }

    /// Parses the display form. Dashes, spaces and letter case are ignored.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect(),
        );
        if !cleaned.is_ascii() {
            return Err(Error::InvalidRecoveryKey(
                "contains characters that cannot appear in a recovery key",
            ));
        }
        if cleaned.len() != RECOVERY_BODY_CHARS + RECOVERY_CHECK_CHARS {
            return Err(Error::InvalidRecoveryKey(
                "expected 56 characters (14 groups of 4)",
            ));
        }
        let (body, check) = cleaned.split_at(RECOVERY_BODY_CHARS);
        let decoded = Zeroizing::new(crockford_decode(body).ok_or(Error::InvalidRecoveryKey(
            "contains characters that cannot appear in a recovery key",
        ))?);
        let key: SecretBytes<32> =
            SecretBytes::from_slice(&decoded).ok_or(Error::InvalidRecoveryKey("malformed key"))?;
        let check: Option<String> = check.chars().map(crockford_normalize).collect();
        if check.as_deref() != Some(checksum(&key).as_str()) {
            return Err(Error::InvalidRecoveryKey(
                "checksum mismatch, check for typos",
            ));
        }
        Ok(Self(key))
    }
}

impl PartialEq for RecoveryKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

fn checksum(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    crockford_encode(&digest[..3])[..RECOVERY_CHECK_CHARS].to_string()
}

#[cfg(test)]
impl MasterKey {
    pub(crate) fn from_bytes_for_test(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(SecretBytes::from_slice(&bytes).expect("exact length"))
    }
}

#[cfg(test)]
impl RecoveryKey {
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_slice(&bytes).expect("exact length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_round_trips() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.to_display_string();
        assert_eq!(shown.len(), 14 * 4 + 13);
        assert!(RecoveryKey::parse(&shown).unwrap() == key);
        let sloppy = shown.to_lowercase().replace('-', " ");
        assert!(RecoveryKey::parse(&sloppy).unwrap() == key);
    }

    #[test]
    fn recovery_key_typo_is_reported() {
        let key = RecoveryKey::generate().unwrap();
        let mut shown: Vec<char> = key.to_display_string().chars().collect();
        shown[0] = if shown[0] == 'A' { 'B' } else { 'A' };
        let typo: String = shown.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(Error::InvalidRecoveryKey(_))
        ));
    }

    #[test]
    fn non_ascii_recovery_key_is_an_error_not_a_panic() {
        // 56 characters but more than 56 bytes: used to split mid-character.
        let input = format!("é{}", "0".repeat(55));
        assert!(matches!(
            RecoveryKey::parse(&input),
            Err(Error::InvalidRecoveryKey(_))
        ));
    }

    #[test]
    fn wrong_kek_does_not_unwrap() {
        let master = MasterKey::generate().unwrap();
        let (nonce, wrapped) = wrap_master(&[1; 32], &master, b"aad").unwrap();
        assert!(unwrap_master(&[1; 32], &nonce, &wrapped, b"aad").is_some());
        assert!(unwrap_master(&[2; 32], &nonce, &wrapped, b"aad").is_none());
        assert!(unwrap_master(&[1; 32], &nonce, &wrapped, b"other").is_none());
    }

    #[test]
    fn kdf_bounds() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        let huge = KdfParams {
            memory_kib: u32::MAX,
            ..KdfParams::DEFAULT
        };
        assert!(huge.validate().is_err());
        let zero = KdfParams {
            iterations: 0,
            ..KdfParams::DEFAULT
        };
        assert!(zero.validate().is_err());
    }

    #[test]
    fn calibration_never_weakens() {
        let base = KdfParams {
            memory_kib: 64,
            iterations: 2,
            parallelism: 1,
        };
        let fast = base.calibrate(Duration::ZERO).unwrap();
        assert_eq!(fast, base);
        let slow = base.calibrate(Duration::from_millis(20)).unwrap();
        assert!(slow.iterations >= base.iterations && slow.iterations <= MAX_CALIBRATED_ITERATIONS);
        assert_eq!(
            (slow.memory_kib, slow.parallelism),
            (base.memory_kib, base.parallelism)
        );
        slow.validate().unwrap();
    }
}
