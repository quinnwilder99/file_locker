//! `vault.json`: format version, KDF parameters and key slots. Holds no secret
//! in clear; a backup copy is written before every change.

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fs_util::write_atomic;
use crate::keys::KdfParams;
use crate::{Error, Result};

pub(crate) const CONFIG_FILE: &str = "vault.json";
pub(crate) const BACKUP_FILE: &str = "vault.json.bak";
const FORMAT: &str = "file_locker-vault";
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultConfig {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub slots: Vec<KeySlot>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeySlot {
    pub kind: SlotKind,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SlotKind {
    Password,
    Recovery,
}

impl VaultConfig {
    pub(crate) fn new(kdf: KdfParams, slots: Vec<KeySlot>) -> Self {
        Self {
            format: FORMAT.into(),
            version: FORMAT_VERSION,
            kdf,
            slots,
        }
    }

    /// Loads `vault.json`, falling back to the backup if it is missing or unreadable.
    pub(crate) fn load(root: &Path) -> Result<Self> {
        match Self::read(root, CONFIG_FILE) {
            Ok(config) => Ok(config),
            Err(primary) => Self::read(root, BACKUP_FILE).map_err(|_| primary),
        }
    }

    fn read(root: &Path, file: &str) -> Result<Self> {
        let bytes = match fs::read(root.join(file)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NotAVault(root.into()))
            }
            Err(e) => return Err(e.into()),
        };
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|e| Error::Corrupt(format!("{file}: {e}")))?;
        if config.format != FORMAT {
            return Err(Error::NotAVault(root.into()));
        }
        if config.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(config.version));
        }
        Ok(config)
    }

    /// Writes the backup first, then the main file, each atomically.
    pub(crate) fn save(&self, root: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).expect("config always serializes");
        write_atomic(&root.join(BACKUP_FILE), &json)?;
        write_atomic(&root.join(CONFIG_FILE), &json)
    }

    pub(crate) fn slot(&self, kind: SlotKind) -> Result<&KeySlot> {
        self.slots
            .iter()
            .find(|s| s.kind == kind)
            .ok_or_else(|| Error::Corrupt(format!("vault has no {kind:?} key slot")))
    }

    pub(crate) fn replace_slot(&mut self, slot: KeySlot) {
        self.slots.retain(|s| s.kind != slot.kind);
        self.slots.push(slot);
    }
}

/// Associated data binding a wrapped key to its slot kind and KDF parameters.
pub(crate) fn slot_aad(kind: SlotKind, kdf: &KdfParams) -> Vec<u8> {
    match kind {
        SlotKind::Password => format!(
            "file_locker/slot/v1/password/argon2id/{}/{}/{}",
            kdf.memory_kib, kdf.iterations, kdf.parallelism
        )
        .into_bytes(),
        SlotKind::Recovery => b"file_locker/slot/v1/recovery".to_vec(),
    }
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}
