//! Known-answer vectors for the deterministic parts of vault format v1. If any
//! of these change, existing vaults stop opening: bump the format version
//! instead of editing a vector.
//!
//! Subkeys, storage paths and the recovery-key text were cross-checked against
//! an independent Python (stdlib HMAC/HKDF) implementation. The name and KEK
//! vectors come from this implementation and guard against regressions.

use crate::keys::{password_kek, KdfParams, MasterKey, RecoveryKey, VaultKeys};
use crate::names::{dir_storage_path, encrypt_name, StoredName};
use crate::{config, hex};

fn counting<const N: usize>() -> [u8; N] {
    std::array::from_fn(|i| i as u8)
}

#[test]
fn subkeys() {
    let keys = VaultKeys::derive(&MasterKey::from_bytes_for_test(counting()));
    assert_eq!(
        hex(&keys.content[..]),
        "fb89c89884d4a777ba1297809dd49eb9ba9f02ace24051c885de0f244f4fd90b"
    );
    assert_eq!(
        hex(&keys.names[..]),
        "2edf3b276ef0523ac4fe72b31dcdcacee3fc30496cd58441dce9c505050c9727\
         ae82757ea27fb761b73a24c893f8bf42247eb192a4c1bf2ecad112a5ea91c0d5"
    );
    assert_eq!(
        hex(&keys.dir_hash[..]),
        "03b69144a4c87a0a63a4d21b43ab6e21f79094bf8a2cc043bca703b8452d655b"
    );
}

#[test]
fn storage_paths() {
    let key = [0x11; 32];
    let path = |id| {
        dir_storage_path(&key, id)
            .to_string_lossy()
            .replace('\\', "/")
    };
    assert_eq!(path(""), "d/0B/1CNS2ZGB74PXPCEPGRQ6QGTSZCKCQA");
    assert_eq!(
        path("00112233445566778899aabbccddeeff"),
        "d/DT/AMPPTK7WW0NVRZE4GX37FQE90VY961"
    );
}

#[test]
fn recovery_key_text() {
    let key = RecoveryKey::from_bytes_for_test(counting());
    let text = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W";
    assert_eq!(key.to_display_string().as_str(), text);
    assert!(RecoveryKey::parse(text).unwrap() == key);
}

#[test]
fn name_encryption() {
    assert_eq!(
        encrypt_name(&[0x22; 64], "", "Résumé 2026.docx").unwrap(),
        StoredName::Plain("Hn_xnc2RY5fwVTZlNEsOPd3pdKTxEd7CXcKUXx3nBHsCNQ.flk".into())
    );
}

#[test]
fn password_kek_argon2id() {
    let kdf = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let kek = password_kek(b"password", &[0x33; 16], &kdf).unwrap();
    assert_eq!(
        hex(&kek[..]),
        "b22003f4c6a769c94ed5cf0ab7dd0197b1c35b97f4e4be332b79ea65ca957974"
    );
}

#[test]
fn slot_associated_data() {
    let kdf = KdfParams {
        memory_kib: 262144,
        iterations: 3,
        parallelism: 4,
    };
    assert_eq!(
        config::slot_aad(config::SlotKind::Password, &kdf),
        b"file_locker/slot/v1/password/argon2id/262144/3/4"
    );
    assert_eq!(
        config::slot_aad(config::SlotKind::Recovery, &kdf),
        b"file_locker/slot/v1/recovery"
    );
}
