//! Core of file_locker: the on-disk vault format, key management, and
//! file-content and file-name encryption. See `docs/DESIGN.md`.

mod config;
mod content;
mod encoding;
mod error;
#[cfg(test)]
mod format_vectors;
mod fs_util;
mod keys;
mod names;
mod vault;

pub use error::{Error, Result};
pub use keys::{KdfParams, RecoveryKey};
pub use vault::{Entry, EntryKind, Stats, Vault};

/// Fills `buf` from the operating system's CSPRNG.
pub(crate) fn random_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Random(e.to_string()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
