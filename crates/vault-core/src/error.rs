use std::path::PathBuf;

use crate::KdfParams;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("wrong password")]
    WrongPassword,

    #[error("wrong recovery key")]
    WrongRecoveryKey,

    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(&'static str),

    #[error("{} is not a file_locker vault", .0.display())]
    NotAVault(PathBuf),

    #[error("{0} already exists")]
    AlreadyExists(String),

    #[error("{0} not found in the vault")]
    NotFound(String),

    #[error("{0} is a folder")]
    IsADirectory(String),

    #[error("{0} is not a folder")]
    NotADirectory(String),

    #[error("cannot {0}")]
    NotAllowed(&'static str),

    #[error("invalid name {0:?}")]
    InvalidName(String),

    #[error("name is longer than Windows allows: {0:?}")]
    NameTooLong(String),

    #[error("vault data is corrupt: {0}")]
    Corrupt(String),

    /// Authenticated decryption failed: the data was damaged or tampered with.
    #[error("vault data failed authentication (damaged or tampered with): {0}")]
    Integrity(String),

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),

    #[error("key-derivation parameters out of range: {0:?}")]
    InvalidKdf(KdfParams),

    #[error("the operating system's random number generator failed: {0}")]
    Random(String),
}
