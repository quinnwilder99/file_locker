//! Mounts an unlocked vault as a Windows drive through WinFsp. Every read and
//! write goes through `vault-core`; nothing decrypted is written to disk.
//!
//! Requires WinFsp (https://winfsp.dev) to be installed.

mod fs;
mod win;

use std::fmt;

use vault_core::Vault;
use winfsp::host::{FileSystemHost, FineGuard, VolumeParams};

pub use win::free_drive_letter;

/// A mounted vault. Dropping it (or calling [`unmount`](Self::unmount))
/// removes the drive, then drops the vault, which zeroizes its keys.
pub struct MountedVault {
    host: FileSystemHost<fs::VaultFs>,
    mount_point: String,
}

#[derive(Debug)]
pub enum MountError {
    /// WinFsp is not installed or its DLL could not be loaded.
    WinFspMissing,
    /// Setting up the mount failed (e.g. the drive letter is in use).
    Failed(String),
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::WinFspMissing => {
                write!(f, "WinFsp is not installed; get it from https://winfsp.dev")
            }
            MountError::Failed(why) => write!(f, "mounting failed: {why}"),
        }
    }
}

impl std::error::Error for MountError {}

/// Mounts `vault` at `mount_point`, such as `"V:"`.
pub fn mount(vault: Vault, mount_point: &str) -> Result<MountedVault, MountError> {
    winfsp::winfsp_init().map_err(|_| MountError::WinFspMissing)?;
    let failed = |what: &str, e: &dyn fmt::Debug| MountError::Failed(format!("{what}: {e:?}"));

    let label = vault
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Vault")
        .to_string();
    let context = fs::VaultFs::new(vault, label).map_err(|e| failed("security setup", &e))?;

    let mut params = VolumeParams::new();
    params
        .filesystem_name("file_locker")
        .sector_size(4096)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .volume_creation_time(win::now_filetime())
        .volume_serial_number(win::now_filetime() as u32)
        .file_info_timeout(1000)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(true)
        .post_cleanup_when_modified_only(true);

    // Fine-grained guard: operations run concurrently; VaultFs locks internally.
    let mut host: FileSystemHost<fs::VaultFs, FineGuard> =
        FileSystemHost::new(params, context).map_err(|e| failed("create", &e))?;
    host.mount(mount_point)
        .map_err(|e| failed(&format!("mount at {mount_point}"), &e))?;
    host.start().map_err(|e| failed("start", &e))?;
    Ok(MountedVault {
        host,
        mount_point: mount_point.to_string(),
    })
}

impl MountedVault {
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// Removes the drive and locks the vault.
    pub fn unmount(self) {}
}

impl Drop for MountedVault {
    fn drop(&mut self) {
        self.host.stop();
        self.host.unmount();
    }
}
