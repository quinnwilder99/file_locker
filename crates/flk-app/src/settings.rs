//! Settings and the list of known vaults, saved as JSON in
//! `%APPDATA%\File Locker\settings.json`. Nothing secret is stored here.

use std::path::{Path, PathBuf};
use std::{env, fs, io};

use serde::{Deserialize, Serialize};

const FILE: &str = "settings.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub vaults: Vec<VaultEntry>,
    pub lock_on_sleep: bool,
    pub lock_on_windows_lock: bool,
    /// Lock after this many idle minutes; 0 means never.
    pub idle_minutes: u32,
    pub open_explorer: bool,
    /// Ctrl+Alt+L locks every vault.
    pub hotkey: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            vaults: Vec::new(),
            lock_on_sleep: true,
            lock_on_windows_lock: true,
            idle_minutes: 0,
            open_explorer: true,
            hotkey: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub path: PathBuf,
    pub name: String,
    /// The drive letter used last time, reused when free.
    #[serde(default)]
    pub drive: Option<String>,
}

/// Where settings live. `FILE_LOCKER_DATA_DIR` overrides it (tests, portable use).
pub fn data_dir() -> PathBuf {
    if let Some(dir) = env::var_os("FILE_LOCKER_DATA_DIR") {
        return dir.into();
    }
    env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("File Locker")
}

/// Where the log file lives: `%LOCALAPPDATA%\File Locker`.
pub fn log_dir() -> PathBuf {
    if let Some(dir) = env::var_os("FILE_LOCKER_DATA_DIR") {
        return dir.into();
    }
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("File Locker")
}

impl Settings {
    /// Loads settings; a missing or unreadable file gives the defaults.
    pub fn load_from(dir: &Path) -> Self {
        match fs::read(dir.join(FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                log::warn!("settings unreadable, using defaults: {e}");
                Self::default()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                log::warn!("settings unreadable, using defaults: {e}");
                Self::default()
            }
        }
    }

    /// Saves atomically (temporary file, then rename).
    pub fn save_to(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{FILE}.tmp"));
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).expect("settings serialize"),
        )?;
        fs::rename(&tmp, dir.join(FILE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_tolerates_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load_from(dir.path()), Settings::default());

        let s = Settings {
            idle_minutes: 20,
            vaults: vec![VaultEntry {
                path: "D:\\Vaults\\Work".into(),
                name: "Work".into(),
                drive: Some("V:".into()),
            }],
            ..Settings::default()
        };
        s.save_to(dir.path()).unwrap();
        assert_eq!(Settings::load_from(dir.path()), s);

        fs::write(dir.path().join(FILE), b"{ not json").unwrap();
        assert_eq!(Settings::load_from(dir.path()), Settings::default());

        // Unknown and missing fields are fine (older or newer versions).
        fs::write(dir.path().join(FILE), br#"{"hotkey": false, "future": 1}"#).unwrap();
        let loaded = Settings::load_from(dir.path());
        assert!(!loaded.hotkey && loaded.lock_on_sleep);
    }
}
