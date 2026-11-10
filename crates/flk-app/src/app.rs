//! The controller: known vaults, unlocked drives, and every action the
//! windows, the tray and the auto-lock triggers share. No UI code here.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flk_mount::{MountError, MountedVault};
use vault_core::{Error, KdfParams, RecoveryKey, Vault};

use crate::settings::{Settings, VaultEntry};

/// Created in every vault so it can be unlocked by double-clicking in Explorer.
pub const MARKER_FILE: &str = "Unlock vault.flkvault";
pub const MARKER_EXTENSION: &str = "flkvault";
pub const MIN_PASSWORD_CHARS: usize = 8;
/// How long unlocking should take on the machine that creates the vault.
const KDF_TARGET: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq)]
pub struct VaultView {
    pub name: String,
    pub path: PathBuf,
    pub unlocked: bool,
    pub drive: String,
    pub busy: bool,
}

#[derive(Debug, PartialEq)]
pub enum LockResult {
    Locked,
    NotUnlocked,
    /// Not locked: these files on the drive are open.
    FilesOpen(Vec<String>),
}

struct Unlocked {
    mount: MountedVault,
    drive: String,
    root: PathBuf,
    name: String,
}

pub struct App {
    data_dir: PathBuf,
    settings: Mutex<Settings>,
    unlocked: Mutex<HashMap<String, Unlocked>>,
    busy: Mutex<HashSet<String>>,
    on_change: Box<dyn Fn() + Send + Sync>,
}

/// Case-insensitive key for a vault folder, as Windows compares paths.
fn key(path: &Path) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    absolute
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_lowercase()
}

impl App {
    pub fn new(data_dir: PathBuf, on_change: Box<dyn Fn() + Send + Sync>) -> Arc<Self> {
        let settings = Settings::load_from(&data_dir);
        Arc::new(Self {
            data_dir,
            settings: Mutex::new(settings),
            unlocked: Mutex::new(HashMap::new()),
            busy: Mutex::new(HashSet::new()),
            on_change,
        })
    }

    fn changed(&self) {
        (self.on_change)();
    }

    pub fn settings(&self) -> Settings {
        self.settings.lock().unwrap().clone()
    }

    pub fn update_settings(&self, change: impl FnOnce(&mut Settings)) -> Result<(), String> {
        let snapshot = {
            let mut settings = self.settings.lock().unwrap();
            change(&mut settings);
            settings.clone()
        };
        snapshot
            .save_to(&self.data_dir)
            .map_err(|e| format!("Could not save settings: {e}"))
    }

    /// Known vaults, in the order they were added.
    pub fn vaults(&self) -> Vec<VaultView> {
        let entries = self.settings.lock().unwrap().vaults.clone();
        let unlocked = self.unlocked.lock().unwrap();
        let busy = self.busy.lock().unwrap();
        entries
            .into_iter()
            .map(|e| {
                let k = key(&e.path);
                let drive = unlocked.get(&k).map(|u| u.drive.clone());
                VaultView {
                    name: e.name,
                    unlocked: drive.is_some(),
                    drive: drive.unwrap_or_default(),
                    busy: busy.contains(&k),
                    path: e.path,
                }
            })
            .collect()
    }

    pub fn entry(&self, path: &Path) -> Option<VaultEntry> {
        let k = key(path);
        self.settings
            .lock()
            .unwrap()
            .vaults
            .iter()
            .find(|e| key(&e.path) == k)
            .cloned()
    }

    /// The vault folder for a path from Explorer: the folder itself, or the
    /// folder holding a `.flkvault` file.
    pub fn vault_root(path: &Path) -> PathBuf {
        let is_marker = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(MARKER_EXTENSION));
        let path = if is_marker {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
    }

    /// Adds an existing vault to the list (no-op if already listed).
    pub fn add_vault(&self, path: &Path) -> Result<VaultEntry, String> {
        let root = Self::vault_root(path);
        if let Some(entry) = self.entry(&root) {
            return Ok(entry);
        }
        Vault::check(&root).map_err(|e| friendly(&e))?;
        write_marker(&root);
        let entry = VaultEntry {
            name: root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.display().to_string()),
            path: root,
            drive: None,
        };
        self.update_settings(|s| s.vaults.push(entry.clone()))?;
        self.changed();
        Ok(entry)
    }

    /// Removes a vault from the list. Its folder and files are untouched.
    pub fn remove_vault(&self, path: &Path) -> Result<(), String> {
        if self.drive(path).is_some() {
            return Err("Lock the vault before removing it from the list.".into());
        }
        let k = key(path);
        self.update_settings(|s| s.vaults.retain(|e| key(&e.path) != k))?;
        self.changed();
        Ok(())
    }

    pub fn drive(&self, path: &Path) -> Option<String> {
        self.unlocked
            .lock()
            .unwrap()
            .get(&key(path))
            .map(|u| u.drive.clone())
    }

    pub fn any_unlocked(&self) -> bool {
        !self.unlocked.lock().unwrap().is_empty()
    }

    /// `(name, drive)` of every unlocked vault.
    pub fn unlocked_drives(&self) -> Vec<(String, String)> {
        let mut list: Vec<_> = self
            .unlocked
            .lock()
            .unwrap()
            .values()
            .map(|u| (u.name.clone(), u.drive.clone()))
            .collect();
        list.sort();
        list
    }

    fn set_busy(&self, path: &Path, busy: bool) -> bool {
        let k = key(path);
        let changed = {
            let mut set = self.busy.lock().unwrap();
            if busy {
                set.insert(k)
            } else {
                set.remove(&k)
            }
        };
        if changed {
            self.changed();
        }
        changed
    }

    /// Unlocks with a password and mounts the vault. Returns the drive, like
    /// `"V:"`. Slow by design (about a second): call it off the UI thread.
    pub fn unlock(&self, path: &Path, password: &[u8]) -> Result<String, String> {
        if let Some(drive) = self.drive(path) {
            return Ok(drive);
        }
        if !self.set_busy(path, true) {
            return Err("This vault is already being unlocked.".into());
        }
        let result = Vault::unlock(path, password)
            .map_err(|e| friendly(&e))
            .and_then(|vault| self.mount_vault(path, vault));
        self.set_busy(path, false);
        result
    }

    /// Mounts a vault that is already unlocked (after creating or recovering it).
    pub fn mount_vault(&self, path: &Path, vault: Vault) -> Result<String, String> {
        if let Some(drive) = self.drive(path) {
            return Ok(drive);
        }
        if !flk_mount::winfsp_available() {
            return Err(WINFSP_MISSING.into());
        }
        let entry = match self.entry(path) {
            Some(entry) => entry,
            None => self.add_vault(path)?,
        };
        let drive = entry
            .drive
            .clone()
            .filter(|d| crate::system::drive_letter_free(d))
            .or_else(flk_mount::free_drive_letter)
            .ok_or("There is no free drive letter for the vault.")?;
        let mount = flk_mount::mount(vault, &drive).map_err(|e| match e {
            MountError::WinFspMissing => WINFSP_MISSING.to_string(),
            MountError::Failed(why) => format!("The vault could not be opened as a drive ({why})."),
        })?;
        self.unlocked.lock().unwrap().insert(
            key(path),
            Unlocked {
                mount,
                drive: drive.clone(),
                root: entry.path.clone(),
                name: entry.name.clone(),
            },
        );
        let k = key(path);
        let remembered = drive.clone();
        if let Err(e) = self.update_settings(|s| {
            if let Some(e) = s.vaults.iter_mut().find(|e| key(&e.path) == k) {
                e.drive = Some(remembered);
            }
        }) {
            log::warn!("{e}");
        }
        log::info!("unlocked {} at {drive}", entry.path.display());
        self.changed();
        Ok(drive)
    }

    /// Locks one vault. Without `force`, refuses while files are open.
    pub fn lock(&self, path: &Path, force: bool) -> LockResult {
        let k = key(path);
        if !force {
            let open =
                self.settled_open_files(|unlocked| unlocked.get(&k).map(|u| u.mount.open_files()));
            match open {
                None => return LockResult::NotUnlocked,
                Some(open) if !open.is_empty() => return LockResult::FilesOpen(open),
                Some(_) => {}
            }
        }
        let removed = self.unlocked.lock().unwrap().remove(&k);
        if removed.is_none() {
            return LockResult::NotUnlocked;
        }
        if let Some(u) = removed {
            log::info!("locked {}", u.root.display());
            drop(u); // unmounts, then zeroizes the keys
        }
        self.changed();
        LockResult::Locked
    }

    /// Open files, re-checked for up to two seconds: antivirus scanners and
    /// the search indexer briefly open files right after they are written,
    /// and those handles should not count as "in use".
    fn settled_open_files(
        &self,
        query: impl Fn(&HashMap<String, Unlocked>) -> Option<Vec<String>>,
    ) -> Option<Vec<String>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let open = query(&self.unlocked.lock().unwrap())?;
            if open.is_empty() || std::time::Instant::now() >= deadline {
                return Some(open);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Locks every vault. Without `force`, locks nothing and returns the open
    /// files if any. On success returns the names of the vaults locked.
    pub fn lock_all(&self, force: bool) -> Result<Vec<String>, Vec<String>> {
        if !force {
            let open = self.settled_open_files(|unlocked| {
                Some(
                    unlocked
                        .values()
                        .flat_map(|u| u.mount.open_files())
                        .collect(),
                )
            });
            if let Some(open) = open.filter(|o| !o.is_empty()) {
                return Err(open);
            }
        }
        let removed: Vec<Unlocked> = self
            .unlocked
            .lock()
            .unwrap()
            .drain()
            .map(|(_, u)| u)
            .collect();
        let names: Vec<String> = removed.iter().map(|u| u.name.clone()).collect();
        drop(removed);
        if !names.is_empty() {
            log::info!("locked all: {names:?}");
            self.changed();
        }
        Ok(names)
    }

    /// Locks vaults whose folder has disappeared (USB stick pulled, network
    /// share gone). Returns their names.
    pub fn lock_missing(&self) -> Vec<String> {
        let removed: Vec<Unlocked> = {
            let mut unlocked = self.unlocked.lock().unwrap();
            let gone: Vec<String> = unlocked
                .iter()
                .filter(|(_, u)| !u.root.join("vault.json").exists())
                .map(|(k, _)| k.clone())
                .collect();
            gone.iter().filter_map(|k| unlocked.remove(k)).collect()
        };
        let names: Vec<String> = removed.iter().map(|u| u.name.clone()).collect();
        drop(removed);
        if !names.is_empty() {
            log::warn!("locked vaults whose folder disappeared: {names:?}");
            self.changed();
        }
        names
    }

    /// Creates a vault folder `parent\name`, adds it to the list, and returns
    /// it unlocked with its recovery key. Slow (calibrates the password hash).
    pub fn create_vault(
        &self,
        parent: &Path,
        name: &str,
        password: &[u8],
    ) -> Result<(PathBuf, Vault, RecoveryKey), String> {
        let name = name.trim();
        check_vault_name(name)?;
        if parent.as_os_str().is_empty() || !parent.is_dir() {
            return Err("Choose a location that exists.".into());
        }
        let root = std::path::absolute(parent.join(name)).map_err(|e| e.to_string())?;
        if root.exists()
            && fs::read_dir(&root)
                .map(|mut d| d.next().is_some())
                .unwrap_or(true)
        {
            return Err(format!(
                "“{}” already exists and is not empty. Choose another name or location.",
                root.display()
            ));
        }
        let kdf = KdfParams::DEFAULT
            .calibrate(KDF_TARGET)
            .map_err(|e| friendly(&e))?;
        let (vault, recovery) = Vault::create(&root, password, kdf).map_err(|e| friendly(&e))?;
        log::info!("created vault {}", root.display());
        self.add_vault(&root)?;
        Ok((root, vault, recovery))
    }

    pub fn change_password(&self, path: &Path, current: &[u8], new: &[u8]) -> Result<(), String> {
        let mut vault = Vault::unlock(path, current).map_err(|e| friendly(&e))?;
        vault.change_password(new).map_err(|e| friendly(&e))?;
        log::info!("changed password of {}", path.display());
        Ok(())
    }

    /// Opens a vault with its recovery key and sets a new password. Returns
    /// the unlocked vault, ready to mount.
    pub fn recover(&self, path: &Path, recovery_key: &str, new: &[u8]) -> Result<Vault, String> {
        let key = RecoveryKey::parse(recovery_key).map_err(|e| friendly(&e))?;
        let mut vault = Vault::unlock_with_recovery_key(path, &key).map_err(|e| friendly(&e))?;
        vault.change_password(new).map_err(|e| friendly(&e))?;
        log::info!("reset password of {} with its recovery key", path.display());
        Ok(vault)
    }
}

pub const WINFSP_MISSING: &str =
    "WinFsp, which File Locker needs to open vaults as drives, is not installed. Reinstall File Locker to add it.";

/// Checks a new password and its confirmation.
pub fn check_new_password(password: &str, confirm: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "Use at least {MIN_PASSWORD_CHARS} characters for the password."
        ));
    }
    if password != confirm {
        return Err("The two passwords do not match.".into());
    }
    Ok(())
}

/// `(level 1..=4, label)` for a password strength meter.
pub fn password_strength(password: &str) -> (i32, &'static str) {
    let len = password.chars().count();
    if len == 0 {
        return (0, "");
    }
    if len < MIN_PASSWORD_CHARS {
        return (1, "Too short");
    }
    let classes = [
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    let score = (len >= 12) as usize + (len >= 16) as usize + (classes >= 3) as usize;
    match score {
        0 => (1, "Weak"),
        1 => (2, "Fair"),
        2 => (3, "Good"),
        _ => (4, "Strong"),
    }
}

fn check_vault_name(name: &str) -> Result<(), String> {
    const RESERVED: [&str; 4] = ["con", "prn", "aux", "nul"];
    if name.is_empty() {
        return Err("Give the vault a name.".into());
    }
    if name.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|'])
        || name.ends_with('.')
        || RESERVED.contains(&name.to_lowercase().as_str())
    {
        return Err("A vault name cannot contain \\ / : * ? \" < > | or end with a dot.".into());
    }
    Ok(())
}

/// Writes the double-click-to-unlock file. Best effort: a read-only vault
/// still works without it.
pub fn write_marker(root: &Path) {
    let path = root.join(MARKER_FILE);
    if path.exists() {
        return;
    }
    let text = "This folder is a File Locker vault. Its files are encrypted.\r\n\
                Double-click this file to unlock the vault.\r\n";
    if let Err(e) = fs::write(&path, text) {
        log::warn!("could not write {}: {e}", path.display());
    }
}

/// A sentence a person can act on, for any vault error.
pub fn friendly(error: &Error) -> String {
    match error {
        Error::WrongPassword => "That password is not correct.".into(),
        Error::WrongRecoveryKey => "That recovery key does not belong to this vault.".into(),
        Error::InvalidRecoveryKey(why) => format!("That is not a valid recovery key: {why}."),
        Error::NotAVault(path) => format!("“{}” is not a File Locker vault.", path.display()),
        Error::UnsupportedVersion(_) => {
            "This vault was made by a newer version of File Locker. Update File Locker to open it."
                .into()
        }
        Error::Corrupt(_) | Error::Integrity(_) => format!("The vault is damaged: {error}."),
        Error::Io(e) => format!("The vault folder could not be read or written: {e}."),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(dir: &Path) -> Arc<App> {
        App::new(dir.join("settings"), Box::new(|| {}))
    }

    #[test]
    fn create_list_change_password_recover() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (root, vault, key) = app
            .create_vault(tmp.path(), "Work Files", b"first password")
            .unwrap();
        drop(vault);
        assert!(root.join(MARKER_FILE).exists());
        let list = app.vaults();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Work Files");
        assert!(!list[0].unlocked);

        // Settings persist.
        let again = App::new(tmp.path().join("settings"), Box::new(|| {}));
        assert_eq!(again.vaults(), list);

        assert_eq!(
            app.change_password(&root, b"wrong", b"second password"),
            Err("That password is not correct.".into())
        );
        app.change_password(&root, b"first password", b"second password")
            .unwrap();
        let shown = key.to_display_string();
        app.recover(&root, &shown, b"third password").unwrap();
        Vault::unlock(&root, b"third password").unwrap();

        // Adding the same vault again (via its marker file) does not duplicate it.
        app.add_vault(&root.join(MARKER_FILE)).unwrap();
        assert_eq!(app.vaults().len(), 1);
        app.remove_vault(&root).unwrap();
        assert!(app.vaults().is_empty());
        assert!(
            root.join("vault.json").exists(),
            "removing from the list keeps the files"
        );
    }

    #[test]
    fn rejects_bad_input() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        assert!(app.create_vault(tmp.path(), "a/b", b"password1").is_err());
        assert!(app.create_vault(tmp.path(), "  ", b"password1").is_err());
        assert!(app
            .create_vault(&tmp.path().join("missing"), "x", b"password1")
            .is_err());
        fs::create_dir(tmp.path().join("full")).unwrap();
        fs::write(tmp.path().join("full").join("x"), b"x").unwrap();
        assert!(app.create_vault(tmp.path(), "full", b"password1").is_err());
        assert!(app
            .add_vault(tmp.path())
            .unwrap_err()
            .contains("not a File Locker vault"));
        assert!(check_new_password("short", "short").is_err());
        assert!(check_new_password("long enough", "long enougH").is_err());
        assert!(check_new_password("long enough", "long enough").is_ok());
    }

    #[test]
    fn strength_meter() {
        assert_eq!(password_strength(""), (0, ""));
        assert_eq!(password_strength("abc").1, "Too short");
        assert_eq!(password_strength("abcdefgh").1, "Weak");
        assert_eq!(password_strength("Abcdefgh1!").1, "Fair");
        assert_eq!(password_strength("Correct-Horse-Battery-9").1, "Strong");
    }

    #[test]
    fn vault_root_from_marker_or_folder() {
        let root = App::vault_root(Path::new("C:\\V\\Unlock vault.flkvault"));
        assert_eq!(root, PathBuf::from("C:\\V"));
        assert_eq!(App::vault_root(Path::new("C:\\V")), PathBuf::from("C:\\V"));
        assert_eq!(key(Path::new("C:\\Vault\\")), key(Path::new("c:\\VAULT")));
    }
}
