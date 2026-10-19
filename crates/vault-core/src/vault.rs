//! The vault: unlocking, key slots, and the encrypted folder tree.
//!
//! ```text
//! <vault>/vault.json, vault.json.bak
//! <vault>/d/XX/YYYY.../            storage folder of one vault folder
//!     <encrypted name>.flk         a file
//!     <encrypted name>.flk/dir.id  a subfolder; dir.id holds its folder ID
//!     <hash>.flks/name.flk         an entry whose encrypted name is too long:
//!     <hash>.flks/contents.flk       name.flk holds the full name, plus either
//!     <hash>.flks/dir.id             the file contents or the folder ID
//! ```

use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::config::{slot_aad, KeySlot, SlotKind, VaultConfig};
use crate::content::VaultFile;
use crate::fs_util::{exists, is_empty_dir, write_atomic, write_atomic_with};
use crate::keys::{self, KdfParams, MasterKey, RecoveryKey, VaultKeys, SALT_LEN};
use crate::names::{self, StoredName, ENTRY_SUFFIX, SHORTENED_SUFFIX};
use crate::{content, hex, random_fill, Error, Result};

const ROOT_DIR_ID: &str = "";
const DIR_ID_FILE: &str = "dir.id";
const LONG_NAME_FILE: &str = "name.flk";
const CONTENTS_FILE: &str = "contents.flk";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    /// Plaintext size; `None` for folders.
    pub size: Option<u64>,
    /// Timestamps of the encrypted file (or the folder's entry) on disk.
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
}

impl Entry {
    fn new(name: String, kind: EntryKind, size: Option<u64>, meta: &Metadata) -> Self {
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        Self {
            name,
            kind,
            size,
            created: meta.created().unwrap_or(modified),
            modified,
            accessed: meta.accessed().unwrap_or(modified),
        }
    }
}

/// Totals from an import or export.
#[derive(Debug, Default)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Symlinks, junctions and other non-regular entries that were not imported.
    pub skipped: Vec<PathBuf>,
}

/// An unlocked vault. Keys are zeroized when it is dropped.
pub struct Vault {
    root: PathBuf,
    config: VaultConfig,
    master: MasterKey,
    keys: VaultKeys,
    /// Per folder ID: case-folded name → stored name, for [`Vault::find`].
    name_index: Mutex<HashMap<String, FolderIndex>>,
}

/// A folder's names, valid while its storage folder's modification time is
/// unchanged (so changes made outside this vault object, such as by a sync
/// tool, are noticed). This vault's own changes drop it explicitly.
struct FolderIndex {
    stamp: SystemTime,
    names: Arc<HashMap<String, String>>,
}

#[derive(Clone)]
struct DirRef {
    id: String,
    storage: PathBuf,
}

/// Where one entry lives in its parent's storage folder.
struct Node {
    path: PathBuf,
    /// The full encrypted name, when `path` is a shortened `.flks` folder.
    long_name: Option<String>,
}

impl Node {
    fn contents(&self) -> PathBuf {
        match self.long_name {
            Some(_) => self.path.join(CONTENTS_FILE),
            None => self.path.clone(),
        }
    }

    fn dir_id(&self) -> PathBuf {
        self.path.join(DIR_ID_FILE)
    }

    /// `None` if the entry is missing, or was left incomplete by an interrupted write.
    fn kind(&self) -> Result<Option<EntryKind>> {
        let meta = match fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(if !meta.is_dir() {
            self.long_name.is_none().then_some(EntryKind::File)
        } else if exists(&self.dir_id())? {
            Some(EntryKind::Dir)
        } else if self.long_name.is_some() && exists(&self.contents())? {
            Some(EntryKind::File)
        } else {
            None
        })
    }

    /// Prepares the entry for writing its contents or folder ID.
    fn prepare(&self) -> Result<()> {
        match &self.long_name {
            Some(full) => {
                fs::create_dir_all(&self.path)?;
                write_atomic(&self.path.join(LONG_NAME_FILE), full.as_bytes())
            }
            // Clears an empty folder left by an interrupted folder creation.
            None if self.path.is_dir() => Ok(fs::remove_dir(&self.path)?),
            None => Ok(()),
        }
    }
}

impl Vault {
    /// Creates a vault in `root`, which must be missing or an empty folder.
    /// Returns the unlocked vault and its recovery key, which must be shown to
    /// the user: it is never stored.
    pub fn create(root: &Path, password: &[u8], kdf: KdfParams) -> Result<(Vault, RecoveryKey)> {
        kdf.validate()?;
        if exists(root)? {
            if !root.is_dir() || !is_empty_dir(root)? {
                return Err(Error::AlreadyExists(root.display().to_string()));
            }
        } else {
            fs::create_dir_all(root)?;
        }
        let master = MasterKey::generate()?;
        let recovery = RecoveryKey::generate()?;
        let slots = vec![
            password_slot(&master, password, &kdf)?,
            recovery_slot(&master, &recovery)?,
        ];
        let vault = Self::open(root, VaultConfig::new(kdf, slots), master);
        fs::create_dir_all(&vault.root_dir().storage)?;
        vault.config.save(root)?;
        Ok((vault, recovery))
    }

    pub fn unlock(root: &Path, password: &[u8]) -> Result<Vault> {
        let config = VaultConfig::load(root)?;
        let slot = config.slot(SlotKind::Password)?;
        let kek = keys::password_kek(password, &slot.salt, &config.kdf)?;
        let master = keys::unwrap_master(
            &kek,
            &slot.nonce,
            &slot.wrapped_key,
            &slot_aad(SlotKind::Password, &config.kdf),
        )
        .ok_or(Error::WrongPassword)?;
        Ok(Self::open(root, config, master))
    }

    pub fn unlock_with_recovery_key(root: &Path, recovery: &RecoveryKey) -> Result<Vault> {
        let config = VaultConfig::load(root)?;
        let slot = config.slot(SlotKind::Recovery)?;
        let kek = keys::recovery_kek(recovery, &slot.salt);
        let master = keys::unwrap_master(
            &kek,
            &slot.nonce,
            &slot.wrapped_key,
            &slot_aad(SlotKind::Recovery, &config.kdf),
        )
        .ok_or(Error::WrongRecoveryKey)?;
        Ok(Self::open(root, config, master))
    }

    /// Replaces the password. Only the password slot is rewritten; contents and
    /// the recovery key are unchanged.
    pub fn change_password(&mut self, new_password: &[u8]) -> Result<()> {
        let slot = password_slot(&self.master, new_password, &self.config.kdf)?;
        self.config.replace_slot(slot);
        self.config.save(&self.root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lists a vault folder, sorted by name. `path` uses `/` or `\`; `/` is the root.
    pub fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let dir = self.resolve_dir(&split_path(path)?, path)?;
        Ok(self
            .read_dir(&dir)?
            .into_iter()
            .map(|(entry, _)| entry)
            .collect())
    }

    /// Encrypts the file or folder `source` into the vault folder `dest`,
    /// keeping its name. Fails if that name already exists there.
    pub fn import(&self, source: &Path, dest: &str) -> Result<Stats> {
        let parent = self.resolve_dir(&split_path(dest)?, dest)?;
        let mut stats = Stats::default();
        self.import_entry(source, &parent, source_name(source)?, &mut stats)?;
        Ok(stats)
    }

    /// Like [`import`](Self::import), but replaces an existing file or folder
    /// of the same name. The new copy is written in full under a temporary
    /// name before the old one is removed, so a failure never loses the old copy.
    pub fn import_replacing(&self, source: &Path, dest: &str) -> Result<Stats> {
        let parent = self.resolve_dir(&split_path(dest)?, dest)?;
        let name = source_name(source)?;
        let existing = self.node(&parent, name)?;
        let Some(old_kind) = existing.kind()? else {
            return self.import(source, dest);
        };

        let mut tag = [0u8; 8];
        random_fill(&mut tag)?;
        let temp_name = format!("~flk-replacing-{}", hex(&tag));
        let mut stats = Stats::default();
        if let Err(e) = self.import_entry(source, &parent, &temp_name, &mut stats) {
            let temp = self.node(&parent, &temp_name)?;
            if let Ok(Some(kind)) = temp.kind() {
                let _ = self.remove_node(&temp, kind, &mut Stats::default());
            }
            self.forget_index(&parent.id);
            return Err(e);
        }
        let temp = self.node(&parent, &temp_name)?;
        let new_kind = temp
            .kind()?
            .ok_or_else(|| Error::Corrupt(format!("{temp_name} vanished while importing")))?;
        self.remove_node(&existing, old_kind, &mut Stats::default())?;
        self.move_node(&temp, new_kind, &existing)?;
        self.forget_index(&parent.id);
        Ok(stats)
    }

    /// Deletes a vault file, or a folder and everything in it.
    pub fn remove(&self, path: &str) -> Result<Stats> {
        let components = split_path(path)?;
        let (name, parents) = components
            .split_last()
            .ok_or(Error::NotAllowed("remove the vault root"))?;
        let parent = self.resolve_dir(parents, path)?;
        let node = self.node(&parent, name)?;
        let kind = node.kind()?.ok_or_else(|| Error::NotFound(path.into()))?;
        let mut stats = Stats::default();
        self.remove_node(&node, kind, &mut stats)?;
        self.index_changed(&parent, None, Some(name));
        Ok(stats)
    }

    /// Renames or moves a vault file or folder to the full path `to`, which
    /// must not exist. File contents are not re-encrypted.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.rename_with(from, to, false)
    }

    /// Like [`rename`](Self::rename); with `replace`, an existing *file* at
    /// `to` is replaced (as Windows' rename-and-replace does). Folders are never
    /// replaced.
    pub fn rename_with(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        let from_parts = split_path(from)?;
        let to_parts = split_path(to)?;
        let ((from_name, from_parents), (to_name, to_parents)) =
            match (from_parts.split_last(), to_parts.split_last()) {
                (Some(f), Some(t)) => (f, t),
                _ => return Err(Error::NotAllowed("move the vault root")),
            };
        let src_parent = self.resolve_dir(from_parents, from)?;
        let src = self.node(&src_parent, from_name)?;
        let kind = src.kind()?.ok_or_else(|| Error::NotFound(from.into()))?;
        if kind == EntryKind::Dir
            && to_parts.len() > from_parts.len()
            && to_parts.starts_with(&from_parts)
        {
            return Err(Error::NotAllowed("move a folder into itself"));
        }
        let dst_parent = self.resolve_dir(to_parents, to)?;
        let dst = self.node(&dst_parent, to_name)?;
        match dst.kind()? {
            None => {}
            Some(_) if from_parts == to_parts => return Ok(()),
            Some(EntryKind::File) if replace => {
                self.remove_node(&dst, EntryKind::File, &mut Stats::default())?
            }
            Some(EntryKind::Dir) if replace => {
                return Err(Error::NotAllowed("replace a folder"));
            }
            Some(_) => return Err(Error::AlreadyExists(to.into())),
        }
        fs::create_dir_all(&dst_parent.storage)?;
        self.move_node(&src, kind, &dst)?;
        self.index_changed(&src_parent, None, Some(from_name));
        self.index_changed(&dst_parent, Some(to_name), None);
        Ok(())
    }

    /// Details of one file or folder; the root is a folder named "".
    pub fn stat(&self, path: &str) -> Result<Entry> {
        let components = split_path(path)?;
        let Some((name, parents)) = components.split_last() else {
            let meta = fs::metadata(&self.root)?;
            return Ok(Entry::new(String::new(), EntryKind::Dir, None, &meta));
        };
        let node = self.node(&self.resolve_dir(parents, path)?, name)?;
        let kind = node.kind()?.ok_or_else(|| Error::NotFound(path.into()))?;
        self.entry(name.to_string(), kind, &node)
    }

    /// Finds `path` ignoring letter case, as Windows does. Returns the path
    /// with each component spelled as stored (`/` for the root), or `None`.
    ///
    /// Exact matches are cheap; other spellings use a per-folder index that
    /// is built once and reused until the folder changes.
    pub fn find(&self, path: &str) -> Result<Option<String>> {
        let components = split_path(path)?;
        let mut dir = self.root_dir();
        let mut found = String::new();
        for (i, name) in components.iter().enumerate() {
            let exact = self.node(&dir, name)?;
            let (stored, node, kind) = match exact.kind()? {
                Some(kind) => (name.to_string(), exact, kind),
                None => {
                    let Some(stored) = self.folder_index(&dir)?.get(&fold(name)).cloned() else {
                        return Ok(None);
                    };
                    let node = self.node(&dir, &stored)?;
                    let Some(kind) = node.kind()? else {
                        return Ok(None);
                    };
                    (stored, node, kind)
                }
            };
            found.push('/');
            found.push_str(&stored);
            if i + 1 < components.len() {
                if kind != EntryKind::Dir {
                    return Ok(None);
                }
                dir = self.open_dir(&node)?;
            }
        }
        Ok(Some(if found.is_empty() { "/".into() } else { found }))
    }

    /// Creates an empty file and returns it open. Fails if the name exists.
    pub fn create_file(&self, path: &str) -> Result<VaultFile> {
        let (parent, name) = self.parent_and_name(path)?;
        let node = self.node(&parent, name)?;
        if node.kind()?.is_some() {
            return Err(Error::AlreadyExists(path.into()));
        }
        fs::create_dir_all(&parent.storage)?;
        node.prepare()?;
        let file = VaultFile::create(&self.keys.content, &node.contents())?;
        self.index_changed(&parent, Some(name), None);
        Ok(file)
    }

    /// Creates an empty folder. Fails if the name exists.
    pub fn create_dir(&self, path: &str) -> Result<()> {
        let (parent, name) = self.parent_and_name(path)?;
        self.make_dir(&parent, name).map(|_| ())
    }

    /// Opens a file for reads and writes at any offset.
    pub fn open_file(&self, path: &str) -> Result<VaultFile> {
        let (parent, name) = self.parent_and_name(path)?;
        let node = self.node(&parent, name)?;
        match node.kind()? {
            Some(EntryKind::File) => VaultFile::open(&self.keys.content, &node.contents()),
            Some(EntryKind::Dir) => Err(Error::IsADirectory(path.into())),
            None => Err(Error::NotFound(path.into())),
        }
    }

    /// Sets timestamps; `None` leaves one unchanged.
    pub fn set_times(
        &self,
        path: &str,
        created: Option<SystemTime>,
        accessed: Option<SystemTime>,
        modified: Option<SystemTime>,
    ) -> Result<()> {
        let target = match split_path(path)?.split_last() {
            None => self.root.clone(),
            Some((name, parents)) => {
                let node = self.node(&self.resolve_dir(parents, path)?, name)?;
                match node.kind()? {
                    Some(EntryKind::File) => node.contents(),
                    Some(EntryKind::Dir) => node.path,
                    None => return Err(Error::NotFound(path.into())),
                }
            }
        };
        let mut times = fs::FileTimes::new();
        if let Some(t) = accessed {
            times = times.set_accessed(t);
        }
        if let Some(t) = modified {
            times = times.set_modified(t);
        }
        #[cfg(windows)]
        if let Some(t) = created {
            use std::os::windows::fs::FileTimesExt;
            times = times.set_created(t);
        }
        #[cfg(not(windows))]
        let _ = created;
        open_for_attributes(&target)?.set_times(times)?;
        Ok(())
    }

    /// Decrypts the vault file or folder `path` into `dest`, which must be
    /// missing or an empty folder. A folder's contents go directly into `dest`;
    /// a file is written as `dest/<name>`.
    pub fn export(&self, path: &str, dest: &Path) -> Result<Stats> {
        if exists(dest)? && (!dest.is_dir() || !is_empty_dir(dest)?) {
            return Err(Error::AlreadyExists(dest.display().to_string()));
        }
        let components = split_path(path)?;
        let mut stats = Stats::default();
        fs::create_dir_all(dest)?;
        match components.split_last() {
            None => self.export_dir(&self.root_dir(), dest, &mut stats)?,
            Some((name, parents)) => {
                let node = self.node(&self.resolve_dir(parents, path)?, name)?;
                match node.kind()? {
                    None => return Err(Error::NotFound(path.into())),
                    Some(EntryKind::Dir) => {
                        self.export_dir(&self.open_dir(&node)?, dest, &mut stats)?
                    }
                    Some(EntryKind::File) => {
                        self.export_file(&node, &dest.join(name), &mut stats)?
                    }
                }
            }
        }
        Ok(stats)
    }

    fn open(root: &Path, config: VaultConfig, master: MasterKey) -> Self {
        let keys = VaultKeys::derive(&master);
        Self {
            root: root.into(),
            config,
            master,
            keys,
            name_index: Mutex::new(HashMap::new()),
        }
    }

    fn dir_ref(&self, id: String) -> DirRef {
        let storage = self
            .root
            .join(names::dir_storage_path(&self.keys.dir_hash, &id));
        DirRef { id, storage }
    }

    fn root_dir(&self) -> DirRef {
        self.dir_ref(ROOT_DIR_ID.into())
    }

    fn node(&self, dir: &DirRef, name: &str) -> Result<Node> {
        Ok(
            match names::encrypt_name(&self.keys.names, &dir.id, name)? {
                StoredName::Plain(stored) => Node {
                    path: dir.storage.join(stored),
                    long_name: None,
                },
                StoredName::Shortened { short, full } => Node {
                    path: dir.storage.join(short),
                    long_name: Some(full),
                },
            },
        )
    }

    fn open_dir(&self, node: &Node) -> Result<DirRef> {
        let id = fs::read_to_string(node.dir_id())?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Corrupt(format!(
                "invalid folder ID in {}",
                node.path.display()
            )));
        }
        Ok(self.dir_ref(id))
    }

    fn resolve_dir(&self, components: &[&str], path: &str) -> Result<DirRef> {
        let mut dir = self.root_dir();
        for name in components {
            let node = self.node(&dir, name)?;
            dir = match node.kind()? {
                Some(EntryKind::Dir) => self.open_dir(&node)?,
                Some(EntryKind::File) => return Err(Error::NotADirectory(path.into())),
                None => return Err(Error::NotFound(path.into())),
            };
        }
        Ok(dir)
    }

    fn read_dir(&self, dir: &DirRef) -> Result<Vec<(Entry, Node)>> {
        let mut entries = Vec::new();
        // An empty folder's storage may be missing: git and some sync tools drop empty folders.
        let items = match fs::read_dir(&dir.storage) {
            Ok(items) => items,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e.into()),
        };
        for item in items {
            let item = item?;
            let file_name = item.file_name();
            // Anything else is a temporary file from an interrupted write.
            let Some(stored) = file_name.to_str() else {
                continue;
            };
            let node = if stored.ends_with(ENTRY_SUFFIX) {
                Node {
                    path: item.path(),
                    long_name: None,
                }
            } else if stored.ends_with(SHORTENED_SUFFIX) {
                let full = match fs::read_to_string(item.path().join(LONG_NAME_FILE)) {
                    Ok(full) => full,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                if names::shorten(&full) != stored {
                    return Err(Error::Integrity(format!(
                        "long name does not match its entry {stored}"
                    )));
                }
                Node {
                    path: item.path(),
                    long_name: Some(full),
                }
            } else {
                continue;
            };
            let Some(kind) = node.kind()? else { continue };
            let name = names::decrypt_name(
                &self.keys.names,
                &dir.id,
                node.long_name.as_deref().unwrap_or(stored),
            )?;
            entries.push((self.entry(name, kind, &node)?, node));
        }
        entries.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        Ok(entries)
    }

    /// Case-folded name → stored name for every entry in `dir`.
    fn folder_index(&self, dir: &DirRef) -> Result<Arc<HashMap<String, String>>> {
        // Read the stamp before listing: a change during the listing moves
        // it, so the next lookup rebuilds.
        let stamp = match fs::metadata(&dir.storage) {
            Ok(meta) => meta.modified().ok(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(stamp) = stamp {
            if let Some(index) = self.name_index.lock().unwrap().get(&dir.id) {
                if index.stamp == stamp {
                    return Ok(index.names.clone());
                }
            }
        }
        let names: Arc<HashMap<String, String>> = Arc::new(
            self.read_names(dir)?
                .into_iter()
                .map(|name| (fold(&name), name))
                .collect(),
        );
        if let Some(stamp) = stamp {
            self.name_index.lock().unwrap().insert(
                dir.id.clone(),
                FolderIndex {
                    stamp,
                    names: names.clone(),
                },
            );
        }
        Ok(names)
    }

    fn forget_index(&self, dir_id: &str) {
        self.name_index.lock().unwrap().remove(dir_id);
    }

    /// Keeps a folder's cached index current after this vault added or
    /// removed one of its names, instead of rebuilding it from disk.
    ///
    /// The index adopts the folder's new modification time, so an outside
    /// change landing at the same moment can be missed until the next one.
    fn index_changed(&self, dir: &DirRef, added: Option<&str>, removed: Option<&str>) {
        let mut cache = self.name_index.lock().unwrap();
        let Some(index) = cache.get_mut(&dir.id) else {
            return;
        };
        match fs::metadata(&dir.storage).and_then(|m| m.modified()) {
            Ok(stamp) => {
                let names = Arc::make_mut(&mut index.names);
                if let Some(name) = removed {
                    names.remove(&fold(name));
                }
                if let Some(name) = added {
                    names.insert(fold(name), name.to_string());
                }
                index.stamp = stamp;
            }
            Err(_) => {
                cache.remove(&dir.id);
            }
        }
    }

    /// Decrypted names in `dir`, without checking each entry on disk.
    fn read_names(&self, dir: &DirRef) -> Result<Vec<String>> {
        let items = match fs::read_dir(&dir.storage) {
            Ok(items) => items,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for item in items {
            let item = item?;
            let file_name = item.file_name();
            let Some(stored) = file_name.to_str() else {
                continue;
            };
            let full = if stored.ends_with(ENTRY_SUFFIX) {
                stored.to_string()
            } else if stored.ends_with(SHORTENED_SUFFIX) {
                match fs::read_to_string(item.path().join(LONG_NAME_FILE)) {
                    Ok(full) => full,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                }
            } else {
                continue;
            };
            names.push(names::decrypt_name(&self.keys.names, &dir.id, &full)?);
        }
        Ok(names)
    }

    fn entry(&self, name: String, kind: EntryKind, node: &Node) -> Result<Entry> {
        Ok(match kind {
            EntryKind::Dir => Entry::new(name, kind, None, &fs::metadata(&node.path)?),
            EntryKind::File => {
                let meta = fs::metadata(node.contents())?;
                // A damaged file (e.g. cut short by a crash) must not hide its
                // folder's other entries: list it as empty, and opening it
                // reports the damage.
                let size = content::plaintext_len(meta.len()).unwrap_or(0);
                Entry::new(name, kind, Some(size), &meta)
            }
        })
    }

    fn parent_and_name<'p>(&self, path: &'p str) -> Result<(DirRef, &'p str)> {
        let components = split_path(path)?;
        let (name, parents) = components
            .split_last()
            .ok_or(Error::NotAllowed("use the vault root as a file"))?;
        Ok((self.resolve_dir(parents, path)?, name))
    }

    fn make_dir(&self, parent: &DirRef, name: &str) -> Result<DirRef> {
        let node = self.node(parent, name)?;
        if node.kind()?.is_some() {
            return Err(Error::AlreadyExists(name.into()));
        }
        fs::create_dir_all(&parent.storage)?;
        let mut raw_id = [0u8; 16];
        random_fill(&mut raw_id)?;
        let child = self.dir_ref(hex(&raw_id));
        // Storage first: a crash before dir.id is written leaves only an
        // unreferenced folder and an incomplete entry, both ignored.
        fs::create_dir_all(&child.storage)?;
        if node.long_name.is_some() {
            node.prepare()?;
        } else {
            fs::create_dir_all(&node.path)?;
        }
        write_atomic(&node.dir_id(), child.id.as_bytes())?;
        self.index_changed(parent, Some(name), None);
        Ok(child)
    }

    fn import_entry(
        &self,
        source: &Path,
        parent: &DirRef,
        name: &str,
        stats: &mut Stats,
    ) -> Result<()> {
        let file_type = fs::symlink_metadata(source)?.file_type();
        if file_type.is_dir() {
            let dir = self.make_dir(parent, name)?;
            stats.dirs += 1;
            let mut children = fs::read_dir(source)?.collect::<io::Result<Vec<_>>>()?;
            children.sort_by_key(|c| c.file_name());
            for child in children {
                let child_name = child.file_name();
                let child_name = child_name
                    .to_str()
                    .ok_or_else(|| Error::InvalidName(child.path().display().to_string()))?;
                self.import_entry(&child.path(), &dir, child_name, stats)?;
            }
        } else if file_type.is_file() {
            let node = self.node(parent, name)?;
            if node.kind()?.is_some() {
                return Err(Error::AlreadyExists(name.into()));
            }
            fs::create_dir_all(&parent.storage)?;
            node.prepare()?;
            let input = BufReader::new(File::open(source)?);
            stats.bytes += write_atomic_with(&node.contents(), |w| {
                content::encrypt(&self.keys.content, input, w)
            })?;
            self.index_changed(parent, Some(name), None);
            stats.files += 1;
        } else {
            stats.skipped.push(source.into());
        }
        Ok(())
    }

    /// Deletes children first, so an interrupted delete leaves a smaller but
    /// consistent tree rather than unreachable storage.
    fn remove_node(&self, node: &Node, kind: EntryKind, stats: &mut Stats) -> Result<()> {
        match kind {
            EntryKind::Dir => {
                let dir = self.open_dir(node)?;
                for (entry, child) in self.read_dir(&dir)? {
                    self.remove_node(&child, entry.kind, stats)?;
                }
                remove_storage(&dir.storage)?;
                self.forget_index(&dir.id);
                stats.dirs += 1;
                fs::remove_dir_all(&node.path)?;
            }
            EntryKind::File => {
                stats.files += 1;
                match node.long_name {
                    Some(_) => fs::remove_dir_all(&node.path)?,
                    None => fs::remove_file(&node.path)?,
                }
            }
        }
        Ok(())
    }

    /// Moves `src` to the empty location `dst`. Only the file contents or the
    /// folder's `dir.id` move; a folder's children stay in its storage folder.
    fn move_node(&self, src: &Node, kind: EntryKind, dst: &Node) -> Result<()> {
        match kind {
            EntryKind::File => {
                dst.prepare()?;
                fs::rename(src.contents(), dst.contents())?;
            }
            EntryKind::Dir => {
                if dst.long_name.is_some() {
                    dst.prepare()?;
                } else {
                    fs::create_dir_all(&dst.path)?;
                }
                fs::rename(src.dir_id(), dst.dir_id())?;
            }
        }
        // Whatever is left of `src` (an empty folder, or one holding only
        // name.flk) is incomplete and already ignored; tidy it up.
        if src.path.is_dir() {
            fs::remove_dir_all(&src.path)?;
        }
        Ok(())
    }

    fn export_dir(&self, dir: &DirRef, dest: &Path, stats: &mut Stats) -> Result<()> {
        for (entry, node) in self.read_dir(dir)? {
            let target = dest.join(&entry.name);
            match entry.kind {
                EntryKind::Dir => {
                    fs::create_dir(&target)?;
                    stats.dirs += 1;
                    self.export_dir(&self.open_dir(&node)?, &target, stats)?;
                }
                EntryKind::File => self.export_file(&node, &target, stats)?,
            }
        }
        Ok(())
    }

    fn export_file(&self, node: &Node, target: &Path, stats: &mut Stats) -> Result<()> {
        let input = BufReader::new(File::open(node.contents())?);
        stats.bytes +=
            write_atomic_with(target, |w| content::decrypt(&self.keys.content, input, w))?;
        stats.files += 1;
        Ok(())
    }
}

fn password_slot(master: &MasterKey, password: &[u8], kdf: &KdfParams) -> Result<KeySlot> {
    let mut salt = vec![0u8; SALT_LEN];
    random_fill(&mut salt)?;
    let kek = keys::password_kek(password, &salt, kdf)?;
    let (nonce, wrapped_key) = keys::wrap_master(&kek, master, &slot_aad(SlotKind::Password, kdf))?;
    Ok(KeySlot {
        kind: SlotKind::Password,
        salt,
        nonce,
        wrapped_key,
    })
}

fn recovery_slot(master: &MasterKey, recovery: &RecoveryKey) -> Result<KeySlot> {
    let mut salt = vec![0u8; SALT_LEN];
    random_fill(&mut salt)?;
    let kek = keys::recovery_kek(recovery, &salt);
    // The recovery slot's AAD does not depend on the KDF parameters.
    let (nonce, wrapped_key) = keys::wrap_master(
        &kek,
        master,
        &slot_aad(SlotKind::Recovery, &KdfParams::DEFAULT),
    )?;
    Ok(KeySlot {
        kind: SlotKind::Recovery,
        salt,
        nonce,
        wrapped_key,
    })
}

/// Case-folds a name by Unicode upper case, close to how Windows compares names.
fn fold(name: &str) -> String {
    name.chars().flat_map(char::to_uppercase).collect()
}

/// Opens a file or folder just to change its timestamps.
fn open_for_attributes(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000; // required to open folders
        options
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    #[cfg(not(windows))]
    options.write(true);
    Ok(options.open(path)?)
}

fn source_name(source: &Path) -> Result<&str> {
    source
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::InvalidName(source.display().to_string()))
}

/// Removes a folder's storage, then its `d/XX` parent if that is now empty.
fn remove_storage(storage: &Path) -> Result<()> {
    match fs::remove_dir_all(storage) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if let Some(parent) = storage.parent() {
        let _ = fs::remove_dir(parent); // fails harmlessly unless empty
    }
    Ok(())
}

fn split_path(path: &str) -> Result<Vec<&str>> {
    path.split(['/', '\\'])
        .filter(|c| !c.is_empty())
        .map(|c| names::validate_name(c).map(|()| c))
        .collect()
}
