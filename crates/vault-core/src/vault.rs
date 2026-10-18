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

use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use crate::config::{slot_aad, KeySlot, SlotKind, VaultConfig};
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
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::InvalidName(source.display().to_string()))?;
        let mut stats = Stats::default();
        self.import_entry(source, &parent, name, &mut stats)?;
        Ok(stats)
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
            let size = match kind {
                EntryKind::Dir => None,
                EntryKind::File => Some(
                    content::plaintext_len(fs::metadata(node.contents())?.len())
                        .ok_or_else(|| Error::Corrupt(format!("{name} has an impossible size")))?,
                ),
            };
            entries.push((Entry { name, kind, size }, node));
        }
        entries.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        Ok(entries)
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
            stats.files += 1;
        } else {
            stats.skipped.push(source.into());
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

fn split_path(path: &str) -> Result<Vec<&str>> {
    path.split(['/', '\\'])
        .filter(|c| !c.is_empty())
        .map(|c| names::validate_name(c).map(|()| c))
        .collect()
}
