//! The WinFsp file system: translates Windows file operations into vault calls.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vault_core::{Entry, EntryKind, Error, Vault, VaultFile};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    ModificationDescriptor, OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::{FspError, U16CStr};

use crate::win;

const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const CLEANUP_DELETE: u32 = 0x01;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

// NTSTATUS codes returned to Windows.
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_FILE_CORRUPT_ERROR: u32 = 0xC000_0102;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_FILE_DELETED: u32 = 0xC000_0123;

fn nt(code: u32) -> FspError {
    FspError::NTSTATUS(code as i32)
}

/// Maps a vault error to the closest NTSTATUS. Damage and I/O failures are
/// also logged, since Windows only shows a generic error.
fn to_nt(e: Error) -> FspError {
    let code = match &e {
        Error::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::AlreadyExists(_) => STATUS_OBJECT_NAME_COLLISION,
        Error::IsADirectory(_) => STATUS_FILE_IS_A_DIRECTORY,
        Error::NotADirectory(_) => STATUS_NOT_A_DIRECTORY,
        Error::InvalidName(_) | Error::NameTooLong(_) => STATUS_OBJECT_NAME_INVALID,
        Error::NotAllowed(_) => STATUS_ACCESS_DENIED,
        Error::Integrity(_) => STATUS_DATA_ERROR,
        Error::Corrupt(_) => STATUS_FILE_CORRUPT_ERROR,
        Error::Io(_) => 0,
        _ => STATUS_UNSUCCESSFUL,
    };
    if matches!(
        code,
        STATUS_DATA_ERROR | STATUS_FILE_CORRUPT_ERROR | STATUS_UNSUCCESSFUL | 0
    ) {
        eprintln!("flk: {e}");
    }
    match e {
        Error::Io(io) => io.into(),
        _ => nt(code),
    }
}

pub(crate) struct VaultFs {
    vault: Vault,
    label: String,
    security: Vec<u8>,
    /// Every file or folder with open handles, by case-folded path. Handles
    /// to the same file share one `VaultFile`, so they agree on its length.
    open: Mutex<HashMap<String, Arc<OpenEntry>>>,
}

pub(crate) struct OpenEntry {
    /// Current vault path, as stored; updated when it or a parent is renamed.
    path: Mutex<String>,
    kind: EntryKind,
    /// `None` for folders, and after the file is deleted.
    file: Mutex<Option<VaultFile>>,
    /// Changed only while holding `VaultFs::open`.
    handles: AtomicUsize,
}

pub(crate) struct Handle {
    entry: Arc<OpenEntry>,
    dir_buffer: DirBuffer,
}

impl Handle {
    fn path(&self) -> String {
        self.entry.path.lock().unwrap().clone()
    }
}

impl VaultFs {
    pub(crate) fn new(vault: Vault, label: String) -> io::Result<Self> {
        Ok(Self {
            vault,
            label,
            security: win::security_descriptor()?,
            open: Mutex::new(HashMap::new()),
        })
    }

    /// Resolves a Windows name case-insensitively to its stored vault path.
    fn find(&self, file_name: &U16CStr) -> winfsp::Result<String> {
        let path = vault_path(file_name)?;
        if let Some(found) = self.vault.find(&path).map_err(to_nt)? {
            return Ok(found);
        }
        let (parent, _) = split_parent(&path);
        Err(match self.vault.find(parent).map_err(to_nt)? {
            Some(_) => nt(STATUS_OBJECT_NAME_NOT_FOUND),
            None => nt(STATUS_OBJECT_PATH_NOT_FOUND),
        })
    }

    /// Adds a handle to `path`'s shared entry. `created` is a file that was
    /// just created and is already open, so it need not be reopened.
    fn acquire(
        &self,
        path: String,
        kind: EntryKind,
        created: Option<VaultFile>,
    ) -> winfsp::Result<Handle> {
        let mut open = self.open.lock().unwrap();
        let entry = match open.get(&fold(&path)) {
            Some(entry) => entry.clone(),
            None => {
                let file = match (kind, created) {
                    (EntryKind::File, Some(file)) => Some(file),
                    (EntryKind::File, None) => Some(self.vault.open_file(&path).map_err(to_nt)?),
                    (EntryKind::Dir, _) => None,
                };
                let entry = Arc::new(OpenEntry {
                    path: Mutex::new(path.clone()),
                    kind,
                    file: Mutex::new(file),
                    handles: AtomicUsize::new(0),
                });
                open.insert(fold(&path), entry.clone());
                entry
            }
        };
        entry.handles.fetch_add(1, Ordering::SeqCst);
        Ok(Handle {
            entry,
            dir_buffer: DirBuffer::new(),
        })
    }

    fn release(&self, handle: Handle) {
        let mut open = self.open.lock().unwrap();
        if handle.entry.handles.fetch_sub(1, Ordering::SeqCst) == 1 {
            let key = fold(&handle.path());
            if open
                .get(&key)
                .is_some_and(|e| Arc::ptr_eq(e, &handle.entry))
            {
                open.remove(&key);
            }
        }
    }

    /// Opens a handle to `path` and describes it in `file_info`.
    fn open_path(
        &self,
        path: String,
        created: Option<VaultFile>,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let entry = self.vault.stat(&path).map_err(to_nt)?;
        let handle = self.acquire(path.clone(), entry.kind, created)?;
        let size = self.file_len(&handle);
        fill(file_info.as_mut(), &path, &entry, size);
        file_info.set_normalized_name(&windows_path(&path), None);
        Ok(handle)
    }

    fn file_len(&self, handle: &Handle) -> Option<u64> {
        handle
            .entry
            .file
            .lock()
            .unwrap()
            .as_ref()
            .map(VaultFile::len)
    }

    fn info(&self, handle: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        let path = handle.path();
        let entry = self.vault.stat(&path).map_err(to_nt)?;
        fill(file_info, &path, &entry, self.file_len(handle));
        Ok(())
    }

    fn with_file<T>(
        &self,
        handle: &Handle,
        f: impl FnOnce(&mut VaultFile) -> winfsp::Result<T>,
    ) -> winfsp::Result<T> {
        let mut guard = handle.entry.file.lock().unwrap();
        match guard.as_mut() {
            Some(file) => f(file),
            None if handle.entry.kind == EntryKind::Dir => Err(nt(STATUS_FILE_IS_A_DIRECTORY)),
            None => Err(nt(STATUS_FILE_DELETED)),
        }
    }

    fn copy_security(&self, buffer: Option<&mut [c_void]>) {
        if let Some(buffer) = buffer {
            if buffer.len() >= self.security.len() {
                // SAFETY: the destination holds at least `security.len()` bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.security.as_ptr(),
                        buffer.as_mut_ptr().cast::<u8>(),
                        self.security.len(),
                    )
                };
            }
        }
    }

    /// After a rename, points open entries at and below `from` to `to`.
    fn rekey(&self, from: &str, to: &str) {
        let mut open = self.open.lock().unwrap();
        let old = fold(from);
        let below = format!("{old}/");
        let moved: Vec<String> = open
            .keys()
            .filter(|k| **k == old || k.starts_with(&below))
            .cloned()
            .collect();
        for key in moved {
            let entry = open.remove(&key).expect("key was just listed");
            let new_path = {
                let mut path = entry.path.lock().unwrap();
                *path = format!("{to}{}", path.get(from.len()..).unwrap_or(""));
                path.clone()
            };
            open.insert(fold(&new_path), entry);
        }
    }
}

impl FileSystemContext for VaultFs {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = self.find(file_name)?;
        let entry = self.vault.stat(&path).map_err(to_nt)?;
        self.copy_security(security_descriptor);
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: self.security.len() as u64,
            attributes: attributes(entry.kind),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = self.find(file_name)?;
        self.open_path(path, None, file_info)
    }

    fn close(&self, context: Handle) {
        self.release(context);
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = vault_path(file_name)?;
        let (parent, name) = split_parent(&path);
        let parent = self
            .vault
            .find(parent)
            .map_err(to_nt)?
            .ok_or(nt(STATUS_OBJECT_PATH_NOT_FOUND))?;
        if self.vault.stat(&parent).map_err(to_nt)?.kind != EntryKind::Dir {
            return Err(nt(STATUS_OBJECT_PATH_NOT_FOUND));
        }
        let target = join(&parent, name);
        if self.vault.find(&target).map_err(to_nt)?.is_some() {
            return Err(nt(STATUS_OBJECT_NAME_COLLISION));
        }
        let created = if create_options & FILE_DIRECTORY_FILE != 0 {
            self.vault.create_dir(&target).map_err(to_nt)?;
            None
        } else {
            Some(self.vault.create_file(&target).map_err(to_nt)?)
        };
        self.open_path(target, created, file_info)
    }

    fn cleanup(&self, context: &Handle, _file_name: Option<&U16CStr>, flags: u32) {
        if flags & CLEANUP_DELETE == 0 {
            return;
        }
        // Close the encrypted file first so it can be removed straight away.
        context.entry.file.lock().unwrap().take();
        let path = context.path();
        if let Err(e) = self.vault.remove(&path) {
            eprintln!("flk: deleting {path}: {e}");
        }
    }

    fn flush(&self, context: Option<&Handle>, file_info: &mut FileInfo) -> winfsp::Result<()> {
        let Some(handle) = context else {
            return Ok(());
        };
        if handle.entry.kind == EntryKind::File {
            self.with_file(handle, |f| f.sync().map_err(to_nt))?;
        }
        self.info(handle, file_info)
    }

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        self.info(context, file_info)
    }

    fn get_security(
        &self,
        _context: &Handle,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        self.copy_security(security_descriptor);
        Ok(self.security.len() as u64)
    }

    /// Permissions are not stored in the vault; changes are accepted and dropped.
    fn set_security(
        &self,
        _context: &Handle,
        _security_information: u32,
        _modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Handle,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.with_file(context, |f| f.set_len(0).map_err(to_nt))?;
        self.info(context, file_info)
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if marker.is_none() {
            let path = context.path();
            let entries = self.vault.list(&path).map_err(to_nt)?;
            let this = self.vault.stat(&path).map_err(to_nt)?;
            let lock = context.dir_buffer.acquire(true, None)?;
            if path != "/" {
                for (dot, dot_path) in [(".", path.as_str()), ("..", split_parent(&path).0)] {
                    let mut info = DirInfo::<255>::new();
                    fill(info.file_info_mut(), dot_path, &this, None);
                    let name: Vec<u16> = dot.encode_utf16().collect();
                    info.set_name_raw(name.as_slice())?;
                    lock.write(&mut info)?;
                }
            }
            for entry in entries {
                let mut info = DirInfo::<255>::new();
                fill(
                    info.file_info_mut(),
                    &join(&path, &entry.name),
                    &entry,
                    None,
                );
                let name: Vec<u16> = entry.name.encode_utf16().collect();
                info.set_name_raw(name.as_slice())?;
                lock.write(&mut info)?;
            }
        }
        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn rename(
        &self,
        context: &Handle,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let from = context.path();
        let requested = vault_path(new_file_name)?;
        let (parent, name) = split_parent(&requested);
        let parent = self
            .vault
            .find(parent)
            .map_err(to_nt)?
            .ok_or(nt(STATUS_OBJECT_PATH_NOT_FOUND))?;
        let to = join(&parent, name);
        if let Some(existing) = self.vault.find(&to).map_err(to_nt)? {
            // A case-only rename finds the entry itself; that is not a clash.
            if fold(&existing) != fold(&from) {
                if !replace_if_exists {
                    return Err(nt(STATUS_OBJECT_NAME_COLLISION));
                }
                if self.vault.stat(&existing).map_err(to_nt)?.kind == EntryKind::Dir {
                    return Err(nt(STATUS_ACCESS_DENIED));
                }
                self.vault.remove(&existing).map_err(to_nt)?;
            }
        }
        self.vault.rename(&from, &to).map_err(to_nt)?;
        self.rekey(&from, &to);
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Handle,
        _file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let times = [creation_time, last_access_time, last_write_time].map(win::from_filetime);
        if times.iter().any(Option::is_some) {
            self.vault
                .set_times(&context.path(), times[0], times[1], times[2])
                .map_err(to_nt)?;
        }
        self.info(context, file_info)
    }

    fn set_delete(
        &self,
        context: &Handle,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if delete_file
            && context.entry.kind == EntryKind::Dir
            && !self.vault.list(&context.path()).map_err(to_nt)?.is_empty()
        {
            return Err(nt(STATUS_DIRECTORY_NOT_EMPTY));
        }
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Handle,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.with_file(context, |f| {
            // Allocation size only matters when it cuts into the data.
            if !set_allocation_size || new_size < f.len() {
                f.set_len(new_size).map_err(to_nt)?;
            }
            Ok(())
        })?;
        self.info(context, file_info)
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        self.with_file(context, |f| {
            if offset >= f.len() {
                return Err(nt(STATUS_END_OF_FILE));
            }
            Ok(f.read_at(offset, buffer).map_err(to_nt)? as u32)
        })
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let written = self.with_file(context, |f| {
            let len = f.len();
            // Constrained (paging) I/O may not extend the file.
            let (offset, data) = if constrained_io {
                if offset >= len {
                    return Ok(0);
                }
                let n = buffer.len().min((len - offset) as usize);
                (offset, &buffer[..n])
            } else if write_to_eof {
                (len, buffer)
            } else {
                (offset, buffer)
            };
            f.write_at(offset, data).map_err(to_nt)?;
            Ok(data.len())
        })?;
        self.info(context, file_info)?;
        Ok(written as u32)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let (total, free) = win::disk_space(self.vault.root());
        out_volume_info.total_size = total;
        out_volume_info.free_size = free;
        out_volume_info.set_volume_label(&self.label);
        Ok(())
    }
}

fn attributes(kind: EntryKind) -> u32 {
    match kind {
        EntryKind::Dir => FILE_ATTRIBUTE_DIRECTORY,
        EntryKind::File => FILE_ATTRIBUTE_ARCHIVE,
    }
}

/// Describes `entry`, found at vault path `path`, to Windows.
fn fill(info: &mut FileInfo, path: &str, entry: &Entry, size: Option<u64>) {
    let size = size.or(entry.size).unwrap_or(0);
    info.file_attributes = attributes(entry.kind);
    info.reparse_tag = 0;
    info.file_size = size;
    info.allocation_size = size.next_multiple_of(4096);
    info.creation_time = win::to_filetime(entry.created);
    info.last_access_time = win::to_filetime(entry.accessed);
    info.last_write_time = win::to_filetime(entry.modified);
    info.change_time = info.last_write_time;
    info.index_number = file_index(path);
    info.hard_links = 0;
    info.ea_size = 0;
}

/// A stable, non-zero file index (Windows' inode number) per path. Tools
/// compare it to tell files apart: tar, for one, skips any file whose index
/// matches the archive it is writing. Changes when the entry is renamed.
fn file_index(path: &str) -> u64 {
    // FNV-1a over the case-folded path, so every spelling maps to one index.
    let hash = fold(path).bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    hash.max(1)
}

/// `\dir\file` → `/dir/file`.
fn vault_path(file_name: &U16CStr) -> winfsp::Result<String> {
    let path = file_name
        .to_string()
        .map_err(|_| nt(STATUS_OBJECT_NAME_INVALID))?;
    Ok(path.replace('\\', "/"))
}

/// `/dir/file` → `\dir\file` as UTF-16.
fn windows_path(path: &str) -> Vec<u16> {
    path.replace('/', "\\").encode_utf16().collect()
}

/// Case-folded key for the open-file table.
fn fold(path: &str) -> String {
    path.chars().flat_map(char::to_uppercase).collect()
}

/// `/a/b/c` → (`/a/b`, `c`); `/c` → (`/`, `c`).
fn split_parent(path: &str) -> (&str, &str) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((parent, name)) => (parent, name),
        None => ("/", trimmed),
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers() {
        assert_eq!(split_parent("/a/b/c"), ("/a/b", "c"));
        assert_eq!(split_parent("/c"), ("/", "c"));
        assert_eq!(join("/", "x"), "/x");
        assert_eq!(join("/a", "x"), "/a/x");
        assert_eq!(fold("/Docs/Résumé"), "/DOCS/RÉSUMÉ");
    }

    #[test]
    fn file_indexes_are_distinct_and_case_blind() {
        assert_eq!(file_index("/Docs/a.txt"), file_index("/DOCS/A.TXT"));
        assert_ne!(file_index("/Docs/a.txt"), file_index("/Docs/b.txt"));
        assert_ne!(file_index("/"), 0);
    }
}
