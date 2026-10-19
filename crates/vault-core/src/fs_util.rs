use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::{hex, random_fill, Error, Result};

/// Writes `path` by streaming into a temporary file in the same folder, syncing
/// it, then renaming it into place, so readers never see a half-written file.
/// The temporary file is removed if `write` fails.
pub(crate) fn write_atomic_with<T>(
    path: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> Result<T>,
) -> Result<T> {
    let tmp = temp_path_beside(path)?;
    let result: Result<T> = (|| {
        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let mut writer = BufWriter::new(file);
        let value = write(&mut writer)?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(value)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// A fresh temporary name in `path`'s folder. Listings skip these names.
pub(crate) fn temp_path_beside(path: &Path) -> Result<PathBuf> {
    let dir = path.parent().ok_or_else(|| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path has no parent",
        ))
    })?;
    let mut tag = [0u8; 8];
    random_fill(&mut tag)?;
    Ok(dir.join(format!(".{}.tmp", hex(&tag))))
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_with(path, |w| Ok(w.write_all(bytes)?))
}

/// True if `path` exists, without following symlinks.
pub(crate) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn is_empty_dir(path: &Path) -> Result<bool> {
    Ok(fs::read_dir(path)?.next().is_none())
}
