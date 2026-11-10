//! "Move into vault": copy files and folders onto an unlocked vault's drive,
//! check every copied file against its original, then delete the originals.
//!
//! An original is deleted only after its whole copy has been verified. If
//! anything fails or the user stops, unfinished copies are removed and the
//! originals stay where they were.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const BUFFER: usize = 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub current: String,
}

#[derive(Debug, Default)]
pub struct Report {
    /// Sources moved, with where they ended up.
    pub moved: Vec<(PathBuf, PathBuf)>,
    /// Sources left in place, with the reason.
    pub kept: Vec<(PathBuf, String)>,
    pub cancelled: bool,
}

enum Failure {
    Cancelled,
    Io(String),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Io(e.to_string())
    }
}

/// Moves `sources` into the folder `dest` (normally a vault drive's root).
pub fn move_into(
    sources: &[PathBuf],
    dest: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Report {
    let mut report = Report::default();
    let mut state = Progress {
        total: sources.iter().map(|s| size_of(s)).sum(),
        ..Progress::default()
    };
    for source in sources {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            report.kept.push((source.clone(), "stopped".into()));
            continue;
        }
        let Some(name) = source.file_name() else {
            report
                .kept
                .push((source.clone(), "not a file or folder".into()));
            continue;
        };
        if !source.exists() {
            report
                .kept
                .push((source.clone(), "no longer exists".into()));
            continue;
        }
        let target = unique_target(dest, name);
        let mut links = 0;
        match copy_tree(source, &target, cancel, &mut state, progress, &mut links) {
            Ok(()) if links > 0 => {
                report.kept.push((
                    source.clone(),
                    "copied, but the original was kept because it contains shortcuts or links that were not copied".into(),
                ));
            }
            Ok(()) => match remove_original(source) {
                Ok(()) => report.moved.push((source.clone(), target)),
                Err(e) => report.kept.push((
                    source.clone(),
                    format!("copied, but the original could not be deleted: {e}"),
                )),
            },
            Err(failure) => {
                let _ = remove_tree(&target);
                match failure {
                    Failure::Cancelled => {
                        report.cancelled = true;
                        report.kept.push((source.clone(), "stopped".into()));
                    }
                    Failure::Io(why) => report.kept.push((source.clone(), why)),
                }
            }
        }
    }
    report
}

/// Total bytes of regular files under `path`, not following links.
fn size_of(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        meta.len()
    } else if meta.is_dir() {
        fs::read_dir(path)
            .map(|items| items.flatten().map(|i| size_of(&i.path())).sum())
            .unwrap_or(0)
    } else {
        0
    }
}

/// `dest\name`, or `dest\name (2).ext` and so on if that is taken.
fn unique_target(dest: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let first = dest.join(name);
    if !first.exists() {
        return first;
    }
    let path = Path::new(name);
    let stem = path.file_stem().unwrap_or(name).to_string_lossy();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (2..)
        .map(|n| dest.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .expect("some name is free")
}

fn copy_tree(
    source: &Path,
    target: &Path,
    cancel: &AtomicBool,
    state: &mut Progress,
    progress: &mut dyn FnMut(&Progress),
    links: &mut usize,
) -> Result<(), Failure> {
    let meta = fs::symlink_metadata(source)?;
    if meta.is_dir() {
        fs::create_dir(target)?;
        let mut children: Vec<_> = fs::read_dir(source)?.collect::<io::Result<_>>()?;
        children.sort_by_key(|c| c.file_name());
        for child in children {
            copy_tree(
                &child.path(),
                &target.join(child.file_name()),
                cancel,
                state,
                progress,
                links,
            )?;
        }
        Ok(())
    } else if meta.is_file() {
        copy_and_verify(source, target, cancel, state, progress)
    } else {
        // Symlinks, junctions and other special entries are not copied.
        *links += 1;
        Ok(())
    }
}

fn copy_and_verify(
    source: &Path,
    target: &Path,
    cancel: &AtomicBool,
    state: &mut Progress,
    progress: &mut dyn FnMut(&Progress),
) -> Result<(), Failure> {
    state.current = source.display().to_string();
    progress(state);
    let mut input = File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let mut buf = vec![0u8; BUFFER];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Failure::Cancelled);
        }
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        state.done += n as u64;
        progress(state);
    }
    output.sync_all()?;
    drop(output);
    if let Ok(modified) = fs::metadata(source).and_then(|m| m.modified()) {
        let _ = File::options()
            .write(true)
            .open(target)
            .and_then(|f| f.set_modified(modified));
    }
    if !same_contents(source, target)? {
        return Err(Failure::Io(format!(
            "the copy of {} did not match the original",
            source.display()
        )));
    }
    Ok(())
}

fn same_contents(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut a, mut b) = (File::open(a)?, File::open(b)?);
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let (mut x, mut y) = (vec![0u8; BUFFER], vec![0u8; BUFFER]);
    loop {
        let n = read_full(&mut a, &mut x)?;
        let m = read_full(&mut b, &mut y)?;
        if n != m || x[..n] != y[..m] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

fn read_full(input: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Deletes an original, clearing read-only flags that would block it.
fn remove_original(path: &Path) -> io::Result<()> {
    clear_read_only(path);
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn clear_read_only(path: &Path) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    let mut perms = meta.permissions();
    if perms.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
    if meta.is_dir() {
        if let Ok(items) = fs::read_dir(path) {
            for item in items.flatten() {
                clear_read_only(&item.path());
            }
        }
    }
}

fn remove_tree(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
            for item in fs::read_dir(dir).unwrap().flatten() {
                let p = item.path();
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                if p.is_dir() {
                    out.push((rel + "/", Vec::new()));
                    walk(&p, root, out);
                } else {
                    out.push((rel, fs::read(&p).unwrap()));
                }
            }
        }
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn moves_files_and_folders_and_reports_progress() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dest = tmp.path().join("dest");
        fs::create_dir_all(src.join("Photos").join("2026")).unwrap();
        fs::write(
            src.join("Photos").join("2026").join("a.jpg"),
            vec![1u8; 3_000_000],
        )
        .unwrap();
        fs::write(src.join("Photos").join("b.txt"), b"bee").unwrap();
        fs::write(src.join("notes.txt"), b"notes").unwrap();
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("notes.txt"), b"already here").unwrap();
        let mut readonly = fs::metadata(src.join("notes.txt")).unwrap().permissions();
        readonly.set_readonly(true);
        fs::set_permissions(src.join("notes.txt"), readonly).unwrap();
        let expected_photos = tree(&src.join("Photos"));

        let mut last = Progress::default();
        let report = move_into(
            &[src.join("Photos"), src.join("notes.txt")],
            &dest,
            &AtomicBool::new(false),
            &mut |p| last = p.clone(),
        );
        assert_eq!(report.kept, vec![]);
        assert_eq!(report.moved.len(), 2);
        assert_eq!(last.done, last.total);
        assert_eq!(last.total, 3_000_000 + 3 + 5);
        assert!(!src.join("Photos").exists() && !src.join("notes.txt").exists());
        assert_eq!(tree(&dest.join("Photos")), expected_photos);
        // The name was taken, so the moved file got a new one.
        assert_eq!(fs::read(dest.join("notes.txt")).unwrap(), b"already here");
        assert_eq!(fs::read(dest.join("notes (2).txt")).unwrap(), b"notes");
    }

    #[test]
    fn stopping_keeps_originals_and_removes_partial_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("big");
        let dest = tmp.path().join("dest");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir(&dest).unwrap();
        for i in 0..3 {
            fs::write(src.join(format!("{i}.bin")), vec![9u8; 3 * BUFFER]).unwrap();
        }
        let cancel = AtomicBool::new(false);
        let report = move_into(std::slice::from_ref(&src), &dest, &cancel, &mut |p| {
            if p.done > BUFFER as u64 {
                cancel.store(true, Ordering::Relaxed);
            }
        });
        assert!(report.cancelled);
        assert!(report.moved.is_empty());
        assert_eq!(fs::read_dir(&src).unwrap().count(), 3, "originals kept");
        assert!(!dest.join("big").exists(), "partial copy removed");
    }

    #[test]
    fn missing_sources_are_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let report = move_into(
            &[tmp.path().join("nope")],
            tmp.path(),
            &AtomicBool::new(false),
            &mut |_| {},
        );
        assert_eq!(report.kept.len(), 1);
        assert!(report.moved.is_empty());
    }
}
