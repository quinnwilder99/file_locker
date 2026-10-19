//! Mounts a real vault through WinFsp and drives it with ordinary file APIs.
//! Skipped (with a message) when WinFsp is not installed.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use vault_core::{KdfParams, Vault};

const TEST_KDF: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};
const MARKER: &[u8] = b"plaintext marker 7f3a9c that must never reach the disk";

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for item in fs::read_dir(root).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn mounted_drive_behaves_like_a_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    let letter = flk_mount::free_drive_letter().expect("a free drive letter");
    let mounted = match flk_mount::mount(vault, &letter) {
        Ok(m) => m,
        Err(flk_mount::MountError::WinFspMissing) => {
            eprintln!("skipping: WinFsp is not installed");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let root = PathBuf::from(format!("{letter}\\"));
    let big = pseudo_random(3 * 1024 * 1024 + 4321, 42);

    // Create, write, read.
    fs::create_dir_all(root.join("Docs").join("Sub")).unwrap();
    fs::write(root.join("Docs").join("hello.txt"), MARKER).unwrap();
    assert_eq!(
        fs::read(root.join("Docs").join("hello.txt")).unwrap(),
        MARKER
    );
    fs::write(root.join("Docs").join("big.bin"), &big).unwrap();
    assert_eq!(fs::read(root.join("Docs").join("big.bin")).unwrap(), big);
    assert_eq!(
        fs::metadata(root.join("Docs").join("big.bin"))
            .unwrap()
            .len(),
        big.len() as u64
    );

    // Case-insensitive, case-preserving.
    assert_eq!(
        fs::read(root.join("DOCS").join("HELLO.TXT")).unwrap(),
        MARKER
    );
    assert_eq!(names(&root), ["Docs"]);
    assert!(matches!(
        fs::create_dir(root.join("docs")).map_err(|e| e.kind()),
        Err(ErrorKind::AlreadyExists)
    ));

    // Append, overwrite in the middle, truncate, extend.
    let path = root.join("Docs").join("edit.txt");
    fs::write(&path, b"0123456789").unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"abc")
        .unwrap();
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(2)).unwrap();
        f.write_all(b"XY").unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut back = String::new();
        f.read_to_string(&mut back).unwrap();
        assert_eq!(back, "01XY456789abc");
        f.set_len(4).unwrap();
        f.set_len(6).unwrap();
    }
    assert_eq!(fs::read(&path).unwrap(), b"01XY\0\0");

    // Several handles to one file agree on its contents and length.
    {
        let mut a = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut b = OpenOptions::new().read(true).open(&path).unwrap();
        a.seek(SeekFrom::End(0)).unwrap();
        a.write_all(b"tail").unwrap();
        let mut seen = Vec::new();
        b.read_to_end(&mut seen).unwrap();
        assert_eq!(seen, b"01XY\0\0tail");
    }

    // Renames: file, folder (contents follow), case-only, and replace.
    fs::rename(&path, root.join("Docs").join("edited.txt")).unwrap();
    fs::rename(root.join("Docs").join("Sub"), root.join("Moved")).unwrap();
    fs::write(root.join("Moved").join("inner.txt"), b"inner").unwrap();
    fs::rename(root.join("Moved"), root.join("Docs").join("Moved")).unwrap();
    assert_eq!(
        fs::read(root.join("Docs").join("Moved").join("inner.txt")).unwrap(),
        b"inner"
    );
    fs::rename(
        root.join("Docs").join("edited.txt"),
        root.join("Docs").join("EDITED.txt"),
    )
    .unwrap();
    fs::write(root.join("Docs").join("old.txt"), b"old").unwrap();
    fs::rename(
        root.join("Docs").join("EDITED.txt"),
        root.join("Docs").join("old.txt"),
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("Docs").join("old.txt")).unwrap(),
        b"01XY\0\0tail"
    );
    assert_eq!(
        names(&root.join("Docs")),
        ["Moved", "big.bin", "hello.txt", "old.txt"]
    );

    // Timestamps can be set and read back.
    let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    OpenOptions::new()
        .write(true)
        .open(root.join("Docs").join("hello.txt"))
        .unwrap()
        .set_modified(when)
        .unwrap();
    assert_eq!(
        fs::metadata(root.join("Docs").join("hello.txt"))
            .unwrap()
            .modified()
            .unwrap(),
        when
    );

    // Deletes; a non-empty folder cannot be removed.
    assert!(fs::remove_dir(root.join("Docs").join("Moved")).is_err());
    fs::remove_file(root.join("Docs").join("Moved").join("inner.txt")).unwrap();
    fs::remove_dir(root.join("Docs").join("Moved")).unwrap();
    fs::remove_file(root.join("Docs").join("old.txt")).unwrap();
    // The name is free again straight away.
    fs::write(root.join("Docs").join("old.txt"), b"again").unwrap();
    assert_eq!(
        names(&root.join("Docs")),
        ["big.bin", "hello.txt", "old.txt"]
    );

    // Nothing readable reached the vault folder.
    for file in files_under(&vault_dir) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !bytes.windows(MARKER.len()).any(|w| w == MARKER),
            "{} holds plaintext",
            file.display()
        );
        let name = file.to_string_lossy().to_lowercase();
        assert!(!name.contains("hello") && !name.contains("docs"), "{name}");
    }

    // Unmount, then check the vault directly.
    mounted.unmount();
    assert!(!root.exists(), "drive is gone after unmounting");
    let vault = Vault::unlock(&vault_dir, b"pw").unwrap();
    let out = tmp.path().join("out");
    vault.export("/", &out).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("big.bin")).unwrap(), big);
    assert_eq!(
        fs::read(out.join("Docs").join("hello.txt")).unwrap(),
        MARKER
    );
    assert_eq!(
        fs::read(out.join("Docs").join("old.txt")).unwrap(),
        b"again"
    );
}
