//! How real applications use a disk, replayed against a mounted vault:
//! Office-style safe saves, delete-on-close temp files, renames under open
//! handles, memory-mapped files, running programs, Explorer's copy engine,
//! plus the mount's own promises (damage tolerance, owner, attributes,
//! volume info, large listings). Skipped when WinFsp is not installed.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use vault_core::{KdfParams, Vault};

const TEST_KDF: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;

fn files_under(root: &Path) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for item in fs::read_dir(root).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.insert(path);
        }
    }
    out
}

fn names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}

/// Runs a PowerShell script and returns its trimmed output.
fn powershell(script: &str) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("powershell");
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        out.status.success(),
        "powershell failed:\n{script}\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

/// Creates `path` through the drive and returns the encrypted file that
/// appeared for it in the vault folder.
fn create_and_find_ciphertext(vault_dir: &Path, path: &Path, bytes: &[u8]) -> PathBuf {
    let before = files_under(vault_dir);
    fs::write(path, bytes).unwrap();
    let mut new: Vec<_> = files_under(vault_dir)
        .difference(&before)
        .cloned()
        .collect();
    assert_eq!(new.len(), 1, "expected one new encrypted file: {new:?}");
    new.pop().unwrap()
}

#[test]
fn applications_work_on_a_mounted_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("MyVault");
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
    let drive = PathBuf::from(format!("{letter}\\"));

    // --- Volume: label is the vault folder's name; sizes come from the host disk.
    let volume = powershell(&format!(
        "$d = [IO.DriveInfo]::new('{letter}'); \"$($d.VolumeLabel)|$($d.TotalSize -gt 0)|$($d.AvailableFreeSpace -gt 0)\""
    ));
    assert_eq!(volume, "MyVault|True|True", "volume info");

    // --- Owner is the current user (git depends on it); not content-indexed.
    fs::write(drive.join("owned.txt"), b"x").unwrap();
    let owner = powershell(&format!(
        "(Get-Acl -LiteralPath '{letter}\\owned.txt').Owner -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name"
    ));
    assert_eq!(owner, "True", "owner is the current user");
    let attrs = fs::metadata(drive.join("owned.txt"))
        .unwrap()
        .file_attributes();
    assert_ne!(
        attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        0,
        "not content indexed"
    );

    // --- Large folder: listings arrive in pages; every entry must come back.
    let many = drive.join("many");
    fs::create_dir(&many).unwrap();
    for i in 0..1200 {
        fs::write(many.join(format!("entry-{i:04}.txt")), b"").unwrap();
    }
    assert_eq!(names(&many).len(), 1200, "large listing complete");

    // --- Delete-on-close temp files vanish when closed.
    let temp = drive.join("scratch.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&temp)
            .unwrap();
        f.write_all(b"temporary").unwrap();
        assert!(temp.exists());
    }
    assert!(!temp.exists(), "delete-on-close");

    // --- Rename a file, and its folder, under an open handle; keep writing.
    fs::create_dir(drive.join("work")).unwrap();
    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(drive.join("work").join("draft.txt"))
            .unwrap();
        f.write_all(b"one ").unwrap();
        fs::rename(
            drive.join("work").join("draft.txt"),
            drive.join("work").join("final.txt"),
        )
        .unwrap();
        f.write_all(b"two ").unwrap();
        // Like NTFS: a folder holding an open file cannot be renamed.
        let err = fs::rename(drive.join("work"), drive.join("done")).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::PermissionDenied,
            "rename busy folder"
        );
        f.write_all(b"three").unwrap();
    }
    fs::rename(drive.join("work"), drive.join("done")).unwrap();
    assert_eq!(
        fs::read(drive.join("done").join("final.txt")).unwrap(),
        b"one two three"
    );

    // --- Rename-and-replace onto a file someone has open fails, like NTFS.
    fs::write(drive.join("target.txt"), b"target").unwrap();
    fs::write(drive.join("incoming.txt"), b"incoming").unwrap();
    {
        let _open = fs::File::open(drive.join("target.txt")).unwrap();
        let err = fs::rename(drive.join("incoming.txt"), drive.join("target.txt")).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::PermissionDenied,
            "replace open target"
        );
    }
    fs::rename(drive.join("incoming.txt"), drive.join("target.txt")).unwrap();
    assert_eq!(fs::read(drive.join("target.txt")).unwrap(), b"incoming");

    // --- Office-style safe save: new copy to a temp name, swap, delete backup.
    let doc = drive.join("Report.docx");
    fs::write(&doc, b"version 1").unwrap();
    fs::write(drive.join("~WRL1234.tmp"), b"version 2").unwrap();
    fs::rename(&doc, drive.join("~WRL0001.tmp")).unwrap();
    fs::rename(drive.join("~WRL1234.tmp"), &doc).unwrap();
    fs::remove_file(drive.join("~WRL0001.tmp")).unwrap();
    assert_eq!(fs::read(&doc).unwrap(), b"version 2", "safe save");
    assert!(!names(&drive).iter().any(|n| n.starts_with("~WRL")));

    // --- Memory-mapped writes (paging I/O) land in the file.
    let mapped = drive.join("mapped.bin");
    fs::write(&mapped, vec![0u8; 200_000]).unwrap();
    powershell(&format!(
        "$m = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile('{}', 'Open'); \
         $a = $m.CreateViewAccessor(); $a.Write(5, [byte]42); $a.Write(150000, [byte]99); \
         $a.Flush(); $a.Dispose(); $m.Dispose()",
        mapped.display()
    ));
    let bytes = fs::read(&mapped).unwrap();
    assert_eq!(
        (bytes.len(), bytes[5], bytes[150_000]),
        (200_000, 42, 99),
        "memory map"
    );

    // --- Programs run from the drive (the loader maps the image).
    fs::create_dir(drive.join("bin")).unwrap();
    let exe = drive.join("bin").join("whoami.exe");
    fs::copy(r"C:\Windows\System32\whoami.exe", &exe).unwrap();
    let out = Command::new(&exe).output().unwrap();
    assert!(
        out.status.success() && !out.stdout.is_empty(),
        "run exe from drive"
    );

    // --- Explorer's copy engine (Shell.Application.CopyHere).
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let expected: BTreeSet<String> = names(&source);
    powershell(&format!(
        "$shell = New-Object -ComObject Shell.Application; \
         $shell.NameSpace('{letter}\\').CopyHere('{}', 4 + 16 + 512 + 1024); \
         $deadline = (Get-Date).AddSeconds(60); \
         while ((Get-ChildItem '{letter}\\src' -ErrorAction SilentlyContinue).Count -lt {} -and (Get-Date) -lt $deadline) {{ Start-Sleep -Milliseconds 200 }}; \
         Start-Sleep -Milliseconds 500",
        source.display(),
        expected.len()
    ));
    assert_eq!(names(&drive.join("src")), expected, "Explorer copy");
    for name in &expected {
        assert_eq!(
            fs::read(drive.join("src").join(name)).unwrap(),
            fs::read(source.join(name)).unwrap(),
            "Explorer copy of {name}"
        );
    }

    // --- A damaged file does not hide its folder; opening it reports damage.
    fs::create_dir(drive.join("damage")).unwrap();
    fs::write(drive.join("damage").join("fine.txt"), b"fine").unwrap();
    let cut = create_and_find_ciphertext(
        &vault_dir,
        &drive.join("damage").join("cut.bin"),
        &[7; 100_000],
    );
    let wrecked = create_and_find_ciphertext(
        &vault_dir,
        &drive.join("damage").join("wrecked.bin"),
        &[7; 1000],
    );
    // Cut 10 bytes off the end: a valid-looking size, but the last chunk fails.
    let len = fs::metadata(&cut).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&cut)
        .unwrap()
        .set_len(len - 10)
        .unwrap();
    // Cut into the first chunk's nonce: no valid file has this size.
    OpenOptions::new()
        .write(true)
        .open(&wrecked)
        .unwrap()
        .set_len(70)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100)); // past WinFsp's metadata cache
    assert_eq!(
        names(&drive.join("damage")),
        ["cut.bin", "fine.txt", "wrecked.bin"]
            .map(String::from)
            .into(),
        "damaged files still listed"
    );
    assert_eq!(
        fs::read(drive.join("damage").join("fine.txt")).unwrap(),
        b"fine"
    );
    assert!(
        fs::read(drive.join("damage").join("cut.bin")).is_err(),
        "cut file reports damage"
    );
    assert!(
        fs::read(drive.join("damage").join("wrecked.bin")).is_err(),
        "wrecked file reports damage"
    );

    mounted.unmount();
    assert!(!drive.exists());
}
