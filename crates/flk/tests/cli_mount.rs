//! End to end: `flk create`, `flk mount`, write through the drive, Ctrl+Break
//! to lock, then check the vault. Skipped if WinFsp is not installed.

use std::io::{BufRead, BufReader, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use std::{fs, thread};

use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};

const FLK: &str = env!("CARGO_BIN_EXE_flk");
const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
const PASSWORD: &str = "correct horse battery";

fn flk(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(FLK)
        .arg("--password-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn mount_write_and_lock_with_ctrl_break() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    let vault = vault.to_str().unwrap();
    let created = flk(&["create", vault], &format!("{PASSWORD}\n"));
    assert!(created.status.success(), "{created:?}");

    let Some(drive) = flk_mount_free_letter() else {
        eprintln!("skipping: no free drive letter");
        return;
    };
    let mut child = Command::new(FLK)
        // Typed sloppily on purpose ("t" for "T:"); flk normalizes it.
        .args([
            "--password-stdin",
            "mount",
            vault,
            "--drive",
            &drive.trim_end_matches(':').to_lowercase(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();

    // Wait for the "Unlocked at" line (or the process to fail).
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let _ = tx.send(line.unwrap());
        }
    });
    let first = rx.recv_timeout(Duration::from_secs(30));
    let Ok(first) = first else {
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("WinFsp is not installed") {
            eprintln!("skipping: WinFsp is not installed");
            return;
        }
        panic!("flk mount did not start: {err}");
    };
    assert!(
        first.starts_with(&format!("Unlocked at {drive}")),
        "{first}"
    );

    let root = format!("{drive}\\");
    fs::write(format!("{root}note.txt"), b"written through the drive").unwrap();

    // SAFETY: plain Win32 call; the child is in its own process group.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) };
    assert_ne!(sent, 0, "GenerateConsoleCtrlEvent failed");
    let locked = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(locked, "Locked.");
    assert!(child.wait().unwrap().success());
    assert!(!std::path::Path::new(&root).exists(), "drive removed");

    let out = tmp.path().join("out");
    let exported = flk(
        &["export", vault, out.to_str().unwrap()],
        &format!("{PASSWORD}\n"),
    );
    assert!(exported.status.success(), "{exported:?}");
    assert_eq!(
        fs::read(out.join("note.txt")).unwrap(),
        b"written through the drive"
    );
}

/// The highest free drive letter, like `flk mount` would pick.
fn flk_mount_free_letter() -> Option<String> {
    (b'D'..=b'Z')
        .rev()
        .map(|l| format!("{}:", l as char))
        .find(|d| !std::path::Path::new(&format!("{d}\\")).exists())
}
