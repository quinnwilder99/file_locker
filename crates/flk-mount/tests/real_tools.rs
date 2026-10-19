//! Drives a mounted vault with real Windows tools: robocopy, git, tar and
//! 7-Zip. Each tool is skipped (with a message) if it is not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use vault_core::{KdfParams, Vault};

const TEST_KDF: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// Relative path → contents for every file under `root`.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for item in fs::read_dir(dir).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn tool(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| {
        p.is_file()
            || Command::new(p)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
    })
}

fn run(program: &Path, args: &[&str], dir: &Path) -> String {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", program.display()));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{} {args:?} failed:\n{text}",
        program.display()
    );
    text
}

#[test]
fn real_tools_work_on_a_mounted_vault() {
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
    let drive = PathBuf::from(format!("{letter}\\"));
    // This repository's own source tree: a realistic mix of files and folders.
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let expected = tree(source);

    // robocopy: multithreaded copy in, byte-for-byte check.
    let copy = drive.join("src");
    let status = Command::new("robocopy")
        .arg(source)
        .arg(&copy)
        .args(["/E", "/MT:8", "/NFL", "/NDL", "/NJH", "/NJS", "/NP"])
        .status()
        .expect("robocopy");
    assert!(
        status.code().is_some_and(|c| c < 8),
        "robocopy failed: {status}"
    );
    assert_eq!(tree(&copy), expected, "robocopy copy differs");

    // git: a full workflow, then gc (heavy on renames and deletes) and fsck.
    if let Some(git) = tool(&["git"]) {
        let repo = drive.join("repo");
        fs::create_dir(&repo).unwrap();
        let id = [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
        ];
        run(&git, &["init", "-q", "-b", "main"], &repo);
        // Byte-exact checkouts regardless of the machine's global git config.
        run(&git, &["config", "core.autocrlf", "false"], &repo);
        for (rel, bytes) in &expected {
            let path = repo.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        run(&git, &["add", "-A"], &repo);
        run(
            &git,
            &[id[0], id[1], id[2], id[3], "commit", "-q", "-m", "first"],
            &repo,
        );
        assert_eq!(run(&git, &["status", "--porcelain"], &repo), "");
        fs::write(repo.join("NEW.md"), b"second commit\n").unwrap();
        fs::remove_file(repo.join(&expected[0].0)).unwrap();
        run(&git, &["add", "-A"], &repo);
        run(
            &git,
            &[id[0], id[1], id[2], id[3], "commit", "-q", "-m", "second"],
            &repo,
        );
        run(&git, &["gc", "-q", "--aggressive", "--prune=now"], &repo);
        run(&git, &["fsck", "--full", "--strict"], &repo);
        assert_eq!(
            run(&git, &["rev-list", "--count", "HEAD"], &repo).trim(),
            "2"
        );
        run(&git, &["checkout", "-q", "HEAD~1"], &repo);
        assert_eq!(fs::read(repo.join(&expected[0].0)).unwrap(), expected[0].1);
    } else {
        eprintln!("skipping git: not installed");
    }

    // tar (bundled with Windows): archive and extract on the drive.
    if let Some(tar) = tool(&[r"C:\Windows\System32\tar.exe"]) {
        run(&tar, &["-cf", "src.tar", "src"], &drive);
        fs::create_dir(drive.join("untar")).unwrap();
        run(&tar, &["-xf", "src.tar", "-C", "untar"], &drive);
        assert_eq!(
            tree(&drive.join("untar").join("src")),
            expected,
            "tar round trip"
        );
    } else {
        eprintln!("skipping tar: not found");
    }

    // 7-Zip: compressed archive with a test pass, then extract.
    if let Some(seven) = tool(&[r"C:\Program Files\7-Zip\7z.exe", "7z"]) {
        run(&seven, &["a", "-bd", "-mx=5", "src.7z", "src"], &drive);
        run(&seven, &["t", "-bd", "src.7z"], &drive);
        run(&seven, &["x", "-bd", "-ounzip", "src.7z"], &drive);
        assert_eq!(
            tree(&drive.join("unzip").join("src")),
            expected,
            "7-Zip round trip"
        );
    } else {
        eprintln!("skipping 7-Zip: not installed");
    }

    // Everything survives unmounting.
    mounted.unmount();
    let vault = Vault::unlock(&vault_dir, b"pw").unwrap();
    let out = tmp.path().join("out");
    vault.export("/src", &out).unwrap();
    assert_eq!(tree(&out), expected, "contents after unmount");
}
