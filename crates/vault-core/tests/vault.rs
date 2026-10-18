use std::fs;
use std::path::{Path, PathBuf};

use vault_core::{EntryKind, Error, KdfParams, RecoveryKey, Vault};

/// Cheap parameters so tests run fast. Real vaults use `KdfParams::DEFAULT`.
const TEST_KDF: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};
const SECRET: &[u8] = b"the launch code is 0000; the secret recipe is cinnamon";

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for item in fs::read_dir(root).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        }
        out.push(path);
    }
    out
}

fn sample_tree(root: &Path) {
    fs::create_dir_all(root.join("secret-plans/nested/deeper")).unwrap();
    fs::create_dir_all(root.join("secret-plans/empty")).unwrap();
    fs::write(root.join("secret-plans/notes.txt"), SECRET).unwrap();
    fs::write(
        root.join("secret-plans/nested/Résumé 2026.docx"),
        vec![0xAB; 200_000],
    )
    .unwrap();
    fs::write(root.join("secret-plans/nested/deeper/empty.bin"), b"").unwrap();
}

#[test]
fn import_export_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir, out) = (
        tmp.path().join("src"),
        tmp.path().join("vault"),
        tmp.path().join("out"),
    );
    sample_tree(&src);

    let (vault, _) = Vault::create(&vault_dir, b"correct horse", TEST_KDF).unwrap();
    let stats = vault.import(&src.join("secret-plans"), "/").unwrap();
    assert_eq!((stats.files, stats.dirs), (3, 4));
    drop(vault);

    let vault = Vault::unlock(&vault_dir, b"correct horse").unwrap();
    let listing = vault.list("/secret-plans").unwrap();
    let names: Vec<_> = listing
        .iter()
        .map(|e| (e.name.as_str(), e.kind, e.size))
        .collect();
    assert_eq!(
        names,
        [
            ("empty", EntryKind::Dir, None),
            ("nested", EntryKind::Dir, None),
            ("notes.txt", EntryKind::File, Some(SECRET.len() as u64)),
        ]
    );

    vault.export("/", &out).unwrap();
    assert_eq!(
        fs::read(out.join("secret-plans/notes.txt")).unwrap(),
        SECRET
    );
    assert_eq!(
        fs::read(out.join("secret-plans/nested/Résumé 2026.docx")).unwrap(),
        vec![0xAB; 200_000]
    );
    assert!(fs::read(out.join("secret-plans/nested/deeper/empty.bin"))
        .unwrap()
        .is_empty());
    assert!(out.join("secret-plans/empty").is_dir());

    let single = tmp.path().join("single");
    vault.export("secret-plans\\notes.txt", &single).unwrap();
    assert_eq!(fs::read(single.join("notes.txt")).unwrap(), SECRET);
}

#[test]
fn nothing_readable_at_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir) = (tmp.path().join("src"), tmp.path().join("vault"));
    sample_tree(&src);
    let (vault, _) = Vault::create(&vault_dir, b"correct horse", TEST_KDF).unwrap();
    vault.import(&src.join("secret-plans"), "/").unwrap();

    for path in files_under(&vault_dir) {
        let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
        for word in ["secret", "notes", "nested", "sum", "empty", "deeper"] {
            assert!(!name.contains(word), "{} leaks a name", path.display());
        }
        if path.is_file() {
            let bytes = fs::read(&path).unwrap();
            assert!(
                !bytes.windows(SECRET.len()).any(|w| w == SECRET),
                "{} leaks content",
                path.display()
            );
        }
    }
}

#[test]
fn passwords_and_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let (_, recovery) = Vault::create(&vault_dir, b"first password", TEST_KDF).unwrap();

    assert!(matches!(
        Vault::unlock(&vault_dir, b"wrong"),
        Err(Error::WrongPassword)
    ));

    let mut vault = Vault::unlock(&vault_dir, b"first password").unwrap();
    vault.change_password(b"second password").unwrap();
    assert!(matches!(
        Vault::unlock(&vault_dir, b"first password"),
        Err(Error::WrongPassword)
    ));
    Vault::unlock(&vault_dir, b"second password").unwrap();

    // Forgot the password: the recovery key still opens the vault, and can set a new one.
    let shown = recovery.to_display_string();
    let mut vault =
        Vault::unlock_with_recovery_key(&vault_dir, &RecoveryKey::parse(&shown).unwrap()).unwrap();
    vault.change_password(b"third password").unwrap();
    Vault::unlock(&vault_dir, b"third password").unwrap();

    let (_, other) = Vault::create(&tmp.path().join("other"), b"x", TEST_KDF).unwrap();
    assert!(matches!(
        Vault::unlock_with_recovery_key(&vault_dir, &other),
        Err(Error::WrongRecoveryKey)
    ));
}

#[test]
fn config_falls_back_to_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    fs::write(vault_dir.join("vault.json"), b"{ truncated").unwrap();
    Vault::unlock(&vault_dir, b"pw").unwrap();
}

#[test]
fn tampered_file_is_rejected_on_export() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir) = (tmp.path().join("src"), tmp.path().join("vault"));
    sample_tree(&src);
    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    vault
        .import(&src.join("secret-plans/notes.txt"), "/")
        .unwrap();

    let stored = files_under(&vault_dir)
        .into_iter()
        .find(|p| p.is_file() && p.extension().is_some_and(|e| e == "flk"))
        .unwrap();
    let mut bytes = fs::read(&stored).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&stored, bytes).unwrap();

    let out = tmp.path().join("out");
    assert!(matches!(vault.export("/", &out), Err(Error::Integrity(_))));
    assert!(
        !out.join("notes.txt").exists(),
        "no partial plaintext left behind"
    );
}

#[test]
fn refuses_to_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir) = (tmp.path().join("src"), tmp.path().join("vault"));
    sample_tree(&src);
    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    vault.import(&src.join("secret-plans"), "/").unwrap();

    assert!(matches!(
        vault.import(&src.join("secret-plans"), "/"),
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(
        Vault::create(&vault_dir, b"pw", TEST_KDF),
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(
        vault.export("/", &src),
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(vault.list("/missing"), Err(Error::NotFound(_))));
    assert!(matches!(
        vault.list("/secret-plans/notes.txt"),
        Err(Error::NotADirectory(_))
    ));
    assert!(matches!(vault.list("/../x"), Err(Error::InvalidName(_))));
}

#[test]
fn long_names_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir, out) = (
        tmp.path().join("src"),
        tmp.path().join("vault"),
        tmp.path().join("out"),
    );
    let long_dir = "Ð".repeat(120);
    let long_file = format!("{}.txt", "f".repeat(240));
    fs::create_dir_all(src.join("top").join(&long_dir)).unwrap();
    fs::write(src.join("top").join(&long_dir).join(&long_file), SECRET).unwrap();

    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    vault.import(&src.join("top"), "/").unwrap();

    for path in files_under(&vault_dir) {
        let len = path.file_name().unwrap().len();
        assert!(len <= 220, "stored name of {len} chars: {}", path.display());
    }
    let inner = vault.list(&format!("/top/{long_dir}")).unwrap();
    assert_eq!(inner[0].name, long_file);
    assert_eq!(inner[0].size, Some(SECRET.len() as u64));
    assert!(matches!(
        vault.import(&src.join("top").join(&long_dir), "/top"),
        Err(Error::AlreadyExists(_))
    ));

    vault.export("/", &out).unwrap();
    assert_eq!(
        fs::read(out.join("top").join(&long_dir).join(&long_file)).unwrap(),
        SECRET
    );
}

#[test]
fn incomplete_entries_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir) = (tmp.path().join("src"), tmp.path().join("vault"));
    sample_tree(&src);
    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    vault
        .import(&src.join("secret-plans/notes.txt"), "/")
        .unwrap();

    // Leftovers of interrupted writes: a temp file, a folder entry without its
    // dir.id, and a shortened entry without its name file.
    let storage = files_under(&vault_dir.join("d"))
        .into_iter()
        .find(|p| p.extension().is_some_and(|e| e == "flk"))
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    fs::write(storage.join(".0123456789abcdef.tmp"), b"partial").unwrap();
    fs::create_dir(storage.join("AAAA.flk")).unwrap();
    fs::create_dir(storage.join("BBBB.flks")).unwrap();

    let names: Vec<_> = vault
        .list("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["notes.txt"]);
}

#[test]
fn empty_folder_survives_losing_its_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, vault_dir) = (tmp.path().join("src"), tmp.path().join("vault"));
    fs::create_dir_all(src.join("box")).unwrap();
    let (vault, _) = Vault::create(&vault_dir, b"pw", TEST_KDF).unwrap();
    vault.import(&src.join("box"), "/").unwrap();

    // Simulate git or a sync tool dropping every empty folder.
    for path in files_under(&vault_dir).into_iter().rev() {
        if path.is_dir() && fs::read_dir(&path).unwrap().next().is_none() {
            fs::remove_dir(&path).unwrap();
        }
    }
    assert!(vault.list("/box").unwrap().is_empty());
    fs::write(src.join("note.txt"), SECRET).unwrap();
    vault.import(&src.join("note.txt"), "/box").unwrap();
    assert_eq!(vault.list("/box").unwrap()[0].name, "note.txt");
}

#[test]
fn not_a_vault() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        Vault::unlock(tmp.path(), b"pw"),
        Err(Error::NotAVault(_))
    ));
}
