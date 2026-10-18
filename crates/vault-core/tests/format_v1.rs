//! Freezes vault format v1 end to end. `tests/fixtures/v1/vault` was created
//! once by `generate_v1_fixture` and is committed; every later version must
//! still open it and get the same files back. Regenerate it only when
//! deliberately starting a new format version:
//!
//! ```text
//! cargo test -p vault-core --test format_v1 -- --ignored generate_v1_fixture
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vault_core::{KdfParams, RecoveryKey, Vault};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1");
const PASSWORD: &[u8] = b"fixture password v1";

/// Every file in the fixture, by `/`-separated path, with its contents.
fn expected_files() -> BTreeMap<String, Vec<u8>> {
    let pattern = |len: usize| (0..len).map(|i| (i * 7 % 256) as u8).collect::<Vec<u8>>();
    let long_dir = "Ð".repeat(120);
    let long_file = format!("{}.txt", "f".repeat(240));
    BTreeMap::from([
        ("empty.txt".to_string(), vec![]),
        ("hello.txt".to_string(), b"Hello, vault!\n".to_vec()),
        ("Ünïcødé folder/résumé.docx".to_string(), pattern(1000)),
        (
            "Ünïcødé folder/chunks/exactly-one-chunk.bin".to_string(),
            pattern(65536),
        ),
        (
            "Ünïcødé folder/chunks/two-and-a-bit.bin".to_string(),
            pattern(2 * 65536 + 123),
        ),
        (format!("{long_dir}/{long_file}"), b"long names\n".to_vec()),
    ])
}

const EXPECTED_EMPTY_DIRS: &[&str] = &["Ünïcødé folder/empty folder"];

fn read_tree(
    root: &Path,
    prefix: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    empty_dirs: &mut Vec<String>,
) {
    let mut any = false;
    for item in fs::read_dir(root).unwrap() {
        any = true;
        let item = item.unwrap();
        let rel = format!("{prefix}{}", item.file_name().to_str().unwrap());
        if item.path().is_dir() {
            read_tree(&item.path(), &format!("{rel}/"), files, empty_dirs);
        } else {
            files.insert(rel, fs::read(item.path()).unwrap());
        }
    }
    if !any && !prefix.is_empty() {
        empty_dirs.push(prefix.trim_end_matches('/').to_string());
    }
}

fn assert_matches_fixture(vault: &Vault) {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    vault.export("/", &out).unwrap();
    let (mut files, mut empty_dirs) = (BTreeMap::new(), Vec::new());
    read_tree(&out, "", &mut files, &mut empty_dirs);
    assert_eq!(files, expected_files());
    assert_eq!(empty_dirs, EXPECTED_EMPTY_DIRS);
}

#[test]
fn opens_v1_fixture_with_password() {
    assert_matches_fixture(&Vault::unlock(&Path::new(FIXTURE).join("vault"), PASSWORD).unwrap());
}

#[test]
fn opens_v1_fixture_with_recovery_key() {
    let text = fs::read_to_string(Path::new(FIXTURE).join("recovery-key.txt")).unwrap();
    let recovery = RecoveryKey::parse(text.trim()).unwrap();
    assert_matches_fixture(
        &Vault::unlock_with_recovery_key(&Path::new(FIXTURE).join("vault"), &recovery).unwrap(),
    );
}

#[test]
#[ignore = "regenerates the committed fixture; run only when starting a new format version"]
fn generate_v1_fixture() {
    let fixture = PathBuf::from(FIXTURE);
    if fixture.exists() {
        fs::remove_dir_all(&fixture).unwrap();
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    for (path, bytes) in expected_files() {
        let path = src.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    for dir in EXPECTED_EMPTY_DIRS {
        fs::create_dir_all(src.join(dir)).unwrap();
    }

    // Cheap KDF so the test stays fast; the format is the same at any cost.
    let kdf = KdfParams {
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };
    let (vault, recovery) = Vault::create(&fixture.join("vault"), PASSWORD, kdf).unwrap();
    let mut top: Vec<_> = fs::read_dir(&src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    top.sort();
    for path in top {
        vault.import(&path, "/").unwrap();
    }
    fs::write(
        fixture.join("recovery-key.txt"),
        format!("{}\n", recovery.to_display_string().as_str()),
    )
    .unwrap();
    assert_matches_fixture(&vault);
}
