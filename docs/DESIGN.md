# file_locker — Design

Status: draft · 2026-10-18

## Goal

Lock folders and files on Windows so they stay unreadable at rest, on this PC or any other, while
using them feels as smooth as BitLocker: enter a password, a drive letter appears, work normally,
lock it and it's gone. Target platform is Windows 10/11, including **Home editions**, which ship
without full BitLocker.

## Threat model

**Protects against**
- A lost or stolen laptop, disk or USB stick.
- Someone reading the vault from another machine, another OS (Linux live USB), or with raw disk tools.
- Someone on this PC while the vault is locked.
- Tampering with vault contents: modified, truncated, reordered or extended file data, altered
  names, and entries moved between folders are all detected (see Crypto). **Not** detected:
  swapping two whole encrypted files with each other, or restoring an older copy of a file
  (rollback). File contents are not bound to their name, which keeps renames cheap; Cryptomator
  makes the same trade-off.

**Does not protect against**
- Malware or another user on the PC *while the vault is unlocked* (same as BitLocker).
- Keyloggers capturing the password.
- Plaintext copies a user makes outside the vault, or originals that were "moved in" but remain
  recoverable on disk (see Import).
- File count, approximate sizes and directory shape are visible to someone with the vault folder
  (contents and names are not).
- Copies Windows and apps make *outside* the vault while it is mounted: Explorer's thumbnail cache,
  Recent files and jump lists, apps' own temp and autosave files, and the pagefile, all on the
  (unencrypted, on Home editions) system drive. Entries on the mounted drive are marked "not
  content indexed" so Windows Search skips them. BitLocker avoids this class of leak by encrypting
  the whole system drive; a folder vault cannot.

## Architecture

```
 Explorer / any app
        │  (plain files on V:)
        ▼
 ┌──────────────────────┐
 │ WinFsp mount (V:)    │  user-mode filesystem, decrypts/encrypts on the fly
 ├──────────────────────┤
 │ Vault core           │  path ↔ encrypted name mapping, chunked file crypto
 ├──────────────────────┤
 │ Key manager          │  Argon2id, key slots, recovery key, zeroization
 └──────────────────────┘
        │  (ciphertext only)
        ▼
 Vault folder on NTFS / exFAT / USB / cloud-synced folder
```

### Why per-file encryption, not one container file

WinFsp works at the *filesystem* level, not the block-device level. A single encrypted container
file (VeraCrypt-style) would need either a kernel block driver (signing, high risk) or our own
filesystem implementation inside the container. Instead we use the model proven by Cryptomator:
the vault is an ordinary folder of individually encrypted files with encrypted names, and the WinFsp
layer presents the decrypted view.

Trade-offs accepted:
- ➕ No filesystem to write; the host filesystem handles allocation, journaling, crash safety.
- ➕ Corruption is limited to one file; vaults sync well with OneDrive/Dropbox (only changed files).
- ➖ File count, approximate sizes and tree shape are visible (listed in the threat model).

## Vault layout

```
MyVault/
  vault.json            format version, KDF params, key slots (no secrets in clear)
  vault.json.bak        identical backup, written first on every change
  d/<2 chars>/<30 chars>/   one directory per vault directory, named by keyed hash of its directory ID
       <encrypted-name>.flk          encrypted file
       <encrypted-name>.flk/dir.id   marks a subdirectory, holds its directory ID
       <hash>.flks/                  entry whose encrypted name is over 220 chars:
           name.flk                    the full encrypted name
           contents.flk | dir.id       the file contents, or the subdirectory's ID
```

An empty directory's storage folder may be missing (git and some sync tools drop empty folders);
it reads as empty and is recreated on the next write. Entries left incomplete by an interrupted
write (a `.tmp` file, an entry folder without `dir.id`, a `.flks` folder without `name.flk`) are
ignored.

`dir.id` is stored in clear (random 128-bit IDs, like Cryptomator). Someone with write access to
the vault folder could swap two subfolders' IDs; names would then fail authentication on listing,
so the swap is detected rather than silent.

## Crypto

| Purpose | Choice | Notes |
|---|---|---|
| Password → key | **Argon2id**, default m = 256 MiB, t = 3, p = 4, 16-byte random salt | Params stored in `vault.json`. At creation, `t` is raised until one derivation takes ~1 s on that machine (capped at 32, never below the default). |
| Master key | 64 random bytes from the OS CSPRNG | HKDF-SHA-256 derives three subkeys: content (wraps per-file keys), names (AES-SIV) and directory hashing (HMAC-SHA-256 for storage paths). |
| Key slots | Master key wrapped with AES-256-GCM under each slot's key | Slot 1: password. Slot 2: recovery key. Changing the password rewraps only slot 1, no re-encryption. |
| Recovery key | 32 random bytes, shown once as 52 Crockford-base32 chars + 4-char checksum, in 14 groups of 4 | Replaces "password recovery". Nothing in the vault can reveal the password. The checksum reports typos as typos instead of "wrong key". |
| File contents | AES-256-GCM in 64 KiB chunks; file header holds a random 32-byte per-file key wrapped by the content key | Each chunk: fresh random 12-byte nonce + 16-byte tag (0.04 % overhead). AAD = header nonce ‖ chunk index ‖ last-chunk flag. The final chunk is always shorter than a full one (possibly empty), so chunks can't be swapped, reordered, truncated or appended to undetected. |
| File names | AES-SIV (deterministic) with the parent directory ID as AAD, base64url | Deterministic so lookups work; same name in different directories encrypts differently. Encrypted names over 220 chars are stored as a SHA-256-based `.flks` stand-in plus a `name.flk` file holding the full name. Names over 255 UTF-16 units (Windows' limit) are rejected. |

Rules:
- Never reuse a nonce: every chunk write draws a new random nonce, including rewrites.
- Keys live in locked, non-pageable memory where possible, and are zeroized on lock. Implemented by
  `SecretBytes`: each key (master, subkeys, KEKs, per-file keys, recovery key) gets its own page,
  locked with `VirtualLock` and zeroized before being freed. The crypto crates' own `zeroize`
  features are on, so AES/GHASH/CMAC key schedules and Argon2 working memory are wiped too.
  Short-lived copies (the unwrapped key buffer, typed passwords) are wiped but not page-locked.
- Header and `vault.json` parsing must reject anything unexpected (fuzzed, see Milestones).
- No custom crypto primitives; use vetted libraries only.

## User experience

- **Create vault:** pick a folder + password → show recovery key → require the user to confirm it.
- **Unlock:** tray icon or double-click the vault → password → mounts at the next free drive letter
  and opens Explorer.
- **Lock:** tray menu, hotkey, or automatically on sleep, Windows lock, idle timeout, or USB
  removal. Locking unmounts, then zeroizes keys. Open files are flushed first; if an app holds a
  file open the user is told which app.
- **Import:** right-click a folder → "Move into vault". Copies into the vault, verifies, then deletes
  the originals. The UI warns that deleted originals may remain recoverable, especially on SSDs, and
  recommends creating sensitive files inside the vault from the start.
- **No WinFsp available** (e.g. a borrowed PC without admin rights): a CLI fallback can decrypt a
  vault to a chosen folder or re-encrypt it, without mounting: `flk export`, edit, then
  `flk import --replace`, which writes the new copy in full before removing the old one.
  `flk rm` and `flk mv` delete and rename inside the vault.

## Lessons from LockDir (prior-art analysis)

Static analysis of KakaSoft LockDir / Folder Protector (unpacked UPX, Delphi, build 2021-10-15) for
reference only; no code or assets are reused. Findings come from strings and imports and were not
confirmed by decompilation.

| LockDir behaviour | Our position |
|---|---|
| Default "Normal" mode is *hide and lock*, not encryption: reserved device names (`com1`), trailing-dot paths and shell CLSID disguises. Data stays plaintext on disk. | Every mode encrypts. No hiding tricks; they fail on other machines and OSes. |
| "High" mode only scrambles file headers. | No partial-encryption modes. |
| "Highest" mode is AES-256 but re-encrypts the whole folder on every lock/unlock (~15 MB/s). | On-the-fly encryption; unlock time is independent of vault size. |
| Password is recoverable ("Your password is: %s", email retrieval, rescue password tied to licence key). | The password is never stored in any reversible form. A recovery key replaces recovery. |
| Unlocking requires copying the program into the protected folder. | Vault and app are independent; a CLI fallback covers machines without the app installed. |

## Implementation

Rust (decided 2026-10-18), MSVC toolchain. Crypto comes from RustCrypto: `aes-gcm` 0.11,
`aes-siv` 0.8, `argon2` 0.6, `hkdf` 0.13, `hmac` 0.13, `sha2` 0.11; secrets are wrapped in
`zeroize::Zeroizing`.

The format is frozen by two kinds of test:
- `src/format_vectors.rs`: known-answer vectors for subkeys, storage paths, recovery-key text, name
  encryption and Argon2id. Subkeys, paths and recovery-key text were cross-checked against an
  independent Python implementation.
- `tests/format_v1.rs`: a committed vault under `tests/fixtures/v1/` that every build must still open
  (with the password and with the recovery key) and export to the exact expected files. It covers
  empty, single-chunk, exact-chunk and multi-chunk files, Unicode names, long names and an empty folder.
  Changing either means a new format version, not an edited vector.

```
crates/vault-core   library: vault format, keys, content and name encryption, random-access files
crates/flk-mount    WinFsp file system over vault-core
crates/flk          CLI: create, import [--replace], export, ls, rm, mv, passwd, recover, mount
```

Build and test: `cargo test --workspace`. CLI help: `cargo run -p flk -- --help`.
`--password-stdin` reads secrets one per line for scripting (a leading UTF-8 BOM, which Windows
PowerShell adds to piped text, is ignored).

Build requirements (Windows): Visual Studio Build Tools with the C++ workload; WinFsp 2.1 with its
**Developer** feature (`msiexec /i winfsp-2.1.msi ADDLOCAL=F.Main,F.User,F.Developer`); LLVM, for
the libclang that generates the WinFsp bindings. Running `flk mount` needs only WinFsp itself.
Mount tests skip themselves (with a message) when WinFsp is missing.

### Mounted drive (`flk mount`)

`flk mount <vault> [--drive V:] [--open]` unlocks the vault as a drive letter until Ctrl+C, then
unmounts and drops the keys. If the process is killed, WinFsp removes the drive.

How Windows semantics map onto the vault:
- **Reads and writes at any offset** go through `VaultFile`, which re-encrypts only the 64 KiB
  chunks a write touches (fresh nonce each time) and keeps the final-chunk rule, so every file stays
  valid for whole-file decryption. Handles to the same file share one `VaultFile`.
- **Case-insensitive, case-preserving names.** Exact spellings are found directly. Other spellings
  use a per-folder index (case-folded name → stored name) that this vault keeps current as it
  changes the folder, and rebuilds when the folder's modification time moves, so changes made from
  outside (another process, a sync tool) are noticed. An outside change that lands in the same
  timestamp tick as one of ours can be missed until the next change.
- **Security descriptor:** every entry reports the current user as owner, with full control for the
  user, SYSTEM and Administrators. Git requires the owner to be the current user. Permission
  changes are accepted and dropped; the vault does not store ACLs.
- **File index** (Windows' inode number) is a hash of the case-folded path. Tools compare it (tar
  refuses to archive a file whose index matches the archive's), so it must be unique; it changes
  when an entry is renamed.
- **Timestamps** are the encrypted file's own NTFS times; setting them sets those.
- **Renames follow NTFS:** an open file can be renamed and its handle keeps working; a folder
  holding an open file cannot be renamed; rename-and-replace refuses folders and files that are
  open elsewhere.
- **Attributes:** every entry is reported "not content indexed" (see the threat model).

Not stored (yet): file attributes such as hidden, read-only or system; ACLs; alternate data streams;
reparse points and hard links.

Durability: a new file is not flushed to disk when created, and chunk rewrites are not atomic. An
app's flush (`FlushFileBuffers`) syncs the file. A crash mid-write can leave the chunk being written
failing authentication; the folder still lists, and opening that file reports the damage.

Measured on the development machine (NVMe, release build, Defender on):

| Workload | Plain NTFS | Mounted vault |
|---|---|---|
| Write / read 256 MB | 1,430 / 3,300 MB/s | 750 / 670 MB/s |
| Create 1,000 × 4 KB files | 0.35 s | 4.3 s (linear in count) |
| List 3,000 files | 0.03 s (1,000) | 0.23 s |
| 2,000 random 4 KB writes into a 256 MB file | 0.03 s | 0.6 s |

Windows Defender scans every new random-looking file the first time it is opened (~8 ms on this
machine). The vault already avoids reopening files it just created. Excluding the **vault folder**
(not the mounted drive) from real-time scanning removes the rest of that cost; it is safe because
the ciphertext cannot be meaningfully scanned, and files are still scanned in plaintext when apps
open them on the mounted drive. This is a user choice; `flk` does not change Defender settings.

Tested with real tools on a mounted vault (`crates/flk-mount/tests/real_tools.rs`): robocopy
(multithreaded copy, byte-exact), git (commit, `gc --aggressive`, `fsck --full --strict`, checkout),
Windows tar and 7-Zip (archive, test, extract, byte-exact).

Application patterns (`crates/flk-mount/tests/app_patterns.rs`): Office-style safe save (write temp,
swap by renames, delete backup), delete-on-close temp files, renames under open handles,
memory-mapped writes, running an `.exe` from the drive, Explorer's copy engine
(`Shell.Application.CopyHere`), a 1,200-entry listing, volume label and sizes, owner check, and
damaged files (still listed; reading them fails and is logged).

Not yet tested: Microsoft Office itself (not installed on the development machine; its save
sequence is replayed above) and clicking through Explorer by hand.

## Open decisions

1. **Vault-format compatibility with Cryptomator.** The current format is our own (`.flk`), though
   structurally similar. Matching Cryptomator exactly would let users open vaults with an existing
   audited tool, at the cost of its KDF choice and recovery-key format.
2. **WinFsp installation.** Bundle the official signed installer with ours, or require it separately.
3. **Attributes.** Store hidden / read-only / system attributes (e.g. in the file header or a
   sidecar), or keep reporting every file as a plain archive file.

## Milestones

1. **Core + CLI** ✅ (2026-10-18): vault format, key slots, file and name crypto, `create / import
   [--replace] / export / ls / rm / mv / passwd / recover`, long-name shortening, KDF calibration
   (~1 s unlock), page-locked zeroized keys, format frozen by known-answer vectors and a committed
   fixture vault. 40 tests: round-trip, tamper, at-rest leak, recovery, long names, interrupted
   writes, lost empty folders, remove/rename/replace, memory locking.
2. **Mount** ✅ (2026-10-18): WinFsp file system over the core (`flk-mount`), `flk mount` with
   Ctrl+C to lock, random-access `VaultFile`, case-insensitive lookup with a per-folder index,
   shared handles, rename-and-replace, delete-on-close. Audited 2026-10-19 against every claim
   above. 53 tests in all, including a randomized model test of `VaultFile`, a live mount driven
   through `std::fs`, real tools (robocopy, git, tar, 7-Zip), application patterns (safe save,
   memory maps, running programs, Explorer's copy engine, damaged files) and an end-to-end CLI test
   that locks with Ctrl+Break. Open items: Office and Explorer by hand, attributes (see Open
   decisions), per-file overhead of ~4 ms.
3. **Desktop app:** tray icon, unlock dialog, auto-lock triggers, Explorer context menu, installer.
4. **Hardening:** fuzz `vault.json` and file-header parsing, crash-consistency tests (power loss
   mid-write), external review of the crypto design before any 1.0.
