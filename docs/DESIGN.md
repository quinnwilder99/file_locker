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
- Tampering with vault contents (detected, see Crypto).

**Does not protect against**
- Malware or another user on the PC *while the vault is unlocked* (same as BitLocker).
- Keyloggers capturing the password.
- Plaintext copies a user makes outside the vault, or originals that were "moved in" but remain
  recoverable on disk (see Import).
- File count, approximate sizes and directory shape are visible to someone with the vault folder
  (contents and names are not).

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
| Master key | 64 random bytes from the OS CSPRNG | Split into content key and name key via HKDF-SHA-256. |
| Key slots | Master key wrapped with AES-256-GCM under each slot's key | Slot 1: password. Slot 2: recovery key. Changing the password rewraps only slot 1, no re-encryption. |
| Recovery key | 32 random bytes, shown once as 52 Crockford-base32 chars + 4-char checksum, in 14 groups of 4 | Replaces "password recovery". Nothing in the vault can reveal the password. The checksum reports typos as typos instead of "wrong key". |
| File contents | AES-256-GCM in 64 KiB chunks; file header holds a random 32-byte per-file key wrapped by the content key | Each chunk: fresh random 12-byte nonce + 16-byte tag (0.04 % overhead). AAD = header nonce ‖ chunk index ‖ last-chunk flag. The final chunk is always shorter than a full one (possibly empty), so chunks can't be swapped, reordered, truncated or appended to undetected. |
| File names | AES-SIV (deterministic) with the parent directory ID as AAD, base64url | Deterministic so lookups work; same name in different directories encrypts differently. Encrypted names over 220 chars are stored as a SHA-256-based `.flks` stand-in plus a `name.flk` file holding the full name. Names over 255 UTF-16 units (Windows' limit) are rejected. |

Rules:
- Never reuse a nonce: every chunk write draws a new random nonce, including rewrites.
- Keys live in locked, non-pageable memory where possible, and are zeroized on lock.
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
  vault to a chosen folder or re-encrypt it, without mounting.

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
crates/vault-core   library: vault format, keys, content and name encryption
crates/flk          CLI: create, import, export, ls, passwd, recover
```

Build and test: `cargo test --workspace`. CLI help: `cargo run -p flk -- --help`.
`--password-stdin` reads secrets one per line for scripting (a leading UTF-8 BOM, which Windows
PowerShell adds to piped text, is ignored).

## Open decisions

1. **Vault-format compatibility with Cryptomator.** The current format is our own (`.flk`), though
   structurally similar. Matching Cryptomator exactly would let users open vaults with an existing
   audited tool, at the cost of its KDF choice and recovery-key format.
2. **WinFsp installation.** Bundle the official signed installer with ours, or require it separately.
3. **Case-insensitive lookup** (milestone 2). Windows treats `A.txt` and `a.txt` as the same file;
   encrypted names do not. The mount layer must make lookups case-insensitive.

## Milestones

1. **Core + CLI** ✅ (2026-10-18): vault format, key slots, file and name crypto, `create / import /
   export / ls / passwd / recover`, long-name shortening, KDF calibration (~1 s unlock), format
   frozen by known-answer vectors and a committed fixture vault. 34 tests: round-trip, tamper,
   at-rest leak, recovery, long names, interrupted writes, lost empty folders.
2. **Mount:** WinFsp filesystem over the core; stress test with real apps (Office, git, 7-Zip).
3. **Desktop app:** tray icon, unlock dialog, auto-lock triggers, Explorer context menu, installer.
4. **Hardening:** fuzz `vault.json` and file-header parsing, crash-consistency tests (power loss
   mid-write), external review of the crypto design before any 1.0.
