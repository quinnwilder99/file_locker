# File Locker

Encrypted folder vaults for Windows. A vault is an ordinary folder whose files are always
encrypted on disk. Unlock it with your password and it opens as a drive in Explorer, like a
USB stick; lock it and the drive disappears. Works on Windows 10 and 11, including Home
editions, which do not have BitLocker.

## Install

Run `FileLocker-Setup-0.1.0.exe` and approve the administrator prompt. Setup:

- installs File Locker and adds it to the Start menu;
- installs [WinFsp](https://winfsp.dev) if it is missing (it lets vaults appear as drives);
- adds "Unlock vault" for vault files and "Move into vault…" to Explorer's right-click menu;
- optionally starts File Locker when you sign in (you can change this later in Settings).

File Locker then lives in the notification area (the tray, next to the clock). The icon is
blue while every vault is locked and green while any vault is unlocked.

## Everyday use

**Create a vault.** Open File Locker, choose *Create a vault*, give it a name, a location and a
password. File Locker then shows your **recovery key**. Copy it or save it to a file, keep it
somewhere safe away from the computer, tick *I saved my recovery key*, and press *Finish*.

**Unlock.** Any of these works:
- *Unlock* next to the vault in File Locker's window;
- the tray icon's menu;
- double-click **Unlock vault** inside the vault's folder.

Enter your password: the vault opens as a drive (such as `Z:`) in Explorer. Use it like any
other drive: open, edit and save files with any program.

**Lock.** *Lock* in the window or the tray menu, *Lock all*, or press **Ctrl+Alt+L**. If files
on the drive are still open, File Locker tells you which ones (and which programs have them)
and asks before locking.

**Automatic locking** (Settings): when the PC sleeps or hibernates, when Windows is locked
(Win+L), after a chosen idle time, with Ctrl+Alt+L, when you sign out, and when the drive
holding the vault is unplugged. File Locker shows a notification when it locks something.

**Move files into a vault.** Right-click files or folders in Explorer and choose
*Move into vault…* (on Windows 11, it is under *Show more options*). File Locker copies them
into the vault, checks every copy against the original, and only then deletes the originals.

**Forgot your password?** Choose *Unlock*, then *Forgot password?*, enter your recovery key
and a new password.

**Change the password:** *•••* next to the vault, then *Change password…*. Your files are not
re-encrypted and the recovery key stays the same.

**Use a vault on another PC or a USB stick.** Copy or move the whole vault folder, install
File Locker there, and double-click *Unlock vault* in it (or use *Add existing…*).

## What is protected

- Files in a vault are encrypted with AES-256 (file contents and names). Someone with the vault
  folder, a stolen laptop or USB stick, or another operating system sees only scrambled data.
- Your password is never stored. Unlocking takes about a second on purpose, which makes
  guessing passwords slow.
- While a vault is unlocked, anything running on the PC can read its drive, the same as with
  BitLocker. Lock it when you step away (or let File Locker do it automatically).
- Windows and apps can keep their own copies of things you open while a vault is unlocked:
  thumbnails, recent-file lists, autosaves. Those live outside the vault. On Windows Home the
  system drive is usually not encrypted, so be mindful of what you open.
- Moving files into a vault deletes the originals, but deleted files can sometimes be recovered
  from the disk with special tools, especially on SSDs. Create sensitive files inside the vault
  when you can.

## Uninstall

Settings > Apps > File Locker > Uninstall. Your vault folders and their files are not touched.
WinFsp stays installed (other programs may use it) and can be removed separately.

## Troubleshooting

- **"WinFsp is not installed"**: run the File Locker setup again.
- **Copying many small files is slower than on a normal drive.** Windows Defender scans each
  new encrypted file. Excluding the *vault folder* (not the unlocked drive) from real-time
  scanning makes it faster, and is safe: files are still scanned when programs open them on the
  unlocked drive. Windows Security > Virus & threat protection > Manage settings > Exclusions.
- **"Files are still open" right after saving**: Windows sometimes needs a moment to finish
  with a file. Wait a few seconds and lock again.
- A log is kept in `%LOCALAPPDATA%\File Locker\FileLocker.log` (no passwords or file
  contents are ever written to it).

## Command line

`flk.exe` (installed next to File Locker) does everything without a window: `create`,
`import`, `export`, `ls`, `rm`, `mv`, `passwd`, `recover` and `mount`. Run `flk --help`.

## For developers

Rust workspace; see [docs/DESIGN.md](docs/DESIGN.md) for the design, file format and threat
model.

```
crates/vault-core   vault format, keys, encryption (no Windows-specific code)
crates/flk-mount    WinFsp file system over vault-core
crates/flk          command-line tool
crates/flk-app      FileLocker.exe: tray app and windows (Slint)
installer/          Inno Setup script
scripts/            installer build, GUI end-to-end tests
```

Requirements: Rust (MSVC toolchain), Visual Studio Build Tools (C++), WinFsp 2.1 with its
Developer feature, LLVM (for the WinFsp bindings), and Inno Setup 6 for the installer.

```
cargo test --workspace                                   # unit, format and mount tests
powershell -File scripts\gui-tests\gui-e2e.ps1           # create / unlock / lock in the GUI
powershell -File scripts\gui-tests\gui-e2e2.ps1          # auto-lock, move into vault, tray
powershell -File scripts\build-installer.ps1             # dist\FileLocker-Setup-<ver>.exe
```

The GUI tests drive the real app through UI Automation, using a separate settings folder
under `%TEMP%`; they briefly show windows on screen.
