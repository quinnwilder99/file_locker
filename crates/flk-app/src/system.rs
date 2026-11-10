//! Small Windows helpers: message boxes, Explorer, clipboard, registry,
//! drive letters, single instance, and which apps hold files open.

use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HWND};
use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
};
use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
    RM_PROCESS_INFO,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IsIconic, MessageBoxW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOWNORMAL,
};

pub const MB_OK: u32 = 0x0;
pub const MB_YESNO: u32 = 0x4;
pub const MB_ICONERROR: u32 = 0x10;
pub const MB_ICONWARNING: u32 = 0x30;
pub const MB_ICONINFORMATION: u32 = 0x40;
pub const MB_DEFBUTTON2: u32 = 0x100;
const MB_SETFOREGROUND: u32 = 0x1_0000;
pub const IDYES: i32 = 6;
const CF_UNICODETEXT: u32 = 13;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "File Locker";

/// NUL-terminated UTF-16.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// A native message box; `owner` is a window handle or 0. Returns the
/// button pressed (e.g. [`IDYES`]).
pub fn message_box(owner: isize, title: &str, text: &str, style: u32) -> i32 {
    let (title, text) = (wide(title), wide(text));
    // SAFETY: both strings are NUL-terminated; owner may be null.
    unsafe {
        MessageBoxW(
            owner as HWND,
            text.as_ptr(),
            title.as_ptr(),
            style | MB_SETFOREGROUND,
        )
    }
}

pub fn error_box(owner: isize, text: &str) {
    message_box(owner, "File Locker", text, MB_OK | MB_ICONERROR);
}

/// Opens a folder (or a drive like `V:\`) in Explorer.
pub fn open_in_explorer(path: &str) {
    let (verb, file, args) = (
        wide("open"),
        wide("explorer.exe"),
        wide(&format!("\"{path}\"")),
    );
    // SAFETY: all strings are NUL-terminated.
    unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            args.as_ptr(),
            null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Brings a window to the front, restoring it if minimized.
pub fn bring_to_front(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    // SAFETY: plain window calls on a handle we own.
    unsafe {
        if IsIconic(hwnd as HWND) != 0 {
            ShowWindow(hwnd as HWND, SW_RESTORE);
        }
        SetForegroundWindow(hwnd as HWND);
    }
}

pub fn set_clipboard(owner: isize, text: &str) -> bool {
    let data = wide(text);
    let bytes = data.len() * 2;
    // SAFETY: the clipboard takes ownership of the global memory on success.
    unsafe {
        if OpenClipboard(owner as HWND) == 0 {
            return false;
        }
        EmptyClipboard();
        let memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
        let mut ok = false;
        if !memory.is_null() {
            let target = GlobalLock(memory);
            if !target.is_null() {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr().cast::<u8>(),
                    target.cast::<u8>(),
                    bytes,
                );
                GlobalUnlock(memory);
                ok = !SetClipboardData(CF_UNICODETEXT, memory).is_null();
            }
        }
        CloseClipboard();
        ok
    }
}

/// True if no drive uses `letter` (like `"V:"`).
pub fn drive_letter_free(letter: &str) -> bool {
    let Some(c) = letter.chars().next().map(|c| c.to_ascii_uppercase()) else {
        return false;
    };
    if !c.is_ascii_uppercase() {
        return false;
    }
    // SAFETY: no arguments.
    let used = unsafe { GetLogicalDrives() };
    used & (1 << (c as u32 - 'A' as u32)) == 0
}

/// Keeps the first instance's mutex for the life of the process. Returns
/// false if another instance already holds it.
pub fn claim_single_instance() -> bool {
    let name = wide("Local\\FileLocker.Instance");
    // SAFETY: the handle is intentionally leaked; it lives as long as the process.
    unsafe {
        let handle = CreateMutexW(null(), 1, name.as_ptr());
        !handle.is_null() && GetLastError() != ERROR_ALREADY_EXISTS
    }
}

/// Whether File Locker starts at sign-in (HKCU Run key).
pub fn starts_with_windows() -> bool {
    let (key, value) = (wide(RUN_KEY), wide(RUN_VALUE));
    let mut size = 0u32;
    // SAFETY: querying only the size.
    unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            null_mut(),
            &mut size,
        ) == 0
    }
}

pub fn set_start_with_windows(enable: bool) -> Result<(), String> {
    let (key, value) = (wide(RUN_KEY), wide(RUN_VALUE));
    let status = if enable {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let command = wide(&format!("\"{}\" --tray", exe.display()));
        // SAFETY: data is a NUL-terminated UTF-16 string of the given byte size.
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                REG_SZ,
                command.as_ptr().cast::<c_void>(),
                (command.len() * 2) as u32,
            )
        }
    } else {
        // SAFETY: plain registry call.
        let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) };
        if status == 2 {
            0 // already absent
        } else {
            status
        }
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Could not change the startup setting (error {status})."
        ))
    }
}

/// Names of the applications holding any of `files` open, via the Restart
/// Manager. Empty if none are found or the query fails.
pub fn apps_using(files: &[String]) -> Vec<String> {
    if files.is_empty() {
        return Vec::new();
    }
    let paths: Vec<Vec<u16>> = files.iter().take(64).map(|f| wide(f)).collect();
    let pointers: Vec<*const u16> = paths.iter().map(|p| p.as_ptr()).collect();
    let mut session = 0u32;
    let mut session_key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: buffers are sized as the API requires; the session is always ended.
    unsafe {
        if RmStartSession(&mut session, 0, session_key.as_mut_ptr()) != 0 {
            return Vec::new();
        }
        let mut names = Vec::new();
        if RmRegisterResources(
            session,
            pointers.len() as u32,
            pointers.as_ptr(),
            0,
            null(),
            0,
            null(),
        ) == 0
        {
            let mut infos: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); 32];
            let (mut needed, mut count, mut reasons) = (0u32, infos.len() as u32, 0u32);
            if RmGetList(
                session,
                &mut needed,
                &mut count,
                infos.as_mut_ptr(),
                &mut reasons,
            ) == 0
            {
                for info in &infos[..count as usize] {
                    let end = info
                        .strAppName
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(info.strAppName.len());
                    let name = String::from_utf16_lossy(&info.strAppName[..end]);
                    if !name.is_empty() && !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
        RmEndSession(session);
        names
    }
}

/// The user's Documents folder (a sensible default for new vaults).
pub fn documents_dir() -> std::path::PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| ".".into());
    let docs = home.join("Documents");
    if docs.is_dir() {
        docs
    } else {
        home
    }
}

/// True if `path` is on the given drive (like `"V:"`).
pub fn is_on_drive(path: &Path, drive: &str) -> bool {
    path.to_string_lossy()
        .to_ascii_uppercase()
        .starts_with(&drive.to_ascii_uppercase())
}
