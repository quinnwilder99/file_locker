//! Small Win32 helpers: the security descriptor, disk space, drive letters, times.

use std::io;
use std::path::Path;
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetLogicalDrives};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Self-relative security descriptor giving the current user, SYSTEM and
/// Administrators full control, with the current user as owner. Git refuses
/// repositories whose owner is not the current user ("dubious ownership").
pub(crate) fn security_descriptor() -> io::Result<Vec<u8>> {
    let sid = current_user_sid()?;
    let sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut size = 0u32;
    // SAFETY: `wide` is NUL-terminated; on success the descriptor is a
    // LocalAlloc'd buffer of `size` bytes, freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let bytes = std::slice::from_raw_parts(descriptor.cast::<u8>(), size as usize).to_vec();
        LocalFree(descriptor);
        Ok(bytes)
    }
}

fn current_user_sid() -> io::Result<String> {
    // SAFETY: standard token query; every handle and buffer is released on
    // all paths, and the TOKEN_USER buffer is 8-byte aligned.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let error = io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(error);
        }
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let mut text = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut end = 0;
        while *text.add(end) != 0 {
            end += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, end));
        LocalFree(text.cast());
        Ok(sid)
    }
}

/// `(total, free)` bytes of the disk holding `path`.
pub(crate) fn disk_space(path: &Path) -> (u64, u64) {
    let wide: Vec<u16> = path.as_os_str().encode_wide_nul();
    let (mut free, mut total, mut _all_free) = (0u64, 0u64, 0u64);
    // SAFETY: `wide` is NUL-terminated; outputs are valid u64 pointers.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut _all_free) };
    if ok == 0 {
        (0, 0)
    } else {
        (total, free)
    }
}

/// The highest unused drive letter from Z: down to D:, like `"V:"`.
pub fn free_drive_letter() -> Option<String> {
    // SAFETY: no arguments; returns a bitmask of drives in use.
    let used = unsafe { GetLogicalDrives() };
    (b'D'..=b'Z')
        .rev()
        .find(|letter| used & (1 << (letter - b'A')) == 0)
        .map(|letter| format!("{}:", letter as char))
}

/// Windows FILETIME: 100 ns intervals since 1601-01-01.
pub(crate) fn to_filetime(time: SystemTime) -> u64 {
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => EPOCH_DIFFERENCE + (since.as_nanos() / 100) as u64,
        Err(before) => EPOCH_DIFFERENCE.saturating_sub((before.duration().as_nanos() / 100) as u64),
    }
}

/// `None` for 0 and -1, which mean "leave unchanged" in file-time setters.
pub(crate) fn from_filetime(filetime: u64) -> Option<SystemTime> {
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    if filetime == 0 || filetime == u64::MAX {
        return None;
    }
    let delta = |t: u64| std::time::Duration::from_nanos(t.saturating_mul(100));
    Some(if filetime >= EPOCH_DIFFERENCE {
        UNIX_EPOCH + delta(filetime - EPOCH_DIFFERENCE)
    } else {
        UNIX_EPOCH - delta(EPOCH_DIFFERENCE - filetime)
    })
}

pub(crate) fn now_filetime() -> u64 {
    to_filetime(SystemTime::now())
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_round_trip() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(from_filetime(to_filetime(t)), Some(t));
        assert_eq!(to_filetime(UNIX_EPOCH), 116_444_736_000_000_000);
        assert_eq!(from_filetime(0), None);
        assert_eq!(from_filetime(u64::MAX), None);
    }

    #[test]
    fn builds_a_security_descriptor() {
        assert!(security_descriptor().unwrap().len() > 20);
    }
}
