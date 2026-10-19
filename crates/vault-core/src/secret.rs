//! Fixed-size secrets, each in its own page of memory that is locked into RAM
//! where the OS allows it (so it never reaches the pagefile) and zeroized
//! before it is freed.

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use zeroize::Zeroize;

pub(crate) struct SecretBytes<const N: usize> {
    ptr: NonNull<[u8; N]>,
    layout: Layout,
    locked: bool,
}

// SAFETY: `SecretBytes` exclusively owns its allocation, like `Box<[u8; N]>`.
unsafe impl<const N: usize> Send for SecretBytes<N> {}
// SAFETY: shared access only hands out `&[u8; N]`.
unsafe impl<const N: usize> Sync for SecretBytes<N> {}

impl<const N: usize> SecretBytes<N> {
    pub(crate) fn zeroed() -> Self {
        // A whole page per secret, so unlocking one secret never unlocks
        // another that shared its page.
        let page = sys::page_size();
        let layout = Layout::from_size_align(N.max(1).next_multiple_of(page), page)
            .expect("page-sized layout is valid");
        // SAFETY: `layout` has a non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw.cast::<[u8; N]>()).unwrap_or_else(|| handle_alloc_error(layout));
        let locked = sys::lock(raw, layout.size());
        Self {
            ptr,
            layout,
            locked,
        }
    }

    /// Copies `bytes` into a new secret; `None` if the length is not `N`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut secret = Self::zeroed();
        if bytes.len() != N {
            return None;
        }
        secret.copy_from_slice(bytes);
        Some(secret)
    }

    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        // SAFETY: `ptr` is a live, initialized allocation owned by `self`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<const N: usize> DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as in `deref`, and `&mut self` guarantees exclusive access.
        unsafe { self.ptr.as_mut() }
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.deref_mut().zeroize();
        let raw = self.ptr.as_ptr().cast::<u8>();
        if self.locked {
            sys::unlock(raw, self.layout.size());
        }
        // SAFETY: allocated in `zeroed` with this exact layout, freed once.
        unsafe { dealloc(raw, self.layout) };
    }
}

#[cfg(windows)]
mod sys {
    use std::sync::OnceLock;

    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    pub(super) fn page_size() -> usize {
        static PAGE: OnceLock<usize> = OnceLock::new();
        *PAGE.get_or_init(|| {
            // SAFETY: SYSTEM_INFO is plain data; GetSystemInfo fills it in.
            let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
            unsafe { GetSystemInfo(&mut info) };
            (info.dwPageSize as usize).max(4096)
        })
    }

    /// Fails (returns false) if the process's minimum working set is exhausted.
    pub(super) fn lock(ptr: *mut u8, len: usize) -> bool {
        // SAFETY: `ptr..ptr+len` is a live allocation owned by the caller.
        unsafe { VirtualLock(ptr.cast(), len) != 0 }
    }

    pub(super) fn unlock(ptr: *mut u8, len: usize) {
        // SAFETY: as in `lock`; the range was locked by `lock`.
        unsafe { VirtualUnlock(ptr.cast(), len) };
    }
}

#[cfg(not(windows))]
mod sys {
    pub(super) fn page_size() -> usize {
        4096
    }

    pub(super) fn lock(_ptr: *mut u8, _len: usize) -> bool {
        false
    }

    pub(super) fn unlock(_ptr: *mut u8, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_copies_bytes() {
        let mut secret = SecretBytes::<32>::zeroed();
        assert_eq!(*secret, [0; 32]);
        secret[5] = 9;
        assert_eq!(secret[5], 9);
        assert_eq!(
            *SecretBytes::<3>::from_slice(&[1, 2, 3]).unwrap(),
            [1, 2, 3]
        );
        assert!(SecretBytes::<3>::from_slice(&[1, 2]).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn is_locked_into_memory_on_windows() {
        let secrets: Vec<_> = (0..8).map(|_| SecretBytes::<64>::zeroed()).collect();
        assert!(secrets.iter().all(SecretBytes::is_locked));
    }
}
