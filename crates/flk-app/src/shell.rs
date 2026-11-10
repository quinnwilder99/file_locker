//! The shell thread: a hidden top-level window that owns the tray icon and
//! receives the system events behind auto-lock (sleep, Windows lock, sign-out,
//! drive removal, idle timer, hotkey), plus commands from later launches.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetLastInputInfo, RegisterHotKey, UnregisterHotKey, LASTINPUTINFO, MOD_ALT, MOD_CONTROL,
    MOD_NOREPEAT,
};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO,
    NIIF_RESPECT_QUIET_TIME, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICONDATAW,
    NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, GetSystemMetrics, LoadImageW,
    PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SendMessageTimeoutW,
    SetForegroundWindow, SetMenuDefaultItem, SetTimer, TrackPopupMenuEx, TranslateMessage, HICON,
    IMAGE_ICON, LR_DEFAULTCOLOR, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, SMTO_ABORTIFHUNG,
    SM_CXSMICON, SM_CYSMICON, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_CONTEXTMENU, WM_COPYDATA,
    WM_DESTROY, WM_DEVICECHANGE, WM_ENDSESSION, WM_HOTKEY, WM_LBUTTONDBLCLK, WM_NULL,
    WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_TIMER, WNDCLASSW,
};

use crate::app::App;
use crate::system::wide;
use crate::{actions, ui};

const CLASS: &str = "FileLocker.Shell";
/// Marks `WM_COPYDATA` messages from another File Locker process.
const COPYDATA_ARGS: usize = 0x464C_4B41;

const WM_TRAY: u32 = WM_APP + 1;
const WM_REFRESH: u32 = WM_APP + 2;
const WM_BALLOON: u32 = WM_APP + 3;
const WM_SET_HOTKEY: u32 = WM_APP + 4;
const WM_STOP: u32 = WM_APP + 5;

const NIN_SELECT: u32 = 0x400;
const NIN_KEYSELECT: u32 = 0x401;
const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WTS_SESSION_LOCK: usize = 0x7;
const PBT_APMSUSPEND: usize = 0x4;
const DBT_DEVICEREMOVECOMPLETE: usize = 0x8004;
const NOTIFY_FOR_THIS_SESSION: u32 = 0;
const TIMER_ID: usize = 1;
const TIMER_MS: u32 = 5_000;
const HOTKEY_ID: i32 = 1;

const ID_OPEN_APP: u32 = 1;
const ID_CREATE: u32 = 2;
const ID_SETTINGS: u32 = 3;
const ID_LOCK_ALL: u32 = 4;
const ID_EXIT: u32 = 5;
const ID_VAULT_BASE: u32 = 100;
const ACTION_UNLOCK: u32 = 0;
const ACTION_OPEN: u32 = 1;
const ACTION_LOCK: u32 = 2;

static HWND_VALUE: AtomicIsize = AtomicIsize::new(0);
static APP: OnceLock<Arc<App>> = OnceLock::new();
static BALLOONS: Mutex<VecDeque<(String, String)>> = Mutex::new(VecDeque::new());
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();

fn hwnd() -> HWND {
    HWND_VALUE.load(Ordering::SeqCst) as HWND
}

fn post(message: u32, wparam: usize) {
    let hwnd = hwnd();
    if !hwnd.is_null() {
        // SAFETY: posting to our own window.
        unsafe { PostMessageW(hwnd, message, wparam, 0) };
    }
}

/// Starts the shell thread and waits until its window exists.
pub fn start(app: Arc<App>) {
    let _ = APP.set(app);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("shell".into())
        .spawn(move || run(ready_tx))
        .expect("spawn shell thread");
    let _ = ready_rx.recv();
}

/// Updates the tray icon and tooltip after a vault was locked or unlocked.
pub fn refresh() {
    post(WM_REFRESH, 0);
}

/// Shows a tray notification.
pub fn notify(title: &str, text: &str) {
    BALLOONS
        .lock()
        .unwrap()
        .push_back((title.to_string(), text.to_string()));
    post(WM_BALLOON, 0);
}

pub fn set_hotkey(enabled: bool) {
    post(WM_SET_HOTKEY, enabled as usize);
}

/// Removes the tray icon and ends the shell thread.
pub fn stop() {
    post(WM_STOP, 0);
}

/// Hands the command line to an already running File Locker. Returns false
/// if none answered.
pub fn forward_to_running(args: &[String]) -> bool {
    let class = wide(CLASS);
    let payload: Vec<u16> = args.join("\0").encode_utf16().collect();
    for _ in 0..50 {
        // SAFETY: plain window lookup and a synchronous WM_COPYDATA send; the
        // payload outlives the call.
        unsafe {
            let target = FindWindowW(class.as_ptr(), null());
            if !target.is_null() {
                let data = COPYDATASTRUCT {
                    dwData: COPYDATA_ARGS,
                    cbData: (payload.len() * 2) as u32,
                    lpData: payload.as_ptr() as *mut c_void,
                };
                let mut result = 0usize;
                SendMessageTimeoutW(
                    target,
                    WM_COPYDATA,
                    0,
                    &data as *const COPYDATASTRUCT as LPARAM,
                    SMTO_ABORTIFHUNG,
                    5_000,
                    &mut result,
                );
                return true;
            }
        }
        // The first instance may still be starting.
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn run(ready: std::sync::mpsc::Sender<()>) {
    // SAFETY: standard window creation and message loop on this thread.
    unsafe {
        let instance = GetModuleHandleW(null());
        let class = wide(CLASS);
        let mut wc: WNDCLASSW = zeroed();
        wc.lpfnWndProc = Some(window_proc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);
        let _ = TASKBAR_CREATED.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));
        // A hidden top-level window: message-only windows miss broadcasts such
        // as sleep and sign-out.
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide("File Locker").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        HWND_VALUE.store(hwnd as isize, Ordering::SeqCst);
        add_tray_icon(hwnd);
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        SetTimer(hwnd, TIMER_ID, TIMER_MS, None);
        apply_hotkey(hwnd, app().settings().hotkey);
        let _ = ready.send(());

        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn app() -> &'static Arc<App> {
    APP.get().expect("shell started with an app")
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if Some(&msg) == TASKBAR_CREATED.get() {
        // Explorer restarted: the tray icon must be added again.
        add_tray_icon(hwnd);
        return 0;
    }
    match msg {
        WM_TRAY => {
            match (lparam & 0xFFFF) as u32 {
                NIN_SELECT | NIN_KEYSELECT | WM_LBUTTONDBLCLK => ui::show_main(),
                WM_CONTEXTMENU => show_menu(hwnd),
                _ => {}
            }
            0
        }
        WM_REFRESH => {
            update_tray_icon(hwnd, NIM_MODIFY);
            0
        }
        WM_BALLOON => {
            while let Some((title, text)) = BALLOONS.lock().unwrap().pop_front() {
                show_balloon(hwnd, &title, &text);
            }
            0
        }
        WM_SET_HOTKEY => {
            apply_hotkey(hwnd, wparam != 0);
            0
        }
        WM_STOP => {
            remove_tray_icon(hwnd);
            WTSUnRegisterSessionNotification(hwnd);
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        WM_COPYDATA => {
            let data = &*(lparam as *const COPYDATASTRUCT);
            if data.dwData == COPYDATA_ARGS {
                let units =
                    std::slice::from_raw_parts(data.lpData as *const u16, data.cbData as usize / 2);
                let text = String::from_utf16_lossy(units);
                let args: Vec<String> = if text.is_empty() {
                    Vec::new()
                } else {
                    text.split('\0').map(String::from).collect()
                };
                crate::dispatch(crate::parse_args(&args));
                1
            } else {
                0
            }
        }
        WM_WTSSESSION_CHANGE => {
            if wparam == WTS_SESSION_LOCK && app().settings().lock_on_windows_lock {
                auto_lock("Windows was locked");
            }
            0
        }
        WM_POWERBROADCAST => {
            if wparam == PBT_APMSUSPEND && app().settings().lock_on_sleep {
                auto_lock("the PC went to sleep");
            }
            1
        }
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                let _ = app().lock_all(true);
            }
            0
        }
        WM_DEVICECHANGE => {
            if wparam == DBT_DEVICEREMOVECOMPLETE {
                lock_missing();
            }
            1
        }
        WM_TIMER => {
            lock_missing();
            check_idle();
            0
        }
        WM_HOTKEY => {
            if wparam as i32 == HOTKEY_ID {
                auto_lock("you pressed Ctrl+Alt+L");
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Locks everything now (open files or not) and says why.
fn auto_lock(reason: &str) {
    if let Ok(names) = app().lock_all(true) {
        if !names.is_empty() {
            notify(
                "Vaults locked",
                &format!("{} locked because {reason}.", list(&names)),
            );
        }
    }
}

fn lock_missing() {
    let names = app().lock_missing();
    if !names.is_empty() {
        notify(
            "Vault locked",
            &format!(
                "{} locked because its folder is no longer available (was a drive removed?).",
                list(&names)
            ),
        );
    }
}

fn check_idle() {
    let minutes = app().settings().idle_minutes;
    if minutes == 0 || !app().any_unlocked() {
        return;
    }
    // SAFETY: plain system queries.
    let idle_ms = unsafe {
        let mut info = LASTINPUTINFO {
            cbSize: size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if GetLastInputInfo(&mut info) == 0 {
            return;
        }
        GetTickCount().wrapping_sub(info.dwTime)
    };
    if u64::from(idle_ms) >= u64::from(minutes) * 60_000 {
        auto_lock(&format!("the PC was idle for {minutes} minutes"));
    }
}

fn list(names: &[String]) -> String {
    match names {
        [one] => format!("“{one}” was"),
        many => format!(
            "{} were",
            many.iter()
                .map(|n| format!("“{n}”"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

unsafe fn apply_hotkey(hwnd: HWND, enabled: bool) {
    UnregisterHotKey(hwnd, HOTKEY_ID);
    if enabled
        && RegisterHotKey(
            hwnd,
            HOTKEY_ID,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
            u32::from(b'L'),
        ) == 0
    {
        log::warn!("Ctrl+Alt+L is already used by another program");
    }
}

fn tray_data(hwnd: HWND) -> NOTIFYICONDATAW {
    // SAFETY: NOTIFYICONDATAW is plain data.
    let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = 1;
    data
}

fn copy_into(dest: &mut [u16], text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(dest.len() - 1).collect();
    dest[..units.len()].copy_from_slice(&units);
    dest[units.len()] = 0;
}

fn load_icon(id: u16) -> HICON {
    // SAFETY: loads an icon resource embedded by build.rs.
    unsafe {
        LoadImageW(
            GetModuleHandleW(null()),
            id as usize as *const u16,
            IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON),
            LR_DEFAULTCOLOR,
        ) as HICON
    }
}

fn add_tray_icon(hwnd: HWND) {
    update_tray_icon(hwnd, NIM_ADD);
    let mut data = tray_data(hwnd);
    data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    // SAFETY: valid NOTIFYICONDATAW for our window.
    unsafe { Shell_NotifyIconW(NIM_SETVERSION, &data) };
}

fn update_tray_icon(hwnd: HWND, operation: u32) {
    let drives = app().unlocked_drives();
    let mut data = tray_data(hwnd);
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = load_icon(if drives.is_empty() { 101 } else { 102 });
    let tip = match drives.as_slice() {
        [] => "File Locker — all vaults locked".to_string(),
        [(name, drive)] => format!("File Locker — “{name}” unlocked ({drive})"),
        many => format!("File Locker — {} vaults unlocked", many.len()),
    };
    copy_into(&mut data.szTip, &tip);
    // SAFETY: valid NOTIFYICONDATAW for our window.
    unsafe { Shell_NotifyIconW(operation, &data) };
}

fn remove_tray_icon(hwnd: HWND) {
    let data = tray_data(hwnd);
    // SAFETY: valid NOTIFYICONDATAW for our window.
    unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
}

fn show_balloon(hwnd: HWND, title: &str, text: &str) {
    let mut data = tray_data(hwnd);
    data.uFlags = NIF_INFO;
    copy_into(&mut data.szInfoTitle, title);
    copy_into(&mut data.szInfo, text);
    data.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
    // SAFETY: valid NOTIFYICONDATAW for our window.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

unsafe fn show_menu(hwnd: HWND) {
    let vaults = app().vaults();
    let menu = CreatePopupMenu();
    let add = |id: u32, text: &str, enabled: bool| {
        let flags = if enabled {
            MF_STRING
        } else {
            MF_STRING | MF_GRAYED
        };
        AppendMenuW(menu, flags, id as usize, wide(text).as_ptr());
    };
    add(ID_OPEN_APP, "Open File Locker", true);
    SetMenuDefaultItem(menu, ID_OPEN_APP, 0);
    AppendMenuW(menu, MF_SEPARATOR, 0, null());
    for (i, vault) in vaults.iter().enumerate() {
        let base = ID_VAULT_BASE + i as u32 * 4;
        // "&&" shows a literal ampersand in menus.
        let name = vault.name.replace('&', "&&");
        if vault.unlocked {
            add(
                base + ACTION_OPEN,
                &format!("Open “{name}” ({})", vault.drive),
                true,
            );
            add(base + ACTION_LOCK, &format!("Lock “{name}”"), !vault.busy);
        } else {
            add(
                base + ACTION_UNLOCK,
                &format!("Unlock “{name}”…"),
                !vault.busy,
            );
        }
    }
    if !vaults.is_empty() {
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
    }
    add(ID_LOCK_ALL, "Lock all vaults", app().any_unlocked());
    add(ID_CREATE, "Create a vault…", true);
    add(ID_SETTINGS, "Settings…", true);
    AppendMenuW(menu, MF_SEPARATOR, 0, null());
    add(ID_EXIT, "Exit", true);

    let mut point = POINT { x: 0, y: 0 };
    GetCursorPos(&mut point);
    // Required so the menu closes when clicking elsewhere.
    SetForegroundWindow(hwnd);
    let command = TrackPopupMenuEx(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        point.x,
        point.y,
        hwnd,
        null(),
    ) as u32;
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
    run_command(hwnd, command, &vaults);
}

fn run_command(hwnd: HWND, command: u32, vaults: &[crate::app::VaultView]) {
    match command {
        0 => {}
        ID_OPEN_APP => ui::show_main(),
        ID_CREATE => ui::show_create(),
        ID_SETTINGS => ui::show_settings(),
        ID_LOCK_ALL => {
            actions::lock_all_interactive(app(), hwnd as isize);
        }
        ID_EXIT => {
            if actions::lock_all_interactive(app(), hwnd as isize) {
                ui::quit();
            }
        }
        id if id >= ID_VAULT_BASE => {
            let index = ((id - ID_VAULT_BASE) / 4) as usize;
            let Some(vault) = vaults.get(index) else {
                return;
            };
            match (id - ID_VAULT_BASE) % 4 {
                ACTION_UNLOCK => ui::show_unlock(vault.path.clone()),
                ACTION_OPEN => crate::system::open_in_explorer(&format!("{}\\", vault.drive)),
                ACTION_LOCK => {
                    actions::lock_interactive(app(), &vault.path, hwnd as isize);
                }
                _ => {}
            }
        }
        _ => {}
    }
}
