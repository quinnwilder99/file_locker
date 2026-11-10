//! The windows. Everything here runs on the UI (main) thread; other threads
//! reach it through the `show_*` functions and [`refresh`], which post to the
//! Slint event loop. Slow work (unlocking, creating, copying) runs on worker
//! threads and reports back the same way.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use vault_core::Vault;
use zeroize::Zeroizing;

use crate::app::{check_new_password, password_strength, App, VaultView};
use crate::moveinto::{move_into, Report};
use crate::system::{self, error_box, message_box, MB_ICONINFORMATION, MB_OK};
use crate::{actions, shell};

slint::include_modules!();

type AfterUnlock = Box<dyn FnOnce(&Rc<Ui>)>;

pub struct Ui {
    app: Arc<App>,
    main: MainWindow,
    unlock: UnlockDialog,
    create: CreateDialog,
    recover: RecoverDialog,
    password: PasswordDialog,
    settings: SettingsDialog,
    mover: MoveDialog,
    about: AboutDialog,
    /// The vault list shown in the main window, updated row by row so that
    /// buttons are not recreated (and clicks not lost) on every refresh.
    rows: Rc<VecModel<VaultRow>>,
    state: RefCell<State>,
}

#[derive(Default)]
struct State {
    unlock_path: Option<PathBuf>,
    after_unlock: Option<AfterUnlock>,
    /// The vault just created, unlocked, until the wizard finishes.
    created: Option<(PathBuf, Vault)>,
    recovery_text: Zeroizing<String>,
    recover_path: Option<PathBuf>,
    password_path: Option<PathBuf>,
    move_sources: Vec<PathBuf>,
    move_targets: Vec<PathBuf>,
    move_cancel: Arc<AtomicBool>,
    moving: bool,
    centered: HashSet<&'static str>,
}

thread_local! {
    static UI: RefCell<Option<Rc<Ui>>> = const { RefCell::new(None) };
}

fn with_ui<R>(f: impl FnOnce(&Rc<Ui>) -> R) -> Option<R> {
    let ui = UI.with(|u| u.borrow().clone());
    ui.map(|ui| f(&ui))
}

/// Runs `f` on the UI thread.
fn post(f: impl FnOnce(&Rc<Ui>) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        with_ui(f);
    });
}

fn hwnd(window: &slint::Window) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let handle = window.window_handle();
    match handle.window_handle().map(|h| h.as_raw()) {
        Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
        _ => 0,
    }
}

/// Shows a window, centred the first time, and brings it to the front.
fn present(ui: &Ui, id: &'static str, window: &slint::Window) {
    let _ = window.show();
    if ui.state.borrow_mut().centered.insert(id) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
        };
        let size = window.size();
        // SAFETY: plain metric queries.
        let (sw, sh) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
        let x = (sw - size.width as i32).max(0) / 2;
        let y = (sh - size.height as i32).max(0) / 3;
        window.set_position(slint::PhysicalPosition::new(x, y));
    }
    system::bring_to_front(hwnd(window));
}

fn spawn(work: impl FnOnce() + Send + 'static) {
    std::thread::spawn(work);
}

pub fn init(app: Arc<App>) -> Result<(), slint::PlatformError> {
    let ui = Rc::new(Ui {
        app,
        main: MainWindow::new()?,
        unlock: UnlockDialog::new()?,
        create: CreateDialog::new()?,
        recover: RecoverDialog::new()?,
        password: PasswordDialog::new()?,
        settings: SettingsDialog::new()?,
        mover: MoveDialog::new()?,
        about: AboutDialog::new()?,
        rows: Rc::new(VecModel::default()),
        state: RefCell::new(State::default()),
    });
    ui.main.set_vaults(ModelRc::from(ui.rows.clone()));
    wire_main(&ui);
    wire_unlock(&ui);
    wire_create(&ui);
    wire_recover(&ui);
    wire_password(&ui);
    wire_settings(&ui);
    wire_move(&ui);
    refresh_now(&ui);
    UI.with(|u| *u.borrow_mut() = Some(ui));
    Ok(())
}

// ---------------------------------------------------------------- public API

pub fn show_main() {
    post(|ui| {
        refresh_now(ui);
        present(ui, "main", ui.main.window());
    });
}

/// Unlocks the vault at `path` (a vault folder or its `.flkvault` file),
/// adding it to the list first if it is new.
pub fn show_unlock(path: PathBuf) {
    post(move |ui| match ui.app.add_vault(&path) {
        Ok(entry) => open_unlock(ui, entry.path, None),
        Err(e) => error_box(0, &e),
    });
}

pub fn show_create() {
    post(open_create);
}

pub fn show_settings() {
    post(open_settings);
}

pub fn show_move(paths: Vec<PathBuf>) {
    post(move |ui| open_move(ui, paths));
}

pub fn refresh() {
    post(refresh_now);
}

pub fn quit() {
    post(|ui| {
        for window in [
            ui.main.window(),
            ui.unlock.window(),
            ui.create.window(),
            ui.recover.window(),
            ui.password.window(),
            ui.settings.window(),
            ui.mover.window(),
            ui.about.window(),
        ] {
            let _ = window.hide();
        }
        let _ = slint::quit_event_loop();
    });
}

// ---------------------------------------------------------------- main window

fn refresh_now(ui: &Rc<Ui>) {
    let rows: Vec<VaultRow> = ui
        .app
        .vaults()
        .into_iter()
        .map(|v| VaultRow {
            name: v.name.into(),
            path: v.path.display().to_string().into(),
            unlocked: v.unlocked,
            drive: v.drive.into(),
            busy: v.busy,
        })
        .collect();
    ui.main.set_any_unlocked(rows.iter().any(|r| r.unlocked));
    use slint::Model;
    let model = &ui.rows;
    for (i, row) in rows.iter().enumerate() {
        match model.row_data(i) {
            Some(old) if old == *row => {}
            Some(_) => model.set_row_data(i, row.clone()),
            None => model.push(row.clone()),
        }
    }
    while model.row_count() > rows.len() {
        model.remove(model.row_count() - 1);
    }
}

fn status(ui: &Ui, text: &str, is_error: bool) {
    ui.main.set_status(text.into());
    ui.main.set_status_is_error(is_error);
}

fn vault_at(ui: &Ui, index: i32) -> Option<VaultView> {
    ui.app
        .vaults()
        .into_iter()
        .nth(usize::try_from(index).ok()?)
}

fn wire_main(ui: &Rc<Ui>) {
    ui.main.on_unlock(|i| {
        with_ui(|ui| {
            if let Some(v) = vault_at(ui, i) {
                open_unlock(ui, v.path, None);
            }
        });
    });
    ui.main.on_open(|i| {
        with_ui(|ui| {
            if let Some(v) = vault_at(ui, i).filter(|v| v.unlocked) {
                system::open_in_explorer(&format!("{}\\", v.drive));
            }
        });
    });
    ui.main.on_lock(|i| {
        with_ui(|ui| {
            if let Some(v) = vault_at(ui, i) {
                status(ui, "", false);
                actions::lock_interactive(&ui.app, &v.path, hwnd(ui.main.window()));
            }
        });
    });
    ui.main.on_change_password(|i| {
        with_ui(|ui| {
            if let Some(v) = vault_at(ui, i) {
                open_password(ui, v);
            }
        });
    });
    ui.main.on_remove(|i| {
        with_ui(|ui| {
            let Some(v) = vault_at(ui, i) else { return };
            let text = format!(
                "Remove “{}” from the list?\n\nThe vault folder and the files in it are not deleted. You can add it back with “Add existing”.",
                v.name
            );
            if message_box(hwnd(ui.main.window()), "Remove vault", &text, system::MB_YESNO | system::MB_ICONWARNING | system::MB_DEFBUTTON2) == system::IDYES {
                match ui.app.remove_vault(&v.path) {
                    Ok(()) => status(ui, &format!("Removed “{}” from the list.", v.name), false),
                    Err(e) => status(ui, &e, true),
                }
            }
        });
    });
    ui.main.on_create(|| {
        with_ui(open_create);
    });
    ui.main.on_add_existing(|| {
        with_ui(|ui| {
            let Some(folder) = rfd::FileDialog::new()
                .set_title("Choose the vault folder")
                .pick_folder()
            else {
                return;
            };
            match ui.app.add_vault(&folder) {
                Ok(entry) => status(ui, &format!("Added “{}”.", entry.name), false),
                Err(e) => status(ui, &e, true),
            }
        });
    });
    ui.main.on_settings(|| {
        with_ui(open_settings);
    });
    ui.main.on_lock_all(|| {
        with_ui(|ui| {
            status(ui, "", false);
            actions::lock_all_interactive(&ui.app, hwnd(ui.main.window()));
        });
    });
}

// ---------------------------------------------------------------- unlock

fn open_unlock(ui: &Rc<Ui>, path: PathBuf, after: Option<AfterUnlock>) {
    if let Some(drive) = ui.app.drive(&path) {
        match after {
            Some(after) => after(ui),
            None => system::open_in_explorer(&format!("{drive}\\")),
        }
        return;
    }
    let name = ui
        .app
        .entry(&path)
        .map(|e| e.name)
        .unwrap_or_else(|| path.display().to_string());
    let d = &ui.unlock;
    d.set_vault_name(name.into());
    d.set_vault_path(path.display().to_string().into());
    d.set_error("".into());
    d.set_busy(false);
    d.set_password("".into());
    {
        let mut st = ui.state.borrow_mut();
        st.unlock_path = Some(path);
        st.after_unlock = after;
    }
    present(ui, "unlock", d.window());
    d.invoke_focus_password();
}

fn wire_unlock(ui: &Rc<Ui>) {
    ui.unlock.on_unlock(|password| {
        with_ui(|ui| {
            let Some(path) = ui.state.borrow().unlock_path.clone() else {
                return;
            };
            let password = Zeroizing::new(password.to_string());
            let d = &ui.unlock;
            d.set_password("".into());
            d.set_error("".into());
            d.set_busy(true);
            let app = ui.app.clone();
            spawn(move || {
                let result = app.unlock(&path, password.as_bytes());
                post(move |ui| finish_unlock(ui, result));
            });
        });
    });
    ui.unlock.on_cancel(|| {
        with_ui(|ui| {
            ui.state.borrow_mut().after_unlock = None;
            let _ = ui.unlock.hide();
        });
    });
    ui.unlock.on_forgot(|| {
        with_ui(|ui| {
            let Some(path) = ui.state.borrow().unlock_path.clone() else {
                return;
            };
            ui.state.borrow_mut().after_unlock = None;
            let _ = ui.unlock.hide();
            open_recover(ui, path);
        });
    });
}

fn finish_unlock(ui: &Rc<Ui>, result: Result<String, String>) {
    let d = &ui.unlock;
    d.set_busy(false);
    match result {
        Ok(drive) => {
            let _ = d.hide();
            let after = ui.state.borrow_mut().after_unlock.take();
            match after {
                Some(after) => after(ui),
                None if ui.app.settings().open_explorer => {
                    system::open_in_explorer(&format!("{drive}\\"))
                }
                None => {}
            }
        }
        Err(e) => {
            d.set_error(e.into());
            d.invoke_focus_password();
        }
    }
}

// ---------------------------------------------------------------- create

fn open_create(ui: &Rc<Ui>) {
    let d = &ui.create;
    if ui.state.borrow().created.is_none() && !d.get_busy() {
        d.set_page(0);
        d.set_name("My Vault".into());
        d.set_location(system::documents_dir().display().to_string().into());
        d.set_password("".into());
        d.set_confirm("".into());
        d.set_strength("".into());
        d.set_strength_level(0);
        d.set_error("".into());
        d.set_saved(false);
        d.set_unlock_now(true);
        d.set_key_note("".into());
    }
    present(ui, "create", d.window());
}

fn wire_create(ui: &Rc<Ui>) {
    ui.create.on_browse(|| {
        with_ui(|ui| {
            let current = ui.create.get_location().to_string();
            let mut dialog = rfd::FileDialog::new().set_title("Choose where to create the vault");
            if Path::new(&current).is_dir() {
                dialog = dialog.set_directory(&current);
            }
            if let Some(folder) = dialog.pick_folder() {
                ui.create.set_location(folder.display().to_string().into());
            }
        });
    });
    ui.create.on_password_edited(|text| {
        with_ui(|ui| {
            let (level, label) = password_strength(&text);
            ui.create.set_strength_level(level);
            ui.create.set_strength(label.into());
        });
    });
    ui.create.on_create(|name, location, password, confirm| {
        with_ui(|ui| {
            let d = &ui.create;
            let password = Zeroizing::new(password.to_string());
            if let Err(e) = check_new_password(&password, &confirm) {
                d.set_error(e.into());
                return;
            }
            d.set_error("".into());
            d.set_busy(true);
            let app = ui.app.clone();
            let (name, location) = (name.to_string(), PathBuf::from(location.to_string()));
            spawn(move || {
                let result = app.create_vault(&location, &name, password.as_bytes());
                post(move |ui| finish_create(ui, result));
            });
        });
    });
    ui.create.on_copy_key(|| {
        with_ui(|ui| {
            let text = ui.state.borrow().recovery_text.clone();
            let ok = system::set_clipboard(hwnd(ui.create.window()), &text);
            ui.create
                .set_key_note(if ok { "Copied." } else { "Could not copy." }.into());
        });
    });
    ui.create.on_save_key(|| {
        with_ui(|ui| {
            let name = ui.create.get_name().to_string();
            let Some(file) = rfd::FileDialog::new()
                .set_title("Save the recovery key")
                .set_file_name(format!("{} recovery key.txt", name.trim()))
                .add_filter("Text file", &["txt"])
                .save_file()
            else {
                return;
            };
            let path = ui
                .state
                .borrow()
                .created
                .as_ref()
                .map(|(p, _)| p.display().to_string())
                .unwrap_or_default();
            let text = Zeroizing::new(format!(
                "File Locker recovery key\r\n\r\nVault: {}\r\nFolder: {path}\r\n\r\nRecovery key:\r\n{}\r\n\r\nUse it in File Locker with \"Forgot password?\" to set a new password.\r\nKeep this file somewhere safe and away from the vault.\r\n",
                name.trim(),
                ui.state.borrow().recovery_text.as_str()
            ));
            match std::fs::write(&file, text.as_bytes()) {
                Ok(()) => ui.create.set_key_note("Saved.".into()),
                Err(e) => error_box(hwnd(ui.create.window()), &format!("Could not save the file: {e}")),
            }
        });
    });
    ui.create.on_finish(|unlock_now| {
        with_ui(|ui| finish_wizard(ui, unlock_now));
    });
    ui.create.on_cancel(|| {
        with_ui(|ui| {
            let _ = ui.create.hide();
        });
    });
    ui.create.window().on_close_requested(|| {
        with_ui(|ui| {
            let d = &ui.create;
            if d.get_busy() {
                return slint::CloseRequestResponse::KeepWindowShown;
            }
            if d.get_page() == 1 {
                if !d.get_saved() {
                    message_box(
                        hwnd(d.window()),
                        "Save your recovery key",
                        "Your vault is created. Save its recovery key, then tick “I saved my recovery key” and press Finish.\n\nWithout it, a forgotten password means losing your files.",
                        MB_OK | system::MB_ICONWARNING,
                    );
                    return slint::CloseRequestResponse::KeepWindowShown;
                }
                finish_wizard(ui, false);
            }
            slint::CloseRequestResponse::HideWindow
        })
        .unwrap_or_default()
    });
}

fn finish_create(ui: &Rc<Ui>, result: Result<(PathBuf, Vault, vault_core::RecoveryKey), String>) {
    let d = &ui.create;
    d.set_busy(false);
    match result {
        Ok((root, vault, key)) => {
            let text = key.to_display_string();
            let groups: Vec<&str> = text.split('-').collect();
            let half = groups.len().div_ceil(2);
            d.set_key_line_1(groups[..half].join("-").into());
            d.set_key_line_2(groups[half..].join("-").into());
            d.set_password("".into());
            d.set_confirm("".into());
            d.set_saved(false);
            d.set_page(1);
            let mut st = ui.state.borrow_mut();
            st.recovery_text = Zeroizing::new(text.to_string());
            st.created = Some((root, vault));
        }
        Err(e) => d.set_error(e.into()),
    }
}

fn finish_wizard(ui: &Rc<Ui>, unlock_now: bool) {
    let created = {
        let mut st = ui.state.borrow_mut();
        st.recovery_text = Zeroizing::default();
        st.created.take()
    };
    let d = &ui.create;
    d.set_key_line_1("".into());
    d.set_key_line_2("".into());
    d.set_page(0);
    let _ = d.hide();
    let Some((root, vault)) = created else { return };
    if unlock_now {
        let app = ui.app.clone();
        spawn(move || {
            let result = app.mount_vault(&root, vault);
            post(move |ui| finish_unlock(ui, result));
        });
    }
    refresh_now(ui);
    present(ui, "main", ui.main.window());
}

// ---------------------------------------------------------------- recovery

fn open_recover(ui: &Rc<Ui>, path: PathBuf) {
    let d = &ui.recover;
    let name = ui
        .app
        .entry(&path)
        .map(|e| e.name)
        .unwrap_or_else(|| path.display().to_string());
    d.set_vault_name(name.into());
    d.set_key("".into());
    d.set_password("".into());
    d.set_confirm("".into());
    d.set_error("".into());
    d.set_busy(false);
    ui.state.borrow_mut().recover_path = Some(path);
    present(ui, "recover", d.window());
}

fn wire_recover(ui: &Rc<Ui>) {
    ui.recover.on_reset(|key, password, confirm| {
        with_ui(|ui| {
            let d = &ui.recover;
            let Some(path) = ui.state.borrow().recover_path.clone() else { return };
            let password = Zeroizing::new(password.to_string());
            if let Err(e) = check_new_password(&password, &confirm) {
                d.set_error(e.into());
                return;
            }
            let key = Zeroizing::new(key.to_string());
            d.set_error("".into());
            d.set_busy(true);
            let app = ui.app.clone();
            spawn(move || {
                // Reset, then unlock straight away: that is what the user wanted.
                let result = app
                    .recover(&path, &key, password.as_bytes())
                    .map(|vault| app.mount_vault(&path, vault).ok());
                post(move |ui| {
                    let d = &ui.recover;
                    d.set_busy(false);
                    match result {
                        Ok(drive) => {
                            d.set_key("".into());
                            d.set_password("".into());
                            d.set_confirm("".into());
                            let _ = d.hide();
                            let name = d.get_vault_name();
                            match drive {
                                Some(drive) => {
                                    status(ui, &format!("New password set. “{name}” is unlocked as {drive}."), false);
                                    if ui.app.settings().open_explorer {
                                        system::open_in_explorer(&format!("{drive}\\"));
                                    }
                                }
                                None => status(ui, &format!("New password set for “{name}”. Unlock it with the new password."), false),
                            }
                        }
                        Err(e) => d.set_error(e.into()),
                    }
                });
            });
        });
    });
    ui.recover.on_cancel(|| {
        with_ui(|ui| {
            let _ = ui.recover.hide();
        });
    });
}

// ---------------------------------------------------------------- change password

fn open_password(ui: &Rc<Ui>, vault: VaultView) {
    let d = &ui.password;
    d.set_vault_name(vault.name.into());
    d.set_current("".into());
    d.set_password("".into());
    d.set_confirm("".into());
    d.set_error("".into());
    d.set_busy(false);
    ui.state.borrow_mut().password_path = Some(vault.path);
    present(ui, "password", d.window());
}

fn wire_password(ui: &Rc<Ui>) {
    ui.password.on_change(|current, password, confirm| {
        with_ui(|ui| {
            let d = &ui.password;
            let Some(path) = ui.state.borrow().password_path.clone() else { return };
            let password = Zeroizing::new(password.to_string());
            if let Err(e) = check_new_password(&password, &confirm) {
                d.set_error(e.into());
                return;
            }
            let current = Zeroizing::new(current.to_string());
            d.set_error("".into());
            d.set_busy(true);
            let app = ui.app.clone();
            spawn(move || {
                let result = app.change_password(&path, current.as_bytes(), password.as_bytes());
                post(move |ui| {
                    let d = &ui.password;
                    d.set_busy(false);
                    match result {
                        Ok(()) => {
                            d.set_current("".into());
                            d.set_password("".into());
                            d.set_confirm("".into());
                            let _ = d.hide();
                            let name = d.get_vault_name();
                            status(ui, &format!("Password changed for “{name}”."), false);
                            message_box(
                                hwnd(ui.main.window()),
                                "Password changed",
                                &format!("The password of “{name}” was changed. Your recovery key still works."),
                                MB_OK | MB_ICONINFORMATION,
                            );
                        }
                        Err(e) => d.set_error(e.into()),
                    }
                });
            });
        });
    });
    ui.password.on_cancel(|| {
        with_ui(|ui| {
            let _ = ui.password.hide();
        });
    });
}

// ---------------------------------------------------------------- settings

fn open_settings(ui: &Rc<Ui>) {
    let s = ui.app.settings();
    let d = &ui.settings;
    d.set_lock_on_sleep(s.lock_on_sleep);
    d.set_lock_on_windows_lock(s.lock_on_windows_lock);
    d.set_idle_enabled(s.idle_minutes > 0);
    d.set_idle_minutes(if s.idle_minutes > 0 {
        s.idle_minutes as i32
    } else {
        15
    });
    d.set_open_explorer(s.open_explorer);
    d.set_hotkey(s.hotkey);
    d.set_start_with_windows(system::starts_with_windows());
    d.set_version(env!("CARGO_PKG_VERSION").into());
    d.set_winfsp(
        if flk_mount::winfsp_available() {
            "WinFsp installed"
        } else {
            "WinFsp is NOT installed: vaults cannot be opened as drives"
        }
        .into(),
    );
    present(ui, "settings", d.window());
}

fn wire_settings(ui: &Rc<Ui>) {
    ui.settings.on_save(|| {
        with_ui(|ui| {
            let d = &ui.settings;
            let idle = if d.get_idle_enabled() {
                d.get_idle_minutes().clamp(1, 240) as u32
            } else {
                0
            };
            let hotkey = d.get_hotkey();
            let result = ui.app.update_settings(|s| {
                s.lock_on_sleep = d.get_lock_on_sleep();
                s.lock_on_windows_lock = d.get_lock_on_windows_lock();
                s.idle_minutes = idle;
                s.open_explorer = d.get_open_explorer();
                s.hotkey = hotkey;
            });
            let startup = if d.get_start_with_windows() != system::starts_with_windows() {
                system::set_start_with_windows(d.get_start_with_windows())
            } else {
                Ok(())
            };
            shell::set_hotkey(hotkey);
            match result.and(startup) {
                Ok(()) => {
                    let _ = d.hide();
                }
                Err(e) => error_box(hwnd(d.window()), &e),
            }
        });
    });
    ui.settings.on_cancel(|| {
        with_ui(|ui| {
            let _ = ui.settings.hide();
        });
    });
    ui.settings.on_about(|| {
        with_ui(|ui| {
            ui.about.set_version(env!("CARGO_PKG_VERSION").into());
            present(ui, "about", ui.about.window());
        });
    });
    ui.about.on_dismiss(|| {
        with_ui(|ui| {
            let _ = ui.about.hide();
        });
    });
}

// ---------------------------------------------------------------- move into vault

/// `(item lines, "from" line)` for the move window: names, not full paths.
fn describe_sources(sources: &[PathBuf]) -> (String, String) {
    const SHOWN: usize = 4;
    let mut lines: Vec<String> = sources
        .iter()
        .take(SHOWN)
        .map(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.display().to_string());
            if p.is_dir() {
                format!("📁 {name}")
            } else {
                format!("📄 {name}")
            }
        })
        .collect();
    if sources.len() > SHOWN {
        lines.push(format!("…and {} more", sources.len() - SHOWN));
    }
    let parents: HashSet<_> = sources.iter().filter_map(|p| p.parent()).collect();
    let from = match parents.into_iter().collect::<Vec<_>>().as_slice() {
        [one] => format!("From {}", one.display()),
        [] => String::new(),
        _ => "From several folders".to_string(),
    };
    (lines.join("\n"), from)
}

fn open_move(ui: &Rc<Ui>, paths: Vec<PathBuf>) {
    let d = &ui.mover;
    if ui.state.borrow().moving {
        error_box(
            hwnd(d.window()),
            "A move is already in progress. Wait for it to finish, then try again.",
        );
        return;
    }
    // Explorer starts one process per selected item; collect them all.
    if d.get_state() == 2 {
        ui.state.borrow_mut().move_sources.clear();
    }
    {
        let mut st = ui.state.borrow_mut();
        for path in paths {
            let path = std::path::absolute(&path).unwrap_or(path);
            if !st.move_sources.contains(&path) {
                st.move_sources.push(path);
            }
        }
    }
    let vaults = ui.app.vaults();
    let names: Vec<SharedString> = vaults
        .iter()
        .map(|v| {
            if v.unlocked {
                format!("{} (unlocked, {})", v.name, v.drive)
            } else {
                v.name.clone()
            }
            .into()
        })
        .collect();
    let preferred = vaults.iter().position(|v| v.unlocked).unwrap_or(0);
    let sources = ui.state.borrow().move_sources.clone();
    let (items, from) = describe_sources(&sources);
    d.set_sources(items.into());
    d.set_from(from.into());
    d.set_source_count(sources.len() as i32);
    d.set_vault_names(ModelRc::new(VecModel::from(names)));
    d.set_vault_index(preferred as i32);
    d.set_state(0);
    d.set_progress(0.0);
    d.set_status(
        if vaults.is_empty() {
            "Create a vault first."
        } else {
            ""
        }
        .into(),
    );
    d.set_status_is_error(false);
    ui.state.borrow_mut().move_targets = vaults.into_iter().map(|v| v.path).collect();
    present(ui, "move", d.window());
}

fn wire_move(ui: &Rc<Ui>) {
    ui.mover.on_move(|index| {
        with_ui(|ui| {
            let Some(target) = ui.state.borrow().move_targets.get(index as usize).cloned() else {
                return;
            };
            let sources = ui.state.borrow().move_sources.clone();
            let target_key = target.to_string_lossy().to_lowercase();
            if let Some(bad) = sources.iter().find(|s| {
                let s = s.to_string_lossy().to_lowercase();
                s.starts_with(&target_key) || target_key.starts_with(&s)
            }) {
                error_box(hwnd(ui.mover.window()), &format!(
                    "“{}” is part of the vault's own folder (or contains it) and cannot be moved into it.",
                    bad.display()
                ));
                return;
            }
            if let Some(drive) = ui.app.drive(&target) {
                if let Some(bad) = sources.iter().find(|s| system::is_on_drive(s, &drive)) {
                    error_box(hwnd(ui.mover.window()), &format!("“{}” is already in this vault.", bad.display()));
                    return;
                }
            }
            let then = target.clone();
            open_unlock(ui, target, Some(Box::new(move |ui| start_move(ui, then))));
        });
    });
    ui.mover.on_cancel(|| {
        with_ui(|ui| ui.state.borrow().move_cancel.store(true, Ordering::Relaxed));
    });
    ui.mover.on_dismiss(|| {
        with_ui(|ui| {
            if !ui.state.borrow().moving {
                ui.state.borrow_mut().move_sources.clear();
                let _ = ui.mover.hide();
            }
        });
    });
    ui.mover.window().on_close_requested(|| {
        with_ui(|ui| {
            if ui.state.borrow().moving {
                return slint::CloseRequestResponse::KeepWindowShown;
            }
            ui.state.borrow_mut().move_sources.clear();
            slint::CloseRequestResponse::HideWindow
        })
        .unwrap_or_default()
    });
}

fn start_move(ui: &Rc<Ui>, target: PathBuf) {
    let Some(drive) = ui.app.drive(&target) else {
        return;
    };
    let vault_name = ui.app.entry(&target).map(|e| e.name).unwrap_or_default();
    let cancel = Arc::new(AtomicBool::new(false));
    let sources = {
        let mut st = ui.state.borrow_mut();
        st.moving = true;
        st.move_cancel = cancel.clone();
        st.move_sources.clone()
    };
    let d = &ui.mover;
    d.set_state(1);
    d.set_progress(0.0);
    d.set_status("Starting…".into());
    d.set_status_is_error(false);
    present(ui, "move", d.window());
    spawn(move || {
        let dest = PathBuf::from(format!("{drive}\\"));
        let mut last = Instant::now() - Duration::from_secs(1);
        let report = move_into(&sources, &dest, &cancel, &mut |p| {
            if last.elapsed() >= Duration::from_millis(100) {
                last = Instant::now();
                let fraction = if p.total == 0 {
                    0.0
                } else {
                    p.done as f32 / p.total as f32
                };
                let current = Path::new(&p.current)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                post(move |ui| {
                    ui.mover.set_progress(fraction);
                    ui.mover.set_status(format!("Copying {current}…").into());
                });
            }
        });
        post(move |ui| finish_move(ui, &vault_name, &drive, report));
    });
}

fn finish_move(ui: &Rc<Ui>, vault: &str, drive: &str, report: Report) {
    let d = &ui.mover;
    {
        let mut st = ui.state.borrow_mut();
        st.moving = false;
        st.move_sources = report.kept.iter().map(|(p, _)| p.clone()).collect();
    }
    d.set_state(2);
    d.set_progress(1.0);
    let moved = report.moved.len();
    let mut text = match moved {
        0 => "Nothing was moved.".to_string(),
        1 => format!("Moved 1 item into “{vault}” ({drive})."),
        n => format!("Moved {n} items into “{vault}” ({drive})."),
    };
    if report.cancelled {
        text.push_str(" Stopped before the end; the rest stayed where it was.");
    }
    let problems: Vec<_> = report
        .kept
        .iter()
        .filter(|(_, why)| why != "stopped")
        .collect();
    for (path, why) in problems.iter().take(4) {
        text.push_str(&format!("\n• {} was kept: {why}.", path.display()));
    }
    d.set_status(text.into());
    d.set_status_is_error(!problems.is_empty());
    if moved > 0 && ui.app.settings().open_explorer {
        system::open_in_explorer(&format!("{drive}\\"));
    }
}
