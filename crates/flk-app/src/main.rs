//! File Locker: a tray app that unlocks encrypted vaults as drives.
//!
//! ```text
//! FileLocker.exe                      open the main window
//! FileLocker.exe --tray               start in the tray only (sign-in)
//! FileLocker.exe --unlock <path>      unlock a vault (folder or .flkvault file)
//! FileLocker.exe --move-into <path>…  move files or folders into a vault
//! ```
//! A second launch hands its command line to the running instance.

#![windows_subsystem = "windows"]

mod actions;
mod app;
mod logging;
mod moveinto;
mod settings;
mod shell;
mod system;
mod ui;

use std::path::PathBuf;

use app::App;

#[derive(Debug, PartialEq)]
pub enum Command {
    Show,
    Tray,
    Unlock(PathBuf),
    MoveInto(Vec<PathBuf>),
}

pub fn parse_args(args: &[String]) -> Command {
    match args.first().map(String::as_str) {
        Some("--tray") => Command::Tray,
        Some("--unlock") if args.len() > 1 => Command::Unlock(PathBuf::from(&args[1])),
        Some("--move-into") if args.len() > 1 => {
            Command::MoveInto(args[1..].iter().map(PathBuf::from).collect())
        }
        // Double-clicking a .flkvault file may pass just the path.
        Some(path) if path.to_lowercase().ends_with(".flkvault") => {
            Command::Unlock(PathBuf::from(path))
        }
        _ => Command::Show,
    }
}

/// Acts on a command, from this launch or a later one.
pub fn dispatch(command: Command) {
    match command {
        Command::Show => ui::show_main(),
        Command::Tray => {}
        Command::Unlock(path) => ui::show_unlock(path),
        Command::MoveInto(paths) => ui::show_move(paths),
    }
}

fn main() {
    logging::init(settings::log_dir());
    std::panic::set_hook(Box::new(|info| {
        log::error!("crash: {info}");
        system::error_box(
            0,
            &format!("File Locker ran into a problem and has to close. Unlocked vaults are locked.\n\n{info}"),
        );
    }));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = parse_args(&args);
    if !system::claim_single_instance() {
        if !shell::forward_to_running(&args) {
            system::error_box(0, "File Locker is already running but does not respond.");
        }
        return;
    }
    log::info!("starting File Locker {}", env!("CARGO_PKG_VERSION"));

    let app = App::new(
        settings::data_dir(),
        Box::new(|| {
            ui::refresh();
            shell::refresh();
        }),
    );
    if let Err(e) = ui::init(app.clone()) {
        system::error_box(0, &format!("File Locker could not open its windows: {e}"));
        return;
    }
    shell::start(app.clone());
    if !flk_mount::winfsp_available() {
        system::message_box(
            0,
            "File Locker",
            app::WINFSP_MISSING,
            system::MB_OK | system::MB_ICONWARNING,
        );
    }
    dispatch(command);

    if let Err(e) = slint::run_event_loop_until_quit() {
        log::error!("event loop: {e}");
    }
    let _ = app.lock_all(true);
    shell::stop();
    log::info!("exited");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn command_line() {
        assert_eq!(parse_args(&[]), Command::Show);
        assert_eq!(parse_args(&args(&["--tray"])), Command::Tray);
        assert_eq!(
            parse_args(&args(&["--unlock", "D:\\V"])),
            Command::Unlock("D:\\V".into())
        );
        assert_eq!(
            parse_args(&args(&["D:\\V\\Unlock vault.flkvault"])),
            Command::Unlock("D:\\V\\Unlock vault.flkvault".into())
        );
        assert_eq!(
            parse_args(&args(&["--move-into", "a", "b"])),
            Command::MoveInto(vec!["a".into(), "b".into()])
        );
        assert_eq!(parse_args(&args(&["--unlock"])), Command::Show);
    }
}
