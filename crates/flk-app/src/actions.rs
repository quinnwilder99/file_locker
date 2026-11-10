//! Locking with the user in the loop, shared by the tray and the windows.

use std::path::Path;

use crate::app::{App, LockResult};
use crate::system::{apps_using, message_box, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO};

/// Locks a vault. If files on it are open, says which (and which apps hold
/// them) and asks first. Returns true if the vault ends up locked.
pub fn lock_interactive(app: &App, path: &Path, owner: isize) -> bool {
    match app.lock(path, false) {
        LockResult::Locked | LockResult::NotUnlocked => true,
        LockResult::FilesOpen(files) => {
            if confirm_open_files(&files, owner) {
                app.lock(path, true);
                true
            } else {
                false
            }
        }
    }
}

/// Locks every vault, asking first if files are open. Returns true if all
/// vaults end up locked.
pub fn lock_all_interactive(app: &App, owner: isize) -> bool {
    match app.lock_all(false) {
        Ok(_) => true,
        Err(files) => {
            if confirm_open_files(&files, owner) {
                let _ = app.lock_all(true);
                true
            } else {
                false
            }
        }
    }
}

fn confirm_open_files(files: &[String], owner: isize) -> bool {
    const SHOWN: usize = 8;
    let mut text = String::from("These files are still open:\n\n");
    for file in files.iter().take(SHOWN) {
        text.push_str(&format!("    {file}\n"));
    }
    if files.len() > SHOWN {
        text.push_str(&format!("    …and {} more\n", files.len() - SHOWN));
    }
    let apps = apps_using(files);
    if apps.is_empty() {
        text.push_str("\nNo program could be named; Windows may still be finishing with them. Waiting a few seconds and trying again usually helps.\n");
    } else {
        text.push_str(&format!("\nThey are used by: {}.\n", apps.join(", ")));
    }
    text.push_str(
        "\nSave your work and close them first. If you lock now, unsaved changes in those apps may be lost.\n\nLock anyway?",
    );
    message_box(
        owner,
        "Files are still open",
        &text,
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
    ) == IDYES
}
