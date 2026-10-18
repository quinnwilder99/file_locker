//! `flk`: create, fill, read and manage file_locker vaults from the command line.

use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_core::{EntryKind, KdfParams, RecoveryKey, Stats, Vault};
use zeroize::Zeroizing;

const MIN_PASSWORD_CHARS: usize = 8;
/// How long unlocking should take on the machine that creates the vault.
const KDF_TARGET: Duration = Duration::from_secs(1);

#[derive(Parser)]
#[command(name = "flk", version, about = "Encrypted folder vaults")]
struct Cli {
    /// Read passwords and recovery keys from stdin, one per line, instead of prompting.
    #[arg(long, global = true)]
    password_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty vault and show its recovery key.
    Create { vault: PathBuf },
    /// Encrypt a file or folder into the vault.
    Import {
        vault: PathBuf,
        source: PathBuf,
        /// Vault folder to import into.
        #[arg(long, default_value = "/")]
        to: String,
    },
    /// Decrypt a vault file or folder into a new folder on disk.
    Export {
        vault: PathBuf,
        dest: PathBuf,
        /// Vault file or folder to export.
        #[arg(long, default_value = "/")]
        from: String,
    },
    /// List a vault folder.
    Ls {
        vault: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(short, long)]
        recursive: bool,
    },
    /// Change the vault password.
    Passwd { vault: PathBuf },
    /// Open the vault with its recovery key and set a new password.
    Recover { vault: PathBuf },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let input = SecretInput {
        from_stdin: cli.password_stdin,
    };
    match cli.command {
        Command::Create { vault } => create(&vault, &input),
        Command::Import { vault, source, to } => {
            let vault = unlock(&vault, &input)?;
            let stats = vault
                .import(&source, &to)
                .with_context(|| format!("importing {}", source.display()))?;
            report("Imported", &stats);
            Ok(())
        }
        Command::Export { vault, dest, from } => {
            let vault = unlock(&vault, &input)?;
            let stats = vault
                .export(&from, &dest)
                .with_context(|| format!("exporting to {}", dest.display()))?;
            report("Exported", &stats);
            Ok(())
        }
        Command::Ls {
            vault,
            path,
            recursive,
        } => print_tree(&unlock(&vault, &input)?, &path, recursive),
        Command::Passwd { vault } => {
            let mut vault = unlock(&vault, &input)?;
            let password = input.new_password()?;
            vault.change_password(password.as_bytes())?;
            println!("Password changed. Your recovery key is unchanged.");
            Ok(())
        }
        Command::Recover { vault: path } => {
            let text = input.secret("Recovery key: ")?;
            let recovery = RecoveryKey::parse(&text)?;
            let mut vault = Vault::unlock_with_recovery_key(&path, &recovery)?;
            let password = input.new_password()?;
            vault.change_password(password.as_bytes())?;
            println!("New password set. Your recovery key is unchanged.");
            Ok(())
        }
    }
}

fn create(path: &Path, input: &SecretInput) -> Result<()> {
    let password = input.new_password()?;
    eprintln!("Tuning password protection for this PC...");
    let kdf = KdfParams::DEFAULT.calibrate(KDF_TARGET)?;
    eprintln!("Creating vault...");
    let (_, recovery) = Vault::create(path, password.as_bytes(), kdf)
        .with_context(|| format!("creating {}", path.display()))?;
    println!("Vault created at {}\n", path.display());
    println!("RECOVERY KEY: write it down and keep it somewhere safe, away from this computer.");
    println!(
        "It is the only way back in if you forget your password. It will not be shown again.\n"
    );
    println!("    {}\n", recovery.to_display_string().as_str());

    if !input.from_stdin {
        loop {
            let typed = input.secret("Type the recovery key to confirm you saved it: ")?;
            match RecoveryKey::parse(&typed) {
                Ok(key) if key == recovery => break,
                Ok(_) => eprintln!("That is a valid key, but not this vault's. Try again."),
                Err(e) => eprintln!("{e}. Try again."),
            }
        }
        println!("Recovery key confirmed.");
    }
    Ok(())
}

fn unlock(path: &Path, input: &SecretInput) -> Result<Vault> {
    let password = input.secret("Password: ")?;
    eprintln!("Unlocking...");
    Vault::unlock(path, password.as_bytes())
        .with_context(|| format!("unlocking {}", path.display()))
}

fn print_tree(vault: &Vault, path: &str, recursive: bool) -> Result<()> {
    for entry in vault.list(path)? {
        let full = format!("{}/{}", path.trim_end_matches(['/', '\\']), entry.name);
        match entry.kind {
            EntryKind::Dir => {
                println!("{:>14}  {full}/", "<dir>");
                if recursive {
                    print_tree(vault, &full, true)?;
                }
            }
            EntryKind::File => println!("{:>14}  {full}", entry.size.unwrap_or_default()),
        }
    }
    Ok(())
}

fn report(verb: &str, stats: &Stats) {
    println!(
        "{verb} {} files and {} folders ({} bytes).",
        stats.files, stats.dirs, stats.bytes
    );
    if !stats.skipped.is_empty() {
        println!("Skipped (links and other special files are not imported):");
        for path in &stats.skipped {
            println!("  {}", path.display());
        }
    }
}

struct SecretInput {
    from_stdin: bool,
}

impl SecretInput {
    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if self.from_stdin {
            let mut line = Zeroizing::new(String::new());
            if io::stdin().lock().read_line(&mut line)? == 0 {
                bail!("expected another line on stdin");
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).len();
            line.truncate(trimmed);
            // Windows PowerShell prefixes piped text with a UTF-8 byte-order mark.
            if line.starts_with('\u{feff}') {
                line.drain(..'\u{feff}'.len_utf8());
            }
            Ok(line)
        } else {
            Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
        }
    }

    fn new_password(&self) -> Result<Zeroizing<String>> {
        let password = self.secret("New password: ")?;
        if password.chars().count() < MIN_PASSWORD_CHARS {
            bail!("password must be at least {MIN_PASSWORD_CHARS} characters");
        }
        if !self.from_stdin && *self.secret("Repeat password: ")? != *password {
            bail!("passwords do not match");
        }
        Ok(password)
    }
}
