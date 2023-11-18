use std::borrow::BorrowMut;

use clap::{Args, Parser, Subcommand};
use inquire::validator::Validation;
use inquire::{Password, PasswordDisplayMode};

use crate::pass::master::{MasterPassword, Verified};
use crate::pass::store::get_table;
use crate::pass::util::{ask_for_confirm, generate_random_password, prompt_string, PASS_DIR_PATH};
use crate::pass::{
    entry::PasswordEntry,
    store::{PasswordStore, PasswordStoreError, PASS_ENTRY_STORE},
    util::copy_to_clipboard,
};

use super::CliError;

// TODO: pass gen -Uuds 2 shows vague error

// CLI Design
#[derive(Parser)]
#[clap(
    name = "pass",
    version = "0.0.1",
    author = "Ishan Grover & Tanveer Raza",
    about = "A easy-to-use CLI password manager"
)]
pub struct Cli {
    /// Subcommand to do some operation like add, remove, etc.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize the pass
    Init,

    /// Change Master password
    ChangeMaster,

    /// Make a new password
    Add(AddArgs),

    /// Remove a password
    Remove(RemoveArgs),

    /// Update a password
    Update(UpdateArgs),

    /// List all made password
    List,

    /// Get a password
    Get(GetArgs),

    /// Generate a password
    Gen(GenArgs),

    /// Reset features for pass directory
    Reset(ResetArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AddArgs {
    /// Service name for identify any password
    #[clap(required = true)]
    service: String,

    /// Username/email of the account
    #[clap(long, short, aliases=&["user"], default_value = None)]
    username: Option<String>,

    /// Password of the account (if not provided, a random password will be generated)
    #[clap(short, default_value = None)]
    password: Option<String>,

    /// Notes for the account
    #[clap(long, short, default_value = None)]
    notes: Option<String>,
}

impl From<&mut AddArgs> for PasswordEntry {
    fn from(value: &mut AddArgs) -> Self {
        PasswordEntry::new(
            value.service.to_owned(),
            value.username.to_owned(),
            value.password.to_owned(),
            value.notes.to_owned(),
        )
    }
}

impl AddArgs {
    pub fn add_entries(
        &mut self,
        master_password: &MasterPassword<Verified>,
    ) -> Result<(), PasswordStoreError> {
        let mut manager =
            PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password.to_owned())?;

        self.set_params();

        // Push the new entries
        manager.push_entry(self.into());

        // New entries are pushed to database
        manager.dump(PASS_ENTRY_STORE.to_path_buf())?;

        // TODO: Impl Drop trait to automatically dump all password entries in DB

        Ok(())
    }

    /// Ask for [AddArgs] variants and set it.
    fn set_params(&mut self) {
        let service = self.service.clone();

        // Prompt for username & set in object
        self.username.is_none().then(|| -> anyhow::Result<()> {
            self.borrow_mut().username = prompt_string(format!("Enter username for {}: ", service))
                .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;
            Ok(())
        });

        // Prompt for password & set in object
        self.password.is_none().then(|| -> anyhow::Result<()> {
            self.set_password()?;
            Ok(())
        });

        // Prompt for notes & set in object
        self.notes.is_none().then(|| -> anyhow::Result<()> {
            self.borrow_mut().notes = prompt_string(format!("Enter notes for {}: ", service))
                .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;
            Ok(())
        });
    }

    fn set_password(&mut self) -> anyhow::Result<()> {
        let choice = ask_for_confirm("Generate random password?")?;

        self.borrow_mut().password = match choice {
            true => Some(generate_random_password(12).as_ref().to_string()),
            false => Some(
                Password::new("Enter password: ")
                    .with_display_toggle_enabled()
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .with_custom_confirmation_message("Confirm password:")
                    .with_custom_confirmation_error_message("The password don't match.")
                    .with_validator(|input: &str| {
                        if input.len() < 8 {
                            Ok(Validation::Invalid(
                                "Password must be more than 8 bytes".into(),
                            ))
                        } else {
                            Ok(Validation::Valid)
                        }
                    })
                    .prompt()
                    .unwrap(),
            ),
        };

        Ok(())
    }
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Service name for identify any password
    service: String,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Service name for identify any password
    service: String,
}

pub fn list_entries(master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
    let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

    match get_table(manager.passwords) {
        Ok(table) => {
            println!("{table}");
        }
        Err(PasswordStoreError::NoEntryAvailable) => {
            colour::e_red_ln!("No entry available");
        }
        Err(error) => {
            return Err(error.into());
        }
    };

    Ok(())
}

#[derive(Args)]
pub struct GetArgs {
    /// Service name to identify any password
    service: String,
}

impl GetArgs {
    pub fn get_entries(&self, master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
        /*
         * 1. Check entry exist by service or not
         * 2. If 1 entry found => print
         *     If more entry found => print username of entry and prompt which entry to get.
         *     If no entry found => Give suggestion of fuzzy_find search
         * */

        let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

        let result = manager.get(self.service.clone());
        match result.is_empty() {
            true => {
                colour::e_red_ln!("No entry found for {}", self.service);

                // let fuzzy_choice = ask_for_confirm("Do you want to fuzzy find it? ");

                /* TODO: Fuzzy search the list if no entry found
                 * get list of entries through fuzzy search
                 * then print that you got "n" no. of response "do you want to show the list?"
                 * show the list then and ask what password entry they want to access */
            }
            false => {
                colour::green_ln!("{} entry found", result.len());

                // TODO: ASK user to whether show password from any found entry

                if result.len() == 1 {
                    let table = get_table(result)?;
                    println!("{}", table);
                } else {
                    let confirm = ask_for_confirm(format!(
                        "Do you want to print all {} found entries?",
                        result.len()
                    ))?;

                    match confirm {
                        true => {
                            let table = get_table(result)?;
                            println!("{}", table);
                        }
                        false => {
                            colour::e_blue_ln!("Not showing entries")
                        }
                    }
                }
            }
        };

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct GenArgs {
    /// Length of generated password
    #[clap(default_value_t = 12)]
    length: usize,

    /// Number of password to be generated
    #[arg(short = 'n', default_value_t = 1)]
    count: usize,

    /// Flag to include uppercase letters in password
    #[arg(short = 'U')]
    uppercase: bool,

    /// Flag to include lowercase letters in password
    #[arg(short = 'u')]
    lowercase: bool,

    /// Flag to include digits in password
    #[arg(short)]
    digits: bool,

    /// Flag to include symbols in password
    #[arg(short)]
    symbols: bool,
}

impl GenArgs {
    /// Generate random password based on flags
    pub fn generate_password(self) {
        // If no flags is given then generate a password including Uppercase, lowercase & digits
        let password_generator = if self.digits || self.lowercase || self.uppercase || self.symbols
        {
            passwords::PasswordGenerator::new()
                .length(self.length)
                .lowercase_letters(self.lowercase)
                .uppercase_letters(self.uppercase)
                .numbers(self.digits)
                .symbols(self.symbols)
                .strict(true)
        } else {
            passwords::PasswordGenerator::new()
                .length(self.length)
                .uppercase_letters(true)
                .symbols(false)
                .strict(true)
        };

        if self.count > 1 {
            match password_generator.generate(self.count) {
                Ok(passwords) => {
                    for password in passwords {
                        colour::yellow_ln!("{password}");
                    }
                }
                Err(_) => colour::e_red_ln!("Error in creating passwords"),
            }
        } else {
            match password_generator.generate_one() {
                Ok(password) => {
                    colour::yellow_ln!("{password}");
                    match copy_to_clipboard(password) {
                        Ok(_) => {
                            colour::green_ln!("Password copied to clipboard");
                        }
                        Err(_) => {
                            colour::e_red_ln!("Unable to copy password");
                        }
                    }
                }
                Err(_) => colour::e_red_ln!("Error in creating passwords"),
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct ResetArgs {
    /// Flag to remove whole "pass" directory from db
    #[arg(long, default_value_t = false)]
    hard: bool,

    // TODO: Add option to take backup somewhere before reset if --backup flag passed
    #[arg(long)]
    backup: bool,
}

impl ResetArgs {
    pub fn reset(&self) -> Result<(), CliError> {
        if self.hard {
            if ask_for_confirm("Do you really want to remove whole 'pass' directory?")
                .map_err(|_| CliError::UnableToReadFromConsole)?
            {
                std::fs::remove_dir_all(PASS_DIR_PATH.as_path())
                    .map_err(CliError::UnableToResetPassDir)?;
                println!("`pass` directory has been removed");
            } else {
                println!("Reset command has been aborted");
            }
        } else {
            if ask_for_confirm("Do you really want to reset all password entry?")
                .map_err(|_| CliError::UnableToReadFromConsole)?
            {
                std::fs::remove_file(PASS_ENTRY_STORE.as_path())
                    .map_err(CliError::UnableToResetPassDir)?;
                println!("All password entry has been reset");
            } else {
                println!("Reset command has been aborted");
            }
        }

        Ok(())
    }
}
