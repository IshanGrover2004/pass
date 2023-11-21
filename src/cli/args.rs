use std::borrow::BorrowMut;

use clap::{Args, Parser, Subcommand};
use inquire::validator::Validation;
use inquire::{Password, PasswordDisplayMode};

use crate::pass::master::{MasterPassword, Verified};
use crate::pass::store::print_table;
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

    /// Get a password entry
    Get(GetArgs),

    /// Fuzzy search passsword entries
    Search(SearchArgs),

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

impl RemoveArgs {
    pub fn remove_entries(
        &mut self,
        master_password: MasterPassword<Verified>,
    ) -> anyhow::Result<()> {
        let mut manager =
            PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password.to_owned())?;

        let found_entry = manager.get(&self.service);

        if found_entry.is_empty() {
            // TODO: Ask user to apply fuzzy search to remove
            colour::e_red_ln!(
                "Can't find matching entry with service name '{}'",
                self.service
            );
        } else if found_entry.len() == 1 {
            colour::blue_ln!("Found matching service name");

            match ask_for_confirm("Confirm to remove this entry?") {
                Ok(true) => manager.remove(found_entry)?,
                Err(_) | Ok(false) => {
                    colour::e_red_ln!("Aborted!!");
                }
            };
        } else {
            colour::green_ln!("Found {} matching entries", found_entry.len());

            // TODO: Selection of entry to remove is done using inquire::Select
            match ask_for_confirm("Confirm to remove these entry?") {
                Ok(true) => manager.remove(found_entry)?,
                Err(_) | Ok(false) => {
                    colour::e_red_ln!("Aborted!!");
                }
            };
        }

        Ok(())
    }

    // fn take_consent_and_remove() {}
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Service name for identify any password
    service: String,
}

pub fn list_entries(master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
    let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

    print_table(manager.passwords);

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

        let result = manager.get(&self.service);
        match result.is_empty() {
            true => {
                colour::e_red_ln!("No entry found for {}", self.service);

                // let fuzzy_choice = ask_for_confirm("Do you want to fuzzy find it? ");

                /* TODO: Fuzzy search the list if no entry found
                 * then print that you got "n" no. of response "do you want to show the list?".
                 * Show the result then and ask what password entry they want to access */
            }
            false => {
                colour::green_ln!("{} entry found", result.len());

                // TODO: ASK user to whether show password from any found entry

                if result.len() == 1 {
                    print_table(result);
                } else {
                    let confirm = ask_for_confirm(format!(
                        "Do you want to print all {} found entries?",
                        result.len()
                    ))?;

                    match confirm {
                        true => {
                            print_table(result);
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
pub struct SearchArgs {
    service: String,
}

impl SearchArgs {
    pub fn fuzzy_search(&self, master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
        let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

        let result = manager.fuzzy_find(self.service.clone());
        match result.is_empty() {
            true => {
                colour::e_red_ln!("No entry exist related to '{}'", self.service);
            }
            false => {
                // TODO: Make methods like fuzzy_find_by_username & fuzzy_find_by_service
                colour::green_ln!("Your search results: ");
                result.iter().enumerate().for_each(|(idx, entry)| {
                    colour::green_ln!("{}. {}", idx + 1, entry.service);
                });
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
        if self.length < 4 {
            colour::e_red_ln!("Password length must be greater than or equal to 4");
            return;
        }

        // If no flags is given then generate a password including Uppercase, lowercase & digits
        let password_generator = self.generator();

        match self.count > 1 {
            true => Self::generate_multiple(self.count, password_generator),
            false => Self::generate_one(password_generator),
        };
    }

    fn generate_one(password_generator: passwords::PasswordGenerator) {
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
            Err(_) => {
                colour::e_red_ln!("Error in creating passwords")
            }
        }
    }

    fn generate_multiple(count: usize, password_generator: passwords::PasswordGenerator) {
        match password_generator.generate(count) {
            Ok(passwords) => {
                for password in passwords {
                    colour::yellow_ln!("{password}");
                }
            }
            Err(_) => {
                colour::e_red_ln!("Error in creating passwords")
            }
        }
    }

    fn generator(&self) -> passwords::PasswordGenerator {
        match self.digits || self.lowercase || self.uppercase || self.symbols {
            true => passwords::PasswordGenerator::new()
                .length(self.length)
                .lowercase_letters(self.lowercase)
                .uppercase_letters(self.uppercase)
                .numbers(self.digits)
                .symbols(self.symbols)
                .strict(true),

            false => passwords::PasswordGenerator::new()
                .length(self.length)
                .uppercase_letters(true)
                .symbols(false)
                .strict(true),
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
            Self::reset_hard()?;
        } else {
            Self::reset_passwords()?;
        }

        Ok(())
    }

    fn reset_hard() -> Result<(), CliError> {
        let confirm_for_removal =
            ask_for_confirm("Do you really want to remove whole 'pass' directory?")
                .map_err(|_| CliError::UnableToReadFromConsole)?;

        match confirm_for_removal {
            true => {
                std::fs::remove_dir_all(PASS_DIR_PATH.as_path())
                    .map_err(CliError::UnableToResetPassDir)?;
                colour::green_ln!("`pass` directory has been removed");
            }
            false => {
                colour::e_red_ln!("Reset command has been aborted");
            }
        };

        Ok(())
    }

    fn reset_passwords() -> Result<(), CliError> {
        let confirm_for_removal =
            ask_for_confirm("Do you really want to reset all password entry?")
                .map_err(|_| CliError::UnableToReadFromConsole)?;

        match confirm_for_removal {
            true => {
                std::fs::remove_file(PASS_ENTRY_STORE.as_path())
                    .map_err(CliError::UnableToResetPassDir)?;
                colour::green_ln!("All password entry has been reset");
            }
            false => {
                colour::e_red_ln!("Aborted!!");
            }
        }

        Ok(())
    }
}
