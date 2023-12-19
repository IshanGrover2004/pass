use std::borrow::BorrowMut;

use clap::{Args, Parser, Subcommand};
use inquire::{Password, PasswordDisplayMode};

use crate::pass::master::{MasterPassword, Verified};
use crate::pass::store::print_table;
use crate::pass::util::{
    ask_for_confirm, choose_entry_with_interaction, input_number, print_pass_entry_info,
    prompt_string, PASS_DIR_PATH,
};
use crate::pass::{
    entry::PasswordEntry,
    store::{PasswordStore, PasswordStoreError, PASS_ENTRY_STORE},
    util::copy_to_clipboard,
};

use super::CliError;

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

    random_password: bool,

    /// Notes for the account
    #[clap(long, short, default_value = None)]
    notes: Option<String>,
}

impl From<&mut AddArgs> for PasswordEntry {
    fn from(value: &mut AddArgs) -> Self {
        PasswordEntry::new(
            value.service.clone(),
            value.username.clone(),
            value.password.clone(),
            value.notes.clone(),
        )
    }
}

impl AddArgs {
    pub fn add_entries(
        &mut self,
        master_password: &MasterPassword<Verified>,
    ) -> anyhow::Result<()> {
        let mut manager =
            PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password.to_owned())?;

        self.set_params();

        // Push the new entries
        manager.push_entry(self.into());

        // New entries are pushed to database
        manager.dump(PASS_ENTRY_STORE.to_path_buf())?;

        if self.random_password {
            colour::green_ln!("\nPassword copied to clipboard");
            copy_to_clipboard(
                self.password
                    .clone()
                    .expect("Unreachable: Password is generated randomly"),
            )
            .expect("Unable to clipboard");
        }

        // TODO: Impl Drop trait to automatically dump all password entries in DB

        Ok(())
    }

    /// Ask for [`AddArgs`] variants and set it.
    fn set_params(&mut self) {
        let service = self.service.clone();

        println!();

        // Prompt for username & set in object
        self.username
            .is_none()
            .then(|| -> Result<(), PasswordStoreError> {
                self.borrow_mut().username =
                    prompt_string(format!("Enter username for {service}: "))
                        .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;
                Ok(())
            });

        // Prompt for password & set in object
        self.password
            .is_none()
            .then(|| -> Result<(), PasswordStoreError> {
                self.set_password()?;
                Ok(())
            });

        // Prompt for notes & set in object
        self.notes
            .is_none()
            .then(|| -> Result<(), PasswordStoreError> {
                self.borrow_mut().notes = prompt_string(format!("Enter notes for {service}: "))
                    .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;
                Ok(())
            });
    }

    fn set_password(&mut self) -> Result<(), PasswordStoreError> {
        let choice = ask_for_confirm("Generate random password?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        self.borrow_mut().password = if choice {
            self.random_password = true;
            Some(Self::generate_random_password_with_interaction()?)
        } else {
            Some(Self::generate_new_password()?)
        };

        Ok(())
    }

    fn generate_new_password() -> Result<String, PasswordStoreError> {
        Password::new("Enter password: ")
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_custom_confirmation_message("Confirm password:")
            .with_custom_confirmation_error_message("The password don't match.")
            .prompt()
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)
    }

    fn generate_random_password_with_interaction() -> Result<String, PasswordStoreError> {
        let length =
            input_number("How long?").map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        let uppercase = ask_for_confirm("Include uppercase letters?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        let lowercase = ask_for_confirm("Include lowercase letters?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        let digits = ask_for_confirm("Include digits?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        let symbols = ask_for_confirm("Include symbols?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        let gen_arg = GenArgs {
            length,
            count: 1,
            uppercase,
            lowercase,
            digits,
            symbols,
        };

        Ok(gen_arg
            .generator()
            .generate_one()
            .expect("Unreachable code"))
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
        let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password.clone())?;

        let found_entry = manager.get(&self.service);

        if found_entry.is_empty() {
            self.handle_no_entry_found(manager)?;
        } else if found_entry.len() == 1 {
            Self::handle_one_entry_found(manager, found_entry)?;
        } else {
            Self::handle_multiple_entry_found(manager, found_entry)?;
        }

        Ok(())
    }

    fn handle_no_entry_found(&self, mut manager: PasswordStore) -> Result<(), PasswordStoreError> {
        colour::e_red_ln!(
            "Can't find matching entry with service name '{}'",
            self.service
        );

        let fuzzy_search_choice = ask_for_confirm("Want to do fuzzy search for this?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        if fuzzy_search_choice {
            let fuzzy_search = manager.fuzzy_find(&self.service);
            print_pass_entry_info(&fuzzy_search);

            match choose_entry_with_interaction(
                fuzzy_search,
                "Which entry to remove? (eg. 1,2,3): ",
            ) {
                Ok(entry) => {
                    ask_for_confirm("Confirm to remove? ")
                        .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?
                        .then(|| -> Result<(), PasswordStoreError> {
                            manager.remove(vec![entry])?;
                            Ok(())
                        });
                }
                Err(_) => {
                    colour::e_red_ln!("there is nothing to do");
                }
            };
        } else {
            colour::e_red_ln!("there is nothing to do");
        }

        Ok(())
    }

    fn handle_one_entry_found(
        mut manager: PasswordStore,
        found_entry: Vec<PasswordEntry>,
    ) -> Result<(), PasswordStoreError> {
        colour::blue_ln!("Found matching service name");

        match ask_for_confirm("Confirm to remove this entry?") {
            Ok(true) => manager.remove(found_entry)?,
            Err(_) | Ok(false) => {
                colour::e_red_ln!("Aborted!!");
            }
        };

        Ok(())
    }

    fn handle_multiple_entry_found(
        mut manager: PasswordStore,
        found_entry: Vec<PasswordEntry>,
    ) -> Result<(), PasswordStoreError> {
        colour::green_ln!("Found {} matching entries", found_entry.len());
        print_pass_entry_info(&found_entry);

        match choose_entry_with_interaction(found_entry, "Which entry to remove? (eg. 1,2,3): ") {
            Ok(entry) => {
                manager.remove(vec![entry])?;
            }
            Err(_) => {
                colour::e_red_ln!("there is nothing to do");
            }
        };

        Ok(())
    }
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Service name for identify any password
    service: String,
}

pub fn list_entries(master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
    let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

    print_table(manager.passwords);

    println!("Not showing passwords due to security reasons");
    println!("Use '$ pass_rs get <service>' to get password entry info with password");

    Ok(())
}

#[derive(Args)]
pub struct GetArgs {
    /// Service name to identify any password
    service: String,

    #[arg(short, long)]
    print: bool,
}

impl GetArgs {
    pub fn get_entries(&self, master_password: MasterPassword<Verified>) -> anyhow::Result<()> {
        let manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), master_password)?;

        let result = manager.get(&self.service);

        if result.is_empty() {
            self.handle_no_entry_found(manager)?;
        } else if result.len() == 1 {
            self.handle_one_entry_found(result)?;
        } else {
            self.handle_multiple_entry_found(result)?;
        }

        Ok(())
    }

    fn handle_no_entry_found(&self, manager: PasswordStore) -> Result<(), PasswordStoreError> {
        colour::e_red_ln!(
            "Can't find matching entry with service name '{}'",
            self.service
        );

        let fuzzy_search_choice = ask_for_confirm("Want to do fuzzy search for this?")
            .map_err(|_| PasswordStoreError::UnableToReadFromConsole)?;

        if fuzzy_search_choice {
            let fuzzy_search = manager.fuzzy_find(&self.service);
            print_pass_entry_info(&fuzzy_search);

            match choose_entry_with_interaction(
                fuzzy_search,
                "Which entry password to show? (eg. 1,2,3): ",
            ) {
                Ok(entry) => {
                    self.print_pass(entry);
                }
                Err(_) => {
                    colour::e_red_ln!("there is nothing to do");
                }
            };
        } else {
            colour::e_red_ln!("there is nothing to do");
        }

        Ok(())
    }

    fn handle_one_entry_found(
        &self,
        found_entry: impl AsRef<[PasswordEntry]>,
    ) -> Result<(), PasswordStoreError> {
        let entry = found_entry
            .as_ref()
            .get(0)
            .expect("Unreachable: Only one entry exists at index 0")
            .clone();

        // Print the password of found 1 entry
        self.print_pass(entry);

        Ok(())
    }

    fn handle_multiple_entry_found(
        &self,
        found_entry: Vec<PasswordEntry>,
    ) -> Result<(), PasswordStoreError> {
        colour::green_ln!("Found {} matching entries", found_entry.len());
        print_pass_entry_info(&found_entry);

        match choose_entry_with_interaction(
            found_entry,
            "Which entry password to show? (eg. 1,2,3): ",
        ) {
            Ok(entry) => {
                self.print_pass(entry);
            }
            Err(_) => {
                colour::e_red_ln!("there is nothing to do");
            }
        };

        Ok(())
    }

    fn print_pass(&self, entry: PasswordEntry) {
        let password = entry.get_pass_str();

        copy_to_clipboard(password.clone()).expect("Unable to copy to clipboard");
        colour::green_ln!("Password copied to clipboard");

        if self.print {
            colour::yellow_ln!("Password: {}", password);
        }
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

                print_table(result);
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

    pub fn generator(&self) -> passwords::PasswordGenerator {
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
