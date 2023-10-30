use clap::{Args, Parser, Subcommand};

use crate::pass::{
    entry::PasswordEntry,
    store::{PasswordStore, PasswordStoreError, PASS_ENTRY_STORE},
    util::copy_to_clipboard,
};

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
    pub commands: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the pass
    Init(InitArgs),

    /// Change Master password
    ChangeMaster,

    /// Make a new password
    Add(AddArgs),

    /// Remove a password
    Remove(RemoveArgs),

    /// Update a password
    Update(UpdateArgs),

    /// List all made password
    List(ListArgs),

    /// Get a password
    Get(GetArgs),

    /// Generate a password
    Gen(GenArgs),
}

#[derive(Args)]
pub struct InitArgs;

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Service name for identify any password
    #[clap(required = true)]
    service: String,

    /// Username/email of the account
    #[clap(long, short, aliases=&["user"], default_value = None)]
    username: Option<String>,

    /// Password of the account (if not provided, a random password will be generated)
    #[clap(long, short, default_value = None)]
    password: Option<String>,

    /// Notes for the account
    #[clap(long, short, default_value = None)]
    notes: Option<String>,
}

impl From<&AddArgs> for PasswordEntry {
    fn from(value: &AddArgs) -> Self {
        PasswordEntry::new(
            value.service.to_owned(),
            value.username.to_owned(),
            value.password.to_owned(),
            value.notes.to_owned(),
        )
    }
}

impl AddArgs {
    pub fn add_entries(&self, master_password: impl AsRef<[u8]>) -> Result<(), PasswordStoreError> {
        let mut manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), &master_password)?;

        // Push the new entries
        manager.push_entry(self.into());

        // New entries are pushed to database
        manager.dump(PASS_ENTRY_STORE.to_path_buf(), &master_password)?;

        Ok(())
    }
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
}

#[derive(Args)]
pub struct ListArgs {}

#[derive(Args)]
pub struct GetArgs {
    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
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
    pub fn generate_password(self) {
        let password_generator;

        // If no flags is given then generate a password including Uppercase, lowercase & digits
        if self.digits || self.lowercase || self.uppercase || self.symbols {
            password_generator = passwords::PasswordGenerator::new()
                .length(self.length)
                .lowercase_letters(self.lowercase)
                .uppercase_letters(self.uppercase)
                .numbers(self.digits)
                .symbols(self.symbols)
                .strict(true);
        } else {
            password_generator = passwords::PasswordGenerator::new()
                .length(self.length)
                .lowercase_letters(true)
                .uppercase_letters(true)
                .numbers(true)
                .symbols(false)
                .strict(true);
        }

        if self.count > 1 {
            match password_generator.generate(self.count) {
                Ok(passwords) => {
                    for password in passwords {
                        colour::e_yellow_ln!("{password}");
                    }
                }
                Err(_) => colour::e_red_ln!("Error in creating passwords"),
            }
        } else {
            match password_generator.generate_one() {
                Ok(password) => {
                    colour::e_yellow_ln!("{password}");
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
