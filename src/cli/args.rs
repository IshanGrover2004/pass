use clap::{Args, Parser, Subcommand};

use crate::pass::{
    entry::PasswordEntry,
    store::{PasswordStore, PasswordStoreError, PASS_ENTRY_STORE},
};

// CLI Design
#[derive(Parser)]
#[clap(
    name = "pass",
    version = "0.0.1",
    author = "Ishan",
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
pub struct InitArgs {}

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

impl Into<PasswordEntry> for &AddArgs {
    fn into(self) -> PasswordEntry {
        PasswordEntry::new(
            self.service.to_owned(),
            self.username.to_owned(),
            self.password.to_owned(),
            self.notes.to_owned(),
        )
    }
}

impl AddArgs {
    pub fn add_entries(&self, master_password: impl AsRef<[u8]>) -> Result<(), PasswordStoreError> {
        let mut manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), &master_password)?;

        // Push the new entries
        manager.push_entry(self.into());

        // New entries are pushed to database
        manager
            .dump(PASS_ENTRY_STORE.to_path_buf(), &master_password)
            .unwrap();

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

    /// Flag to include lowercase letters in password [default: true]
    #[arg(short = 'u', default_value_t = true)]
    lowercase: bool,

    /// Flag to include digits in password [default: true]
    #[arg(short, default_value_t = true)]
    digits: bool,

    /// Flag to include symbols in password
    #[arg(short)]
    symbols: bool,
}

impl GenArgs {
    pub fn generate_password(self) {
        let password_generator = passwords::PasswordGenerator::new()
            .length(self.length)
            .lowercase_letters(self.lowercase)
            .uppercase_letters(self.uppercase)
            .numbers(self.digits)
            .symbols(self.symbols)
            .strict(true);

        if self.count > 1 {
            let passwords = password_generator.generate(self.count).unwrap();

            for password in passwords {
                colour::e_yellow_ln!("{password}");
            }
        } else {
            let password = password_generator.generate_one().unwrap();
            println!("{password}");

            // TODO: Password copy_to_clipboard
        }
    }
}
