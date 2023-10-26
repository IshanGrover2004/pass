// Importing...
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
pub struct InitArgs {
    /// Master password for the pass
    #[clap(required = false, default_value = "")]
    master_password: String,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Service name for identify any password
    #[clap(required = true)]
    service: String,

    /// Username/email of the account
    #[clap(short = 'n', long = None)]
    username: Option<String>,

    /// Password of the account (if not provided, a random password will be generated)
    #[clap(short = 'p', default_value = None)]
    password: Option<String>,

    /// Notes for the account
    #[clap(short = 'm', default_value = None)]
    notes: Option<String>,
}

impl AddArgs {
    pub fn add_entries(&self, master_password: impl AsRef<[u8]>) -> Result<(), PasswordStoreError> {
        // TODO: How to deal with unwrap here
        let mut manager = PasswordStore::new(PASS_ENTRY_STORE.to_path_buf(), &master_password)?;

        let entry = PasswordEntry::new(
            self.service.to_owned(),
            self.username.to_owned(),
            self.password.to_owned(),
            self.notes.to_owned(),
        );

        // Push the new entries
        manager.push_entry(entry);

        // New entries are pushed to database
        manager
            .dump_to_db(PASS_ENTRY_STORE.to_path_buf(), &master_password)
            .unwrap();

        Ok(())
    }
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Master password required for authentication
    #[clap(required = false, default_value = "")]
    master_password: String,

    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Master password required for authentication
    #[clap(required = false, default_value = "")]
    master_password: String,

    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Master password required for authentication
    #[clap(required = false, default_value = "")]
    master_password: String,
}

#[derive(Args)]
pub struct GetArgs {
    // /// Master password required for authentication
    // #[clap(default_value = "")]
    // master_password: String,
    //
    /// Username/email of the account
    // #[clap(short = 'n', long = "name")]
    username: String,
}

#[derive(Args)]
pub struct GenArgs {
    /// Length of generated password
    #[clap(default_value_t = 12)]
    pub length: u8,
}
