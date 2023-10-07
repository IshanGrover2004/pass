// Importing...
use clap::{Args, Parser, Subcommand};

// CLI Design
#[derive(Parser)]
#[clap(
    name = "pass",
    version,
    author = "Ishan",
    about = "A easy-to-use CLI password manager and generator"
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

#[derive(Args)]
pub struct AddArgs {
    /// Master password required for authentication
    #[clap(required = false, default_value = "")]
    master_password: String,

    /// Username/email of the account
    #[clap(short = 'n', long = "name")]
    username: String,

    /// Password of the account (if not provided, a random password will be generated)
    #[clap(short = 'p', long = "pass")]
    password: Option<String>,

    /// URL of the site/app for which the password is
    #[clap(short = 'u', long = "url", default_value = "No URL provided")]
    url: String,

    /// Notes for the account
    #[clap(short = 'm', required = false, default_value = " ")]
    notes: String,
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
