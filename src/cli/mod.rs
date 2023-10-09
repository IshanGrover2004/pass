// Modules required to make
pub mod args;

// Importing...
use crate::{
    cli::args::{Cli, Commands},
    pass::master::{MasterPassword, MasterPasswordError},
    store::pass,
};
use clap::Parser;

// Run the CLI
pub fn run_cli() {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands.unwrap() {
        Commands::Init(_) => {
            MasterPassword::new();
        }

        Commands::ChangeMaster => {
            // Wanted to do this-:
            let master = MasterPassword::new()
                .map_err(|e| eprintln!("{:?}", e))
                .unwrap();
            let mut unlocked = master.unlock().map_err(|e| eprintln!("{:?}", e)).unwrap();
            unlocked.change();
            unlocked.lock();

            colour::green!("Master Password changed successfully...");
        }

        Commands::Add(args) => {
            println!("Adding a password...");
        }

        Commands::Remove(args) => {
            println!("Username for remove password");
        }

        Commands::Update(args) => {
            println!("Username for updating password");
        }

        Commands::List(_) => {
            println!("Listing all passwords...");
        }

        Commands::Get(args) => {
            println!("Password for username ");
        }

        Commands::Gen(args) => {
            // Generate a random password
            let my_password = pass::generate_password(args.length);
            println!("{my_password}");
        }
    };
}
