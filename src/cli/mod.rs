// Modules required to make
pub mod args;

// Importing...
use crate::{
    cli::args::{Cli, Commands},
    pass::master::MasterPassword,
    store::pass,
};
use clap::Parser;

// Run the CLI
pub fn run_cli() {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands.unwrap() {
        Commands::Init(_) => {
            let master = MasterPassword::new().unwrap();
            master.unlock().unwrap();
        }

        Commands::ChangeMaster => {
            // Wanted to do this-:
            // let master = MasterPassword::new();
            // master.unlock();
            // master.change("Password123@");
            // master.lock();
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
