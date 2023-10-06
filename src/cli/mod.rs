// Modules required to make
pub mod args;
pub mod commands;

// Importing...
use crate::{
    cli::args::{Cli, Commands},
    pass::master,
};
use clap::Parser;

// Run the CLI
pub fn run_cli() {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match &args.commands.unwrap() {
        Commands::Init(_) => {
            let master = master::MasterPassword::new().unwrap();
            let unlocked = master.unlock();
        }

        Commands::Add(args) => {
            /*
            println!("Username: {}", args.username);

            // Generating a password if not provided by user
            if args.password.is_none() {
                // args.password = Some(generate_password());
                // println!("Password: {:?}", args.password);
                println!("Password: {:?}", generate_password());
            } else {
                println!("Password: {:?}", args.password);
            }

            println!("URL: {}", args.url);
            println!("Notes: {}", args.notes);
            */
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
            let my_password = args.generate_password();
            println!("{my_password}");
        }
    };
}
