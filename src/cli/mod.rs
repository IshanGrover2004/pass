// Modules required to make
pub mod args;

use clap::Parser;

use crate::{
    cli::args::{Cli, Commands},
    pass::{
        master::MasterPassword,
        store::{PasswordStore, PASS_ENTRY_STORE},
        util::generate_random_password,
    },
};

// Run the CLI
pub fn run_cli() {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands.unwrap() {
        Commands::Init(_) => {
            MasterPassword::new().unwrap();
        }

        Commands::ChangeMaster => {
            // Wanted to do this-:
            let master = MasterPassword::new()
                .map_err(|e| eprintln!("{:?}", e))
                .unwrap();
            let mut unlocked = master.unlock().map_err(|e| eprintln!("{:?}", e)).unwrap();
            unlocked.change().unwrap();
            unlocked.lock();

            colour::green!("Master Password changed successfully...");
        }

        Commands::Add(args) => {
            dbg!(&args);

            let master_password = MasterPassword::password_input().unwrap();
            if MasterPassword::verify(&master_password).unwrap() {
                args.add_entries(master_password.as_ref());
                println!("Successfully stored enty");
                dbg!(
                    PasswordStore::load(PASS_ENTRY_STORE.to_path_buf(), master_password.as_ref())
                        .expect("Error in loading")
                );
            } else {
                colour::red!("Incorrect MasterPassword");
            }
        }

        Commands::Remove(args) => {
            unimplemented!();
        }

        Commands::Update(args) => {
            unimplemented!();
        }

        Commands::List(_) => {
            unimplemented!();
        }

        Commands::Get(args) => {
            unimplemented!();
        }

        Commands::Gen(args) => {
            // Generate a random password
            let my_password = generate_random_password(args.length);
            println!("{:?}", my_password.as_ref());
        }
    };
}
