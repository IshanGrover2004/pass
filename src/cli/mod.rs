// Modules required to make
pub mod args;

use clap::Parser;
use passwords::PasswordGenerator;

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

    match args.commands {
        Some(Commands::Init(_)) => {
            MasterPassword::new().unwrap();
        }

        Some(Commands::ChangeMaster) => {
            // Wanted to do this-:
            let master = MasterPassword::new()
                .map_err(|e| eprintln!("{:?}", e))
                .unwrap();
            let mut unlocked = master.unlock().map_err(|e| eprintln!("{:?}", e)).unwrap();
            unlocked.change().unwrap();
            unlocked.lock();

            colour::green!("Master Password changed successfully...");
        }

        Some(Commands::Add(args)) => {
            let master_password = MasterPassword::password_input().expect("");
            if MasterPassword::verify(&master_password).unwrap() {
                args.add_entries(master_password.as_ref());
            } else {
                colour::red!("Incorrect MasterPassword");
            }
        }

        Some(Commands::Remove(args)) => {
            unimplemented!();
        }

        Some(Commands::Update(args)) => {
            unimplemented!();
        }

        Some(Commands::List(_)) => {
            unimplemented!();
        }

        Some(Commands::Get(args)) => {
            unimplemented!();
        }

        Some(Commands::Gen(args)) => {
            args.generate_password();
        }

        None => {
            const ASCII_ART_ABOUT: &str = r#"
██████╗  █████╗ ███████╗███████╗      ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝      ██╔══██╗██╔════╝
██████╔╝███████║███████╗███████╗█████╗██████╔╝███████╗
██╔═══╝ ██╔══██║╚════██║╚════██║╚════╝██╔══██╗╚════██║
██║     ██║  ██║███████║███████║      ██║  ██║███████║
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝      ╚═╝  ╚═╝╚══════╝

"#;

            const ABOUT_MSG: &str = r"Welcome to Pass! 🔒
Type $ pass --help for looking all options & commands";
            colour::red!("{ASCII_ART_ABOUT}");
            colour::white!("{ABOUT_MSG}")
        }
    };
}
