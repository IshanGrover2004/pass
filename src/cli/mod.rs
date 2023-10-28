// Modules required to make
pub mod args;

use clap::Parser;

use crate::{
    cli::args::{Cli, Commands},
    pass::master::{MasterPassword, MasterPasswordError},
};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Failed to Create Master password")]
    UnableToCreateMaster,

    #[error("Failed to Unlock Master password")]
    UnableToUnlockMaster,

    #[error("Failed to Change Master password")]
    UnableToChangeMaster,
}

// Run the CLI
pub fn run_cli() -> anyhow::Result<()> {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Init(_)) => {
            MasterPassword::new().map_err(|_| CliError::UnableToCreateMaster)?;
        }

        Some(Commands::ChangeMaster) => {
            let master = MasterPassword::new().map_err(|_| CliError::UnableToCreateMaster)?;

            let mut unlocked = master
                .unlock()
                .map_err(|_| CliError::UnableToUnlockMaster)?;

            unlocked
                .change()
                .map_err(|_| CliError::UnableToChangeMaster)?;

            unlocked.lock();

            colour::green!("Master Password changed successfully");
        }

        Some(Commands::Add(args)) => {
            // To Ask: Douwn map_err syntax by clippy
            let master_password = MasterPassword::password_input()
                .map_err(MasterPasswordError::UnableToReadFromConsole)?;

            match MasterPassword::verify(&master_password) {
                Ok(true) => {
                    args.add_entries(master_password.as_ref());
                }
                Ok(false) => {
                    colour::red!("Incorrect MasterPassword");
                }
                Err(error) => {
                    eprintln!("{:?}", error);
                }
            };
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

    Ok(())
}
