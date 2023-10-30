// Modules required to make
pub mod args;

use clap::Parser;

use crate::{
    cli::args::{Cli, Commands},
    pass::{
        master::MasterPassword,
        util::{self, is_pass_initialised},
    },
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
pub fn run_cli(&mut master_password: MasterPassword) -> anyhow::Result<()> {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Init(_)) => {
            match is_pass_initialised() {
                true => {
                    colour::green!("Pass already initialised!!\n");
                }
                false => {
                    MasterPassword::new();
                }
            };
        }

        Some(Commands::ChangeMaster) => {
            let master = master_password;

            let mut unlocked = master.verify()?;

            unlocked.change()?;

            unlocked.lock();
        }

        Some(Commands::Add(args)) => {
            for attempt in 0..3 {
                let master_password = util::password_input("Enter Master password: ")
                    .expect("Unable to read input from IO console");
                match MasterPassword::verify(&master_password) {
                    Ok(true) => {
                        args.add_entries(master_password.as_ref())?;
                        break;
                    }
                    Ok(false) => {
                        if attempt < 2 {
                            colour::red_ln!("Incorrect master password, retry ({}):", 2 - attempt);
                        } else {
                            colour::red_ln!("Wrong master password");
                        }
                    }
                    Err(_) => {
                        colour::e_red_ln!("Failed to add password");
                    }
                };
            }
        }

        Some(Commands::Remove(_args)) => {
            unimplemented!();
        }

        Some(Commands::Update(_args)) => {
            unimplemented!();
        }

        Some(Commands::List(_)) => {
            unimplemented!();
        }

        Some(Commands::Get(_args)) => {
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
Type $ pass --help to have a look on all options & commands
Type $ pass init for setting up your master password.";

            colour::red_ln!("{ASCII_ART_ABOUT}");
            colour::white_ln!("{ABOUT_MSG}")
        }
    };

    Ok(())
}
