// Modules required to make
pub mod args;

use std::borrow::BorrowMut;

use clap::Parser;
use colour::e_red_ln;

use crate::pass::master::{Init, MasterPasswordError};
use crate::{
    cli::args::{Cli, Commands},
    pass::{master::MasterPassword, util::is_pass_initialised},
};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Failed to Create Master password")]
    UnableToCreateMaster,

    #[error("Failed to Unlock Master password")]
    UnableToUnlockMaster,

    #[error("Failed to Change Master password")]
    UnableToChangeMaster,

    #[error("Unable to read from console")]
    UnableToReadFromConsole,
}

// Run the CLI
pub fn run_cli(master_password: MasterPassword<Init>) -> anyhow::Result<()> {
    // Parsing the command line arguments into Cli struct
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Init(_)) => {
            match is_pass_initialised() {
                true => {
                    colour::green_ln!("Pass already initialised!!");
                }
                false => {
                    master_password.init()?;
                }
            };
        }

        Some(Commands::ChangeMaster) => {
            // Initialises master password
            let mut master = master_password.init()?;

            // Prompt and set master password
            master.prompt()?;

            // Change state to verified
            let mut unlocked = master.verify()?;

            // Change the master-pass and store it in db
            unlocked.change()?;

            // Again lock the master-pass
            unlocked.lock();
        }

        Some(Commands::Add(mut args)) => {
            let mut master = master_password.init()?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(verified) => {
                        args.borrow_mut().add_entries(&verified)?;
                        break;
                    }
                    Err(MasterPasswordError::WrongMasterPassword) => {
                        if attempt < 2 {
                            colour::e_red_ln!(
                                "Incorrect master password, retry ({}):",
                                2 - attempt
                            );
                        } else {
                            colour::e_red_ln!("Wrong master password");
                        }
                    }
                    Err(e) => {
                        e_red_ln!("Unable to add password due to: {}", e.to_string());
                        break;
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
            let mut master = master_password.init()?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(verified) => {
                        args::list_entries(verified)?;
                        break;
                    }
                    Err(MasterPasswordError::WrongMasterPassword) => {
                        if attempt < 2 {
                            colour::e_red_ln!(
                                "Incorrect master password, retry ({}):",
                                2 - attempt
                            );
                        } else {
                            colour::e_red_ln!("Wrong master password");
                        }
                    }
                    Err(e) => {
                        e_red_ln!("Unable to add password due to: {}", e.to_string());
                        break;
                    }
                };
            }
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
