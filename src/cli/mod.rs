// Modules required to make
pub mod args;

use std::borrow::BorrowMut;

use clap::Parser;
use colour::e_red_ln;

use crate::pass::master::Init;
use crate::{
    cli::args::{Cli, Command},
    pass::master::MasterPassword,
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

    match args.command {
        Some(Command::Init) => {
            match MasterPassword::is_initialised() {
                true => {
                    colour::green_ln!("Pass already initialised!!");
                }
                false => {
                    master_password.init()?;
                }
            };
        }

        Some(Command::ChangeMaster) => {
            // Initialises master password
            let mut master = master_password.load()?;

            // Prompt and set master password
            master.prompt()?;

            // Change state to verified
            // TODO: Check if password is wrong and handle the case
            let mut unlocked = master.verify()?.unwrap();

            // Change the master-pass and store it in db
            unlocked.change()?;
        }

        Some(Command::Add(mut args)) => {
            let mut master = master_password.load()?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(Some(verified)) => {
                        args.borrow_mut().add_entries(&verified)?;
                        break;
                    }
                    Ok(None) => {
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

        Some(Command::Remove(_args)) => {
            unimplemented!();
        }

        Some(Command::Update(_args)) => {
            unimplemented!();
        }

        Some(Command::List(_)) => {
            let mut master = master_password.load()?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(Some(verified)) => {
                        args::list_entries(verified)?;
                        break;
                    }
                    Ok(None) => {
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

        Some(Command::Get(_args)) => {
            unimplemented!();
        }

        Some(Command::Gen(args)) => {
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
