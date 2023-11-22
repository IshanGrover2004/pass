// Modules required to make
pub mod args;

use std::borrow::BorrowMut;

use clap::Parser;
use colour::e_red_ln;

use crate::pass::master::{Init, UnVerified, Verified};
use crate::{
    cli::args::{Cli, Command},
    pass::master::MasterPassword,
};

use self::args::list_entries;

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

    #[error("Unable to reset the pass dir")]
    UnableToResetPassDir(#[source] std::io::Error),

    #[error("Unable to reset the pass entry file")]
    UnableToResetPassEntry(#[source] std::io::Error),
}

// Run the CLI
pub fn run_cli(master_password: MasterPassword<Init>) -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Some(Command::Init) => {
            match MasterPassword::is_initialised() {
                true => {
                    colour::green_ln!("Pass already initialised!!");
                }
                false => {
                    master_password.initialise()?;
                }
            };
        }

        Some(Command::ChangeMaster) => {
            let mut master = master_password.load()?;

            // password_verification(master, |verified| verified.change())?;

            for attempt in 0..3 {
                master.prompt()?;

                match master.verify() {
                    Ok(Some(mut verified)) => {
                        // Change the master-pass and store it in db
                        verified.change()?;
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

        Some(Command::Add(mut arg)) => {
            let mut master = master_password.load()?;

            // password_verification(master, |verified| arg.add_entries(verified))?;

            for attempt in 0..3 {
                master.prompt()?;

                match master.verify() {
                    Ok(Some(verified)) => {
                        arg.borrow_mut().add_entries(&verified)?;
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

        Some(Command::Remove(mut arg)) => {
            let mut master = master_password.load()?;

            // password_verification(master, |verified| arg.remove_entries(verified))?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(Some(verified)) => {
                        arg.remove_entries(verified)?;
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

        Some(Command::Update(_args)) => {
            unimplemented!();
        }

        Some(Command::List) => {
            let master = master_password.load()?;

            password_verification(master, list_entries)?;
        }

        Some(Command::Get(arg)) => {
            let master = master_password.load()?;

            password_verification(master, |verified| arg.get_entries(verified))?;
        }

        Some(Command::Search(arg)) => {
            let master = master_password.load()?;

            password_verification(master, |verified| arg.fuzzy_search(verified))?;
        }

        Some(Command::Gen(args)) => {
            args.generate_password();
        }

        Some(Command::Reset(arg)) => {
            let mut master = master_password.load()?;

            // password_verification(master, |verified| arg.reset())?;

            for attempt in 0..3 {
                master.borrow_mut().prompt()?;

                match master.verify() {
                    Ok(Some(_)) => {
                        arg.reset()?;
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

fn password_verification<F>(mut master: MasterPassword<UnVerified>, func: F) -> anyhow::Result<()>
where
    F: Fn(MasterPassword<Verified>) -> anyhow::Result<()>,
{
    for attempt in 0..3 {
        master.borrow_mut().prompt()?;

        match master.verify() {
            Ok(Some(verified)) => {
                func(verified)?;
                break;
            }
            Ok(None) => {
                if attempt < 2 {
                    colour::e_red_ln!("Incorrect master password, retry ({}):", 2 - attempt);
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

    Ok(())
}
