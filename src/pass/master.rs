use once_cell::sync::Lazy;
use std::{hash, io::Write, marker::PhantomData};

use crate::{
    encrypt::{self, hash},
    store::pass::{self, is_strong_password},
};

// Making Base directories by xdg config
const APP_NAME: &str = ".pass";

const XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});

const PASS_DIR_PATH: Lazy<std::path::PathBuf> = Lazy::new(|| XDG_BASE.get_data_home()); // $HOME/.local/share/.pass

const MASTER_PASS_STORE: Lazy<std::path::PathBuf> =
    Lazy::new(|| XDG_BASE.place_data_file("master.dat").unwrap()); // $HOME/.local/share/.pass/Master.yml

#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error("The master password store file is not readable due to {0}")]
    UnableToRead(std::io::Error),

    #[error("Unable to create dirs for password storage")]
    UnableToCreateDirs(std::io::Error),

    #[error("Cannot read from console due to: {0}")]
    UnableToReadFromConsole(std::io::Error),

    #[error("Unable to write into master password store file: {0}")]
    UnableToWriteFile(std::io::Error),

    #[error("Master password not matched")]
    WrongMasterPassword,

    #[error("{0}")]
    UnableToConvert(String),

    #[error("{0}")]
    BcryptError(String),
}

// Initialising States & possibilities pub struct Uninit;
pub struct Uninit;
pub struct Locked;
pub struct Unlocked;

#[derive(Debug, Default)]
pub struct MasterPassword<State = Uninit> {
    hash: Option<Vec<u8>>,
    unlocked_pass: Option<Vec<u8>>,
    state: PhantomData<State>,
}

// MasterPassword impl for UnInitialised state
impl MasterPassword<Uninit> {
    pub fn new() -> Result<MasterPassword<Locked>, MasterPasswordError> {
        // Check if pass not exist
        if MASTER_PASS_STORE.exists() {
            let hashed_password = std::fs::read(MASTER_PASS_STORE.to_owned())
                .map_err(|e| MasterPasswordError::UnableToRead(e))?;

            colour::green!("Pass already initialised!!");

            Ok(MasterPassword {
                hash: Some(hashed_password),
                unlocked_pass: None,
                state: PhantomData::<Locked>,
            })
        }
        //
        // if not exist create & ask user for master_password
        else {
            if !PASS_DIR_PATH.exists() {
                std::fs::create_dir_all(PASS_DIR_PATH.to_owned())
                    .map_err(|e| MasterPasswordError::UnableToCreateDirs(e))?
            }

            let prompt_master_password = MasterPassword::prompt()?;
            let hashed_password = hash(&prompt_master_password);

            std::fs::write(MASTER_PASS_STORE.to_owned(), &hashed_password)
                .map_err(|e| MasterPasswordError::UnableToWriteFile(e))?;

            colour::green!("Pass Initialising...\n");

            Ok(MasterPassword {
                hash: Some(hashed_password),
                unlocked_pass: None,
                state: PhantomData::<Locked>,
            })
        }
    }

    // Takes input master_password from user
    pub fn prompt() -> Result<String, MasterPasswordError> {
        std::io::stdout().flush().ok(); // Flush the output to ensure prompt is displayed

        let mut master_password = MasterPassword::password_input()?;
        if !is_strong_password(&master_password) {
            colour::red!("Password is not strong enough!\n");
            return MasterPassword::prompt();
        }

        Ok(master_password.trim().to_string())
    }

    pub fn password_input() -> Result<String, MasterPasswordError> {
        colour::green!("Enter Master password: ");
        let mut master_password = String::new();
        std::io::stdin()
            .read_line(&mut master_password)
            .map_err(|e| MasterPasswordError::UnableToReadFromConsole(e))?;
        Ok(master_password)
    }

    // Check if master password is correct
    pub fn verify(master_password: &str) -> Result<bool, MasterPasswordError> {
        let hashed_password: String = String::from_utf8(
            std::fs::read(MASTER_PASS_STORE.to_owned())
                .map_err(|e| MasterPasswordError::UnableToRead(e))?,
        )
        .map_err(|_| {
            MasterPasswordError::UnableToConvert(String::from("Error in converting utf8 -> String"))
        })?;

        match bcrypt::verify(&master_password, hashed_password.as_str()) {
            Ok(is_correct) => Ok(is_correct),
            Err(_) => Err(MasterPasswordError::BcryptError(String::from(
                "Unable to hash password",
            ))),
        }
    }
}

// MasterPassword impl for Locked state
impl MasterPassword<Locked> {
    // Unlock the master password
    pub fn unlock(self) -> Result<MasterPassword<Unlocked>, MasterPasswordError> {
        std::io::stdout().flush().ok(); // Flush the output to ensure prompt is displayed

        for _ in [0, 1, 2] {
            let master_pass_prompt = MasterPassword::password_input()?;
            let is_prompt_correct: bool = MasterPassword::verify(&master_pass_prompt)?;
            println!("{}", &is_prompt_correct);

            match is_prompt_correct {
                true => {
                    return Ok(MasterPassword {
                        hash: self.hash,
                        unlocked_pass: Some(master_pass_prompt.as_bytes().to_vec()),
                        state: PhantomData::<Unlocked>,
                    });
                }
                false => {
                    println!("Wrong guess!");
                    continue;
                }
            };
        }
        Err(MasterPasswordError::WrongMasterPassword)

        // let input_pass = MasterPassword::password_input()?;
        //
        // let hashed_pass = &self.hash;
        //
        // let status: Option<bool> = hashed_pass
        //     .as_ref()
        //     .and_then(|pass_hash| Some(*pass_hash == hash(&input_pass)));
        // println!("{:?}", status);
        //
        // match status {
        //     Some(_) => Ok(MasterPassword {
        //         hash: None,
        //         unlocked_pass: Some(input_pass.as_bytes().to_vec()),
        //         state: PhantomData::<Unlocked>,
        //     }),
        //     None => {
        //         println!("Err");
        //         Ok(MasterPassword {
        //             hash: None,
        //             unlocked_pass: None,
        //             state: PhantomData::<Unlocked>,
        //         })
        //     }
        // }
    }
}

#[cfg(test)]
mod test {
    use super::MasterPassword;

    #[test]
    fn check_init() {
        let master = MasterPassword::new();
        // println!("{:?}", master);
        let pass = "Hello@123";
        let unlocked = master.unwrap().unlock();
    }
}
