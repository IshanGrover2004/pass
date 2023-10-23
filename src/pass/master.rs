use std::{io::Write, marker::PhantomData};

use once_cell::sync::Lazy;

use super::util::is_strong_password;
use crate::pass::util::hash;

// Making Base directories by xdg config
const APP_NAME: &str = ".pass";

const XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});

const PASS_DIR_PATH: Lazy<std::path::PathBuf> = Lazy::new(|| XDG_BASE.get_state_home()); // $HOME/.local/state/.pass

pub const MASTER_PASS_STORE: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("master.dat")
        .expect("Unable to place master.dat file")
}); // $HOME/.local/state/.pass/Master.yml

#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error("The master password store file is not readable due to {0}")]
    UnableToRead(#[from] std::io::Error),

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

    #[error("Unable to use Console IO: {0}")]
    IO(#[source] std::io::Error),
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

            colour::green!("Pass already initialised!!\n");

            Ok(MasterPassword {
                hash: Some(hashed_password),
                unlocked_pass: None,
                state: PhantomData::<Locked>,
            })
        }
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

        let master_password = MasterPassword::password_input()?;
        if !is_strong_password(&master_password) {
            colour::red!("Password is not strong enough!\n");
            return MasterPassword::prompt();
        }

        Ok(master_password)
    }

    pub fn password_input() -> Result<String, MasterPasswordError> {
        colour::green!("Enter Master password: ");
        let mut master_password = String::new();
        std::io::stdin()
            .read_line(&mut master_password)
            .map_err(|e| MasterPasswordError::UnableToReadFromConsole(e))?;
        Ok(master_password.trim().to_owned())
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
    pub fn unlock(&self) -> Result<MasterPassword<Unlocked>, MasterPasswordError> {
        std::io::stdout()
            .flush()
            .map_err(|e| MasterPasswordError::IO(e))?; // Flush the output to ensure prompt is displayed

        const MAX_ATTEMPT: u32 = 3;

        (0..MAX_ATTEMPT)
            .find_map(|attempt| {
                let master_pass_prompt = MasterPassword::password_input().ok()?;
                MasterPassword::verify(&master_pass_prompt)
                    .ok()
                    .and_then(|is_verified| {
                        if is_verified {
                            Some(MasterPassword {
                                hash: self.hash.clone(),
                                unlocked_pass: Some(master_pass_prompt.as_bytes().to_vec()),
                                state: PhantomData::<Unlocked>,
                            })
                        } else {
                            (attempt < MAX_ATTEMPT)
                                .then(|| colour::red!("Wrong password, Please try again\n"));
                            None
                        }
                    })
            })
            .ok_or(MasterPasswordError::WrongMasterPassword)
    }
}

impl MasterPassword<Unlocked> {
    pub fn lock(&self) -> MasterPassword<Locked> {
        MasterPassword {
            hash: self.hash.clone(),
            unlocked_pass: None,
            state: PhantomData::<Locked>,
        }
    }

    // To change master password
    pub fn change(&mut self) -> Result<(), MasterPasswordError> {
        let mut password = String::new();
        colour::green!("Enter new master password: ");
        std::io::stdin()
            .read_line(&mut password)
            .map_err(|e| MasterPasswordError::UnableToReadFromConsole(e))?;

        if is_strong_password(&password) {
            let password = password.trim();
            self.unlocked_pass = Some(password.as_bytes().to_vec());
            self.hash = Some(hash(&password));
            std::fs::write(MASTER_PASS_STORE.to_owned(), self.hash.as_ref().unwrap())
                .map_err(|e| MasterPasswordError::UnableToWriteFile(e))?;
            Ok(())
        } else {
            colour::red!("Password is not strong enough!\n");
            self.change()
        }
    }

    pub fn check(&self) {
        println!(
            "{:?}-{:?}-{:?}",
            self.hash,
            String::from_utf8(self.unlocked_pass.clone().unwrap()),
            self.state
        );
    }
}

#[cfg(test)]
mod test {
    use super::MasterPassword;

    #[test]
    fn check_init() {
        let master = MasterPassword::new();
        let unlocked = master.unwrap().unlock();
    }
}
