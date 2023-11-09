use std::{io::Write, marker::PhantomData, num::NonZeroU32};

use once_cell::sync::Lazy;
use ring::pbkdf2;
use serde::{Deserialize, Serialize};

use super::util::{is_strong_password, password_input};
use crate::pass::util::{password_hash, PASS_DIR_PATH, XDG_BASE};

pub static MASTER_PASS_STORE: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("master.dat")
        .expect("Unable to place master.dat file")
}); // $HOME/.local/state/.pass/Master.dat

#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error("The master password store file is not readable due to {0}")]
    UnableToRead(std::io::Error),

    #[error("Unable to create dirs for password storage")]
    UnableToCreateDirs(std::io::Error),

    #[error("Cannot read from console due to IO error")]
    UnableToReadFromConsole,

    #[error("Unable to write into master password store file: {0}")]
    UnableToWriteFile(std::io::Error),

    #[error("Master password not matched")]
    WrongMasterPassword,

    #[error("Unable to convert {0}")]
    UnableToConvert(String),

    #[error("Bcrypt Error: {0}")]
    BcryptError(String),

    #[error("Unable to use Console IO: {0}")]
    IO(#[source] std::io::Error),

    #[error("Master password was not confirmed")]
    MasterPassConfirm,

    #[error("Master password is not strong enough")]
    PassNotStrong,
}

/// Default state of [MasterPassword]
pub struct UnInit;

/// Initial state of [MasterPassword]
#[derive(Debug, Clone, Copy)]
pub struct Init;

/// Unverified state of [MasterPassword]
#[derive(Debug, Clone, Copy)]
pub struct UnVerified;

/// Verified state of [MasterPassword]
#[derive(Debug, Clone, Copy)]
pub struct Verified;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct MasterPassword<State = UnInit> {
    /// Master password
    pub master_pass: Option<Vec<u8>>,
    /// Master password hashed
    pub hash: Option<Vec<u8>>,
    /// [MasterPassword] state
    pub state: PhantomData<State>,
}

impl Default for MasterPassword<Init> {
    fn default() -> Self {
        Self {
            master_pass: Default::default(),
            hash: Default::default(),
            state: PhantomData,
        }
    }
}

impl MasterPassword<UnInit> {
    pub fn new() -> MasterPassword<Init> {
        MasterPassword::default()
    }
}

impl MasterPassword<Init> {
    /// Convert initialised state to unverified state
    pub fn init(self) -> Result<MasterPassword<UnVerified>, MasterPasswordError> {
        // If master password file exists, then read hashed password and set to object
        if MASTER_PASS_STORE.exists() {
            let hashed_password = std::fs::read(MASTER_PASS_STORE.to_path_buf())
                .map_err(MasterPasswordError::UnableToRead)?;

            Ok(MasterPassword {
                hash: Some(hashed_password),
                master_pass: None,
                state: PhantomData::<UnVerified>,
            })
        }
        // If master password doesn't exist in db, generate a new one
        else {
            std::fs::create_dir_all(PASS_DIR_PATH.to_owned())
                .map_err(MasterPasswordError::UnableToCreateDirs)?;

            let mut master_pass_input: String;

            loop {
                // Ask user master password
                master_pass_input = password_input("Enter master password:")
                    .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

                if !is_strong_password(&master_pass_input) {
                    colour::e_red_ln!("Password is not strong enough!");
                    continue;
                }

                let confirm_pass = password_input("Confirm master pass:")
                    .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

                if master_pass_input != confirm_pass {
                    colour::e_red_ln!("Password doesn't match");
                    return Err(MasterPasswordError::MasterPassConfirm);
                }

                break;
            }

            // Hashing prompted master password
            let hashed_password = password_hash(&master_pass_input)
                .map_err(|_| MasterPasswordError::BcryptError("Unable to hash".to_string()))?;

            // Store hashed master password
            std::fs::write(MASTER_PASS_STORE.to_path_buf(), &hashed_password)
                .map_err(MasterPasswordError::UnableToWriteFile)?;

            colour::green_ln!("Initialising master pass...");

            Ok(MasterPassword {
                master_pass: None,
                hash: Some(hashed_password),
                state: PhantomData::<UnVerified>,
            })
        }
    }
}

impl MasterPassword<UnVerified> {
    /// Takes input master_password from user
    pub fn prompt(&mut self) -> Result<(), MasterPasswordError> {
        std::io::stdout().flush().ok(); // Flush the output to ensure prompt is displayed

        // Taking input master password
        let prompt_master_password = password_input("Enter Master password: ")
            .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

        // Storing prompt password to object
        self.master_pass = Some(prompt_master_password.as_bytes().to_vec());
        Ok(())
    }

    // Unlock the master password
    pub fn verify(&self) -> Result<MasterPassword<Verified>, MasterPasswordError> {
        std::io::stdout().flush().map_err(MasterPasswordError::IO)?; // Flush the output to ensure prompt is displayed

        // TODO: Improve code
        let password = self.master_pass.clone().unwrap();
        let hash = String::from_utf8(self.hash.clone().unwrap()).unwrap();

        match bcrypt::verify(password, &hash) {
            Ok(true) => Ok(MasterPassword {
                master_pass: self.master_pass.clone(),
                hash: self.hash.clone(),
                state: PhantomData::<Verified>,
            }),
            Ok(false) => Err(MasterPasswordError::WrongMasterPassword),
            Err(e) => Err(MasterPasswordError::BcryptError(e.to_string())),
        }
    }
}

impl MasterPassword<Verified> {
    pub fn lock(self) -> MasterPassword<UnVerified> {
        MasterPassword {
            hash: self.hash,
            master_pass: None,
            state: PhantomData::<UnVerified>,
        }
    }

    // TODO: Encrypt all contents with new pass bcs of changed master-pass

    // To change master password
    pub fn change(&mut self) -> Result<(), MasterPasswordError> {
        let prompt_new_master = password_input("Enter Master password: ")
            .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

        if is_strong_password(&prompt_new_master) {
            for attempt in 0..3 {
                let confirm_master_password = password_input("Confirm master password: ")
                    .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

                if prompt_new_master.as_ref() == confirm_master_password {
                    break;
                }
                if attempt == 2 {
                    colour::e_red_ln!("Confirm password does not match");
                    std::process::exit(1);
                }
                colour::e_red_ln!("Confirm password does not match, retry({})", 2 - attempt);
            }

            let hash = password_hash(prompt_new_master.trim())
                .map_err(|_| MasterPasswordError::BcryptError(String::from("Unable to hash")))?;
            self.hash = Some(hash.clone());

            std::fs::write(MASTER_PASS_STORE.to_path_buf(), hash)
                .map_err(MasterPasswordError::UnableToWriteFile)?;
            colour::green_ln!("Master password changed successfully");

            Ok(())
        } else {
            colour::e_red_ln!("Password is not strong enough!");
            self.change()
        }
    }

    // Derive a encryption key from master password & salt
    pub fn derive_encryption_key(&self, salt: impl AsRef<[u8]>) -> [u8; 32] {
        let mut encryption_key = [0_u8; 32];

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(600_000).unwrap(),
            salt.as_ref(),
            self.master_pass.as_ref().unwrap(),
            &mut encryption_key,
        );

        encryption_key
    }
}

#[cfg(test)]
mod test {
    use super::MasterPassword;

    #[test]
    #[ignore = "unimplemented"]
    fn check_init() {
        let _master = MasterPassword::new();
        // let _unlocked = master.unwrap().verify();
    }
}
