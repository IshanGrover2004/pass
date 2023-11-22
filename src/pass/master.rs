use std::{io::Write, marker::PhantomData, num::NonZeroU32, string::FromUtf8Error};

use anyhow::Context;
use once_cell::sync::Lazy;
use ring::pbkdf2;
use serde::{Deserialize, Serialize};

use super::{
    store::{PasswordStore, PASS_ENTRY_STORE},
    util::password_input,
};

use crate::pass::util::{input_master_pass, password_hash, PASS_DIR_PATH, XDG_BASE};

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
    UnableToConvert(#[source] FromUtf8Error),

    #[error("Bcrypt Error: {0}")]
    BcryptError(String),

    #[error("Unable to flush or use console IO: {0}")]
    IO(#[source] std::io::Error),

    #[error("Master password was not confirmed")]
    MasterPassConfirmFailed,

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
    pub hash: Option<String>,
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

impl MasterPassword {
    pub fn dump(hash_pass: impl AsRef<str>) -> Result<(), MasterPasswordError> {
        std::fs::write(MASTER_PASS_STORE.to_path_buf(), hash_pass.as_ref())
            .map_err(MasterPasswordError::UnableToWriteFile)?;

        Ok(())
    }
}
impl MasterPassword<UnInit> {
    pub fn new() -> MasterPassword<Init> {
        MasterPassword::default()
    }

    pub fn create_pass_dirs() -> Result<(), MasterPasswordError> {
        std::fs::create_dir_all(PASS_DIR_PATH.to_owned())
            .map_err(MasterPasswordError::UnableToCreateDirs)
    }

    pub fn is_initialised() -> bool {
        MASTER_PASS_STORE.exists()
    }
}

impl MasterPassword<Init> {
    pub fn initialise(&self) -> Result<MasterPassword<Verified>, MasterPasswordError> {
        MasterPassword::create_pass_dirs()?;

        let master_pass = input_master_pass("Enter master password: ")
            .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

        colour::green_ln!("Pass initialised successfully");

        MasterPassword::from_pass(master_pass)
    }

    /// Convert initialised state to unverified state
    pub fn load(self) -> Result<MasterPassword<UnVerified>, MasterPasswordError> {
        handle_master_not_initialised();

        // Read hashed password from DB and set to object
        Ok(MasterPassword {
            hash: Some(self.get_master_hash_from_db()?),
            master_pass: None,
            state: PhantomData::<UnVerified>,
        })
    }

    fn get_master_hash_from_db(&self) -> Result<String, MasterPasswordError> {
        String::from_utf8(
            std::fs::read(MASTER_PASS_STORE.to_path_buf())
                .map_err(MasterPasswordError::UnableToRead)?,
        )
        .map_err(MasterPasswordError::UnableToConvert)
    }

    /// Create a verified [MasterPassword] and set master & its hash in it
    pub fn from_pass<P>(password: P) -> Result<MasterPassword<Verified>, MasterPasswordError>
    where
        P: AsRef<[u8]>,
    {
        let hashed_password = password_hash(&password)
            .map_err(|_| MasterPasswordError::BcryptError("Unable to hash".to_string()))?;

        // Store hashed master password
        MasterPassword::dump(&hashed_password)?;

        Ok(MasterPassword {
            master_pass: Some(password.as_ref().to_vec()),
            hash: Some(hashed_password),
            state: PhantomData::<Verified>,
        })
    }
}

impl MasterPassword<UnVerified> {
    /// Takes input master_password from user
    pub fn prompt(&mut self) -> Result<(), MasterPasswordError> {
        std::io::stdout().flush().map_err(MasterPasswordError::IO)?; // Flush the output to ensure prompt is displayed

        // Taking input master password
        let prompt_master_password = password_input("Enter your master password: ")
            .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

        // Storing prompt password to object
        self.master_pass = Some(prompt_master_password);
        Ok(())
    }

    fn get_hash(&self) -> String {
        assert!(self.hash.is_some());
        self.hash
            .clone()
            .expect("Unreachable: Master password hash can not be empty")
    }

    fn get_pass(&self) -> Vec<u8> {
        assert!(self.master_pass.is_some());
        self.master_pass
            .clone()
            .expect("Unreachable: Master password can not be empty")
    }

    pub fn get_master_str(&self) -> String {
        assert!(self.master_pass.is_some());

        let master_vec = self
            .master_pass
            .clone()
            .expect("Unreachable: Master password can not be empty");

        String::from_utf8(master_vec)
            .context("Unable to convert utf8 to String")
            .unwrap()
    }

    // Unlock the master password
    pub fn verify(&self) -> Result<Option<MasterPassword<Verified>>, MasterPasswordError> {
        std::io::stdout().flush().map_err(MasterPasswordError::IO)?; // Flush the output to ensure prompt is displayed

        let password = self.get_pass();
        let hash = self.get_hash();

        bcrypt::verify(&password, &hash)
            .map(|verification_status| {
                verification_status.then_some(MasterPassword {
                    master_pass: Some(password),
                    hash: Some(hash),
                    state: PhantomData::<Verified>,
                })
            })
            .map_err(|e| MasterPasswordError::BcryptError(e.to_string()))
    }
}

impl MasterPassword<Verified> {
    pub fn change(&mut self) -> Result<(), MasterPasswordError> {
        let prompt_new_master = input_master_pass("Enter new master password: ")
            .map_err(|_| MasterPasswordError::UnableToReadFromConsole)?;

        // Storing old master pass for later
        let old_master = self.get_master_str();

        self.set_new_master(prompt_new_master)?;

        // Re-encrypting contents over new master pass
        self.re_encrypt_contents(old_master)
            .expect("Unable to re-encrypt entries");

        // Store hash of changed master pass
        MasterPassword::dump(self.get_hash())?;
        colour::green_ln!("Master password changed successfully");

        Ok(())
    }

    pub fn set_new_master(
        &mut self,
        new_master: impl AsRef<str>,
    ) -> Result<(), MasterPasswordError> {
        // Hash the password and set it to the self
        let hash = password_hash(new_master.as_ref())
            .map_err(|_| MasterPasswordError::BcryptError("Unable to hash".to_string()))?;

        self.master_pass = Some(new_master.as_ref().as_bytes().to_vec());
        self.hash = Some(hash.clone());
        Ok(())
    }

    pub fn re_encrypt_contents<P>(&self, old_master_password: P) -> anyhow::Result<()>
    where
        P: AsRef<[u8]>,
    {
        if PASS_ENTRY_STORE.exists() {
            let master_pass = MasterPassword::from_pass(old_master_password)?;

            // Load all entries form db by old master
            let mut storage = PasswordStore::load(PASS_ENTRY_STORE.to_path_buf(), master_pass)?;

            storage.change_master(self.clone());

            // Again encrypt entries with new pass
            storage.dump(PASS_ENTRY_STORE.to_path_buf())?;
        }

        Ok(())
    }

    pub fn derive_encryption_key(&self, salt: impl AsRef<[u8]>) -> [u8; 32] {
        let mut encryption_key = [0_u8; 32];

        // Deriving a encryption key using master pass
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(600_000).unwrap(),
            salt.as_ref(),
            self.master_pass.as_ref().unwrap(),
            &mut encryption_key,
        );

        encryption_key
    }

    pub fn get_master_str(&self) -> String {
        assert!(self.master_pass.is_some());

        let master_vec = self
            .master_pass
            .clone()
            .expect("Unreachable: Master password can not be empty");

        String::from_utf8(master_vec)
            .context("Unable to convert utf8 to String")
            .unwrap()
    }

    fn get_hash(&self) -> String {
        assert!(self.hash.is_some());
        self.hash
            .clone()
            .expect("Unreachable: Master password hash can not be empty")
    }
}

pub fn handle_master_not_initialised() {
    if !MasterPassword::is_initialised() {
        println!("Pass is not initialised");
        println!("Usage: pass_rs init");
        std::process::exit(0);
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
