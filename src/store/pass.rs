use super::io::*;
use crate::{encrypt, MASTER_PASSWORD_PATH, PASS_DIR_PATH};
use anyhow::{Context, Ok};
use bcrypt::{verify, BcryptError};

#[derive(Debug)]
pub struct MasterPassword {
    hashed_master_password: String,
}
// .init .change .verify .read/retreive .hash .is_correct

impl MasterPassword {
    pub fn new() -> Self {
        MasterPassword::init();
        MasterPassword {
            hashed_master_password: String::new(),
        }
    }

    // Function to initialise PASS
    pub fn init() -> anyhow::Result<Self> {
        // Check for pass already initialised?
        if super::io::is_pass_initialised() {
            colour::green!("Pass already initialised!");
            return Ok(MasterPassword::read());
        }

        // If pass not initialised -> then initialise one
        if !is_path_exist(PASS_DIR_PATH) {
            std::fs::create_dir(PASS_DIR_PATH).context("Error in creating .pass folder")?;
        }

        // Take input Master password from user
        let master_password = ask_master_password();
        let master_password = encrypt::hash(&master_password);

        // Store master password
        std::fs::write(MASTER_PASSWORD_PATH, &master_password)
            .context("Error in writing password in .pass/pass.txt")?;

        colour::blue!("Pass initialised successfully!! \n");

        Ok(MasterPassword {
            hashed_master_password: master_password,
        })
    }

    // Read master password hash from pass directory
    pub fn read() -> Self {
        let hashed_pass = std::fs::read_to_string(MASTER_PASSWORD_PATH)
            .context("Unable to read master password from .pass")
            .unwrap();
        MasterPassword {
            hashed_master_password: hashed_pass,
        }
    }

    // Change master password
    pub fn change(&self) {
        // let master_password = ask_master_password();
        // let is_correct_master_pass = self.verify(&master_password)
    }

    // Check if master password is correct
    pub fn verify(&self, master_password: &str) -> Result<bool, BcryptError> {
        let hashed_master_password = &self.hashed_master_password;

        match verify(&master_password, &hashed_master_password) {
            std::result::Result::Ok(is_correct) => std::result::Result::Ok(is_correct),
            Err(err) => Err(err),
        }
    }
}

// Function to verify the master password is strong enough
pub fn is_strong_password(password: &str) -> bool {
    // Check if the password length is at least 8 characters
    if password.len() < 8 {
        return false;
    }

    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

    return has_lowercase && has_uppercase && has_digit && has_special;
}
