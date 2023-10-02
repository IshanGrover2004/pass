use super::io::*;
use crate::{MASTER_PASSWORD_PATH, PASS_DIR_PATH};
use anyhow::{Context, Ok};
use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};

// Function to initialise PASS
pub fn initialise_pass() -> anyhow::Result<()> {
    // Check for pass already initialised?
    if super::io::is_pass_initialised() {
        colour::green!("Pass already initialised!");
        return Ok(());
    }

    // If pass not initialised -> then initialise one
    if !is_path_exist(PASS_DIR_PATH) {
        std::fs::create_dir(PASS_DIR_PATH).context("Error in creating .pass folder")?;
    }

    // Take input Master password from user
    let master_password = ask_master_password();

    // Store master password
    std::fs::write(MASTER_PASSWORD_PATH, master_password)
        .context("Error in writing password in .pass/pass.txt")?;

    colour::blue!("Pass initialised successfully!! \n");

    Ok(())
}

// Takes input master_password from user
pub fn ask_master_password() -> String {
    // Taking the master password from the user
    colour::cyan!("Enter Master Password: ");
    let mut master_password = String::new();
    std::io::stdin()
        .read_line(&mut master_password)
        .expect("Coudn't read Master Password");

    // Check if the password is strong enough
    if !is_strong_password(&mut master_password) {
        colour::red!("Password is not strong enough!\n");
        let master_password = ask_master_password();
        return master_password;
    }
    master_password
}
// Function to verify the master password is strong enough
pub fn is_strong_password(password: &mut String) -> bool {
    *password = password.trim().to_string();

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

// Read master password from .pass/pass.txt
pub fn read_master_password() -> String {
    std::fs::read_to_string(MASTER_PASSWORD_PATH)
        .context("Unable to read master password from .pass")
        .unwrap()
}

// Check if master password is correct
fn is_correct_master_password(master_password: &str) -> Result<bool, BcryptError> {
    let hashed_master_password = std::fs::read_to_string(MASTER_PASSWORD_PATH).unwrap();

    match verify(&master_password, &hashed_master_password) {
        std::result::Result::Ok(is_correct) => std::result::Result::Ok(is_correct),
        Err(err) => Err(err),
    }
}
