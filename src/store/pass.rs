use anyhow::{Context, Ok};
use bcrypt::{hash, verify, BcryptError};

// Function to initialise PASS
pub fn initialise_pass() -> anyhow::Result<()> {
    // Check for master password already existed?
    if is_path_exist("/home/tan/.local/share/.pass/pass.txt") {
        colour::green!("Pass already initialised!");
        return Ok(());
    }

    // If pass not initialised -> then initialise one
    std::fs::create_dir("/home/tan/.local/share/.pass")
        .context("Error in creating .pass folder")?;
    let master_password = ask_master_password();
    std::fs::write("/home/tan/.local/share/.pass/pass.txt", master_password)
        .context("Error in writing password in .pass/pass.txt")?;

    Ok(())
}

// To check any path exist?
pub fn is_path_exist(path: &str) -> bool {
    let path = std::path::Path::new(path);
    path.exists()
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
        let mut master_password = ask_master_password();
        colour::blue!("Pass initialised SUCCESSFULLY\n");
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
    std::fs::read_to_string("/home/tan/.local/share/.pass/pass.txt")
        .context("Unable to read master password from .pass")
        .unwrap()
}

// Check if master password is correct
fn is_correct_master_password(master_password: &str) -> Result<bool, BcryptError> {
    let hashed_master_password =
        std::fs::read_to_string("/home/tan/.local/share/.pass/pass.txt").unwrap();

    match verify(&master_password, &hashed_master_password) {
        std::result::Result::Ok(is_correct) => std::result::Result::Ok(is_correct),
        Err(err) => Err(err),
    }
}
