// Clap ->  , Scrypt -> For Passsword Verification ,
// Make uuid whenever any new password added for

use pass::cli::{args::*, run_cli};

use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};

fn main() {
    // Making a safe & secure, easy to use password manager and generator

    run_cli();

    // TODO: Add clap for command line arguments
    // TODO: Add bcrypt for hashing passwords
    // TODO: Add file handling for storing passwords
    // TODO: Add anyhow for Error handling
    // TODO: Add rsin_rs for formating in file
    // TODO: Add serde_encrypt for encrypting things
    // TODO: Add bincode for bytes conversion & vice-versa operations
}

fn generate_password() -> String {
    // let generator = PasswordGenerator {
    //     length: 12,
    //     numbers: true,
    //     lowercase_letters: true,
    //     uppercase_letters: true,
    //     symbols: true,
    //     spaces: true,
    //     exclude_similar_characters: false,
    //     strict: true,
    // };
    //
    // generator.generate_one().unwrap().to_string()
    String::new()
}

// Check if master password is correct
fn is_correct_master_password(
    master_password: &str,
    hashed_master_password: &str,
) -> Result<bool, BcryptError> {
    match verify(&master_password, &hashed_master_password) {
        Ok(is_correct) => Ok(true),
        Err(err) => Err(err),
    }
}
/* Imp Notes:
 * For custom name of project -> cargo install --path . && pass
 */
