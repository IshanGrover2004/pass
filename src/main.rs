use pass::cli::run_cli;

fn main() {
    // Making a safe & secure, easy to use password manager and generator
    run_cli();
}

// For custom name of project -> cargo install --path . && pass

// TODO: Add clap for command line arguments
// TODO: Add bcrypt for hashing passwords
// TODO: Add file handling for storing passwords
// TODO: Add anyhow for Error handling
// TODO: Add rsin_rs for formating in file
// TODO: Add serde_encrypt for encrypting things
// TODO: Add bincode for bytes conversion & vice-versa operations
