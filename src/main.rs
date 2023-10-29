//! Making a safe & secure, easy to use password manager and generator
//!
pub mod cli;
pub mod pass;

use cli::run_cli;

fn main() -> anyhow::Result<()> {
    run_cli().expect("Unable to run cli");
    Ok(())
}

// For custom name of project -> cargo install --path . && pass

// TO Check:
// - Module
// - Unwrap/Error handle

// To ASK:
// - Storing SALT
// - entry.rs 24 line no. exposing info to pub

// TODO: Add useful test for every files
// TODO: Ask for Confirm Master password
