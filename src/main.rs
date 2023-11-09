//! Making a safe & secure, easy to use password manager and generator

pub mod cli;
pub mod pass;

use cli::run_cli;
use pass::master::MasterPassword;

fn main() -> anyhow::Result<()> {
    let master_pass = MasterPassword::new();
    run_cli(master_pass).expect("Unable to run cli");
    Ok(())
}
