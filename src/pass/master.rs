use anyhow::Context;
use colour::dark_blue;
use once_cell::sync::Lazy;
use std::marker::PhantomData;

use crate::{encrypt::hash, store::pass::ask_master_password};

// Making Base directories by xdg config
const APP_NAME: &str = ".pass";
const XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});
const PASS_DIR_PATH: Lazy<std::path::PathBuf> = Lazy::new(|| XDG_BASE.get_data_home()); // $HOME/.local/share/.pass
const MASTER_PASS_PATH: Lazy<std::path::PathBuf> =
    Lazy::new(|| XDG_BASE.place_data_file("Master.yml").unwrap()); // $HOME/.local/share/.pass/Master.yml

// Initialising States & posibilities
pub struct Uninit;
pub struct Locked;
pub struct Unlocked;

#[derive(Debug)]
pub struct MasterPassword<State = Uninit> {
    password_hash: Option<Vec<u8>>,
    unlocked_password: Option<Vec<u8>>,
    current_state: PhantomData<State>,
}

// For default skeliton for new funcn
impl<Uninit> Default for MasterPassword<Uninit> {
    fn default() -> Self {
        MasterPassword {
            password_hash: None,
            unlocked_password: None,
            current_state: PhantomData::<Uninit>,
        }
    }
}

// MasterPassword impl for UnInitialised state
impl MasterPassword<Uninit> {
    pub fn new() -> MasterPassword<Locked> {
        // Check if pass not exist
        if MASTER_PASS_PATH.exists() {
            let hashed_password =
                std::fs::read(MASTER_PASS_PATH.to_owned()).expect("Failed to read Master.yml file");

            dark_blue!("Pass already initialised!!");

            MasterPassword {
                password_hash: Some(hashed_password),
                unlocked_password: None,
                current_state: PhantomData::<Locked>,
            }
        }
        // if not exist create & ask user for master_password
        else {
            if !PASS_DIR_PATH.exists() {
                std::fs::create_dir_all(PASS_DIR_PATH.to_owned())
                    .context("Failed to create pass directory!!")
                    .unwrap();
            }

            let prompt_master_password = ask_master_password();
            let hashed_password = hash(&prompt_master_password);

            std::fs::write(MASTER_PASS_PATH.to_owned(), &hashed_password)
                .context("Failed to write master password!")
                .unwrap();

            dark_blue!("Pass initialised successfully!!");

            MasterPassword {
                password_hash: Some(hashed_password.as_bytes().to_vec()),
                unlocked_password: Some(prompt_master_password.as_bytes().to_vec()),
                current_state: PhantomData,
            }
        }
    }
}

// MasterPassword impl for Locked state
impl MasterPassword<Locked> {
    // Unlock the master password
    pub fn unlock(&self, prompt_master_password: &str) -> MasterPassword<Unlocked> {
        MasterPassword {
            password_hash: None,
            unlocked_password: None,
            current_state: PhantomData::<Unlocked>,
        }
    }
}

/*
// MasterPassword impl for Unlocked state
impl<Unlocked> MasterPassword<Unlocked> {
    // Lock the master password & stop from accessing it
    pub fn lock(&self) -> MasterPassword<Locked> {
        MasterPassword {
            password_hash: None,
            unlocked_password: None,
            current_state: PhantomData::<Locked>,
        }
    }

    // To ubdate the master password
    pub fn update(&mut self) {}

    // get the master_password
    pub fn get_password(&self) -> String {
        String::from("ndbhbx")
    }
}
*/
