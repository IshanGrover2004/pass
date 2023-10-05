use once_cell::sync::Lazy;
use std::marker::PhantomData;

// Making Base directories by xdg config
const APP_NAME: &str = ".pass";
const XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});
const MASTER_PASS_PATH: Lazy<std::path::PathBuf> =
    Lazy::new(|| XDG_BASE.get_data_home().join(APP_NAME));

// Initialising States & posibilities
struct Uninit;
struct Locked;
struct Unlocked;

#[derive(Debug)]
struct MasterPassword<State = Uninit> {
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
impl<Uninit> MasterPassword<Uninit> {
    pub fn init(&mut self, hashed_password: String) -> MasterPassword<Locked> {
        MasterPassword {
            password_hash: None,
            unlocked_password: None,
            current_state: PhantomData::<Locked>,
        }
    }
}

// MasterPassword impl for Locked state
impl<Locked> MasterPassword<Locked> {
    // Unlock the master password
    pub fn unlock(&self, prompt_master_password: &str) -> MasterPassword<Unlocked> {
        MasterPassword {
            password_hash: None,
            unlocked_password: None,
            current_state: PhantomData::<Unlocked>,
        }
    }
}

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
