use std::num::NonZeroU32;

use clipboard::{ClipboardContext, ClipboardProvider};
use once_cell::sync::Lazy;
use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};

use super::master::MASTER_PASS_STORE;

// Making Base directories by xdg config
pub(crate) static APP_NAME: &str = ".pass";

pub(crate) static XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});

pub(crate) static PASS_DIR_PATH: Lazy<std::path::PathBuf> = Lazy::new(|| XDG_BASE.get_state_home()); // $HOME/.local/state/.pass

#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    #[error("Bcrypt Error: {0}")]
    BcryptError(String),

    #[error("Unable to read from console")]
    UnableToReadFromConsole,
}

// Derive a encryption key from master password & salt
pub fn derive_encryption_key<T, R>(master_pass: T, salt: R) -> [u8; 32]
where
    T: AsRef<[u8]>,
    R: AsRef<[u8]>,
{
    let mut encryption_key = [0_u8; 32];

    // TODO: Derive key by PBKDF2 & remove ring
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(600_000).unwrap(),
        salt.as_ref(),
        master_pass.as_ref(),
        &mut encryption_key,
    );

    encryption_key
}

// Genrerate a random salt using Rng
pub fn get_random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let r = SystemRandom::new();
    r.fill(&mut salt).unwrap();
    salt
}

// Generate hash for given content
pub fn password_hash(content: impl AsRef<[u8]>) -> Result<Vec<u8>, UtilError> {
    Ok(bcrypt::hash(content, bcrypt::DEFAULT_COST)
        .map_err(|_| UtilError::BcryptError(String::from("Unable to hash password")))?
        .as_bytes()
        .to_vec())
}

// Function to verify the master password is strong enough
pub fn is_strong_password(password: impl AsRef<str>) -> bool {
    // Check if the password length is at least 8 characters
    if password.as_ref().len() < 8 {
        return false;
    }

    let (has_lowercase, has_uppercase, has_digit, has_special) = password.as_ref().chars().fold(
        (false, false, false, false),
        |(has_lowercase, has_uppercase, has_digit, has_special), c| {
            (
                has_lowercase || c.is_ascii_lowercase(),
                has_uppercase || c.is_ascii_uppercase(),
                has_digit || c.is_ascii_digit(),
                has_special || (!c.is_ascii_alphanumeric() && !c.is_ascii_whitespace()),
            )
        },
    );

    has_lowercase && has_uppercase && has_digit && has_special
}

// Generate random password of given length
pub fn generate_random_password(length: u8) -> impl AsRef<str> {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        abcdefghijklmnopqrstuvwxyz\
                        0123456789)(*&^%$#@!~";
    let password_len: u8 = length;
    let mut rng = rand::thread_rng();

    let password: String = (0..password_len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    password
}

// Set content to clipboard
pub fn copy_to_clipboard(password: String) -> anyhow::Result<()> {
    let mut ctx =
        ClipboardContext::new().map_err(|_| anyhow::anyhow!("Unable to initialize clipboard"))?;
    ctx.set_contents(password)
        .map_err(|_| anyhow::anyhow!("Unable to set clipboard contents"))?;

    // Get method is neccessary for some OS. (Refer to this issue: https://github.com/aweinstock314/rust-clipboard/issues/86)
    ctx.get_contents()
        .map_err(|_| anyhow::anyhow!("Unable to get clipboard contents"))?;
    Ok(())
}

// To check any pass initialised
pub fn is_pass_initialised() -> bool {
    MASTER_PASS_STORE.to_path_buf().exists()
}

pub fn password_input(message: impl AsRef<str>) -> Result<String, UtilError> {
    colour::green!("{}", message.as_ref());
    rpassword::read_password().map_err(|_| UtilError::UnableToReadFromConsole)
}
