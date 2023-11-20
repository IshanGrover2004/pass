use clipboard::{ClipboardContext, ClipboardProvider};
use colour::e_prnt_ln;
use once_cell::sync::Lazy;
use ring::rand::{SecureRandom, SystemRandom};

use inquire::{validator::Validation, PasswordDisplayMode, Text};
type InquirePassword<'a> = inquire::Password<'a>;

// Making Base directories by xdg config
pub(crate) static APP_NAME: &str = "pass";
pub(crate) static XDG_BASE: Lazy<xdg::BaseDirectories> = Lazy::new(|| {
    xdg::BaseDirectories::with_prefix(APP_NAME).expect("Failed to initialised XDG BaseDirectories")
});

// $HOME/.local/state/pass
pub(crate) static PASS_DIR_PATH: Lazy<std::path::PathBuf> = Lazy::new(|| XDG_BASE.get_state_home());

#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    #[error("Bcrypt Error: {0}")]
    BcryptError(String),

    #[error("Unable to read from console")]
    UnableToReadFromConsole,
}

// Genrerate a random salt using Rng
pub fn get_random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let r = SystemRandom::new();
    r.fill(&mut salt).unwrap();
    salt
}

// Generate hash for given content
pub fn password_hash(content: impl AsRef<[u8]>) -> Result<String, UtilError> {
    bcrypt::hash(content.as_ref(), bcrypt::DEFAULT_COST)
        .map_err(|_| UtilError::BcryptError(String::from("Unable to hash password")))
}

pub fn input_master_pass() -> anyhow::Result<String> {
    let validator = |input: &str| {
        if !is_strong_password(input) {
            Ok(Validation::Invalid("Password is not strong enough.".into()))
        } else {
            Ok(Validation::Valid)
        }
    };

    let password = InquirePassword::new("Enter master password: ")
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm master password:")
        .with_custom_confirmation_error_message("The password don't match.")
        .with_validator(validator)
        .with_formatter(&|_| String::from("Password stored"))
        .with_help_message("Password must include => lowercase, Uppercase, digits, symbols")
        .prompt()?;

    Ok(password)
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

pub fn prompt_string(message: impl AsRef<str>) -> anyhow::Result<Option<String>> {
    Ok(Text::new(message.as_ref())
        .with_formatter(&|i| i.to_string())
        .with_help_message("Press <Esc> to skip the username")
        .with_validator(|input: &str| {
            if input.is_empty() {
                Ok(Validation::Invalid("To skip, press <ESC>".into()))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt_skippable()
        .map_err(|_| UtilError::UnableToReadFromConsole)?)
}

pub fn prompt_string_without_skip(message: impl AsRef<str>) -> anyhow::Result<String> {
    Ok(Text::new(message.as_ref())
        .with_formatter(&|i| i.to_string())
        .with_help_message("Press <Esc> to skip the username")
        .with_validator(|input: &str| {
            if input.is_empty() {
                Ok(Validation::Invalid("To skip, press <ESC>".into()))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt()
        .map_err(|_| UtilError::UnableToReadFromConsole)?)
}

// Generate random password of given length
pub fn generate_random_password(length: u8) -> impl AsRef<str> {
    if length < 3 {
        e_prnt_ln!("Password length should be more than 3");
    }

    passwords::PasswordGenerator::new()
        .length(length as usize)
        .uppercase_letters(true)
        .symbols(false)
        .strict(true)
        .generate_one()
        .expect("Unble to create random password")
}

pub fn ask_for_confirm(message: impl AsRef<str>) -> Result<bool, inquire::InquireError> {
    inquire::Confirm::new(message.as_ref())
        .with_default(true)
        .prompt()
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

// TODO: Don't use anyhow anywhere other than main.rs
pub fn password_input(message: impl AsRef<str>) -> anyhow::Result<Vec<u8>> {
    Ok(InquirePassword::new(message.as_ref())
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()?
        .as_bytes()
        .to_vec())
}
