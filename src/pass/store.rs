use once_cell::sync::Lazy;

use crate::pass::{
    entry::{self, PasswordEntry},
    master,
    util::XDG_BASE,
};

use super::{
    master::MasterPassword,
    util::{is_pass_initialised, PASS_DIR_PATH},
};

pub(crate) const PASS_ENTRY_STORE: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("passwords.db")
        .expect("Unable to place passwords.db file in state")
});

#[derive(Debug, thiserror::Error)]
pub enum PasswordStoreError {
    #[error("The master password store file is not readable due to {0}")]
    UnableToRead(std::io::Error),

    #[error("Unable to create dirs for password storage")]
    UnableToCreateDirs(std::io::Error),

    #[error("Unable to write into master password store file: {0}")]
    UnableToWriteFile(std::io::Error),

    #[error("Unable to convert {0}")]
    UnableToConvert(String),
}

#[derive(Debug)]
pub struct PasswordStore {
    passwords: Vec<PasswordEntry>,
}

impl PasswordStore {
    // type Error = std::error::Error;

    // Extract the data from database & store in PasswordStore
    pub fn new(master_password: impl AsRef<[u8]>) -> Result<Self, PasswordStoreError> {
        // If no PasswordEntry is stored yet then create file to store it
        if !PASS_ENTRY_STORE.exists() {
            let file = std::fs::File::create(PASS_ENTRY_STORE.to_owned());
            // std::fs::write(PASS_ENTRY_STORE.to_owned(), "")
            //     .map_err(|e| PasswordStoreError::UnableToWriteFile(e))?;

            // Returning an empty Vec bcs of no Entry available
            return Ok(PasswordStore {
                passwords: Vec::new(),
            });
        }

        // Reads the content from database
        let content: String = String::from_utf8(
            std::fs::read(PASS_ENTRY_STORE.to_owned())
                .map_err(|e| PasswordStoreError::UnableToRead(e))?,
        )
        .map_err(|_| PasswordStoreError::UnableToConvert("from UTF-8 to String".to_owned()))?;

        // If no content available
        if content.is_empty() {
            // Returning an empty Vec bcs of no Entry available
            return Ok(PasswordStore {
                passwords: Vec::new(),
            });
        }

        // Convert file content to Password entries
        let entries = content
            .split("\n\n")
            .into_iter()
            .map(|entry| {
                PasswordEntry::decrypt_entry(&entry, &master_password)
                    .expect("Unable to decrypt password content")
            })
            .collect::<Vec<_>>();

        Ok(PasswordStore { passwords: entries })
    }

    // Add entries to the existing entries
    pub fn push(&mut self, entries: Vec<PasswordEntry>) {
        // TODO: If same service of entry exist

        self.passwords.extend(entries.into_iter());
    }

    // Remove entries from existing entries
    pub fn pop(entries: Vec<PasswordEntry>) {
        // TODO: If no entry exist of that service
    }

    pub fn get() -> Vec<PasswordEntry> {
        unimplemented!();
    }

    pub fn fuzzy_find() -> Vec<PasswordEntry> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::PasswordStore;
    use crate::pass::{
        entry::{Password, PasswordEntry},
        master::MasterPassword,
    };

    #[test]
    fn test_storage() {
        let master_pass = MasterPassword::prompt().unwrap();
        let mut store = PasswordStore::new(master_pass.as_ref()).unwrap();

        let entries = vec![PasswordEntry::new(
            "Ishan".to_owned(),
            "shsh".to_owned(),
            None::<&str>,
        )];

        store.push(entries);
    }
}
