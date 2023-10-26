use std::{ops::Deref, path::Path};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::BincodeSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    EncryptedMessage,
};

use crate::pass::{
    entry::PasswordEntry,
    util::{derive_encryption_key, XDG_BASE},
};

pub static PASS_ENTRY_STORE: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("passwords.db")
        .expect("Unable to place passwords.db file in state")
});

pub static TESTING_PASS: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("testing.db")
        .expect("Unable to place testing.db file in state")
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

    #[error("Decrypt Error: {0}")]
    UnableToDecryptError(String),

    #[error("Encrypt Error: {0}")]
    UnableToEncryptError(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordStore {
    passwords: Vec<PasswordEntry>,
}

impl SerdeEncryptSharedKey for PasswordStore {
    type S = BincodeSerializer<Self>;
}

impl PasswordStore {
    // Extract the data from database & store in PasswordStore
    pub fn new(
        file_path: impl AsRef<Path>,
        master_password: impl AsRef<[u8]>,
    ) -> Result<Self, PasswordStoreError> {
        // If no PasswordEntry is stored yet then create file to store it
        if !file_path.as_ref().exists() {
            std::fs::File::create(file_path.as_ref())
                .map_err(|e| PasswordStoreError::UnableToCreateDirs(e))?;

            // Returning an empty Vec bcs of no Entry available
            return Ok(PasswordStore {
                passwords: Vec::new(),
            });
        }

        // Reads the content from database
        let content: String = String::from_utf8(
            std::fs::read(file_path.as_ref()).map_err(|e| PasswordStoreError::UnableToRead(e))?,
        )
        .map_err(|_| PasswordStoreError::UnableToConvert("from UTF-8 to String".to_owned()))?;

        PasswordStore::load_from_db(file_path.as_ref(), master_password)
    }

    /// Encrypt the Password entries
    pub fn encrypt_entry(
        &self,
        master_pass: impl AsRef<[u8]>,
    ) -> Result<impl AsRef<[u8]>, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = self.encrypt(&key)?;
        Ok(encrypted_content.serialize())
    }

    // Decrypt the entry
    pub fn decrypt_entry(
        content: impl AsRef<[u8]>,
        master_pass: impl AsRef<[u8]>,
    ) -> Result<Self, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = EncryptedMessage::deserialize(content.as_ref().to_vec())?;
        let decrypted_content = PasswordStore::decrypt_owned(&encrypted_content, &key)?;
        Ok(decrypted_content)
    }

    // Add entries to the existing entries
    pub fn push_entry(&mut self, entry: PasswordEntry) {
        // TODO: If same service of entry exist

        let x = &self
            .passwords
            .iter()
            .filter(|current_entry| {
                current_entry.service == entry.service //&& current_entry.username == entry.username
            })
            .collect::<Vec<_>>();

        if x.is_empty() {
            self.passwords.push(entry);
            return;
        }

        colour::red_ln!("Password entry of same service & username found");
    }

    // Encrypt the entries & dump it to database
    pub fn dump_to_db(
        &self,
        file_path: impl AsRef<Path>,
        master_pass: impl AsRef<[u8]>,
    ) -> Result<(), PasswordStoreError> {
        let encrypted_data = self.encrypt_entry(master_pass).map_err(|_| {
            PasswordStoreError::UnableToEncryptError("Failed to encrypt entry".to_owned())
        })?;

        std::fs::write(file_path, encrypted_data)
            .map_err(|e| PasswordStoreError::UnableToWriteFile(e))?;

        Ok(())
    }

    // Read entries from database & decrypt it
    pub fn load_from_db(
        file_path: impl AsRef<Path>,
        master_pass: impl AsRef<[u8]>,
    ) -> Result<Self, PasswordStoreError> {
        let encrypted_data =
            std::fs::read(file_path).map_err(|e| PasswordStoreError::UnableToRead(e))?;

        if encrypted_data.is_empty() {
            return Ok(PasswordStore { passwords: vec![] });
        }

        Ok(
            PasswordStore::decrypt_entry(encrypted_data, master_pass).map_err(|_| {
                PasswordStoreError::UnableToDecryptError("Failed to decrypt entries".to_owned())
            })?,
        )
    }

    // Remove entries from existing entries
    pub fn pop(&mut self, _entries: Vec<PasswordEntry>) {
        // TODO: If no entry exist of that service
        unimplemented!();
    }

    pub fn get() -> Vec<PasswordEntry> {
        unimplemented!();
    }

    pub fn fuzzy_find() -> Vec<PasswordEntry> {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pass::entry::PasswordEntry;

    #[test]
    fn test_storage() -> Result<(), PasswordStoreError> {
        let test_master_pass = "TestPassword123@";

        // Making a new Password manager
        let mut manager = PasswordStore::new(TESTING_PASS.to_path_buf(), test_master_pass)?;

        let entries = vec![
            PasswordEntry::new(
                "pass 1".to_owned(),
                Some("Ishan".to_owned()),
                None::<&str>,
                Some("hello notes".to_owned()),
            ),
            PasswordEntry::new(
                "pass 2".to_owned(),
                Some("Tanveer".to_owned()),
                None::<&str>,
                Some("hello notes again".to_owned()),
            ),
        ];

        // Pushing multiple entries
        entries.into_iter().map(|entry| manager.push_entry(entry));

        // Writing these entries to database
        manager.dump_to_db(TESTING_PASS.to_path_buf(), test_master_pass)?;

        // Loading contents from database
        let decrypted_manager =
            PasswordStore::load_from_db(TESTING_PASS.to_path_buf(), test_master_pass)?;

        assert_eq!(manager.passwords[0], decrypted_manager.passwords[0]);
        assert_eq!(manager.passwords[1], decrypted_manager.passwords[1]);

        Ok(())
    }
}
