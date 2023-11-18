use std::path::Path;

use cli_table::format::Justify;
use cli_table::{Cell, Style, Table, TableDisplay};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::BincodeSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    EncryptedMessage,
};

use crate::pass::master::{MasterPassword, Verified};
use crate::pass::{entry::PasswordEntry, util::XDG_BASE};

// $HOME/.local/state/pass/passwords.db
pub static PASS_ENTRY_STORE: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("passwords.db")
        .expect("Unable to place passwords.db file in state")
});

// $HOME/.local/state/pass/testing.db
pub static TESTING_PASS: Lazy<std::path::PathBuf> = Lazy::new(|| {
    XDG_BASE
        .place_state_file("testing.db")
        .expect("Unable to place testing.db file in state")
});

#[derive(Debug, thiserror::Error)]
pub enum PasswordStoreError {
    #[error("The master password store file is not readable due to {0}")]
    UnableToRead(std::io::Error),

    #[error("Unable to read from console")]
    UnableToReadFromConsole,

    #[error("Unable to create dirs for password storage")]
    UnableToCreateDirs(std::io::Error),

    #[error("Unable to create file for password storage")]
    UnableToCreateFile(std::io::Error),

    #[error("Unable to write into master password store file: {0}")]
    UnableToWriteFile(std::io::Error),

    #[error("Unable to convert {0}")]
    UnableToConvert(String),

    #[error("Decrypt Error: {0}")]
    UnableToDecryptError(String),

    #[error("Encrypt Error: {0}")]
    UnableToEncryptError(String),

    #[error("No available entry")]
    NoEntryAvailable,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PasswordStore {
    pub(crate) passwords: Vec<PasswordEntry>,
    pub(crate) master_password: MasterPassword<Verified>,
}

impl SerdeEncryptSharedKey for PasswordStore {
    type S = BincodeSerializer<Self>;
}

impl PasswordStore {
    /// Extract the data from database(if exist) & store in [PasswordStore]
    pub fn new(
        file_path: impl AsRef<Path>,
        master_password: MasterPassword<Verified>,
    ) -> Result<Self, PasswordStoreError> {
        match file_path.as_ref().exists() {
            // Load all existing password entry from db
            true => PasswordStore::load(file_path.as_ref(), master_password),

            // No password entry is stored yet, then create file to store it
            false => {
                std::fs::File::create(file_path.as_ref())
                    .map_err(PasswordStoreError::UnableToCreateFile)?;

                // Returning an empty Vec<> because of no Entry available
                Ok(PasswordStore {
                    passwords: Vec::new(),
                    master_password,
                })
            }
        }
    }

    /// Encrypt the Password entries
    pub fn encrypt_entry(&self) -> Result<impl AsRef<[u8]>, serde_encrypt::Error> {
        // TODO: A method for SALT generation storage in db.

        // Derive encryption key from master password
        let key = self
            .master_password
            .derive_encryption_key("Salt".as_bytes());
        let key = SharedKey::new(key);

        // Encrypt contents and serialize it
        let encrypted_content = self.encrypt(&key)?;
        Ok(encrypted_content.serialize())
    }

    // Decrypt the entry
    pub fn decrypt_entry(
        content: impl AsRef<[u8]>,
        master_password: MasterPassword<Verified>,
    ) -> Result<Self, serde_encrypt::Error> {
        let key = master_password.derive_encryption_key("Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = EncryptedMessage::deserialize(content.as_ref().to_vec())?;
        let decrypted_content = PasswordStore::decrypt_owned(&encrypted_content, &key)?;
        Ok(decrypted_content)
    }

    /// Add entries to the existing entries
    pub fn push_entry(&mut self, entry: PasswordEntry) {
        let is_dupe = self.passwords.iter().any(|current_entry| {
            current_entry.service == entry.service && current_entry.username == entry.username
        });

        if !is_dupe {
            self.passwords.push(entry);
            colour::green_ln!("Successfully added entry");
        } else {
            colour::e_red_ln!("Password entry of same service or username found");
        }
    }

    /// Encrypt the entries & dump it to db
    pub fn dump(&self, file_path: impl AsRef<Path>) -> Result<(), PasswordStoreError> {
        // Encrypting all password entries
        let encrypted_data = self.encrypt_entry().map_err(|_| {
            PasswordStoreError::UnableToEncryptError("Failed to encrypt entry".to_owned())
        })?;

        // Dump it to the db
        std::fs::write(file_path, encrypted_data).map_err(PasswordStoreError::UnableToWriteFile)?;

        Ok(())
    }

    /// Read entries from database & decrypt it
    pub fn load(
        file_path: impl AsRef<Path>,
        master_password: MasterPassword<Verified>,
    ) -> Result<Self, PasswordStoreError> {
        let encrypted_data = std::fs::read(file_path).map_err(PasswordStoreError::UnableToRead)?;

        if encrypted_data.is_empty() {
            return Ok(PasswordStore {
                passwords: vec![],
                master_password,
            });
        }

        PasswordStore::decrypt_entry(encrypted_data, master_password).map_err(|_| {
            PasswordStoreError::UnableToDecryptError("Failed to decrypt entries".to_owned())
        })
    }

    // Remove entries from existing entries
    pub fn remove(&mut self, _t: Vec<PasswordEntry>) {
        unimplemented!();
    }

    // Match service
    pub fn get(&self, service: String) -> Vec<PasswordEntry> {
        self.passwords
            .clone()
            .into_iter()
            .filter(|entry| entry.service.to_lowercase() == service.to_lowercase())
            .collect::<Vec<PasswordEntry>>()
    }

    pub fn fuzzy_find() -> Vec<PasswordEntry> {
        unimplemented!();
    }
}

/// Provide display table having password entry
pub fn get_table(
    passwords: impl AsRef<[PasswordEntry]>,
) -> Result<TableDisplay, PasswordStoreError> {
    if passwords.as_ref().is_empty() {
        return Err(PasswordStoreError::NoEntryAvailable);
    }

    Ok(passwords
        .as_ref()
        .iter()
        .enumerate()
        .map(|(index, data)| {
            let mut table = data.table();
            let serial = (index + 1).to_string().cell().justify(Justify::Center);
            table.insert(0, serial);
            table
        })
        .collect::<Vec<Vec<_>>>()
        .table()
        .title(vec![
            "Serial no.".cell().bold(true),
            "Service".cell().bold(true),
            "Username".cell().bold(true),
            "Notes".cell().bold(true),
        ])
        .bold(true)
        .display()
        .expect("Unable to draw table"))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pass::entry::PasswordEntry;

    #[test]
    fn test_storage() -> Result<(), PasswordStoreError> {
        let test_master_pass = MasterPassword {
            master_pass: Some("Test123@".as_bytes().to_vec()),
            hash: None,
            state: std::marker::PhantomData,
        };
        // Making a new Password manager
        let mut manager = PasswordStore::new(TESTING_PASS.to_path_buf(), test_master_pass.clone())?;

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
        entries
            .into_iter()
            .for_each(|entry| manager.push_entry(entry));

        // Writing these entries to database
        manager.dump(TESTING_PASS.to_path_buf())?;

        // Loading contents from database
        let decrypted_manager = PasswordStore::load(TESTING_PASS.to_path_buf(), test_master_pass)?;

        assert_eq!(manager.passwords[0], decrypted_manager.passwords[0]);
        assert_eq!(manager.passwords[1], decrypted_manager.passwords[1]);

        std::fs::remove_file(TESTING_PASS.as_path()).unwrap();

        Ok(())
    }
}
