use std::slice;

use super::account::Account;
use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::BincodeSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    AsSharedKey, EncryptedMessage,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd)]
struct Password {
    password: Vec<u8>,
}

impl Password {
    pub fn new(password: Option<Vec<u8>>) -> Self {
        match password {
            Some(pass) => Password { password: pass },
            None => Password {
                password: generate_random_password(12).as_bytes().to_vec(),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordEntry {
    /// Name of service/email/website for which password is stored
    service: String,

    /// Password for service
    password: Password,

    /// Additional details like username, notes etc
    details: Option<Account>,
}

impl SerdeEncryptSharedKey for PasswordEntry {
    type S = BincodeSerializer<Self>;
}

impl PasswordEntry {
    /// Function for initialising entry of a password by taking details of it
    pub fn new(service: String, password: Option<Vec<u8>>, details: Option<Account>) -> Self {
        Self {
            service,
            password: Password::new(password),
            details,
        }
    }

    /// Encrypt the entry
    pub fn encrypt_entry(&self, key: &Vec<u8>) -> Result<Vec<u8>, serde_encrypt::Error> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key);

        let key = SharedKey::from_array(arr);

        let encrypted_content = self.encrypt(&key)?;
        Ok(encrypted_content.serialize())
    }

    // Decrypt the entry
    pub fn decrypt_entry(content: &Vec<u8>, key: &Vec<u8>) -> Result<Self, serde_encrypt::Error> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key);

        let key = SharedKey::from_array(arr);

        let encrypted_content = EncryptedMessage::deserialize(content.to_owned())?;
        let decrypted_content = PasswordEntry::decrypt_owned(&encrypted_content, &key)?;
        Ok(decrypted_content)
    }
}

// Function to verify the master password is strong enough
pub fn is_strong_password(password: &str) -> bool {
    // Check if the password length is at least 8 characters
    if password.len() < 8 {
        return false;
    }

    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

    return has_lowercase && has_uppercase && has_digit && has_special;
}

pub fn generate_random_password(length: u8) -> String {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new_password() {
        println!("Random password generating: ");
        dbg!(Password::new(None));

        println!("\nPassword Inputed: ");
        dbg!(Password::new(Some("PasswordInputed".as_bytes().to_vec())));
    }

    #[test]
    fn encrypt_decrypt_works() -> Result<(), serde_encrypt::Error> {
        let any_entry = PasswordEntry::new(
            String::from("Netflix"),
            Some("hello123@".as_bytes().to_vec()),
            None,
        );
        dbg!(&any_entry);

        let key = "this is key".as_bytes().to_vec();

        let encrypted_content = any_entry.encrypt_entry(&key)?;
        dbg!(&encrypted_content);

        let decrypted_content = PasswordEntry::decrypt_entry(&encrypted_content, &key)?;
        dbg!(&decrypted_content);

        // assert_eq!(any_entry, decrypted_content);

        Ok(())
    }
}
