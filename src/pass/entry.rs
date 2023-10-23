use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::BincodeSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    EncryptedMessage,
};

use crate::pass::util::{derive_encryption_key, generate_random_password};

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

    /// Username or Identifer used for that service
    username: String,

    /// Password for service
    password: Password,
}

impl SerdeEncryptSharedKey for PasswordEntry {
    type S = BincodeSerializer<Self>;
}

impl PasswordEntry {
    /// Function for initialising entry of a password by taking details of it
    pub fn new(service: String, username: String, password: Option<Vec<u8>>) -> Self {
        Self {
            service,
            username,
            password: Password::new(password),
        }
    }

    /// Encrypt the entry
    pub fn encrypt_entry(&self, master_pass: &Vec<u8>) -> Result<Vec<u8>, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = self.encrypt(&key)?;
        Ok(encrypted_content.serialize())
    }

    // Decrypt the entry
    pub fn decrypt_entry(
        content: &Vec<u8>,
        master_pass: &Vec<u8>,
    ) -> Result<Self, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = EncryptedMessage::deserialize(content.to_owned())?;
        let decrypted_content = PasswordEntry::decrypt_owned(&encrypted_content, &key)?;
        Ok(decrypted_content)
    }
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
            String::new(),
            Some(b"GxM4B7PDBe3NVY!Yj7A&&hvPs!ssJ3^q".to_vec()),
        );
        dbg!(&any_entry);

        let key = "this is key".as_bytes().to_vec();

        let encrypted_content = any_entry.encrypt_entry(&key)?;
        println!("Encrypted content: {:?}", &encrypted_content);

        let decrypted_content = PasswordEntry::decrypt_entry(&encrypted_content, &key)?;
        println!("Decrypted content: {:?}", &decrypted_content);

        assert_eq!(any_entry.password, decrypted_content.password);

        Ok(())
    }
}
