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
    pub fn new(password: Option<impl AsRef<[u8]>>) -> Self {
        let pass = match password {
            Some(pass) => pass.as_ref().to_vec(),
            None => generate_random_password(12).as_ref().to_vec(),
        };

        Password { password: pass }
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
    pub fn new(service: String, username: String, password: Option<impl AsRef<[u8]>>) -> Self {
        Self {
            service,
            username,
            password: Password::new(password),
        }
    }

    /// Encrypt the entry
    pub fn encrypt_entry(
        &self,
        master_pass: &impl AsRef<[u8]>,
    ) -> Result<impl AsRef<[u8]>, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = self.encrypt(&key)?;
        Ok(encrypted_content.serialize())
    }

    // Decrypt the entry
    pub fn decrypt_entry(
        content: &impl AsRef<[u8]>,
        master_pass: &impl AsRef<[u8]>,
    ) -> Result<Self, serde_encrypt::Error> {
        let key = derive_encryption_key(master_pass, "Salt".as_bytes());
        let key = SharedKey::new(key);

        let encrypted_content = EncryptedMessage::deserialize(content.as_ref().to_vec())?;
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
        dbg!(Password::new(None::<&str>));

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
        println!("Encrypted content: {:?}", &encrypted_content.as_ref());

        let decrypted_content = PasswordEntry::decrypt_entry(&encrypted_content, &key)?;
        println!("Decrypted content: {:?}", &decrypted_content);

        assert_eq!(any_entry.password, decrypted_content.password);

        Ok(())
    }
}
