use serde::{Deserialize, Serialize};

use crate::pass::util::generate_random_password;
use cli_table::{format::Justify, Cell};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Password {
    password: Vec<u8>,
}

impl Password {
    pub fn new(password: Option<impl AsRef<[u8]>>) -> Self {
        let pass = match password {
            Some(pass) => pass.as_ref().to_vec(),
            None => generate_random_password(12).as_ref().as_bytes().to_vec(),
        };

        Password { password: pass }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PasswordEntry {
    /// Name of service/email/website for which password is stored
    pub(crate) service: String,

    /// Username or Identifer used for that service
    pub(crate) username: Option<String>,

    /// Password for service
    password: Password,

    // Other details
    other: Option<String>,
}

impl Default for PasswordEntry {
    fn default() -> Self {
        PasswordEntry {
            service: String::new(),
            username: None,
            password: Password::new(None::<&str>),
            other: None,
        }
    }
}

impl PasswordEntry {
    /// Function for initialising entry of a password by taking details of it
    pub fn new(
        service: String,
        username: Option<String>,
        password: Option<impl AsRef<[u8]>>,
        other: Option<String>,
    ) -> Self {
        Self {
            service,
            username,
            password: Password::new(password),
            other,
        }
    }

    /// Change password in current entry
    pub fn change_password(&mut self, password: impl AsRef<str>) {
        self.password = Password::new(Some(password.as_ref()));
    }

    /// Create table for [PasswordEntry]
    pub fn table(&self) -> Vec<cli_table::CellStruct> {
        let service = self.service.clone();
        let username = self.username.clone().unwrap_or("None".to_string());
        let notes = self.other.clone().unwrap_or("None".to_string());

        vec![
            service.cell().justify(Justify::Center),
            username.cell().justify(Justify::Center),
            notes.cell().justify(Justify::Center),
        ]
    }

    pub fn get_pass_str(&self) -> String {
        String::from_utf8(self.password.password.clone()).expect("Unable to convert u8 to str")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new_password() {
        println!("Random password generating: ");
        dbg!(Password::new(None::<&str>));

        println!("\nPassword Input: ");
        dbg!(Password::new(Some("PasswordInputed")));
    }
}
