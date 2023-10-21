//! This module contains the information regarding hte password
//!
//!

use std::collections::HashMap;

use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

/// Stores the information of the entry in the vault
/// Eg: instagram:username:password:personal id:re-promt-master-pass:false;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// Name can also act as it, as it need to be unique for all entries in the vault
    pub name: String,

    /// Username, email, phone number or any other identifier of the account on the website
    username: String,

    /// Other notes regarding the account, can be 2FA keys or anything
    /// It is in form on K,V, where K is the identifier of the value
    ///
    /// Eg: instagram:username:password:[2FA, burger mango]
    notes: Option<HashMap<String, Option<String>>>,
}

fn rand_str() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(rand::thread_rng().gen_range(0..100))
        .map(char::from)
        .collect()
}

impl Account {
    /// Constructs a new [Account] with given name, username and password
    pub fn new(name: &str, username: &str, password: &str) -> Self {
        Self {
            name: name.to_owned(),
            username: username.to_owned(),
            notes: Some(HashMap::new()),
        }
    }

    pub fn new_rand() -> Self {
        Self {
            name: rand_str(),
            username: rand_str(),
            notes: Some(HashMap::from([
                (rand_str(), Some(rand_str())),
                (rand_str(), Some(rand_str())),
            ])),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Account;

    #[test]
    fn check_rng() {
        let pass = Account::new_rand();

        println!("{:?}", pass);
    }
}
