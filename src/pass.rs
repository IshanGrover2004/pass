//! This module contains the ifnormation regarding hte password
//!
//!

use std::collections::HashMap;

/// Stores the information of the entry in the vault
/// Eg: instagram:username:password:personal id:re-promt-master-pass:false;
#[derive(Debug, PartialEq, Eq)]
struct Account {
    /// Name can also act as it, as it need to be unique for all entries in the vault
    name: String,

    /// Username, email, phone number or any other identifier of the account on the website
    username: String,

    /// Password
    password: String,

    /// Other notes regarding the account, can be 2FA keys or anything
    /// It is in form on K,V, where K is the identifier of the value
    ///
    /// Eg: instagram:username:password:[2FA, burger mango]
    notes: HashMap<String, String>,
}

impl Account {
    /// Constructs a new [Account] with given name, username and password
    pub fn new(name: &str, username: &str, password: &str) -> Self {
        Self {
            name: name.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            notes: HashMap::new(),
        }
    }
}
