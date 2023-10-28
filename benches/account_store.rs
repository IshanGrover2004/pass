use std::{
    collections::HashMap,
    io::{BufReader, Write},
    time::Instant,
};

use criterion::Criterion;
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
    pub fn new(name: &str, username: &str) -> Self {
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

    #[test]
    fn check_rng() {
        let pass = Account::new_rand();

        println!("{:?}", pass);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AccColl {
    accounts: HashMap<String, Account>,
}

fn fill_file() {
    let accounts = (0..100000)
        .map(|_| Account::new_rand())
        .map(|acc| (acc.name.clone(), acc))
        .collect::<HashMap<_, _>>();
    let mut file = std::fs::File::create("./account_store.dat").unwrap();
    let data = bincode::serialize(&accounts).unwrap();
    file.write_all(&data).unwrap();
}

fn read_file() {
    let file = std::fs::File::open("./account_store.dat").unwrap();
    let reader = BufReader::new(file);
    let _data: AccColl = bincode::deserialize_from(reader).unwrap();
}

pub fn create_benchmark(c: &mut Criterion) {
    c.bench_function("Create account", |b| b.iter(fill_file));
}

pub fn read_benchmark(c: &mut Criterion) {
    c.bench_function("Read accounts", |b| b.iter(read_file));
}

// criterion_group!(benches, read_benchmark);
//
// criterion_main!(benches);

fn main() {
    fill_file();

    for _ in 0..100 {
        let time = Instant::now();
        read_file();
        let elasped = time.elapsed();

        println!("{:?}", elasped);
    }
}
