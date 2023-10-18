use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    time::Instant,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pass::store::account::Account;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct AccColl {
    accounts: HashMap<String, Account>,
}

fn fill_file() {
    let accounts = (0..100000)
        .into_iter()
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
    let data: AccColl = bincode::deserialize_from(reader).unwrap();
}

pub fn create_benchmark(c: &mut Criterion) {
    c.bench_function("Create account", |b| b.iter(|| fill_file()));
}

pub fn read_benchmark(c: &mut Criterion) {
    c.bench_function("Read accounts", |b| b.iter(|| read_file()));
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
