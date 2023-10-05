pub fn hash(content: &str) -> Vec<u8> {
    bcrypt::hash(content, bcrypt::DEFAULT_COST)
        .unwrap()
        .as_bytes()
        .to_vec()
}
