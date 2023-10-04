pub fn hash(content: String) -> String {
    bcrypt::hash(content, bcrypt::DEFAULT_COST).unwrap()
}
