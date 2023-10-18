use std::path::PathBuf;

use crate::pass::master::MASTER_PASS_STORE;

// To check any path exist?
pub fn is_path_exist(path: &str) -> bool {
    let path = std::path::Path::new(path);
    path.exists()
}

// To check any pass initialised?
pub fn is_pass_initialised() -> bool {
    let master = MASTER_PASS_STORE;
    let paths = master.to_str();
    let path_buf = PathBuf::from(paths.unwrap());
    path_buf.exists()
}
