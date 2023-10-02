use crate::{MASTER_PASSWORD_PATH, PASS_DIR_PATH};

// To check any path exist?
pub fn is_path_exist(path: &str) -> bool {
    let path = std::path::Path::new(path);
    path.exists()
}

// To check any pass initialised?
pub fn is_pass_initialised() -> bool {
    let path = std::path::Path::new(MASTER_PASSWORD_PATH);
    path.exists()
}
