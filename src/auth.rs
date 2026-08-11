use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates a random 64-character token on startup.
pub fn generate_token() -> String {
    let mut hasher = Sha256::new();
    let sys_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    
    hasher.update(format!("{}-{}", sys_time, pid).as_bytes());
    let result = hasher.finalize();
    
    format!("{:x}", result)
}

/// Writes the token to a file in the data directory.
pub fn write_token_to_file<P: AsRef<Path>>(data_dir: P, token: &str) -> std::io::Result<()> {
    let token_path = data_dir.as_ref().join(".token");
    fs::write(token_path, token)
}

/// Validates an HTTP `Authorization: Bearer <token>` header against the current token.
pub fn validate_bearer_token(header: &str, current_token: &str) -> bool {
    if let Some(token) = header.strip_prefix("Bearer ") {
        token.trim() == current_token
    } else {
        false
    }
}
