use serde::{Deserialize, Serialize};
use std::io;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanCheckpoint {
    pub session_id: String,
    pub source_fingerprint: String,
    pub source_size: u64,
    pub filesystem: String,
    pub scan_mode: String,
    pub current_offset: u64,
    pub completed_ranges: Vec<(u64, u64)>,
    pub filesystem_state: String,
    pub mft_position: Option<u64>,
    pub directory_position: Option<u64>,
    pub carver_state_json: String,
    pub candidate_count: u64,
    pub bad_ranges: Vec<(u64, u64)>,
    pub signature_package_version: String,
    pub engine_version: String,
    pub updated_at: String,
}

pub fn persist(db: &crate::db::Database, cp: &ScanCheckpoint) -> io::Result<()> {
    db.save_checkpoint(&cp.session_id, cp, &cp.updated_at)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
pub fn load(db: &crate::db::Database, id: &str) -> io::Result<Option<ScanCheckpoint>> {
    match db
        .checkpoint(id)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    {
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        None => Ok(None),
    }
}
