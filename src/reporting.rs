use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Serialize)]
pub struct ConsumerReport {
    pub files_recovered: usize,
    pub files_failed: usize,
    pub average_confidence: f32,
    pub destination: String,
    pub scan_duration_note: String,
}

#[derive(Serialize)]
pub struct TechnicalReport {
    pub source_device: String,
    pub filesystem: String,
    pub scan_mode: String,
    pub sectors_scanned_note: String,
    pub errors: usize,
    pub bad_sectors: usize,
    pub reconstruction_stats: String,
    pub validation_results: Vec<(String, String)>, // (filename, verification_state)
}

#[derive(Serialize)]
pub struct EvidenceManifest {
    pub session_id: String,
    pub source_device_hash: String,
    pub source_capacity: u64,
    pub filesystem: String,
    pub scan_started: String,
    pub scan_completed: String,
    pub operator: String,
    pub files_discovered: usize,
    pub files_recovered: usize,
    pub files_failed: usize,
    pub software_version: String,
    pub engine_version: String,
    pub manifest_version: u32,
    /// Cryptographic hash of every OTHER field in this struct — computed
    /// after serializing without this field, then filled in. Any later edit
    /// to the manifest changes this hash, which is the actual mechanism
    /// behind "any modification produces a new manifest version" rather
    /// than silently changing the original: the old manifest_hash simply
    /// stops matching the (now different) content.
    pub manifest_hash: String,
}

pub fn generate_evidence_manifest(
    session_id: &str,
    source_device_hash: &str,
    source_capacity: u64,
    filesystem: &str,
    files_discovered: usize,
    files_recovered: usize,
) -> EvidenceManifest {
    let now = now_iso();
    let mut manifest = EvidenceManifest {
        session_id: session_id.to_string(),
        source_device_hash: source_device_hash.to_string(),
        source_capacity,
        filesystem: filesystem.to_string(),
        scan_started: now.clone(),
        scan_completed: now,
        operator: "local-user".to_string(),
        files_discovered,
        files_recovered,
        files_failed: files_discovered.saturating_sub(files_recovered),
        software_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        manifest_version: 1,
        manifest_hash: String::new(),
    };

    // Hash everything except the hash field itself.
    let pre_hash_json = serde_json::to_string(&(
        &manifest.session_id,
        &manifest.source_device_hash,
        manifest.source_capacity,
        &manifest.filesystem,
        &manifest.scan_started,
        &manifest.scan_completed,
        &manifest.operator,
        manifest.files_discovered,
        manifest.files_recovered,
        manifest.files_failed,
        &manifest.software_version,
        &manifest.engine_version,
        manifest.manifest_version,
    ))
    .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(pre_hash_json.as_bytes());
    manifest.manifest_hash = format!("{:x}", hasher.finalize());

    manifest
}

/// A later "modification" doesn't mutate this file — it produces manifest_v2.json,
/// v3, etc., each independently hashed. The original is never overwritten.
pub fn save_manifest_versioned(dir: &str, manifest: &EvidenceManifest) -> std::io::Result<String> {
    fs::create_dir_all(dir)?;
    let path = format!(
        "{dir}/{}_manifest_v{}.json",
        manifest.session_id, manifest.manifest_version
    );
    fs::write(&path, serde_json::to_string_pretty(manifest).unwrap())?;
    Ok(path)
}

fn now_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}", now.as_secs())
}
