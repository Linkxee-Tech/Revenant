use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use crate::destination::{resolve_collision, sanitize_filename, validate_destination};
use crate::engine::{image_and_register, scan_device_with_mode, DeviceRegistry, ScanError};
use crate::jobs::JobManager;
use crate::provider::RecoveredItem;
use crate::scoring::{label, score};
use crate::session::{save_session, RecoverySession};
use crate::signatures::SignaturePackage;
use crate::verify::verify_bytes_by_ext;
use sha2::{Digest, Sha256};

#[derive(Debug, serde::Deserialize)]
struct ScanRequest {
    device_id: String,
    #[serde(default = "default_mode")]
    mode: String,
}
#[derive(Debug, serde::Deserialize)]
struct RecoveryRequest {
    session_id: String,
    destination: String,
    #[serde(default)]
    candidate_ids: Vec<String>,
}
#[derive(Debug, serde::Deserialize)]
struct ImageRequest {
    device_id: String,
}
fn default_mode() -> String {
    "quick".into()
}
fn parse_json<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, String> {
    serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveredFileRecord {
    pub id: String,
    pub name: String,
    pub file_type: String,
    pub size_bytes: usize,
    pub score: u8,
    pub label: String,
    pub complete: bool,
    pub source: String, // "raw_carving" | "ntfs_metadata" | "fat32_metadata"
    pub sha256: String,
    pub structurally_valid: bool,
    pub verification_state: String, // VERIFIED | RECOVERABLE | UNSUPPORTED_FORMAT | UNVERIFIED_NO_DATA
    pub reconstruction_state: String,
    pub duplicate_of: Option<String>,
    /// Source device the bytes live on. Empty for carved items with embedded
    /// data (which always have resident_data populated instead).
    pub source_device_id: String,
    /// Physical (offset, length) runs into the source device. Empty for
    /// resident/carved items where resident_data is set.
    pub data_runs: Vec<(u64, u64)>,
    /// Inline bytes for small resident MFT data and carved fragments that
    /// fit entirely in RAM during the scan pass.
    pub resident_data: Option<Vec<u8>>,
}

pub struct AppState {
    pub auth_token: String,
    pub sessions: Mutex<HashMap<String, Vec<RecoveredFileRecord>>>,
    pub recoveries: Mutex<HashMap<String, RecoveryManifest>>,
    pub registry: DeviceRegistry,
    pub signature_package: SignaturePackage,
    pub carve_chunk_size: usize,
    pub carve_overlap: usize,
    pub images_dir: String,
    pub recoveries_dir: String,
    pub jobs: JobManager,
    pub db: crate::db::Database,
    pub workers: std::sync::Arc<crate::workers::WorkerPool>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveredFileOutcome {
    pub candidate_id: String,
    pub written_name: String,
    pub requested_name: String,
    pub bytes_written: usize,
    pub sha256_before_write: String,
    pub sha256_after_write: String,
    pub post_write_verified: bool,
    pub status: String, // RECOVERED | FAILED
    pub error: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryManifest {
    pub recovery_id: String,
    pub session_id: String,
    pub destination: String,
    pub started_at: String,
    pub completed_at: String,
    pub files: Vec<RecoveredFileOutcome>,
    pub succeeded: usize,
    pub failed: usize,
}

pub fn run(
    addr: &str,
    registry: DeviceRegistry,
    signature_package: SignaturePackage,
    images_dir: String,
    recoveries_dir: String,
    auth_token: String,
) {
    let state = Arc::new(AppState {
        auth_token,
        sessions: Mutex::new(HashMap::new()),
        recoveries: Mutex::new(HashMap::new()),
        registry,
        signature_package,
        carve_chunk_size: 4 * 1024 * 1024, // 4MB chunks — real full-device coverage, not an 8MB cap
        carve_overlap: 1024 * 1024,    // 1MB boundary overlap — see carve.rs scope note
        images_dir,
        recoveries_dir,
        jobs: JobManager::new(),
        db: crate::db::Database::open(format!("{}/revenant.sqlite3", crate::config::data_dir()))
            .expect("failed to initialize SQLite persistence"),
        workers: std::sync::Arc::new(crate::workers::WorkerPool::new(
            std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(2),
        )),
    });

    let listener = TcpListener::bind(addr).expect("failed to bind");
    println!("\nRevenant core API listening on http://{addr}");
    println!("Endpoints: GET /devices | POST /scans | GET /scans/{{id}} | GET /scan/{{id}}/results | POST /recoveries | GET /recoveries/{{id}} | POST /image");
    println!("NOTE: /scan takes only a registered device_id — no client-supplied file paths are ever accepted.");

    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        handle(stream, state);
    }
}

fn handle(mut stream: TcpStream, state: Arc<AppState>) {
    let mut request = Vec::with_capacity(8192);
    let mut temp = [0u8; 8192];
    let header_end;
    loop {
        match stream.read(&mut temp) {
            Ok(0) => return,
            Ok(n) => {
                request.extend_from_slice(&temp[..n]);
                if let Some(p) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = p + 4;
                    break;
                }
                if request.len() > 256 * 1024 {
                    write_error(
                        &mut stream,
                        "413 Payload Too Large",
                        "request headers too large",
                    );
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let header = String::from_utf8_lossy(&request[..header_end]).to_string();
    let mut lines = header.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let mut content_len = 0usize;
    let mut auth_header = "";
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(usize::MAX);
            } else if k.eq_ignore_ascii_case("authorization") {
                auth_header = v.trim();
            }
        }
    }
    if content_len > 2 * 1024 * 1024 {
        write_error(
            &mut stream,
            "413 Payload Too Large",
            "request body exceeds 2 MiB limit",
        );
        return;
    }
    while request.len() < header_end + content_len {
        match stream.read(&mut temp) {
            Ok(0) => break,
            Ok(n) => request.extend_from_slice(&temp[..n]),
            Err(_) => return,
        }
    }
    if request.len() < header_end + content_len {
        write_error(&mut stream, "400 Bad Request", "incomplete request body");
        return;
    }
    let body = String::from_utf8_lossy(&request[header_end..header_end + content_len]);
    let (status, ctype, payload) = route(method, path, &body, &state, auth_header);
    let response=format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",payload.len(),payload);
    let _ = stream.write_all(response.as_bytes());
}
fn write_error(stream: &mut TcpStream, status: &str, msg: &str) {
    let body = serde_json::json!({"error":msg}).to_string();
    let r=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
    let _ = stream.write_all(r.as_bytes());
}

fn route(
    method: &str,
    path: &str,
    body: &str,
    state: &Arc<AppState>,
    auth_header: &str,
) -> (&'static str, &'static str, String) {
    if (method == "POST" || method == "DELETE")
        && !crate::auth::validate_bearer_token(auth_header, &state.auth_token) {
            return (
                "401 Unauthorized",
                "application/json",
                "{\"error\":\"invalid or missing auth token\"}".to_string(),
            );
        }
    match (method, path) {
        ("GET", "/devices") => {
            let devices = state.registry.list();
            (
                "200 OK",
                "application/json",
                serde_json::to_string(&devices).unwrap_or_else(|_| "[]".into()),
            )
        }
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        ("POST", "/scan") | ("POST", "/scans") => {
            let req: ScanRequest = match parse_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        "400 Bad Request",
                        "application/json",
                        serde_json::json!({"error":e}).to_string(),
                    )
                }
            };
            let device_id = req.device_id;
            let mode = req.mode;
            if device_id.is_empty() {
                return (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"device_id is required\"}".to_string(),
                );
            }
            if mode != "quick" && mode != "deep" {
                return (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"mode must be quick or deep\"}".to_string(),
                );
            }
            let job_id = format!("scan-{}-{}", device_id, now_iso_public());
            state.jobs.create(job_id.clone(), "scan");
            let state2 = Arc::clone(state);
            let job_id2 = job_id.clone();
            let mode_for_job = mode.clone();
            let workers = Arc::clone(&state.workers);
            workers.submit(crate::workers::Priority::Scanning, move || {
                state2.jobs.mark_running(&job_id2, "device_analysis");
                let profile = crate::performance::detect_system();
                let params = crate::performance::adapt(&profile, &mode_for_job);
                let chunk_size = params.read_block_size_kb * 1024;
                let overlap_size = chunk_size / 4;
                let result = scan_device_with_mode(
                    &state2.registry,
                    &device_id,
                    &state2.signature_package,
                    chunk_size,
                    overlap_size,
                    &mode_for_job,
                );
                match result {
                    Ok(engine_result) => {
                        if state2.jobs.is_cancelled(&job_id2) {
                            state2.jobs.mark_cancelled(&job_id2);
                            return;
                        }
                        state2.jobs.update(&job_id2, |j| {
                            j.phase = "indexing_results".into();
                            j.items_total = engine_result.items.len();
                            j.items_done = engine_result.items.len();
                        });
                        let session_id = format!("session-{job_id2}");
                        let mut records = build_records(&session_id, &engine_result.items);
                        // Set source_device_id on all records so the recovery
                        // worker can open the device on demand.
                        for r in &mut records {
                            r.source_device_id = device_id.clone();
                        }
                        let unique_recovered =
                            records.iter().filter(|r| r.duplicate_of.is_none()).count();
                        state2
                            .sessions
                            .lock()
                            .unwrap()
                            .insert(session_id.clone(), records.clone());
                        let session_record = RecoverySession {
                            session_id: session_id.clone(),
                            source_device_id: device_id.clone(),
                            filesystem: engine_result.filesystem.clone(),
                            mode: mode_for_job.clone(),
                            status: "completed".to_string(),
                            started_at: now_iso_public(),
                            completed_at: Some(now_iso_public()),
                            files_discovered: engine_result.items.len(),
                            files_recovered: unique_recovered,
                            bad_sector_count: engine_result.analysis.bad_sector_count,
                        };
                        let _ = save_session(&session_record);
                        let _ = persist_records(&session_id, &device_id, &records);
                        let stored: Vec<crate::db::StoredCandidate> = records
                            .iter()
                            .map(|r| crate::db::StoredCandidate {
                                id: r.id.clone(),
                                session_id: session_id.clone(),
                                name: r.name.clone(),
                                file_type: r.file_type.clone(),
                                size_bytes: r.size_bytes as u64,
                                source: r.source.clone(),
                                source_offset: None,
                                sha256: if r.sha256.is_empty() {
                                    None
                                } else {
                                    Some(r.sha256.clone())
                                },
                                confidence: r.score,
                                verification_state: r.verification_state.clone(),
                                duplicate_of: r.duplicate_of.clone(),
                                reconstruction_state: r.reconstruction_state.clone(),
                                metadata_json: serde_json::to_string(r).unwrap_or_default(),
                            })
                            .collect();
                        let _ = state2.db.replace_candidates(&session_id, &stored);
                        let _ = state2.db.upsert_session(
                            &session_id,
                            &device_id,
                            &engine_result.filesystem,
                            &mode_for_job,
                            "completed",
                            &session_record.started_at,
                            session_record.completed_at.as_deref(),
                            engine_result.items.len() as u64,
                            unique_recovered as u64,
                            engine_result.analysis.bad_sector_count as u64,
                            &session_record,
                        );
                        state2.jobs.update(&job_id2, |j| {
                            j.phase = "completed".into();
                            j.progress = 1.0;
                        });
                        state2.jobs.mark_completed(&job_id2);
                    }
                    Err(e) => state2.jobs.mark_failed(&job_id2, format!("{:?}", e)),
                }
            });
            (
                "202 Accepted",
                "application/json",
                format!(
                    "{{\"job_id\":\"{}\",\"status\":\"QUEUED\",\"mode\":\"{}\"}}",
                    esc(&job_id),
                    esc(&mode)
                ),
            )
        }
        ("GET", p) if p.starts_with("/scans/") => {
            let id = p.trim_start_matches("/scans/");
            match state.jobs.get(id) {
                Some(j) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_string(&j).unwrap(),
                ),
                None => (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"scan job not found\"}".into(),
                ),
            }
        }
        ("GET", p) if p.starts_with("/jobs/") => {
            let id = p.trim_start_matches("/jobs/");
            match state.jobs.get(id) {
                Some(j) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_string(&j).unwrap(),
                ),
                None => (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"job not found\"}".into(),
                ),
            }
        }
        ("POST", p) if p.starts_with("/scans/") && p.ends_with("/pause") => {
            let id = p.trim_start_matches("/scans/").trim_end_matches("/pause");
            state.jobs.pause(id);
            (
                "202 Accepted",
                "application/json",
                format!("{{\"job_id\":\"{}\",\"status\":\"PAUSED\"}}", esc(id)),
            )
        }
        ("POST", p) if p.starts_with("/scans/") && p.ends_with("/resume") => {
            let id = p.trim_start_matches("/scans/").trim_end_matches("/resume");
            state.jobs.resume(id);
            (
                "202 Accepted",
                "application/json",
                format!("{{\"job_id\":\"{}\",\"status\":\"RUNNING\"}}", esc(id)),
            )
        }
        ("POST", p) if p.starts_with("/scans/") && p.ends_with("/cancel") => {
            let id = p.trim_start_matches("/scans/").trim_end_matches("/cancel");
            state.jobs.request_cancel(id);
            (
                "202 Accepted",
                "application/json",
                format!("{{\"job_id\":\"{}\",\"status\":\"CANCELLING\"}}", esc(id)),
            )
        }
        ("POST", "/image") => {
            let req: ImageRequest = match parse_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        "400 Bad Request",
                        "application/json",
                        serde_json::json!({"error":e}).to_string(),
                    )
                }
            };
            let device_id = req.device_id;
            match image_and_register(&state.registry, &device_id, &state.images_dir) {
                Ok((new_device, meta)) => (
                    "200 OK",
                    "application/json",
                    format!(
                        "{{\"new_device_id\":\"{}\",\"bytes_imaged\":{},\"bad_sectors\":{},\"image_sha256\":\"{}\"}}",
                        esc(&new_device.id), meta.bytes_imaged, meta.bad_sectors.len(), esc(&meta.sha256_of_image)
                    ),
                ),
                Err(ScanError::DeviceNotFound) => ("404 Not Found", "application/json", "{\"error\":\"unknown device_id\"}".to_string()),
                Err(ScanError::DeviceNotScanCapable(reason)) => ("422 Unprocessable Entity", "application/json", format!("{{\"error\":\"cannot image this device\",\"reason\":\"{}\"}}", esc(&reason))),
                Err(ScanError::OpenFailed(e)) => ("500 Internal Server Error", "application/json", format!("{{\"error\":\"imaging failed\",\"detail\":\"{}\"}}", esc(&e))),
            }
        }
        ("GET", p) if p.starts_with("/scan/") && p.ends_with("/results") => {
            let id = p.trim_start_matches("/scan/").trim_end_matches("/results");
            let sessions = state.sessions.lock().unwrap();
            match sessions.get(id) {
                Some(records) => ("200 OK", "application/json", results_json(records)),
                None => match load_records(id) {
                    Ok(records) => ("200 OK", "application/json", results_json(&records)),
                    Err(_) => match state.db.candidates(id) {
                        Ok(rows) if !rows.is_empty() => (
                            "200 OK",
                            "application/json",
                            serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()),
                        ),
                        _ => (
                            "404 Not Found",
                            "application/json",
                            "{\"error\":\"session not found\"}".to_string(),
                        ),
                    },
                },
            }
        }
        ("GET", p) if p.starts_with("/candidates/") && p.ends_with("/preview") => {
            let id = p
                .trim_start_matches("/candidates/")
                .trim_end_matches("/preview");
            let found = state
                .sessions
                .lock()
                .unwrap()
                .values()
                .flat_map(|v| v.iter())
                .find(|r| r.id == id)
                .cloned();
            match found {
                Some(r) => {
                    let preview_len = r.size_bytes.min(64 * 1024);
                    // Materialise preview bytes on demand from the source device.
                    let preview_bytes: Vec<u8> = if let Some(ref inline) = r.resident_data {
                        inline[..inline.len().min(preview_len)].to_vec()
                    } else if !r.data_runs.is_empty() && !r.source_device_id.is_empty() {
                        match state.registry.get(&r.source_device_id) {
                            Some(dev) => match dev.backing_path {
                                Some(ref path) => {
                                    match crate::storage::FileBackedReader::open_read_only(path) {
                                        Ok(raw) => {
                                            let mut resilient =
                                                crate::resilience::ResilientReader::new(raw, 3);
                                            crate::fat32::read_runs(
                                                &mut resilient,
                                                &r.data_runs,
                                                preview_len,
                                            )
                                        }
                                        Err(_) => Vec::new(),
                                    }
                                }
                                None => Vec::new(),
                            },
                            None => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    };
                    let preview = crate::preview::inspect(&r.name, &preview_bytes);
                    let hex = preview_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    ("200 OK","application/json",format!("{{\"candidate_id\":\"{}\",\"file_type\":\"{}\",\"size_bytes\":{},\"verification_state\":\"{}\",\"preview\":{},\"preview_bytes\":{},\"preview_hex\":\"{}\"}}",esc(&r.id),esc(&r.file_type),r.size_bytes,esc(&r.verification_state),serde_json::to_string(&preview).unwrap(),preview_bytes.len(),hex))
                }
                None => (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"candidate not found\"}".into(),
                ),
            }
        }
        ("POST", "/recoveries") => {
            let req: RecoveryRequest = match parse_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        "400 Bad Request",
                        "application/json",
                        serde_json::json!({"error":e}).to_string(),
                    )
                }
            };
            let session_id = req.session_id;
            let destination = req.destination;
            let candidate_ids = req.candidate_ids;
            if destination.trim().is_empty() {
                return (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"destination is required\"}".into(),
                );
            }
            let records = match state.sessions.lock().unwrap().get(&session_id) {
                Some(r) => r.clone(),
                None => match load_records(&session_id) {
                    Ok(r) => r,
                    Err(_) => {
                        return (
                            "404 Not Found",
                            "application/json",
                            "{\"error\":\"session not found\"}".into(),
                        )
                    }
                },
            };
            let selected: Vec<RecoveredFileRecord> = if candidate_ids.is_empty() {
                records
            } else {
                records
                    .into_iter()
                    .filter(|r| candidate_ids.contains(&r.id))
                    .collect()
            };
            if selected.is_empty() {
                return (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"no matching candidates in this session\"}".into(),
                );
            }
            let required_bytes = selected
                .iter()
                .fold(0u64, |a, r| a.saturating_add(r.size_bytes as u64));
            let check = validate_destination(&destination, required_bytes, &state.registry);
            if !check.safe {
                return (
                    "422 Unprocessable Entity",
                    "application/json",
                    format!(
                        "{{\"error\":\"destination failed safety checks\",\"issues\":[{}]}}",
                        check
                            .issues
                            .iter()
                            .map(|i| format!("\"{}\"", esc(i)))
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                );
            }
            let recovery_id = format!("recovery-{}", now_iso_public());
            state.jobs.create(recovery_id.clone(), "recovery");
            let _ = state.db.save_recovery(
                &recovery_id,
                &session_id,
                &destination,
                "QUEUED",
                &now_iso_public(),
                None,
                Option::<&RecoveryManifest>::None,
            );
            let state2 = Arc::clone(state);
            let rid = recovery_id.clone();
            let sid = session_id.clone();
            let dest = destination.clone();
            let workers = Arc::clone(&state.workers);
            workers.submit(crate::workers::Priority::Reconstruction, move || {
                state2.jobs.mark_running(&rid, "recovering");
                let started = now_iso_public();
                let mut outcomes = Vec::new();
                let mut succeeded = 0usize;
                let mut failed = 0usize;
                for (idx, record) in selected.iter().enumerate() {
                    if state2.jobs.is_cancelled(&rid) {
                        state2.jobs.mark_cancelled(&rid);
                        break;
                    }
                    state2.jobs.update(&rid, |j| {
                        j.items_done = idx;
                        j.items_total = selected.len();
                        j.progress = if selected.is_empty() {
                            0.0
                        } else {
                            idx as f32 / selected.len() as f32
                        };
                        j.phase = "recovering".into();
                    });
                    state2.jobs.wait_if_paused(&rid);
                    let bytes_to_write: Vec<u8> = if let Some(ref inline) = record.resident_data {
                        inline.clone()
                    } else if !record.data_runs.is_empty() && !record.source_device_id.is_empty() {
                        // Stream from the source device — no RAM spike
                        match state2.registry.get(&record.source_device_id) {
                            Some(dev) => match dev.backing_path {
                                Some(ref path) => {
                                    match crate::storage::FileBackedReader::open_read_only(path) {
                                        Ok(raw) => {
                                            let mut resilient =
                                                crate::resilience::ResilientReader::new(raw, 3);
                                            crate::fat32::read_runs(
                                                &mut resilient,
                                                &record.data_runs,
                                                record.size_bytes,
                                            )
                                        }
                                        Err(_) => Vec::new(),
                                    }
                                }
                                None => Vec::new(),
                            },
                            None => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    };
                    if bytes_to_write.is_empty() {
                        failed += 1;
                        outcomes.push(RecoveredFileOutcome {
                            candidate_id: record.id.clone(),
                            written_name: String::new(),
                            requested_name: record.name.clone(),
                            bytes_written: 0,
                            sha256_before_write: record.sha256.clone(),
                            sha256_after_write: String::new(),
                            post_write_verified: false,
                            status: "FAILED".into(),
                            error: Some("no recovered bytes available".into()),
                        });
                        continue;
                    }
                    let safe = sanitize_filename(&record.name);
                    let final_name = resolve_collision(&dest, &safe);
                    let path = std::path::Path::new(&dest).join(&final_name);
                    match std::fs::File::create(&path) {
                        Ok(mut file) => {
                            use std::io::Write;
                            let mut write_error = None;
                            let mut h = Sha256::new();
                            let mut written_total = 0usize;
                            for chunk in bytes_to_write.chunks(1024 * 1024) {
                                if let Err(e) = file.write_all(chunk) {
                                    write_error = Some(e.to_string());
                                    break;
                                }
                                h.update(chunk);
                                written_total += chunk.len();
                            }
                            let _ = file.flush();
                            let after = format!("{:x}", h.finalize());
                            let ok = write_error.is_none() && after == record.sha256;
                            if ok {
                                succeeded += 1
                            } else {
                                failed += 1
                            }
                            outcomes.push(RecoveredFileOutcome {
                                candidate_id: record.id.clone(),
                                written_name: final_name,
                                requested_name: record.name.clone(),
                                bytes_written: written_total,
                                sha256_before_write: record.sha256.clone(),
                                sha256_after_write: after,
                                post_write_verified: ok,
                                status: if ok {
                                    "RECOVERED".into()
                                } else {
                                    "FAILED".into()
                                },
                                error: if ok {
                                    None
                                } else {
                                    write_error.or(Some("post-write hash mismatch".into()))
                                },
                            })
                        }
                        Err(e) => {
                            failed += 1;
                            outcomes.push(RecoveredFileOutcome {
                                candidate_id: record.id.clone(),
                                written_name: String::new(),
                                requested_name: record.name.clone(),
                                bytes_written: 0,
                                sha256_before_write: record.sha256.clone(),
                                sha256_after_write: String::new(),
                                post_write_verified: false,
                                status: "FAILED".into(),
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
                let manifest = RecoveryManifest {
                    recovery_id: rid.clone(),
                    session_id: sid.clone(),
                    destination: dest.clone(),
                    started_at: started.clone(),
                    completed_at: now_iso_public(),
                    files: outcomes,
                    succeeded,
                    failed,
                };

                // Generate and save cryptographically verifiable evidence manifest (Phase 16 gap closed)
                let record_source_device = selected
                    .first()
                    .map(|r| r.source_device_id.clone())
                    .unwrap_or_default();
                let evidence = crate::reporting::generate_evidence_manifest(
                    &sid,
                    &state2
                        .registry
                        .get(&record_source_device)
                        .and_then(|d| d.backing_path.clone())
                        .unwrap_or_default(),
                    0, // capacity omitted for now
                    "recovered",
                    manifest.files.len(),
                    succeeded,
                );
                let _ =
                    crate::reporting::save_manifest_versioned(&state2.recoveries_dir, &evidence);

                std::fs::create_dir_all(&state2.recoveries_dir).ok();
                let path = format!("{}/{}.json", state2.recoveries_dir, rid);
                let _ = std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap());
                let _ = state2.db.save_recovery(
                    &rid,
                    &sid,
                    &dest,
                    "COMPLETED",
                    &started,
                    Some(&manifest.completed_at),
                    Some(&manifest),
                );
                state2
                    .recoveries
                    .lock()
                    .unwrap()
                    .insert(rid.clone(), manifest);
                state2.jobs.mark_completed(&rid);
            });
            (
                "202 Accepted",
                "application/json",
                format!(
                    "{{\"recovery_id\":\"{}\",\"status\":\"QUEUED\"}}",
                    esc(&recovery_id)
                ),
            )
        }
        ("GET", p) if p.starts_with("/recoveries/") && p.ends_with("/progress") => {
            let id = p
                .trim_start_matches("/recoveries/")
                .trim_end_matches("/progress");
            match state.jobs.get(id) {
                Some(j) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_string(&j).unwrap(),
                ),
                None => (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"recovery job not found\"}".into(),
                ),
            }
        }
        ("POST", p) if p.starts_with("/recoveries/") && p.ends_with("/pause") => {
            let id = p
                .trim_start_matches("/recoveries/")
                .trim_end_matches("/pause");
            state.jobs.pause(id);
            (
                "202 Accepted",
                "application/json",
                format!("{{\"recovery_id\":\"{}\",\"status\":\"PAUSED\"}}", esc(id)),
            )
        }
        ("POST", p) if p.starts_with("/recoveries/") && p.ends_with("/resume") => {
            let id = p
                .trim_start_matches("/recoveries/")
                .trim_end_matches("/resume");
            state.jobs.resume(id);
            (
                "202 Accepted",
                "application/json",
                format!("{{\"recovery_id\":\"{}\",\"status\":\"RUNNING\"}}", esc(id)),
            )
        }
        ("POST", p) if p.starts_with("/recoveries/") && p.ends_with("/cancel") => {
            let id = p
                .trim_start_matches("/recoveries/")
                .trim_end_matches("/cancel");
            state.jobs.request_cancel(id);
            (
                "202 Accepted",
                "application/json",
                format!(
                    "{{\"recovery_id\":\"{}\",\"status\":\"CANCELLING\"}}",
                    esc(id)
                ),
            )
        }
        ("GET", p) if p.starts_with("/recoveries/") => {
            let id = p.trim_start_matches("/recoveries/");
            let recoveries = state.recoveries.lock().unwrap();
            match recoveries.get(id) {
                Some(m) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_string(m).unwrap(),
                ),
                None => {
                    // Fall back to the persisted file — survives a server restart even though the in-memory map doesn't.
                    let manifest_path = format!("{}/{}.json", state.recoveries_dir, id);
                    match std::fs::read_to_string(&manifest_path) {
                        Ok(json) => ("200 OK", "application/json", json),
                        Err(_) => match state.db.recovery_manifest(id) {
                            Ok(Some(json)) => ("200 OK", "application/json", json),
                            _ => (
                                "404 Not Found",
                                "application/json",
                                "{\"error\":\"recovery not found\"}".to_string(),
                            ),
                        },
                    }
                }
            }
        }
        ("GET", "/sessions") => {
            let ids = state
                .db
                .list_sessions()
                .unwrap_or_else(|_| crate::session::list_sessions());
            (
                "200 OK",
                "application/json",
                format!(
                    "[{}]",
                    ids.iter()
                        .map(|i| format!("\"{}\"", esc(i)))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        }
        ("GET", p) if p.starts_with("/sessions/") => {
            let id = p.trim_start_matches("/sessions/");
            match crate::session::load_session(id) {
                Ok(s) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_string(&s).unwrap(),
                ),
                Err(_) => (
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"session not found\"}".to_string(),
                ),
            }
        }
        _ => (
            "404 Not Found",
            "application/json",
            "{\"error\":\"not found\"}".to_string(),
        ),
    }
}

fn records_dir() -> String {
    format!("{}/records", crate::config::data_dir())
}
fn persist_records(
    session_id: &str,
    device_id: &str,
    records: &[RecoveredFileRecord],
) -> std::io::Result<()> {
    let dir = format!("{}/{}", records_dir(), session_id);
    std::fs::create_dir_all(&dir)?;
    let path = format!("{}/metadata.json", dir);
    let tmp = format!("{}.tmp", path);
    // Serialize the full record (data_runs included, resident_data as base64 bytes array).
    // The `data` field no longer exists, so nothing large lives on disk.
    let tagged: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "_device_id".into(),
                    serde_json::Value::String(device_id.to_string()),
                );
            }
            v
        })
        .collect();
    std::fs::write(&tmp, serde_json::to_vec_pretty(&tagged).unwrap())?;
    std::fs::rename(tmp, path)
}
fn load_records(session_id: &str) -> std::io::Result<Vec<RecoveredFileRecord>> {
    let dir = format!("{}/{}", records_dir(), session_id);
    let json = std::fs::read_to_string(format!("{}/metadata.json", dir))?;
    let values: Vec<serde_json::Value> = serde_json::from_str(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut out = Vec::new();
    for v in values {
        let r: RecoveredFileRecord = serde_json::from_value(v)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        out.push(r);
    }
    Ok(out)
}

/// Builds unified result records from mixed metadata/carving items. Scoring
/// is deliberately NOT the same formula for both: metadata-recovered files
/// get a confidence based on whether the filesystem's own chain/allocation
/// data was intact (a genuine structural fact), while carved files use the
/// original signature/fragment/entropy formula. Conflating the two was a
/// specifically flagged problem — this keeps them distinct and labels the
/// source explicitly so nothing downstream has to guess which kind of
/// confidence a number represents.
fn build_records(session_id: &str, items: &[RecoveredItem]) -> Vec<RecoveredFileRecord> {
    let mut records = Vec::new();
    let mut hashes: Vec<(usize, String)> = Vec::new();

    for (i, item) in items.iter().enumerate() {
        #[allow(clippy::type_complexity)]
        let (
            name,
            file_type,
            size_bytes,
            source,
            score_val,
            complete,
            reconstruction_state,
            data_runs,
            resident_data,
        ): (
            String,
            String,
            usize,
            &str,
            u8,
            bool,
            String,
            Vec<(u64, u64)>,
            Option<Vec<u8>>,
        ) = match item {
            RecoveredItem::Carved { file: f, data } => {
                let sb = score(f);
                (
                    format!("recovered_{i:04}.{}", f.ext),
                    f.file_type.clone(),
                    f.size,
                    "raw_carving",
                    sb.score,
                    f.complete,
                    if f.complete {
                        "CONTIGUOUS_VERIFIED".into()
                    } else {
                        "PARTIAL".into()
                    },
                    Vec::new(),
                    Some(data.clone()),
                )
            }
            RecoveredItem::NtfsEntry {
                name,
                size,
                is_directory: _,
                resident_data,
                data_runs,
                chain_verified,
                reconstruction_state,
            } => {
                let ext = guess_ext(name);
                let conf = crate::scoring::unified_confidence(
                    0.0, // signature not applicable
                    if *chain_verified { 1.0 } else { 0.6 },
                    if *chain_verified { 1.0 } else { 0.0 }, // structure assumed good if chain good
                    if *chain_verified { 1.0 } else { 0.4 },
                    1.0, // read success
                    0.0, // overwrite
                    0.8, // ntfs resilience
                );
                (
                    name.clone(),
                    ext,
                    *size as usize,
                    "ntfs_metadata",
                    conf.final_score,
                    *chain_verified,
                    format!("{:?}", reconstruction_state).to_uppercase(),
                    data_runs.clone(),
                    resident_data.clone(),
                )
            }
            RecoveredItem::Fat32Entry {
                name,
                size,
                resident_data,
                data_runs,
                chain_verified,
                reconstruction_state,
            } => {
                let ext = guess_ext(name);
                let conf = crate::scoring::unified_confidence(
                    0.0,
                    if *chain_verified { 1.0 } else { 0.6 },
                    if *chain_verified { 1.0 } else { 0.0 },
                    if *chain_verified { 1.0 } else { 0.3 },
                    1.0,
                    0.0,
                    0.5, // fat32 resilience
                );
                (
                    name.clone(),
                    ext,
                    *size as usize,
                    "fat32_metadata",
                    conf.final_score,
                    *chain_verified,
                    format!("{:?}", reconstruction_state).to_uppercase(),
                    data_runs.clone(),
                    resident_data.clone(),
                )
            }
        };

        // Hash: use resident bytes if present, otherwise skip
        // (we don't materialise multi-GB files just to hash them here).
        let (sha256, structurally_valid, verification_state) =
            if let Some(ref bytes) = resident_data {
                if !bytes.is_empty() {
                    let mut hasher = Sha256::new();
                    hasher.update(bytes);
                    let h = format!("{:x}", hasher.finalize());
                    let ext = guess_ext(&name);
                    match verify_bytes_by_ext(&ext, bytes) {
                        Some(checks) => {
                            let valid = checks.iter().all(|(_, ok)| *ok);
                            (
                                h,
                                valid,
                                if valid { "VERIFIED" } else { "RECOVERABLE" }.to_string(),
                            )
                        }
                        None => (h, false, "UNSUPPORTED_FORMAT".to_string()),
                    }
                } else {
                    (String::new(), false, "UNVERIFIED_NO_DATA".to_string())
                }
            } else if !data_runs.is_empty() {
                // Large file — mark as pending verification
                (String::new(), false, "PENDING_VERIFICATION".to_string())
            } else {
                (String::new(), false, "UNVERIFIED_NO_DATA".to_string())
            };

        if !sha256.is_empty() {
            hashes.push((i, sha256.clone()));
        }

        records.push(RecoveredFileRecord {
            id: format!("{session_id}-{i}"),
            name,
            file_type,
            size_bytes,
            score: score_val,
            label: label(score_val).to_string(),
            complete,
            source: source.to_string(),
            sha256,
            structurally_valid,
            verification_state,
            reconstruction_state,
            duplicate_of: None,
            source_device_id: String::new(), // populated by caller with session's device_id
            data_runs,
            resident_data,
        });
    }

    // Real dedup across whatever has a computed hash (metadata-recovered
    // items; carved items don't get one in this pass — see note above).
    let mut by_hash: HashMap<String, usize> = HashMap::new();
    for (i, h) in &hashes {
        if let Some(&first) = by_hash.get(h) {
            records[*i].duplicate_of = Some(records[first].id.clone());
        } else {
            by_hash.insert(h.clone(), *i);
        }
    }

    records
}

fn guess_ext(name: &str) -> String {
    name.rsplit('.').next().unwrap_or("").to_lowercase()
}

pub fn now_iso_public() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}", now.as_millis())
}

fn results_json(records: &[RecoveredFileRecord]) -> String {
    // Serialize via serde but strip the raw `data` bytes from the wire
    // response — they're large and unused by the listing endpoint. Callers
    // that need the bytes use /recoveries or /candidates/{id}/preview.
    let stripped: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                obj.remove("data");
            }
            v
        })
        .collect();
    serde_json::to_string(&stripped).unwrap_or_else(|_| "[]".into())
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
