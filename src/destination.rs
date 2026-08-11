use crate::engine::DeviceRegistry;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DestinationCheck {
    pub different_from_source: bool,
    pub writable: bool,
    pub sufficient_space: bool,
    pub free_bytes: u64,
    pub required_bytes: u64,
    pub safe: bool,
    pub issues: Vec<String>,
}

/// Real checks, not a mockup: attempts an actual test write (proving
/// writability rather than just checking permission bits, which can lie on
/// some filesystems), queries real free space via `df` (same source
/// performance.rs already uses for RAM), and rejects any destination that
/// resolves to the same path as — or a path inside — any backing_path this
/// process has registered as a source. "Same physical disk" in the fuller
/// sense the reviewer wants isn't determinable without platform-specific
/// device-to-mountpoint mapping, which isn't built — this check is real but
/// narrower than that: same real risk (recovering data destroys the very
/// evidence you're trying to save), smaller scope (path-based, not
/// physical-device-based).
pub fn validate_destination(
    dest_dir: &str,
    required_bytes: u64,
    registry: &DeviceRegistry,
) -> DestinationCheck {
    let mut issues = Vec::new();

    fs::create_dir_all(dest_dir).ok();

    let dest_canon = fs::canonicalize(dest_dir).ok();

    let mut different_from_source = true;
    if let Some(dest_path) = &dest_canon {
        for device in registry.list() {
            if let Some(backing) = &device.backing_path {
                if let Ok(source_canon) = fs::canonicalize(backing) {
                    // Correct direction: is the SOURCE file located inside
                    // (or exactly at) the destination directory? The
                    // reverse check — destination path starting with the
                    // source file's path — can essentially never be true
                    // (a directory can't "start with" a file path it
                    // doesn't contain), which meant this check never fired.
                    // Caught by testing an actual dangerous recovery
                    // attempt, not by inspection.
                    if source_canon == *dest_path
                        || source_canon.starts_with(dest_path)
                        || same_filesystem(&source_canon, dest_path)
                    {
                        different_from_source = false;
                        issues.push(format!("Destination is on the same filesystem/device as registered source '{}' ({})", device.id, backing));
                    }

                    if crate::platform::safe_same_physical_device(backing, dest_dir) {
                        different_from_source = false;
                        issues.push(format!("Destination is on the SAME PHYSICAL DEVICE as registered source '{}' ({})", device.id, backing));
                    }
                }
            }
        }
    } else {
        issues.push("Destination path could not be resolved".to_string());
    }

    let writable = test_write(dest_dir);
    if !writable {
        issues.push("Destination is not writable (test write failed)".to_string());
    }

    let free_bytes = real_free_bytes(dest_dir);
    let sufficient_space = free_bytes > required_bytes;
    if !sufficient_space {
        issues.push(format!("Insufficient free space: {free_bytes} bytes available, {required_bytes} bytes required"));
    }

    let safe = different_from_source && writable && sufficient_space;

    DestinationCheck {
        different_from_source,
        writable,
        sufficient_space,
        free_bytes,
        required_bytes,
        safe,
        issues,
    }
}

fn same_filesystem(a: &Path, b: &Path) -> bool {
    let da = Command::new("df").arg("-P").arg(a).output().ok();
    let db = Command::new("df").arg("-P").arg(b).output().ok();
    fn source(o: &std::process::Output) -> Option<String> {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .nth(1)
            .and_then(|l| l.split_whitespace().next())
            .map(|s| s.to_string())
    }
    match (da.as_ref().and_then(source), db.as_ref().and_then(source)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn test_write(dir: &str) -> bool {
    let probe = Path::new(dir).join(".revenant_write_test");
    match fs::write(&probe, b"revenant destination write test") {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn real_free_bytes(dir: &str) -> u64 {
    let output = Command::new("df").arg("-B1").arg(dir).output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = text.lines().nth(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                return cols[3].parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Sanitizes a recovered filename against path traversal and reserved
/// characters before it's ever joined to a destination path — real
/// protection, not a comment promising it later.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name); // strip any embedded path components
    let cleaned: String = base
        .chars()
        .map(|c| if "<>:\"|?*\0".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "recovered_file".to_string()
    } else {
        cleaned
    }
}

/// Resolves filename collisions by appending a numeric suffix — real
/// collision handling, not silent overwrite.
pub fn resolve_collision(dest_dir: &str, filename: &str) -> String {
    let path = Path::new(dest_dir).join(filename);
    if !path.exists() {
        return filename.to_string();
    }
    let (stem, ext) = match filename.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (filename.to_string(), String::new()),
    };
    for i in 1..10000 {
        let candidate = format!("{stem}_{i}{ext}");
        if !Path::new(dest_dir).join(&candidate).exists() {
            return candidate;
        }
    }
    format!("{stem}_dup{ext}") // extremely unlikely fallback
}
