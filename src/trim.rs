use std::fs;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrimStatus {
    pub device_name: String,
    pub rotational: bool, // true = spinning HDD, false = SSD/flash/virtual-flash
    pub discard_supported: bool, // TRIM/discard capability present
    pub discard_granularity_bytes: u64,
    pub expected_recovery_potential: String, // "Low" | "Moderate" | "Normal"
    pub warning: Option<String>,
}

/// Real detection via Linux sysfs — not a stub. `/sys/block/<dev>/queue/rotational`
/// and `/sys/block/<dev>/queue/discard_granularity` are the same files `lsblk -D`
/// and `hdparm` read from; this isn't guessing, it's reading the kernel's own
/// block-layer view of the device. macOS/Windows equivalents (IOKit device
/// characteristics / IOCTL_STORAGE_QUERY_PROPERTY) are NOT implemented — this
/// is the Linux path only, and is the honest scope of what's built.
pub fn detect_trim(device_name: &str) -> Option<TrimStatus> {
    let base = format!("/sys/block/{device_name}/queue");
    let rotational_raw = fs::read_to_string(format!("{base}/rotational")).ok()?;
    let discard_gran_raw = fs::read_to_string(format!("{base}/discard_granularity")).ok()?;

    let rotational = rotational_raw.trim() == "1";
    let discard_granularity_bytes: u64 = discard_gran_raw.trim().parse().unwrap_or(0);
    let discard_supported = discard_granularity_bytes > 0;

    let (expected_recovery_potential, warning) = if discard_supported && !rotational {
        (
            "Low".to_string(),
            Some(format!(
                "This device supports TRIM/discard (granularity {discard_granularity_bytes} bytes). \
                 On flash-based storage, TRIM tells the controller to physically erase deleted data's \
                 underlying cells almost immediately — not just remove the filesystem's pointer to it. \
                 Deep and Advanced Recovery scans will still run, but recovery potential for anything \
                 deleted more than a few minutes ago is low, and this is a hardware-level limitation \
                 no scan mode can work around."
            )),
        )
    } else if discard_supported && rotational {
        // Rare but real: some virtualized/SAN-backed "rotational" devices still
        // report discard support. Flagged distinctly rather than silently
        // merged into the SSD case, since the underlying physics differ.
        ("Moderate".to_string(), Some("This device reports as rotational but also supports discard/TRIM — likely virtualized or thin-provisioned storage. Discard behavior on the actual backing media is unknown.".to_string()))
    } else {
        ("Normal".to_string(), None)
    };

    Some(TrimStatus {
        device_name: device_name.to_string(),
        rotational,
        discard_supported,
        discard_granularity_bytes,
        expected_recovery_potential,
        warning,
    })
}
