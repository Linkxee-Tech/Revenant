use std::fs;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub mount_point: String,
    pub filesystem: String,
    pub category: String,   // computer | removable | android | ios
    pub capability: String, // full | limited
    pub size_bytes: u64,
    pub used_pct: u8,
}

/// Real device discovery for Linux hosts: reads /proc/mounts (the same source
/// `df`/`lsblk` use) and classifies each mounted volume. On macOS this would
/// use DiskArbitration/IOKit, on Windows SetupAPI + WPD for MTP — those are
/// stubbed in device_macos.rs / device_windows.rs for later phases; this file
/// is the Linux implementation and is fully live, not mocked.
pub fn discover_devices() -> Vec<Device> {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut devices = Vec::new();

    // Filesystem kinds we consider "real storage" worth offering to scan.
    // Pseudo-filesystems (proc, sysfs, tmpfs, overlay, cgroup, etc.) are
    // deliberately excluded — scanning those for "deleted files" is meaningless.
    let real_fs = [
        "ext4", "ext3", "ext2", "xfs", "btrfs", "ntfs", "vfat", "exfat", "f2fs", "apfs", "hfsplus",
    ];

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let source = parts[0];
        let mount_point = parts[1];
        let fstype = parts[2];

        if !real_fs.contains(&fstype) {
            continue;
        }
        // Skip snap/loop-mounted package images — not user storage.
        if source.starts_with("/dev/loop") || mount_point.starts_with("/snap") {
            continue;
        }

        let (total, used_pct) = disk_usage(mount_point);

        let category = if mount_point == "/" || mount_point.starts_with("/boot") {
            "computer"
        } else {
            "removable"
        };

        devices.push(Device {
            id: source.replace('/', "_"),
            name: format!("{} ({})", mount_point, source),
            mount_point: mount_point.to_string(),
            filesystem: fstype.to_uppercase(),
            category: category.to_string(),
            capability: "full".to_string(),
            size_bytes: total,
            used_pct,
        });
    }

    devices
}

/// Uses `df` for real free/used figures rather than re-implementing statvfs syscalls by hand.
fn disk_usage(mount_point: &str) -> (u64, u8) {
    let output = Command::new("df")
        .arg("-B1") // bytes
        .arg(mount_point)
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = text.lines().nth(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 5 {
                let total: u64 = cols[1].parse().unwrap_or(0);
                let pct_str = cols[4].trim_end_matches('%');
                let pct: u8 = pct_str.parse().unwrap_or(0);
                return (total, pct);
            }
        }
    }
    (0, 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusLevel {
    Confirmed,
    Likely,
    Possible,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct DeviceAnalysisReport {
    pub filesystem: String,
    pub capacity: u64,
    pub sector_size: u32,
    pub health: StatusLevel,
    pub trim: StatusLevel,
    pub encryption: StatusLevel,
    pub read_accessibility: StatusLevel,
    pub bad_sectors: StatusLevel,
}
