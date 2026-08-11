use serde::Serialize;
use std::fs::OpenOptions;
use std::io;

#[derive(Debug, Clone, Serialize)]
pub struct RawDeviceInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub platform: String,
    pub scan_capable: bool,
    pub reason: Option<String>,
}

fn can_open_read_only(path: &str) -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
pub fn discover_raw_devices() -> Vec<RawDeviceInfo> {
    let out = std::process::Command::new("lsblk")
        .args(["-b", "-dn", "-o", "NAME,SIZE,TYPE"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() < 3 || p[2] != "disk" {
                return None;
            }
            let path = format!("/dev/{}", p[0]);
            let size = p[1].parse().ok()?;
            match can_open_read_only(&path) {
                Ok(()) => Some(RawDeviceInfo {
                    id: p[0].into(),
                    name: format!("{} ({})", p[0], path),
                    path,
                    size_bytes: size,
                    platform: "linux".into(),
                    scan_capable: true,
                    reason: None,
                }),
                Err(e) => Some(RawDeviceInfo {
                    id: p[0].into(),
                    name: format!("{} ({})", p[0], path),
                    path,
                    size_bytes: size,
                    platform: "linux".into(),
                    scan_capable: false,
                    reason: Some(format!("read-only open failed: {e}")),
                }),
            }
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub fn discover_raw_devices() -> Vec<RawDeviceInfo> {
    // Windows raw disks are exposed through \"\\.\\PhysicalDriveN\". WMI is
    // queried through PowerShell; only handles that can actually be opened
    // read-only are marked scan-capable.
    let script = r#"Get-CimInstance Win32_DiskDrive | ForEach-Object { "$($_.Index)|$($_.Model)|$($_.Size)" }"#;
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let p: Vec<_> = line.split('|').collect();
            if p.len() < 3 {
                return None;
            };
            let path = format!(r"\\.\PhysicalDrive{}", p[0]);
            let size = p[2].trim().parse().unwrap_or(0);
            match can_open_read_only(&path) {
                Ok(()) => Some(RawDeviceInfo {
                    id: format!("PhysicalDrive{}", p[0]),
                    name: p[1].into(),
                    path,
                    size_bytes: size,
                    platform: "windows".into(),
                    scan_capable: true,
                    reason: None,
                }),
                Err(e) => Some(RawDeviceInfo {
                    id: format!("PhysicalDrive{}", p[0]),
                    name: p[1].into(),
                    path,
                    size_bytes: size,
                    platform: "windows".into(),
                    scan_capable: false,
                    reason: Some(e),
                }),
            }
        })
        .collect()
}

#[cfg(target_os = "macos")]
pub fn discover_raw_devices() -> Vec<RawDeviceInfo> {
    let out = std::process::Command::new("diskutil")
        .args(["list", "physical"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut ids = Vec::new();
    for line in text.lines() {
        if let Some(pos) = line.find("/dev/disk") {
            let tail = &line[pos..];
            let id = tail.split_whitespace().next().unwrap_or("");
            if id.starts_with("/dev/disk") && !ids.contains(&id.to_string()) {
                ids.push(id.to_string());
            }
        }
    }
    ids.into_iter()
        .map(|p| {
            let raw = p.replacen("/dev/disk", "/dev/rdisk", 1);
            match can_open_read_only(&raw) {
                Ok(()) => RawDeviceInfo {
                    id: p.clone(),
                    name: p.clone(),
                    path: raw,
                    size_bytes: 0,
                    platform: "macos".into(),
                    scan_capable: true,
                    reason: None,
                },
                Err(e) => RawDeviceInfo {
                    id: p.clone(),
                    name: p.clone(),
                    path: raw,
                    size_bytes: 0,
                    platform: "macos".into(),
                    scan_capable: false,
                    reason: Some(e),
                },
            }
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn discover_raw_devices() -> Vec<RawDeviceInfo> {
    Vec::new()
}

pub fn safe_same_physical_device(source: &str, destination: &str) -> bool {
    let a = std::fs::canonicalize(source).ok();
    let b = std::fs::canonicalize(destination).ok();
    if a.is_some() && b.is_some() && a == b {
        return true;
    }

    #[cfg(target_os = "linux")]
    {
        let sa = std::process::Command::new("lsblk")
            .args(["-no", "PKNAME", source])
            .output()
            .ok();
        let sb = std::process::Command::new("lsblk")
            .args(["-no", "PKNAME", destination])
            .output()
            .ok();
        if let (Some(a), Some(b)) = (sa, sb) {
            if a.stdout == b.stdout && !a.stdout.is_empty() {
                return true;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let get_disk_number = |path: &str| -> Option<String> {
            if let Some(pos) = path.find("PhysicalDrive") {
                let num: String = path[pos + 13..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if !num.is_empty() {
                    return Some(num);
                }
            }
            let drive = path.chars().next()?;
            if !drive.is_ascii_alphabetic() || path.chars().nth(1) != Some(':') {
                return None;
            }
            let script = format!("(Get-Partition -DriveLetter {}).DiskNumber", drive);
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .ok()?;
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        };
        let sa = get_disk_number(source);
        let sb = get_disk_number(destination);
        if let (Some(a), Some(b)) = (sa, sb) {
            if a == b && !a.is_empty() {
                return true;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let get_whole_disk = |path: &str| -> Option<String> {
            let out = std::process::Command::new("diskutil")
                .args(["info", path])
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            
            let mut part_of_whole = None;
            let mut device_node = None;
            
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with("Part of Whole:") {
                    part_of_whole = Some(line.split(':').nth(1)?.trim().to_string());
                } else if line.starts_with("Device Node:") {
                    device_node = Some(line.split(':').nth(1)?.trim().to_string());
                } else if line.starts_with("Device Identifier:") && device_node.is_none() {
                    device_node = Some(line.split(':').nth(1)?.trim().to_string());
                }
            }
            
            if let Some(whole) = part_of_whole {
                return Some(whole);
            }
            if let Some(node) = device_node {
                if let Some(pos) = node.find("disk") {
                    let tail = &node[pos + 4..];
                    let num_str: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !num_str.is_empty() {
                        return Some(format!("disk{}", num_str));
                    }
                }
            }
            
            if let Some(pos) = path.find("disk") {
                let tail = &path[pos + 4..];
                let num_str: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !num_str.is_empty() {
                    return Some(format!("disk{}", num_str));
                }
            }
            None
        };
        
        let sa = get_whole_disk(source);
        let sb = get_whole_disk(destination);
        if let (Some(a), Some(b)) = (sa, sb) {
            if a == b && !a.is_empty() {
                return true;
            }
        }
    }

    false
}

pub fn read_only_open(path: &str) -> io::Result<std::fs::File> {
    OpenOptions::new().read(true).write(false).open(path)
}
