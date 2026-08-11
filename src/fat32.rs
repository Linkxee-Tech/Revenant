/// FAT32 metadata-based recovery, operating through StorageReader with
/// bounded reads — NOT a whole-volume Vec<u8> anymore. Each function reads
/// only the specific sectors/clusters it needs (boot sector, root directory
/// cluster, individual data clusters), which is what makes this safe to run
/// against a real multi-hundred-GB volume instead of just small test images.
use crate::storage::StorageReader;

pub struct Fat32Layout {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub fat_start: u64,
    pub data_start: u64,
    pub cluster_size: u32,
}

impl Fat32Layout {
    pub fn parse(boot_sector: &[u8]) -> Self {
        let bytes_per_sector = u16::from_le_bytes([boot_sector[11], boot_sector[12]]) as u32;
        let sectors_per_cluster = boot_sector[13] as u32;
        let reserved_sectors = u16::from_le_bytes([boot_sector[14], boot_sector[15]]) as u32;
        let num_fats = boot_sector[16] as u32;
        let sectors_per_fat = u32::from_le_bytes([
            boot_sector[36],
            boot_sector[37],
            boot_sector[38],
            boot_sector[39],
        ]);
        let root_cluster = u32::from_le_bytes([
            boot_sector[44],
            boot_sector[45],
            boot_sector[46],
            boot_sector[47],
        ]);

        let fat_start = (reserved_sectors as u64) * (bytes_per_sector as u64);
        let data_start =
            fat_start + (num_fats as u64) * (sectors_per_fat as u64) * (bytes_per_sector as u64);
        let cluster_size = bytes_per_sector * sectors_per_cluster;

        Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_cluster,
            fat_start,
            data_start,
            cluster_size,
        }
    }

    pub fn cluster_offset(&self, cluster: u32) -> u64 {
        self.data_start + ((cluster as u64) - 2) * (self.cluster_size as u64)
    }

    /// Reads one FAT table entry via a single bounded 4-byte read, not by
    /// indexing into a preloaded buffer.
    pub fn fat_entry(&self, reader: &mut dyn StorageReader, cluster: u32) -> u32 {
        let offset = self.fat_start + (cluster as u64) * 4;
        match reader.read_range(offset, 4) {
            Ok(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x0FFFFFFF,
            Err(_) => 0x0FFFFFFF, // unreadable FAT entry treated as end-of-chain, not a crash
        }
    }
}

pub fn parse_boot_sector(reader: &mut dyn StorageReader) -> std::io::Result<Fat32Layout> {
    let boot = reader.read_range(0, 512)?;
    Ok(Fat32Layout::parse(&boot))
}

#[derive(Debug, Clone)]
pub struct DeletedEntry {
    pub name: String,
    pub name_source: String,
    pub start_cluster: u32,
    pub size: u32,
    pub metadata_intact: bool,
}

/// Walks the root directory's FULL cluster chain (not just its first
/// cluster — that was a real bug: FAT32 root directories can span many
/// clusters, and anything past the first was silently invisible). Follows
/// the FAT chain via fat_entry() exactly like file data does, with a safety
/// cap against a corrupt/circular chain.
/// Recursively scans the complete directory tree. Deleted entries are
/// returned, while live subdirectories are traversed so deleted children are
/// not missed merely because they are not in the root directory.
pub fn scan_deleted_recursive(
    reader: &mut dyn StorageReader,
    layout: &Fat32Layout,
) -> Vec<DeletedEntry> {
    use std::collections::HashSet;
    let mut results = Vec::new();
    let mut queue = vec![layout.root_cluster];
    let mut visited = HashSet::new();
    while let Some(dir_cluster) = queue.pop() {
        if dir_cluster < 2 || !visited.insert(dir_cluster) {
            continue;
        }
        let mut cluster = dir_cluster;
        let mut chain_seen = HashSet::new();
        let mut lfn: Vec<(u8, String, u8)> = Vec::new();
        loop {
            if !chain_seen.insert(cluster) {
                break;
            }
            let off = layout.cluster_offset(cluster);
            let bytes = match reader.read_range(off, layout.cluster_size as usize) {
                Ok(b) => b,
                Err(_) => break,
            };
            let mut i = 0usize;
            while i + 32 <= bytes.len() {
                let e = &bytes[i..i + 32];
                if e[0] == 0x00 {
                    break;
                }
                let attr = e[11];
                if attr == 0x0F {
                    lfn.push(((e[0] & 0x1F), decode_lfn_chars(e), e[13]));
                } else {
                    let deleted = e[0] == 0xE5;
                    let is_dir = attr & 0x10 != 0;
                    let start_hi = u16::from_le_bytes([e[20], e[21]]) as u32;
                    let start_lo = u16::from_le_bytes([e[26], e[27]]) as u32;
                    let start = (start_hi << 16) | start_lo;
                    let size = u32::from_le_bytes([e[28], e[29], e[30], e[31]]);
                    let raw_name = &e[0..11];
                    let short_checksum = lfn_checksum(raw_name);
                    let lfn_valid =
                        !lfn.is_empty() && lfn.iter().all(|(_, _, c)| *c == short_checksum);
                    if deleted && !is_dir && start >= 2 {
                        let name = if !lfn.is_empty() && lfn_valid {
                            let mut ordered = lfn.clone();
                            ordered.sort_by(|a, b| b.0.cmp(&a.0));
                            ordered.into_iter().map(|(_, n, _)| n).collect::<String>()
                        } else {
                            let base = String::from_utf8_lossy(&e[1..8]).trim().to_string();
                            let ext = String::from_utf8_lossy(&e[8..11]).trim().to_string();
                            if ext.is_empty() {
                                format!("?{base}")
                            } else {
                                format!("?{base}.{ext}")
                            }
                        };
                        results.push(DeletedEntry {
                            name,
                            name_source: if lfn_valid {
                                "long_filename_reconstructed".into()
                            } else {
                                "short_name_placeholder".into()
                            },
                            start_cluster: start,
                            size,
                            metadata_intact: (2..0x0FFFFFF0).contains(&start),
                        });
                    } else if !deleted && is_dir && start >= 2 {
                        // Skip . and .. entries.
                        let name = String::from_utf8_lossy(&e[0..11]).trim().to_string();
                        if name != ".          " && name != "..         " {
                            queue.push(start);
                        }
                    }
                    lfn.clear();
                }
                i += 32;
            }
            let next = layout.fat_entry(reader, cluster);
            if next == 0 || next >= 0x0FFFFFF8 {
                break;
            }
            cluster = next;
        }
    }
    results
}

fn lfn_checksum(short: &[u8]) -> u8 {
    let mut sum = 0u8;
    for &b in short.iter().take(11) {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

pub fn scan_root_directory_for_deleted(
    reader: &mut dyn StorageReader,
    layout: &Fat32Layout,
) -> Vec<DeletedEntry> {
    let mut results = Vec::new();
    let mut lfn_buffer: Vec<(u8, String, u8)> = Vec::new();

    let mut cluster = layout.root_cluster;
    let mut clusters_visited = 0usize;
    const MAX_ROOT_CLUSTERS: usize = 65536; // safety cap against a corrupt/circular FAT chain

    'outer: loop {
        clusters_visited += 1;
        if clusters_visited > MAX_ROOT_CLUSTERS {
            break; // corrupt chain — stop rather than loop forever
        }

        let off = layout.cluster_offset(cluster);
        let cluster_bytes = match reader.read_range(off, layout.cluster_size as usize) {
            Ok(b) => b,
            Err(_) => break, // unreadable cluster — stop, return what we have
        };

        let mut i = 0usize;
        loop {
            let entry_off = i * 32;
            if entry_off + 32 > cluster_bytes.len() {
                break; // end of this cluster, move to next via FAT chain
            }
            let entry = &cluster_bytes[entry_off..entry_off + 32];
            if entry[0] == 0x00 {
                break 'outer; // 0x00 marks end of the ENTIRE directory listing, not just this cluster
            }
            let attr = entry[11];
            let is_lfn = attr == 0x0F;
            let is_deleted = entry[0] == 0xE5;

            if is_deleted && is_lfn {
                lfn_buffer.push((i as u8, decode_lfn_chars(entry), entry[13]));
                i += 1;
                continue;
            }

            if is_deleted && !is_lfn {
                let start_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let start_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let start_cluster = (start_hi << 16) | start_lo;
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

                let raw_name = &entry[0..11];
                let short_checksum = lfn_checksum(raw_name);
                let lfn_valid = !lfn_buffer.is_empty()
                    && lfn_buffer.iter().all(|(_, _, c)| *c == short_checksum);

                let (name, name_source) = if lfn_valid {
                    let combined: String = lfn_buffer
                        .iter()
                        .rev()
                        .map(|(_, s, _)| s.as_str())
                        .collect();
                    (combined, "long_filename_reconstructed".to_string())
                } else {
                    let raw = &entry[1..11];
                    let name_part: String = raw[0..7]
                        .iter()
                        .map(|&b| b as char)
                        .collect::<String>()
                        .trim()
                        .to_string();
                    let ext_part: String = raw[7..10]
                        .iter()
                        .map(|&b| b as char)
                        .collect::<String>()
                        .trim()
                        .to_string();
                    let placeholder = if ext_part.is_empty() {
                        format!("?{name_part}")
                    } else {
                        format!("?{name_part}.{ext_part}")
                    };
                    (placeholder, "short_name_placeholder".to_string())
                };

                results.push(DeletedEntry {
                    name,
                    name_source,
                    start_cluster,
                    size,
                    metadata_intact: start_cluster > 0 && start_cluster < 0x0FFFFFF0,
                });
                lfn_buffer.clear();
            } else {
                lfn_buffer.clear();
            }

            i += 1;
        }

        let next = layout.fat_entry(reader, cluster);
        if next == 0 || next >= 0x0FFFFFF8 {
            break; // end of chain
        }
        cluster = next;
    }

    results
}

fn decode_lfn_chars(entry: &[u8]) -> String {
    let mut chars = Vec::new();
    for &off in &[1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
        if off + 1 >= entry.len() {
            break;
        }
        let c = u16::from_le_bytes([entry[off], entry[off + 1]]);
        if c == 0x0000 {
            break;
        }
        if c == 0xFFFF {
            continue;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            chars.push(ch);
        }
    }
    chars.into_iter().collect()
}

/// Returns (data_runs, chain_intact) where data_runs is a list of
/// (byte_offset, byte_length) pairs into the volume.  No data is read into
/// RAM — the caller decides when/how much to materialise.
pub fn recover_file_runs(
    reader: &mut dyn StorageReader,
    layout: &Fat32Layout,
    entry: &DeletedEntry,
) -> (Vec<(u64, u64)>, bool) {
    if entry.size == 0 || entry.start_cluster < 2 {
        return (Vec::new(), true);
    }
    let cluster_count =
        (entry.size as u64).div_ceil(layout.cluster_size as u64);

    // Walk the FAT chain
    let mut chain = vec![entry.start_cluster];
    let mut current = entry.start_cluster;
    let mut chain_intact = true;
    for _ in 1..cluster_count {
        let next = layout.fat_entry(reader, current);
        if !(2..0x0FFFFFF8).contains(&next) {
            chain_intact = false;
            break;
        }
        chain.push(next);
        current = next;
    }
    if chain.len() as u64 != cluster_count {
        // FAT chain shorter than expected — fall back to contiguous assumption
        chain_intact = false;
        chain = (0..cluster_count as u32)
            .map(|n| entry.start_cluster + n)
            .collect();
    }

    // Translate clusters → (offset, length) run list, merging adjacent clusters
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut total_bytes = 0u64;
    let expected = entry.size as u64;
    for c in chain {
        let off = layout.cluster_offset(c);
        let bytes_remaining = expected.saturating_sub(total_bytes);
        if bytes_remaining == 0 {
            break;
        }
        let bytes_to_add = (layout.cluster_size as u64).min(bytes_remaining);
        // Merge with last run if physically contiguous
        if let Some(last) = runs.last_mut() {
            if last.0 + last.1 == off {
                last.1 += bytes_to_add;
                total_bytes += bytes_to_add;
                continue;
            }
        }
        runs.push((off, bytes_to_add));
        total_bytes += bytes_to_add;
    }
    (runs, chain_intact)
}

/// Materialise file bytes from a run list — used by preview and direct recovery.
/// Reads only the bytes needed, one run at a time through StorageReader.
pub fn read_runs(reader: &mut dyn StorageReader, runs: &[(u64, u64)], limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for &(off, len) in runs {
        if out.len() >= limit {
            break;
        }
        let want = (len as usize).min(limit - out.len());
        match reader.read_range(off, want) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(_) => break,
        }
    }
    out
}
