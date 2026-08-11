use crate::carve::{
    carve_streaming_mode, read_candidate_bytes, signatures_from_package, CarvedFile,
};
use crate::fat32::{self, Fat32Layout};
use crate::ntfs;
use crate::signatures::SignaturePackage;
use crate::storage::StorageReader;

#[derive(Debug, Clone)]
pub enum RecoveredItem {
    Carved {
        file: CarvedFile,
        data: Vec<u8>,
    },
    NtfsEntry {
        name: String,
        size: u64,
        is_directory: bool,
        resident_data: Option<Vec<u8>>,
        data_runs: Vec<(u64, u64)>,
        chain_verified: bool,
        reconstruction_state: crate::fragment::ReconstructionState,
    },
    Fat32Entry {
        name: String,
        size: u32,
        resident_data: Option<Vec<u8>>,
        data_runs: Vec<(u64, u64)>,
        chain_verified: bool,
        reconstruction_state: crate::fragment::ReconstructionState,
    },
}

/// The extension point (§AD): filesystem-aware and carving providers both
/// implement this, now operating through StorageReader — NOT `&[u8]`. This
/// is the actual fix for the review's Phase 6: the trait boundary now takes
/// bounded reads, so a provider can't accidentally require the whole volume
/// in memory even if it wanted to.
pub trait RecoveryProvider {
    fn name(&self) -> &'static str;
    fn recover(&self, reader: &mut dyn StorageReader) -> Vec<RecoveredItem>;
}

pub struct NtfsFilesystemProvider;
impl RecoveryProvider for NtfsFilesystemProvider {
    fn name(&self) -> &'static str {
        "NtfsFilesystemProvider"
    }
    fn recover(&self, reader: &mut dyn StorageReader) -> Vec<RecoveredItem> {
        let layout = match ntfs::parse_boot_sector(reader) {
            Ok(l) => l,
            Err(_) => return Vec::new(),
        };
        let deleted = ntfs::scan_mft_for_deleted_full(reader, &layout);
        deleted
            .into_iter()
            .map(|d| {
                let (resident_data, data_runs) = if let Some(res) = d.resident_data {
                    (Some(res), Vec::new())
                } else {
                    (None, ntfs::resolve_data_runs(&layout, &d.data_runs, d.logical_size))
                };
                let recovered_bytes = resident_data.as_ref().map(|x| x.len() as u64).unwrap_or_else(|| {
                    data_runs.iter().map(|&(_, len)| len).sum()
                });
                let chain_verified = !d.data_runs.is_empty() && d.logical_size == recovered_bytes;
                let assessment = crate::fragment::assess(
                    d.logical_size,
                    recovered_bytes,
                    chain_verified,
                    d.data_runs.len(),
                    recovered_bytes > 0 || d.logical_size == 0,
                    true,
                );
                RecoveredItem::NtfsEntry {
                    name: d.name,
                    size: d.logical_size,
                    is_directory: d.is_directory,
                    resident_data,
                    data_runs,
                    chain_verified,
                    reconstruction_state: assessment.state,
                }
            })
            .collect()
    }
}

pub struct Fat32FilesystemProvider;
impl RecoveryProvider for Fat32FilesystemProvider {
    fn name(&self) -> &'static str {
        "Fat32FilesystemProvider"
    }
    fn recover(&self, reader: &mut dyn StorageReader) -> Vec<RecoveredItem> {
        let layout: Fat32Layout = match fat32::parse_boot_sector(reader) {
            Ok(l) => l,
            Err(_) => return Vec::new(),
        };
        let deleted = fat32::scan_deleted_recursive(reader, &layout);
        deleted
            .into_iter()
            .map(|entry| {
                let (data_runs, chain_verified) = fat32::recover_file_runs(reader, &layout, &entry);
                let expected = entry.size as u64;
                let recovered_bytes = data_runs.iter().map(|&(_, len)| len).sum();
                let assessment = crate::fragment::assess(
                    expected,
                    recovered_bytes,
                    chain_verified,
                    data_runs.len(),
                    recovered_bytes > 0 || expected == 0,
                    true,
                );
                RecoveredItem::Fat32Entry {
                    name: entry.name,
                    size: entry.size,
                    resident_data: None,
                    data_runs,
                    chain_verified,
                    reconstruction_state: assessment.state,
                }
            })
            .collect()
    }
}

/// Unsupported-but-acknowledged filesystems (§AD requirement: don't silently
/// pretend these work). Each returns zero results and is explicit about why.
pub struct UnsupportedFilesystemProvider {
    pub filesystem_name: &'static str,
}
impl RecoveryProvider for UnsupportedFilesystemProvider {
    fn name(&self) -> &'static str {
        self.filesystem_name
    }
    fn recover(&self, _reader: &mut dyn StorageReader) -> Vec<RecoveredItem> {
        Vec::new() // caller surfaces filesystem_name as "detected but not implemented"
    }
}

/// Streaming raw carving across the FULL device (via carve_streaming), not
/// a fixed-size single read anymore — the fix for the flagged "8MB of a
/// 128GB card" gap. `chunk_size`/`overlap` are server-controlled config,
/// still not client-supplied. Each candidate's real bytes are re-read and
/// attached (RecoveredItem::Carved.data), closing the "carved candidates
/// have no data for hashing/verification" gap.
pub struct RawCarvingProvider {
    pub signature_package: SignaturePackage,
    pub chunk_size: usize,
    pub overlap: usize,
}
impl RawCarvingProvider {
    pub fn recover_with_mode(
        &self,
        reader: &mut dyn StorageReader,
        mode: &str,
    ) -> Vec<RecoveredItem> {
        let sigs = signatures_from_package(&self.signature_package);
        let candidates = carve_streaming_mode(reader, &sigs, self.chunk_size, self.overlap, mode);
        candidates
            .into_iter()
            .map(|file| {
                let data = read_candidate_bytes(reader, &file);
                RecoveredItem::Carved { file, data }
            })
            .collect()
    }
}

impl RecoveryProvider for RawCarvingProvider {
    fn name(&self) -> &'static str {
        "RawCarvingProvider"
    }
    fn recover(&self, reader: &mut dyn StorageReader) -> Vec<RecoveredItem> {
        self.recover_with_mode(reader, "deep")
    }
}
