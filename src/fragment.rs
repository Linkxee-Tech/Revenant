use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconstructionState {
    ContiguousVerified,
    ChainVerified,
    FragmentedReconstructed,
    Partial,
    Corrupted,
    Unreadable,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentAssessment {
    pub state: ReconstructionState,
    pub coverage: f32,
    pub verified_ranges: usize,
    pub missing_ranges: usize,
}

pub struct FragmentReconstructor {
    pub filesystem_evidence: String,
}

impl FragmentReconstructor {
    pub fn new(evidence: &str) -> Self {
        Self {
            filesystem_evidence: evidence.to_string(),
        }
    }

    pub fn validate_format(&self, format: &str) -> bool {
        matches!(format.to_lowercase().as_str(), "ntfs" | "fat32" | "ext4" | "exfat" | "apfs" | "hfs+")
    }
}


pub fn assess(
    expected: u64,
    recovered: u64,
    verified_chain: bool,
    range_count: usize,
    read_ok: bool,
    supported_format: bool,
) -> FragmentAssessment {
    if !supported_format {
        return FragmentAssessment {
            state: ReconstructionState::Unsupported,
            coverage: 0.0,
            verified_ranges: 0,
            missing_ranges: range_count.max(1),
        };
    }
    if !read_ok && recovered == 0 {
        return FragmentAssessment {
            state: ReconstructionState::Unreadable,
            coverage: 0.0,
            verified_ranges: 0,
            missing_ranges: range_count.max(1),
        };
    }
    let coverage = if expected == 0 {
        1.0
    } else {
        (recovered as f32 / expected as f32).clamp(0.0, 1.0)
    };
    let state = if coverage >= 0.999 && verified_chain {
        if range_count == 1 {
            ReconstructionState::ContiguousVerified
        } else if range_count > 1 {
            ReconstructionState::FragmentedReconstructed
        } else {
            ReconstructionState::ChainVerified
        }
    } else if coverage >= 0.5 {
        ReconstructionState::Partial
    } else {
        ReconstructionState::Corrupted
    };
    FragmentAssessment {
        state,
        coverage,
        verified_ranges: range_count.min(usize::MAX),
        missing_ranges: if coverage < 0.999 { 1 } else { 0 },
    }
}
