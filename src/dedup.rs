use crate::carve::CarvedFile;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupGroup {
    pub sha256: String,
    pub candidate_indices: Vec<usize>, // indices into the original carved-file list
    pub is_duplicate_set: bool,        // true when more than one candidate shares this hash
}

/// Real SHA-256 hashing (not a placeholder) of each carved candidate's bytes,
/// grouped so the UI can show "3 copies of the same file" instead of three
/// unrelated results. This is exactly what raw carving produces in practice —
/// the same photo carved once from its live location and again from slack
/// space left by a previous copy.
pub fn hash_and_group(buf: &[u8], files: &[CarvedFile]) -> Vec<DedupGroup> {
    let mut by_hash: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, f) in files.iter().enumerate() {
        let end = (f.offset + f.size).min(buf.len());
        let bytes = &buf[f.offset..end];
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = format!("{:x}", hasher.finalize());
        by_hash.entry(hash).or_default().push(i);
    }

    by_hash
        .into_iter()
        .map(|(sha256, candidate_indices)| {
            let is_duplicate_set = candidate_indices.len() > 1;
            DedupGroup {
                sha256,
                candidate_indices,
                is_duplicate_set,
            }
        })
        .collect()
}

pub struct CandidateResolver {}

impl CandidateResolver {
    pub fn new() -> Self {
        Self {}
    }

    /// Takes a slice of `CarvedFile`s and returns a deduplicated list
    /// by detecting overlapping byte offset ranges and applying 
    /// evidence-based conflict resolution.
    pub fn resolve(&self, candidates: &[CarvedFile]) -> Vec<CarvedFile> {
        let mut sorted = candidates.to_vec();
        // Sort primarily by offset, then by size descending
        sorted.sort_by(|a, b| a.offset.cmp(&b.offset).then_with(|| b.size.cmp(&a.size)));

        let mut resolved: Vec<CarvedFile> = Vec::new();

        for cand in sorted {
            if let Some(last) = resolved.last_mut() {
                let last_end = last.offset + last.size;
                if cand.offset < last_end {
                    // Conflict: Overlapping byte range detected
                    let score_last = Self::score(last);
                    let score_cand = Self::score(&cand);

                    if score_cand > score_last || (score_cand == score_last && cand.size > last.size) {
                        *last = cand;
                    }
                    continue;
                }
            }
            resolved.push(cand);
        }

        resolved
    }

    fn score(c: &CarvedFile) -> f32 {
        let mut s = 0.0;
        if c.complete {
            s += 100.0;
        }
        s += c.signature_match * 10.0;
        s += c.fragment_coverage * 5.0;
        s
    }
}
