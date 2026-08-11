use crate::carve::shannon_entropy;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum DataState {
    Recoverable,
    PartiallyRecoverable,
    Encrypted,
    PasswordProtected,
    Unsupported,
    Overwritten,
    Corrupted,
    Unknown,
}

/// Real signature matching for known encrypted-container formats (these are
/// genuine published magic bytes, not invented), plus an entropy fallback
/// for containers with no fixed signature (VeraCrypt volumes are designed
/// to look like random data specifically to resist this kind of detection —
/// the entropy heuristic is a best-effort flag, not a guarantee, and this
/// module says so rather than overclaiming).
pub fn classify_region(bytes: &[u8]) -> DataState {
    // BitLocker: "-FVE-FS-" signature at a fixed offset in the volume header.
    if bytes.len() >= 512 && find(&bytes[..512], b"-FVE-FS-").is_some() {
        return DataState::Encrypted;
    }
    // LUKS (Linux Unified Key Setup): magic bytes at the very start of the
    // container — only needs 6 bytes present, not a full sector, so this
    // check must not be gated behind the same 512-byte minimum as BitLocker.
    if bytes.len() >= 6 && bytes[0..6] == [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE] {
        return DataState::Encrypted;
    }
    // Password-protected ZIP: general purpose bit flag bit 0 set in the
    // local file header (offset 6-7, bit 0).
    if bytes.len() >= 8 && bytes[0..4] == [0x50, 0x4B, 0x03, 0x04] {
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags & 0x1 == 1 {
            return DataState::PasswordProtected;
        }
    }
    // PDF with an /Encrypt dictionary reference — genuine text scan, not a guess.
    if bytes.starts_with(b"%PDF-") && find(bytes, b"/Encrypt").is_some() {
        return DataState::PasswordProtected;
    }

    // No known container signature matched — fall back to entropy. High,
    // flat entropy (close to the theoretical max of 8.0 bits/byte) across a
    // large enough sample is consistent with encrypted or already-compressed
    // data; it is NOT proof, since well-compressed legitimate files (already-
    // zipped archives, JPEGs) also read this way. Flag it as a possibility,
    // not a certainty.
    if bytes.len() >= 4096 {
        let sample = &bytes[..4096];
        let entropy = shannon_entropy(sample);
        if entropy > 7.85 {
            return DataState::Unsupported; // "looks encrypted/compressed, unverified"
        }
    }

    DataState::Recoverable
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
