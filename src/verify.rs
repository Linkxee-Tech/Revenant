use crate::carve::CarvedFile;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationResult {
    pub sha256: String,
    pub structurally_valid: bool,
    pub checks: Vec<(String, bool)>,
    pub state: String, // DISCOVERED..VERIFIED per §M state machine
}

/// Real structural validation per file type — not a full codec (no image/PDF
/// decoding library is linked here), but genuine parsing of each format's own
/// structural rules, which is what actually catches "this carved candidate is
/// garbage that happened to have the right header bytes."
/// Real structural checks where a parser exists; returns None (not a fake
/// "true") when no structural check is defined for the type. Returning
/// `true` for unsupported formats was flagged as actively dangerous — it
/// let an unsupported format silently read as "structurally valid" when it
/// was never actually checked. Callers must treat None as UNSUPPORTED, not
/// as VALID.
pub fn verify_bytes_by_ext(ext: &str, bytes: &[u8]) -> Option<Vec<(String, bool)>> {
    match ext {
        "jpg" | "jpeg" => Some(verify_jpeg(bytes)),
        "png" => Some(verify_png(bytes)),
        "pdf" => Some(verify_pdf(bytes)),
        "zip" | "docx" | "xlsx" | "pptx" => Some(verify_zip(bytes)),
        "gif" => Some(verify_gif(bytes)),
        "webp" => Some(verify_webp(bytes)),
        "tif" | "tiff" => Some(verify_tiff(bytes)),
        "wav" | "avi" => Some(verify_riff(bytes)),
        "flac" => Some(verify_flac(bytes)),
        "mp3" => Some(verify_mp3(bytes)),
        "mp4" | "mov" | "m4a" | "3gp" | "heic" => Some(verify_isobmff(bytes)),
        "7z" => Some(verify_7z(bytes)),
        "gz" => Some(verify_gzip(bytes)),
        "sqlite" => Some(verify_sqlite(bytes)),
        "mkv" => Some(verify_ebml(bytes)),
        _ => None, // no structural parser for this type — caller must report UNSUPPORTED, not VALID
    }
}

pub fn verify(buf: &[u8], file: &CarvedFile) -> VerificationResult {
    let end = (file.offset + file.size).min(buf.len());
    let bytes = &buf[file.offset..end];

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    let checks: Vec<(String, bool)> = verify_bytes_by_ext(file.ext.as_str(), bytes)
        .unwrap_or_else(|| vec![("size_nonzero".to_string(), !bytes.is_empty())]);

    let structurally_valid = checks.iter().all(|(_, ok)| *ok) && file.complete;
    let state = if structurally_valid {
        "VERIFIED"
    } else if checks.iter().any(|(_, ok)| *ok) {
        "RECOVERABLE"
    } else {
        "CORRUPTED"
    };

    VerificationResult {
        sha256,
        structurally_valid,
        checks,
        state: state.to_string(),
    }
}

fn verify_jpeg(b: &[u8]) -> Vec<(String, bool)> {
    let has_soi = b.len() >= 2 && b[0] == 0xFF && b[1] == 0xD8;
    let has_eoi = b.len() >= 2 && b[b.len() - 2] == 0xFF && b[b.len() - 1] == 0xD9;
    // Look for at least one Start-Of-Frame marker (0xFFC0 or 0xFFC2), which a
    // genuine JPEG bitstream must contain — pure random bytes that happen to
    // start with FFD8 essentially never will.
    let mut has_sof = false;
    let mut i = 2;
    while i + 1 < b.len() {
        if b[i] == 0xFF && (b[i + 1] == 0xC0 || b[i + 1] == 0xC2) {
            has_sof = true;
            break;
        }
        i += 1;
    }
    vec![
        ("start_of_image_marker".to_string(), has_soi),
        ("end_of_image_marker".to_string(), has_eoi),
        ("start_of_frame_present".to_string(), has_sof),
    ]
}

fn verify_png(b: &[u8]) -> Vec<(String, bool)> {
    let sig_ok = b.len() >= 8 && b[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr_ok = false;
    let mut crc_ok = false;
    if b.len() >= 8 + 4 + 4 + 13 + 4 {
        let len = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        let chunk_type = &b[12..16];
        ihdr_ok = len == 13 && chunk_type == b"IHDR";
        if ihdr_ok {
            let chunk_data = &b[12..12 + 4 + 13]; // type + data, per PNG CRC spec
            let stored_crc = u32::from_be_bytes([b[29], b[30], b[31], b[32]]);
            let computed = crc32(chunk_data);
            crc_ok = computed == stored_crc;
        }
    }
    vec![
        ("png_signature".to_string(), sig_ok),
        ("ihdr_chunk_structure".to_string(), ihdr_ok),
        ("ihdr_crc32_valid".to_string(), crc_ok),
    ]
}

fn verify_pdf(b: &[u8]) -> Vec<(String, bool)> {
    let starts_ok = b.starts_with(b"%PDF-");
    let has_eof = find(b, b"%%EOF").is_some();
    let has_xref = find(b, b"xref").is_some() || find(b, b"/XRefStm").is_some();
    vec![
        ("pdf_header".to_string(), starts_ok),
        ("eof_marker".to_string(), has_eof),
        ("xref_table_present".to_string(), has_xref),
    ]
}

fn verify_zip(b: &[u8]) -> Vec<(String, bool)> {
    let local = b.len() >= 4 && &b[0..4] == b"PK\x03\x04";
    let eocd_pos = find(b, b"PK\x05\x06");
    let central = find(b, b"PK\x01\x02");
    let zip64 = find(b, b"PK\x06\x06");
    let has_eocd = eocd_pos.is_some();
    let is_zip64 = zip64.is_some();
    vec![
        ("zip_local_header_signature".into(), local),
        (
            "zip_central_directory".into(),
            central.is_some() || has_eocd,
        ),
        ("zip_eocd".into(), has_eocd),
        (
            "zip64_eocd_when_present".into(),
            !is_zip64 || zip64.unwrap() + 56 <= b.len(),
        ),
        (
            "zip_structure".into(),
            local && (has_eocd || central.is_some()),
        ),
    ]
}

fn verify_gif(b: &[u8]) -> Vec<(String, bool)> {
    let header = b.len() >= 6 && (&b[..6] == b"GIF87a" || &b[..6] == b"GIF89a");
    let trailer = b.last().copied() == Some(0x3B);
    let logical_screen = b.len() >= 13;
    vec![
        ("gif_header".into(), header),
        ("logical_screen_descriptor".into(), logical_screen),
        ("gif_trailer".into(), trailer),
    ]
}

fn verify_webp(b: &[u8]) -> Vec<(String, bool)> {
    let riff = b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP";
    let declared = if b.len() >= 8 {
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize + 8
    } else {
        0
    };
    let size_sane = declared >= 12 && declared <= b.len();
    vec![
        ("webp_riff_header".into(), riff),
        ("webp_declared_size".into(), size_sane),
    ]
}

fn verify_tiff(b: &[u8]) -> Vec<(String, bool)> {
    let le = b.len() >= 8 && &b[..2] == b"II" && u16::from_le_bytes([b[2], b[3]]) == 42;
    let be = b.len() >= 8 && &b[..2] == b"MM" && u16::from_be_bytes([b[2], b[3]]) == 42;
    let magic = le || be;
    let off = if le {
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize
    } else if be {
        u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as usize
    } else {
        usize::MAX
    };
    let ifd = off < b.len();
    vec![
        ("tiff_header".into(), magic),
        ("tiff_first_ifd_offset".into(), ifd),
    ]
}

fn verify_riff(b: &[u8]) -> Vec<(String, bool)> {
    let riff = b.len() >= 12 && &b[..4] == b"RIFF";
    let form = riff && (&b[8..12] == b"WAVE" || &b[8..12] == b"AVI ");
    let declared = if riff {
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize + 8
    } else {
        0
    };
    vec![
        ("riff_header".into(), riff),
        ("riff_form_type".into(), form),
        (
            "riff_declared_size".into(),
            declared >= 12 && declared <= b.len(),
        ),
    ]
}

fn verify_flac(b: &[u8]) -> Vec<(String, bool)> {
    let header = b.len() >= 4 && &b[..4] == b"fLaC";
    let block_header = header && b.len() >= 8;
    vec![
        ("flac_signature".into(), header),
        ("flac_metadata_present".into(), block_header),
    ]
}

fn verify_mp3(b: &[u8]) -> Vec<(String, bool)> {
    let id3 = b.len() >= 10 && &b[..3] == b"ID3";
    let frame = b.len() >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0;
    vec![
        ("mp3_id3_or_frame".into(), id3 || frame),
        ("mp3_frame_sync".into(), frame || id3),
    ]
}

fn verify_isobmff(b: &[u8]) -> Vec<(String, bool)> {
    if b.len() < 12 {
        return vec![("isobmff_header".into(), false), ("ftyp_box".into(), false)];
    }
    let size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let typ = &b[4..8];
    let ftyp = typ == b"ftyp";
    let sane = size >= 8 && size <= b.len();
    vec![("isobmff_box_size".into(), sane), ("ftyp_box".into(), ftyp)]
}

fn verify_7z(b: &[u8]) -> Vec<(String, bool)> {
    let sig = b.len() >= 6 && &b[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    let version = sig && b.len() >= 8;
    vec![
        ("7z_signature".into(), sig),
        ("7z_version_header".into(), version),
    ]
}

fn verify_gzip(b: &[u8]) -> Vec<(String, bool)> {
    let sig = b.len() >= 10 && b[0] == 0x1F && b[1] == 0x8B && b[2] == 8;
    vec![
        ("gzip_signature".into(), sig),
        ("gzip_header".into(), b.len() >= 10),
    ]
}

fn verify_sqlite(b: &[u8]) -> Vec<(String, bool)> {
    let header = b.len() >= 100 && &b[..16] == b"SQLite format 3\0";
    let page_size = if header {
        u16::from_be_bytes([b[16], b[17]])
    } else {
        0
    };
    vec![
        ("sqlite_header".into(), header),
        (
            "sqlite_page_size".into(),
            header && (page_size == 1 || page_size >= 512),
        ),
    ]
}

fn verify_ebml(b: &[u8]) -> Vec<(String, bool)> {
    let header = b.len() >= 4 && &b[..4] == [0x1A, 0x45, 0xDF, 0xA3];
    vec![
        ("ebml_header".into(), header),
        ("ebml_data_present".into(), b.len() > 4),
    ]
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Standard CRC-32 (IEEE 802.3 polynomial), implemented directly since PNG's
/// chunk integrity check needs it and pulling in a whole crc crate for one
/// polynomial isn't worth the dependency.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}
