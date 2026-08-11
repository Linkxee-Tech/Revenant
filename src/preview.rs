use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PreviewResult {
    pub kind: String,
    pub mime: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub readable: bool,
    pub note: String,
}

pub fn inspect(name: &str, data: &[u8]) -> PreviewResult {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return PreviewResult {
            kind: "image".into(),
            mime: "image/jpeg".into(),
            width: jpeg_dim(data).map(|x| x.0),
            height: jpeg_dim(data).map(|x| x.1),
            readable: true,
            note: "JPEG structure detected".into(),
        };
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") && data.len() >= 24 {
        let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        return PreviewResult {
            kind: "image".into(),
            mime: "image/png".into(),
            width: Some(w),
            height: Some(h),
            readable: true,
            note: "PNG header/IHDR detected".into(),
        };
    }
    if data.len() >= 10 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        let w = u16::from_le_bytes([data[6], data[7]]) as u32;
        let h = u16::from_le_bytes([data[8], data[9]]) as u32;
        return PreviewResult {
            kind: "image".into(),
            mime: "image/gif".into(),
            width: Some(w),
            height: Some(h),
            readable: true,
            note: "GIF header detected".into(),
        };
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        let _size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        return PreviewResult {
            kind: "image".into(),
            mime: "image/webp".into(),
            width: None,
            height: None,
            readable: true,
            note: "WebP header detected".into(),
        };
    }
    if data.starts_with(b"%PDF-") {
        return PreviewResult {
            kind: "document".into(),
            mime: "application/pdf".into(),
            width: None,
            height: None,
            readable: true,
            note: "PDF header detected".into(),
        };
    }
    let mime = match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    };
    PreviewResult {
        kind: if mime.starts_with("image/") {
            "image"
        } else if mime.starts_with("video/") {
            "video"
        } else if mime.starts_with("audio/") {
            "audio"
        } else {
            "document"
        }
        .into(),
        mime: mime.into(),
        width: None,
        height: None,
        readable: !data.is_empty(),
        note: "Read-only structural preview; original recovered bytes remain unchanged".into(),
    }
}

fn jpeg_dim(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 4 {
        return None;
    }
    let mut i = 2usize;
    while i + 9 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        i += 2;
        if marker == 0xD8 || marker == 0xD9 || marker == 0x01 {
            continue;
        }
        if i + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        if len < 2 || i + len > data.len() {
            break;
        }
        if ((0xC0..=0xC3).contains(&marker)
            || (0xC5..=0xC7).contains(&marker)
            || (0xC9..=0xCB).contains(&marker)
            || (0xCD..=0xCF).contains(&marker))
            && i + 7 <= data.len() {
                let h = u16::from_be_bytes([data[i + 3], data[i + 4]]) as u32;
                let w = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                return Some((w, h));
            }
        i += len;
    }
    None
}
