use crate::resilience::{BadSectorRecord, ResilientReader};
use crate::storage::StorageReader;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
pub struct ImageMetadata {
    pub source_size: u64,
    pub bytes_imaged: u64,
    pub bad_sectors: Vec<BadSectorRecord>,
    pub sha256_of_image: String,
    pub tool_version: &'static str,
}

/// Images a source (through the resilient reader, so bad sectors are
/// skipped/retried/logged rather than aborting the whole copy) to a raw
/// `.img` file plus a sidecar `.json` metadata file — the "Revenant managed
/// image format" from §H. Once an image exists, all further scanning should
/// target the image, never the original device again.
pub fn image_device<R: StorageReader>(
    reader: &mut ResilientReader<R>,
    dest_img_path: &str,
    dest_meta_path: &str,
) -> std::io::Result<ImageMetadata> {
    let size = reader.get_size()?;
    let chunk = 64 * 1024u64; // 64KB read/write chunks
    let mut out = File::create(dest_img_path)?;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();

    let mut pos = 0u64;
    while pos < size {
        let this_len = chunk.min(size - pos) as usize;
        let data = reader.read_resilient(pos, this_len); // bad sectors handled internally, zero-padded
        out.write_all(&data)?;
        sha2::Digest::update(&mut hasher, &data);
        pos += this_len as u64;
    }
    out.flush()?;

    let sha256_of_image = format!("{:x}", sha2::Digest::finalize(hasher));

    let meta = ImageMetadata {
        source_size: size,
        bytes_imaged: pos,
        bad_sectors: reader.bad_sectors.clone(),
        sha256_of_image,
        tool_version: env!("CARGO_PKG_VERSION"),
    };

    let meta_json = serde_json::to_string_pretty(&meta).unwrap();
    std::fs::write(dest_meta_path, meta_json)?;

    Ok(meta)
}
