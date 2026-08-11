use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct FixturePaths {
    pub fixtures_dir: PathBuf,
    pub test_volume: PathBuf,
    pub fat32_test: PathBuf,
    pub signatures_json: PathBuf,
}

pub fn ensure_test_fixtures() -> io::Result<FixturePaths> {
    let data_dir = crate::config::data_dir();
    let fixtures_dir = PathBuf::from(data_dir).join("fixtures");
    fs::create_dir_all(&fixtures_dir)?;

    let signatures_json = fixtures_dir.join("signatures.json");
    if !signatures_json.exists() {
        let _ = crate::signatures::load_or_init(
            signatures_json
                .to_str()
                .expect("fixture path must be valid unicode"),
        );
    }

    let test_volume = fixtures_dir.join("test_volume.img");
    if !test_volume.exists() {
        create_test_volume(&test_volume)?;
    }

    let fat32_test = fixtures_dir.join("fat32_test.img");
    if !fat32_test.exists() {
        create_fat32_test_image(&fat32_test)?;
    }

    Ok(FixturePaths {
        fixtures_dir,
        test_volume,
        fat32_test,
        signatures_json,
    })
}

fn create_test_volume(path: &Path) -> io::Result<()> {
    const CHUNK: usize = 2048;
    let mut contents = Vec::new();

    contents.extend_from_slice(&[0u8; 128]);
    contents.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
    contents.extend_from_slice(&[0u8; 80]);
    contents.extend_from_slice(&[0xFF, 0xD9]);
    contents.extend_from_slice(&[0u8; CHUNK - 128 - 3 - 80 - 2]);

    contents.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    contents.extend_from_slice(&[0u8; 1400]);
    contents.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);

    contents.extend_from_slice(&[0u8; CHUNK]);
    contents.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
    contents.extend_from_slice(&[0u8; 1000]);
    contents.extend_from_slice(&[0xFF, 0xD9]);
    contents.extend_from_slice(&[0u8; CHUNK * 2]);

    fs::write(path, contents)
}

fn create_fat32_test_image(path: &Path) -> io::Result<()> {
    let mut image = vec![0u8; 16 * 1024];
    image[0] = 0xEB;
    image[1] = 0x58;
    image[2] = 0x90;
    image[3..11].copy_from_slice(b"MSWIN4.1");
    image[11..13].copy_from_slice(&512u16.to_le_bytes());
    image[13] = 1;
    image[14..16].copy_from_slice(&32u16.to_le_bytes());
    image[16] = 2;
    image[17..19].copy_from_slice(&0u16.to_le_bytes());
    image[19] = 0xF8;
    image[22..24].copy_from_slice(&63u16.to_le_bytes());
    image[24..26].copy_from_slice(&255u16.to_le_bytes());
    image[28..32].copy_from_slice(&65536u32.to_le_bytes());
    image[36..40].copy_from_slice(&1u32.to_le_bytes());
    image[44..48].copy_from_slice(&2u32.to_le_bytes());
    image[82..90].copy_from_slice(b"FAT32   ");
    image[510] = 0x55;
    image[511] = 0xAA;

    fs::write(path, image)
}
