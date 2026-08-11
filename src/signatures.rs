use serde::{Deserialize, Serialize};
use std::fs;

/// Signatures now live as versioned data, not compiled Rust — this is the
/// migration path described in §X. Header/footer bytes are hex strings in
/// the JSON file (easier to hand-author/update than raw byte arrays), parsed
/// once at load time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDef {
    pub signature_id: String,
    pub file_type: String,
    pub ext: String,
    pub header_hex: String,
    pub footer_hex: Option<String>,
    pub max_size: usize,
    pub version: u32,
    #[serde(default)]
    pub offset_rule: Option<String>,
    #[serde(default)]
    pub parser: Option<String>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub fragmentation_strategy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePackage {
    pub package_version: String,
    pub signatures: Vec<SignatureDef>,
}

pub fn default_package_json() -> &'static str {
    r#"{
  "package_version": "2.0.0",
  "signatures": [
    {"signature_id":"jpg","file_type":"image","ext":"jpg","header_hex":"FFD8FF","footer_hex":"FFD9","max_size":52428800,"version":2,"parser":"jpeg","fragmentation_strategy":"footer"},
    {"signature_id":"png","file_type":"image","ext":"png","header_hex":"89504E470D0A1A0A","footer_hex":"49454E44AE426082","max_size":52428800,"version":2,"parser":"png","fragmentation_strategy":"footer"},
    {"signature_id":"gif87a","file_type":"image","ext":"gif","header_hex":"474946383761","footer_hex":"003B","max_size":52428800,"version":2,"parser":"gif","fragmentation_strategy":"footer"},
    {"signature_id":"gif89a","file_type":"image","ext":"gif","header_hex":"474946383961","footer_hex":"003B","max_size":52428800,"version":2,"parser":"gif","fragmentation_strategy":"footer"},
    {"signature_id":"webp","file_type":"image","ext":"webp","header_hex":"52494646","footer_hex":null,"max_size":52428800,"version":2,"parser":"riff","container":"riff"},
    {"signature_id":"heic","file_type":"image","ext":"heic","header_hex":"000000186674797068656963","footer_hex":null,"max_size":104857600,"version":2,"parser":"iso-bmff"},
    {"signature_id":"tiff-le","file_type":"image","ext":"tif","header_hex":"49492A00","footer_hex":null,"max_size":104857600,"version":2,"parser":"tiff"},
    {"signature_id":"tiff-be","file_type":"image","ext":"tif","header_hex":"4D4D002A","footer_hex":null,"max_size":104857600,"version":2,"parser":"tiff"},
    {"signature_id":"pdf","file_type":"document","ext":"pdf","header_hex":"255044462D","footer_hex":"2525454F46","max_size":104857600,"version":2,"parser":"pdf","fragmentation_strategy":"footer"},
    {"signature_id":"zip","file_type":"archive","ext":"zip","header_hex":"504B0304","footer_hex":"504B0506","max_size":536870912,"version":2,"parser":"zip","container":"zip"},
    {"signature_id":"rar4","file_type":"archive","ext":"rar","header_hex":"526172211A0700","footer_hex":null,"max_size":536870912,"version":2,"parser":"rar"},
    {"signature_id":"rar5","file_type":"archive","ext":"rar","header_hex":"526172211A070100","footer_hex":null,"max_size":536870912,"version":2,"parser":"rar"},
    {"signature_id":"7z","file_type":"archive","ext":"7z","header_hex":"377ABCAF271C","footer_hex":null,"max_size":536870912,"version":2,"parser":"7z"},
    {"signature_id":"gzip","file_type":"archive","ext":"gz","header_hex":"1F8B08","footer_hex":null,"max_size":268435456,"version":2,"parser":"gzip"},
    {"signature_id":"tar","file_type":"archive","ext":"tar","header_hex":"7573746172","footer_hex":null,"max_size":536870912,"version":2,"parser":"tar"},
    {"signature_id":"mp3-id3","file_type":"audio","ext":"mp3","header_hex":"494433","footer_hex":null,"max_size":104857600,"version":2,"parser":"mp3"},
    {"signature_id":"mp3-frame","file_type":"audio","ext":"mp3","header_hex":"FFF3","footer_hex":null,"max_size":104857600,"version":2,"parser":"mp3"},
    {"signature_id":"wav","file_type":"audio","ext":"wav","header_hex":"52494646","footer_hex":null,"max_size":268435456,"version":2,"parser":"riff"},
    {"signature_id":"flac","file_type":"audio","ext":"flac","header_hex":"664C6143","footer_hex":null,"max_size":268435456,"version":2,"parser":"flac"},
    {"signature_id":"m4a","file_type":"audio","ext":"m4a","header_hex":"00000020667479704D3441","footer_hex":null,"max_size":536870912,"version":2,"parser":"iso-bmff"},
    {"signature_id":"mp4","file_type":"video","ext":"mp4","header_hex":"00000018667479706D703432","footer_hex":null,"max_size":1073741824,"version":2,"parser":"iso-bmff"},
    {"signature_id":"mov","file_type":"video","ext":"mov","header_hex":"000000146674797071742020","footer_hex":null,"max_size":1073741824,"version":2,"parser":"iso-bmff"},
    {"signature_id":"avi","file_type":"video","ext":"avi","header_hex":"52494646","footer_hex":null,"max_size":1073741824,"version":2,"parser":"riff"},
    {"signature_id":"mkv","file_type":"video","ext":"mkv","header_hex":"1A45DFA3","footer_hex":null,"max_size":1073741824,"version":2,"parser":"ebml"},
    {"signature_id":"3gp","file_type":"video","ext":"3gp","header_hex":"0000001466747970336770","footer_hex":null,"max_size":1073741824,"version":2,"parser":"iso-bmff"},
    {"signature_id":"sqlite","file_type":"database","ext":"sqlite","header_hex":"53514C69746520666F726D6174203300","footer_hex":null,"max_size":1073741824,"version":2,"parser":"sqlite"}
  ]
}"#
}

pub fn load_or_init(path: &str) -> SignaturePackage {
    if let Ok(json) = fs::read_to_string(path) {
        if let Ok(pkg) = serde_json::from_str::<SignaturePackage>(&json) {
            return pkg;
        }
    }
    // First run: write the default package to disk so it's a real editable
    // file from here on, not a string baked into the binary.
    let _ = fs::write(path, default_package_json());
    serde_json::from_str(default_package_json()).expect("default signature package must parse")
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
