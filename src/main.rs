use revenant_core::*;

fn main() {
    let data_dir = config::data_dir();
    std::fs::create_dir_all(&data_dir).expect("failed to initialize data directory");
    let auth_token = auth::generate_token();
    if let Err(e) = auth::write_token_to_file(&data_dir, &auth_token) {
        eprintln!("Warning: could not write auth token: {e}");
    }
    println!("Auth token written to {}/.token", data_dir);
    let sig_path = format!("{}/signatures.json", data_dir);
    let signatures = signatures::load_or_init(&sig_path);
    let registry = engine::DeviceRegistry::new();

    for d in platform::discover_raw_devices() {
        registry.register(engine::RegisteredDevice {
            id: d.id.clone(),
            name: d.name.clone(),
            category: "physical-disk".into(),
            backing_path: Some(d.path.clone()),
            scan_capable: d.scan_capable,
            unavailable_reason: d.reason.clone(),
        });
    }

    // Only Revenant-created managed images are auto-registered. Arbitrary paths
    // are never accepted from HTTP clients.
    let images = format!("{}/images", data_dir);
    let _ = std::fs::create_dir_all(&images);
    if let Ok(entries) = std::fs::read_dir(&images) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("img") {
                let stem = p
                    .file_stem()
                    .map(|x| x.to_string_lossy().to_string())
                    .unwrap_or_default();
                let id = format!("image-{stem}");
                registry.register(engine::RegisteredDevice {
                    id: id.clone(),
                    name: id,
                    category: "managed-image".into(),
                    backing_path: Some(p.to_string_lossy().to_string()),
                    scan_capable: true,
                    unavailable_reason: None,
                });
            }
        }
    }

    server::run(
        "127.0.0.1:7878",
        registry,
        signatures,
        images,
        format!("{}/recoveries", data_dir),
        auth_token,
    );
}
