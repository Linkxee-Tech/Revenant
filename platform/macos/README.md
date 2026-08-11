# macOS adapter

The Rust platform adapter discovers physical disks with `diskutil` and uses `/dev/rdiskN` for raw reads. macOS permissions, Full Disk Access, SIP, APFS encryption and mounted-volume state remain OS policy constraints rather than assumptions in the engine.
