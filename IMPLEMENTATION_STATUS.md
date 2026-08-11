# Revenant Core — Integration Status

This package is the result of the requested core-engine gap-closure pass over the supplied `revenant-core.tar.gz`.

## Implemented in this pass

- Production startup no longer creates development fixtures unless `REVENANT_DEMO=1` is explicitly set.
- Added platform raw-device discovery adapter (`platform.rs`) for Linux, with Windows/macOS extension points.
- Added asynchronous scan jobs with job IDs, status, progress, pause/resume/cancel controls.
- Added Quick vs Deep scan mode routing.
- Removed the production NTFS provider's fixed 256-record scan and added `$MFT` run-list based traversal with USA/fixup validation.
- Added recursive FAT32 directory traversal for deleted-file discovery.
- Added FAT32 LFN checksum-aware reconstruction logic.
- Added durable candidate-result JSON persistence and restart fallback for scan results.
- Added asynchronous recovery jobs with progress/cancel controls and persisted manifests.
- Added read-only candidate preview inspection with basic JPEG/PNG structural metadata.
- Replaced hand-rolled JSON field parsing with `serde_json` parsing.
- Added same-filesystem destination protection in addition to path-based protection.
- Expanded the external signature package to 26 common file signatures and added parser/container metadata fields.
- Removed entropy as direct overwrite evidence from the recovery score.
- Added a unified `RecoveryConfidence` model.
- Added a `FragmentAssessment` model for explicit reconstruction states.
- Added persisted re-registration of Revenant-managed disk images after restart.

## Deliberately not claimed as complete

The environment used to prepare this package does not contain the Rust toolchain (`cargo` is unavailable), so the package could not be compiled or run here. No false claim of a passing build is made.

The following remain engineering work rather than being silently presented as complete:

- SQLite-backed persistence (the current durable index is JSON; this should be migrated to SQLite in the next build environment).
- Full stateful multi-chunk fragment reconstruction for arbitrarily large fragmented files.
- Format-native parsing for every expanded signature (the signature database is expanded, while generic carving still uses the existing header/footer engine).
- Full ZIP64/central-directory recovery and deep Office-container reconstruction.
- Native Windows physical-disk access and macOS Disk Arbitration/IOKit adapters; Linux raw-device discovery is present.
- Android/iOS forensic recovery. Normal mobile app sandbox APIs cannot provide arbitrary deleted-file recovery; these require platform-specific forensic acquisition paths and, on iOS, appropriate device-level acquisition capabilities.
- AI repair/ranking. Per the requested architecture, AI remains intentionally disabled until deterministic recovery is stable.
- A production Flutter desktop application is outside this core-engine package.

## Verification limitation

Before commercial or forensic use, run at minimum:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Then execute the disk-image integration suite against known-ground-truth fixtures and verify source SHA-256 before/after every recovery operation.
