# Revenant — Engineering Audit

This audit describes code state. It does not substitute for compiling/running the project on the target operating systems.

## IMPLEMENTED

- Production startup path with no unconditional fixture creation.
- Read-only StorageReader abstraction.
- Linux, Windows and macOS physical-device discovery adapters with read-only-open capability checks.
- NTFS MFT traversal using the $MFT DATA run list, FILE record validation and USA/fixup validation.
- FAT32 recursive deleted-entry traversal with LFN checksum validation.
- Stateful bounded-memory streaming carver with cross-chunk header/footer state.
- Format-aware size detection for PNG, RIFF, ISO-BMFF and ZIP/ZIP64 EOCD detection.
- Expanded structural verification for common image, archive, media and database formats.
- Fragment reconstruction assessment states integrated into filesystem recovery results.
- Async scan/recovery scheduling through the bounded WorkerPool.
- Quick/deep scan selection connected to the real scan path.
- SQLite schema and persistence for sessions, candidates, jobs, recoveries, checkpoints and bad-sector records.
- Binary candidate cache separated from metadata JSON so recovered payloads are not embedded in the metadata index.
- Streamed destination writes and post-write SHA-256 verification.
- Structured JSON request models and request-body size limits.
- Read-only preview inspection.
- Flutter desktop application shell connected to the local API.
- Mobile companion documentation and platform safety boundary.
- Local AI integration boundary with immutable-copy repair semantics.

## CONNECTED

- Device registry -> scan jobs -> engine -> filesystem recovery/raw carving -> unified records -> persistence.
- Recovery selection -> destination validation -> recovery worker -> manifest.
- Imaging -> managed image registration -> later scanning.
- WorkerPool -> scan/recovery job execution.
- SQLite -> durable session/candidate/recovery metadata.

## PERSISTED

- Sessions and candidate metadata in SQLite.
- Recovery manifests in SQLite and sidecar JSON.
- Candidate payloads in per-candidate binary cache files.
- Checkpoint schema in SQLite.

## TESTED

Automated tests are present in the source tree, including source immutability, streaming carving and resilient-reader tests. They were **not executed in this build environment because Rust/Cargo is unavailable here**. Do not represent this package as compilation-verified until `cargo test`, `cargo clippy` and `cargo build --release` pass on a Rust-enabled machine.

## PARTIAL

- True crash-resume orchestration still requires feeding checkpoint offsets into every filesystem/carving phase rather than restarting the engine and reusing the saved metadata.
- Full arbitrary fragmentation reconstruction for every file format is not equivalent to a forensic filesystem implementation; explicit states prevent overclaiming.
- Windows/macOS physical-device access is implemented at the adapter layer but requires OS privileges and deployment signing/configuration.
- Flutter desktop is a functional API shell, not the final polished commercial UI.
- The forensic fixture laboratory contains the required structure but needs target-platform disk images and ground-truth datasets.
- Performance benchmarks are defined but cannot be measured here.

## NOT IMPLEMENTED

- Universal raw deleted-file recovery on stock Android/iOS. The operating systems intentionally restrict this; the mobile companion therefore supports accessible-media acquisition rather than falsely claiming sector-level recovery.
- A trained local AI repair model. The AI boundary is present, but no model is shipped because deterministic recovery must remain authoritative and model quality requires a curated training/evaluation dataset.

## KNOWN LIMITATIONS

- No recovery product can guarantee every deleted file. SSD TRIM, encryption, overwriting, physical failure and filesystem corruption can make recovery impossible.
- A filesystem parser cannot reconstruct bytes that are no longer present.
- AI repair may create plausible content; it must never be presented as original recovered data.

## SECURITY RISKS

- Raw-device recovery requires careful OS privilege configuration.
- The local API is intentionally loopback-bound; production packaging should additionally restrict access through an OS-native IPC boundary or authenticated local token.
- Destination validation must remain enabled and source media must never be used as the recovery destination by default.

## PERFORMANCE RESULTS

No performance number is claimed. The repository includes performance instrumentation and the target benchmark matrix, but measured 1 GB/10 GB/100 GB/500 GB/1 TB results require execution on representative hardware.

## FAILED TESTS

None are claimed because the test suite was not executable in this environment.

## NEXT PRIORITIES

1. Run the complete Rust test/build/clippy suite.
2. Complete checkpoint-driven resume across every engine phase.
3. Build the target-platform forensic fixture corpus and run source-immutability tests.
4. Run 1 GB through 1 TB performance benchmarks.
5. Complete production-grade Flutter UX, installers and code signing.
6. Add a curated optional local AI model only after deterministic recovery metrics are stable.
