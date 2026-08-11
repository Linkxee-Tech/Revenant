# Revenant Core

**Data never truly dies. We just help you find it again.**

Rust recovery-engine prototype focused on safe, read-only acquisition, filesystem metadata recovery, raw carving, verification, scoring, imaging, and asynchronous scan/recovery jobs.

## Safety model

- Storage reads are exposed through `StorageReader` with no write method.
- Recovery writes only to a validated destination.
- Source paths are resolved from the server-side device registry, not from arbitrary HTTP paths.
- Managed images are re-registered after restart.
- Same-filesystem destination checks are enforced.
- Recovered files are hash-verified after writing.

## API highlights

```text
GET  /devices
POST /scan
GET  /scans/{job_id}
POST /scans/{job_id}/pause
POST /scans/{job_id}/resume
POST /scans/{job_id}/cancel
GET  /scan/{session_id}/results
GET  /candidates/{candidate_id}/preview
POST /recoveries
GET  /recoveries/{recovery_id}
GET  /recoveries/{recovery_id}/progress
POST /recoveries/{recovery_id}/pause
POST /recoveries/{recovery_id}/resume
POST /recoveries/{recovery_id}/cancel
POST /image
```

## Example scan request

```json
{"device_id":"raw-sda","mode":"deep"}
```

The request returns a job ID immediately. Poll `/scans/{job_id}` until the job reaches `COMPLETED` or `FAILED`.

## Development demo fixtures

Only when explicitly requested:

```bash
REVENANT_DEMO=1 cargo run
```

Normal startup does **not** create test images or invoke `dd`, `mkfs`, `mcopy`, `mdel`, `ntfs-3g`, or mount utilities.

## Build

```bash
cargo fmt
cargo test
cargo build --release
```

See `IMPLEMENTATION_STATUS.md` for the exact verification limitations of this package.
