# Windows adapter

The Rust platform adapter discovers `\\.\PhysicalDriveN` using WMI/PowerShell and marks a disk scan-capable only after a real read-only handle can be opened. Production deployments should run the signed desktop process with the minimum privileges required by Windows raw-volume access.
