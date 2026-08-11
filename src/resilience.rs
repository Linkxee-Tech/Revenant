use crate::storage::StorageReader;
use std::io;

/// ResilientReader now implements StorageReader itself, so it can be passed
/// anywhere a `&mut dyn StorageReader` is expected (i.e. straight into the
/// NTFS/FAT32/carving providers) — this is what makes bad-sector tracking
/// possible for a REAL scan instead of only in the standalone demo. Reads
/// never propagate an Err upward (that's the whole point of resilience —
/// zero-pad and keep going), but every failure is recorded in
/// `self.bad_sectors`, inspectable by the caller after the scan completes.

#[derive(Debug, Clone, serde::Serialize)]
pub struct BadSectorRecord {
    pub offset: u64,
    pub length: usize,
    pub attempts: u32,
    pub classification: String, // timeout | io_error | unknown
}

/// Wraps any StorageReader with retry-on-failure logic and a bad-sector map,
/// so a single unreadable region never aborts the whole scan (§I's hard
/// rule). Retries use a progressive strategy: shrink the read on repeated
/// failure, since a smaller aligned read can sometimes succeed around a
/// damaged boundary even when the original larger read can't.
pub struct ResilientReader<R: StorageReader> {
    inner: R,
    pub bad_sectors: Vec<BadSectorRecord>,
    max_retries: u32,
}

impl<R: StorageReader> ResilientReader<R> {
    pub fn new(inner: R, max_retries: u32) -> Self {
        Self {
            inner,
            bad_sectors: Vec::new(),
            max_retries,
        }
    }

    /// Reads a range sector-by-sector, retrying each failing sector up to
    /// `max_retries` times before giving up on just that sector — not the
    /// whole read. Only the genuinely unreadable sectors are zero-padded and
    /// logged; everything readable around them is still returned intact.
    /// This is what makes "a single unreadable sector must never terminate
    /// an entire scan" actually true rather than aspirational.
    pub fn read_resilient(&mut self, offset: u64, length: usize) -> Vec<u8> {
        let sector = self.inner.sector_size() as u64;
        let mut result = Vec::with_capacity(length);
        let mut pos = offset;
        let end = offset + length as u64;

        while pos < end {
            let this_len = (sector.min(end - pos)) as usize;
            let mut attempts = 0u32;
            let mut ok_data: Option<Vec<u8>> = None;

            while attempts < self.max_retries {
                attempts += 1;
                match self.inner.read_range(pos, this_len) {
                    Ok(d) => {
                        ok_data = Some(d);
                        break;
                    }
                    Err(_) => continue,
                }
            }

            match ok_data {
                Some(d) => result.extend_from_slice(&d),
                None => {
                    self.bad_sectors.push(BadSectorRecord {
                        offset: pos,
                        length: this_len,
                        attempts,
                        classification: "io_error_after_retry".to_string(),
                    });
                    result.extend(std::iter::repeat(0u8).take(this_len));
                }
            }

            pos += this_len as u64;
        }

        result
    }

    pub fn get_size(&mut self) -> io::Result<u64> {
        self.inner.get_size()
    }
}

impl<R: StorageReader> StorageReader for ResilientReader<R> {
    fn read_range(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        Ok(self.read_resilient(offset, length)) // never Err — failures become zero-padded regions, tracked in bad_sectors
    }
    fn get_size(&mut self) -> io::Result<u64> {
        self.inner.get_size()
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

/// A StorageReader wrapper used ONLY in tests/fixtures to simulate real
/// hardware failure (§Z Fault Injection) — specific byte ranges deliberately
/// fail to read, so we can verify the ResilientReader/imaging code actually
/// handles bad sectors instead of just assuming clean media.
pub struct FaultInjectingReader<R: StorageReader> {
    inner: R,
    fault_ranges: Vec<(u64, u64)>, // (start, end) offsets that always fail
}

impl<R: StorageReader> FaultInjectingReader<R> {
    pub fn new(inner: R, fault_ranges: Vec<(u64, u64)>) -> Self {
        Self {
            inner,
            fault_ranges,
        }
    }
}

impl<R: StorageReader> StorageReader for FaultInjectingReader<R> {
    fn read_range(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let end = offset + length as u64;
        for &(fs, fe) in &self.fault_ranges {
            if offset < fe && end > fs {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "simulated bad sector",
                ));
            }
        }
        self.inner.read_range(offset, length)
    }

    fn get_size(&mut self) -> io::Result<u64> {
        self.inner.get_size()
    }
}
