use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone)]
pub struct Database {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCandidate {
    pub id: String,
    pub session_id: String,
    pub name: String,
    pub file_type: String,
    pub size_bytes: u64,
    pub source: String,
    pub source_offset: Option<u64>,
    pub sha256: Option<String>,
    pub confidence: u8,
    pub verification_state: String,
    pub duplicate_of: Option<String>,
    pub reconstruction_state: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: String,
    pub session_id: Option<String>,
    pub status: String,
    pub mode: String,
    pub created_at: String,
    pub updated_at: String,
    pub progress: f64,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryItem {
    pub id: i64,
    pub recovery_id: String,
    pub candidate_id: String,
    pub status: String,
    pub bytes_written: u64,
    pub sha256: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadSectorRecord {
    pub id: i64,
    pub device_id: Option<String>,
    pub offset: u64,
    pub length: u64,
    pub attempts: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecord {
    pub id: String,
    pub session_id: Option<String>,
    pub manifest_json: String,
    pub created_at: String,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path = path.as_ref().to_string_lossy().to_string();
        if let Some(parent) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let db = Self { path };
        db.migrate()?;
        Ok(db)
    }
    fn conn(&self) -> rusqlite::Result<Connection> {
        let c = Connection::open(&self.path)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        Ok(c)
    }
    fn migrate(&self) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
        INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
        CREATE TABLE IF NOT EXISTS sessions(
          id TEXT PRIMARY KEY, source_device_id TEXT NOT NULL, filesystem TEXT NOT NULL, mode TEXT NOT NULL,
          status TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, files_discovered INTEGER NOT NULL DEFAULT 0,
          files_recovered INTEGER NOT NULL DEFAULT 0, bad_sector_count INTEGER NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_jobs(id TEXT PRIMARY KEY, session_id TEXT, status TEXT NOT NULL, mode TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, progress REAL NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
          name TEXT NOT NULL, file_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, source TEXT NOT NULL, source_offset INTEGER,
          sha256 TEXT, confidence INTEGER NOT NULL, verification_state TEXT NOT NULL, duplicate_of TEXT,
          reconstruction_state TEXT NOT NULL, metadata_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_candidates_session ON candidates(session_id);
        CREATE TABLE IF NOT EXISTS recoveries(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, destination TEXT NOT NULL,
          status TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, manifest_json TEXT);
        CREATE TABLE IF NOT EXISTS recovery_items(id INTEGER PRIMARY KEY AUTOINCREMENT, recovery_id TEXT NOT NULL,
          candidate_id TEXT NOT NULL, status TEXT NOT NULL, bytes_written INTEGER NOT NULL DEFAULT 0, sha256 TEXT,
          error TEXT, FOREIGN KEY(recovery_id) REFERENCES recoveries(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS checkpoints(session_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bad_sector_records(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, offset INTEGER NOT NULL,
          length INTEGER NOT NULL, attempts INTEGER NOT NULL, error TEXT);
        CREATE TABLE IF NOT EXISTS manifests(id TEXT PRIMARY KEY, session_id TEXT, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL);
        "#)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_session<T: Serialize>(
        &self,
        id: &str,
        source: &str,
        fs: &str,
        mode: &str,
        status: &str,
        started: &str,
        completed: Option<&str>,
        discovered: u64,
        recovered: u64,
        bad: u64,
        meta: &T,
    ) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute("INSERT INTO sessions(id,source_device_id,filesystem,mode,status,started_at,completed_at,files_discovered,files_recovered,bad_sector_count,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,completed_at=excluded.completed_at,files_discovered=excluded.files_discovered,files_recovered=excluded.files_recovered,bad_sector_count=excluded.bad_sector_count,metadata_json=excluded.metadata_json", params![id,source,fs,mode,status,started,completed,discovered,recovered,bad,serde_json::to_string(meta).unwrap_or_default()])?;
        Ok(())
    }
    pub fn replace_candidates(
        &self,
        session_id: &str,
        rows: &[StoredCandidate],
    ) -> rusqlite::Result<()> {
        let mut c = self.conn()?;
        let tx = c.transaction()?;
        tx.execute(
            "DELETE FROM candidates WHERE session_id=?",
            params![session_id],
        )?;
        for r in rows {
            tx.execute("INSERT INTO candidates(id,session_id,name,file_type,size_bytes,source,source_offset,sha256,confidence,verification_state,duplicate_of,reconstruction_state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", params![r.id,r.session_id,r.name,r.file_type,r.size_bytes,r.source,r.source_offset,r.sha256,r.confidence,r.verification_state,r.duplicate_of,r.reconstruction_state,r.metadata_json])?;
        }
        tx.commit()
    }
    pub fn candidates(&self, session_id: &str) -> rusqlite::Result<Vec<StoredCandidate>> {
        let c = self.conn()?;
        let mut st=c.prepare("SELECT id,session_id,name,file_type,size_bytes,source,source_offset,sha256,confidence,verification_state,duplicate_of,reconstruction_state,metadata_json FROM candidates WHERE session_id=? ORDER BY id")?;
        let rows = st.query_map(params![session_id], |r| {
            Ok(StoredCandidate {
                id: r.get(0)?,
                session_id: r.get(1)?,
                name: r.get(2)?,
                file_type: r.get(3)?,
                size_bytes: r.get(4)?,
                source: r.get(5)?,
                source_offset: r.get(6)?,
                sha256: r.get(7)?,
                confidence: r.get(8)?,
                verification_state: r.get(9)?,
                duplicate_of: r.get(10)?,
                reconstruction_state: r.get(11)?,
                metadata_json: r.get(12)?,
            })
        })?;
        rows.collect()
    }
    pub fn save_checkpoint<T: Serialize>(
        &self,
        session_id: &str,
        state: &T,
        now: &str,
    ) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute("INSERT INTO checkpoints(session_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(session_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at",params![session_id,serde_json::to_string(state).unwrap_or_default(),now])?;
        Ok(())
    }
    pub fn checkpoint(&self, session_id: &str) -> rusqlite::Result<Option<String>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT state_json FROM checkpoints WHERE session_id=?",
            params![session_id],
            |r| r.get(0),
        )
        .optional()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn save_recovery<T: Serialize>(
        &self,
        id: &str,
        session: &str,
        dest: &str,
        status: &str,
        created: &str,
        completed: Option<&str>,
        manifest: Option<&T>,
    ) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute("INSERT INTO recoveries(id,session_id,destination,status,created_at,completed_at,manifest_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,completed_at=excluded.completed_at,manifest_json=excluded.manifest_json",params![id,session,dest,status,created,completed,manifest.map(|m|serde_json::to_string(m).unwrap_or_default())])?;
        Ok(())
    }
    pub fn recovery_manifest(&self, id: &str) -> rusqlite::Result<Option<String>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT manifest_json FROM recoveries WHERE id=?",
            params![id],
            |r| r.get(0),
        )
        .optional()
    }
    pub fn list_sessions(&self) -> rusqlite::Result<Vec<String>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT id FROM sessions ORDER BY started_at DESC")?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_scan_job<T: Serialize>(
        &self,
        id: &str,
        session_id: Option<&str>,
        status: &str,
        mode: &str,
        created_at: &str,
        updated_at: &str,
        progress: f64,
        metadata: &T,
    ) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute("INSERT INTO scan_jobs(id,session_id,status,mode,created_at,updated_at,progress,metadata_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at,progress=excluded.progress,metadata_json=excluded.metadata_json",
        params![id, session_id, status, mode, created_at, updated_at, progress, serde_json::to_string(metadata).unwrap_or_default()])?;
        Ok(())
    }

    pub fn get_scan_job(&self, id: &str) -> rusqlite::Result<Option<ScanJob>> {
        let c = self.conn()?;
        c.query_row("SELECT id,session_id,status,mode,created_at,updated_at,progress,metadata_json FROM scan_jobs WHERE id=?", params![id], |r| {
            Ok(ScanJob {
                id: r.get(0)?,
                session_id: r.get(1)?,
                status: r.get(2)?,
                mode: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                progress: r.get(6)?,
                metadata_json: r.get(7)?,
            })
        }).optional()
    }

    pub fn list_scan_jobs(&self) -> rusqlite::Result<Vec<ScanJob>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT id,session_id,status,mode,created_at,updated_at,progress,metadata_json FROM scan_jobs ORDER BY created_at DESC")?;
        let rows = st.query_map([], |r| {
            Ok(ScanJob {
                id: r.get(0)?,
                session_id: r.get(1)?,
                status: r.get(2)?,
                mode: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                progress: r.get(6)?,
                metadata_json: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn insert_recovery_items(&self, items: &[RecoveryItem]) -> rusqlite::Result<()> {
        let mut c = self.conn()?;
        let tx = c.transaction()?;
        for r in items {
            tx.execute("INSERT INTO recovery_items(recovery_id,candidate_id,status,bytes_written,sha256,error) VALUES(?,?,?,?,?,?)", params![r.recovery_id, r.candidate_id, r.status, r.bytes_written, r.sha256, r.error])?;
        }
        tx.commit()
    }

    pub fn get_recovery_items(&self, recovery_id: &str) -> rusqlite::Result<Vec<RecoveryItem>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT id,recovery_id,candidate_id,status,bytes_written,sha256,error FROM recovery_items WHERE recovery_id=? ORDER BY id")?;
        let rows = st.query_map(params![recovery_id], |r| {
            Ok(RecoveryItem {
                id: r.get(0)?,
                recovery_id: r.get(1)?,
                candidate_id: r.get(2)?,
                status: r.get(3)?,
                bytes_written: r.get(4)?,
                sha256: r.get(5)?,
                error: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn insert_bad_sectors(&self, records: &[BadSectorRecord]) -> rusqlite::Result<()> {
        let mut c = self.conn()?;
        let tx = c.transaction()?;
        for r in records {
            tx.execute("INSERT INTO bad_sector_records(device_id,offset,length,attempts,error) VALUES(?,?,?,?,?)", params![r.device_id, r.offset, r.length, r.attempts, r.error])?;
        }
        tx.commit()
    }

    pub fn get_bad_sectors(&self, device_id: &str) -> rusqlite::Result<Vec<BadSectorRecord>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT id,device_id,offset,length,attempts,error FROM bad_sector_records WHERE device_id=? ORDER BY offset")?;
        let rows = st.query_map(params![device_id], |r| {
            Ok(BadSectorRecord {
                id: r.get(0)?,
                device_id: r.get(1)?,
                offset: r.get(2)?,
                length: r.get(3)?,
                attempts: r.get(4)?,
                error: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn save_manifest<T: Serialize>(
        &self,
        id: &str,
        session_id: Option<&str>,
        manifest: &T,
        created_at: &str,
    ) -> rusqlite::Result<()> {
        let c = self.conn()?;
        c.execute("INSERT INTO manifests(id,session_id,manifest_json,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET manifest_json=excluded.manifest_json", params![id, session_id, serde_json::to_string(manifest).unwrap_or_default(), created_at])?;
        Ok(())
    }

    pub fn get_manifest(&self, id: &str) -> rusqlite::Result<Option<ManifestRecord>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT id,session_id,manifest_json,created_at FROM manifests WHERE id=?",
            params![id],
            |r| {
                Ok(ManifestRecord {
                    id: r.get(0)?,
                    session_id: r.get(1)?,
                    manifest_json: r.get(2)?,
                    created_at: r.get(3)?,
                })
            },
        )
        .optional()
    }
}
