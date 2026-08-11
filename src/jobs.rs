use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Paused,
    Cancelling,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    pub kind: String,
    pub status: JobStatus,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub progress: f32,
    pub phase: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub items_done: usize,
    pub items_total: usize,
    pub error: Option<String>,
}

#[derive(Clone, Default)]
pub struct JobManager {
    jobs: Arc<Mutex<HashMap<String, JobRecord>>>,
    pause_flags: Arc<Mutex<HashMap<String, bool>>>,
    db: Option<Arc<crate::db::Database>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_db(&mut self, db: Arc<crate::db::Database>) {
        self.db = Some(db);
    }
    fn persist_job(&self, id: &str) {
        if let Some(db) = &self.db {
            if let Some(job) = self.get(id) {
                let updated = job.completed_at.as_deref().unwrap_or(&job.created_at);
                let _ = db.upsert_scan_job(
                    &job.id,
                    None, // session_id isn't directly in JobRecord, but that's fine
                    &format!("{:?}", job.status).to_uppercase(),
                    &job.kind,
                    &job.created_at,
                    updated,
                    job.progress as f64,
                    &job,
                );
            }
        }
    }
    pub fn create(&self, id: String, kind: &str) -> JobRecord {
        let rec = JobRecord {
            id: id.clone(),
            kind: kind.to_string(),
            status: JobStatus::Queued,
            created_at: crate::server::now_iso_public(),
            started_at: None,
            completed_at: None,
            progress: 0.0,
            phase: "queued".to_string(),
            bytes_done: 0,
            bytes_total: 0,
            items_done: 0,
            items_total: 0,
            error: None,
        };
        self.jobs.lock().unwrap().insert(id.clone(), rec.clone());
        self.pause_flags.lock().unwrap().insert(id.clone(), false);
        self.persist_job(&id);
        rec
    }
    pub fn update<F: FnOnce(&mut JobRecord)>(&self, id: &str, f: F) {
        if let Some(j) = self.jobs.lock().unwrap().get_mut(id) {
            f(j);
        }
        self.persist_job(id);
    }
    pub fn get(&self, id: &str) -> Option<JobRecord> {
        self.jobs.lock().unwrap().get(id).cloned()
    }
    pub fn list(&self) -> Vec<JobRecord> {
        self.jobs.lock().unwrap().values().cloned().collect()
    }
    pub fn mark_running(&self, id: &str, phase: &str) {
        self.update(id, |j| {
            j.status = JobStatus::Running;
            j.phase = phase.to_string();
            j.started_at = Some(crate::server::now_iso_public());
        });
        self.persist_job(id);
    }
    pub fn request_cancel(&self, id: &str) {
        self.update(id, |j| j.status = JobStatus::Cancelling);
    }
    pub fn pause(&self, id: &str) {
        self.update(id, |j| {
            if j.status == JobStatus::Running {
                j.status = JobStatus::Paused;
            }
        });
        if self
            .get(id)
            .map(|j| j.status == JobStatus::Paused)
            .unwrap_or(false)
        {
            self.pause_flags
                .lock()
                .unwrap()
                .insert(id.to_string(), true);
        }
        self.persist_job(id);
    }
    pub fn resume(&self, id: &str) {
        self.update(id, |j| {
            if j.status == JobStatus::Paused {
                j.status = JobStatus::Running;
            }
        });
        self.pause_flags
            .lock()
            .unwrap()
            .insert(id.to_string(), false);
        self.persist_job(id);
    }
    pub fn is_paused(&self, id: &str) -> bool {
        self.pause_flags
            .lock()
            .unwrap()
            .get(id)
            .copied()
            .unwrap_or(false)
    }
    pub fn wait_if_paused(&self, id: &str) {
        while self.is_paused(id) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    pub fn is_cancelled(&self, id: &str) -> bool {
        matches!(
            self.get(id).map(|j| j.status),
            Some(JobStatus::Cancelling | JobStatus::Cancelled)
        )
    }
    pub fn mark_cancelled(&self, id: &str) {
        self.update(id, |j| {
            j.status = JobStatus::Cancelled;
            j.phase = "cancelled".into();
            j.completed_at = Some(crate::server::now_iso_public());
        });
        self.pause_flags
            .lock()
            .unwrap()
            .insert(id.to_string(), false);
        self.persist_job(id);
    }
    pub fn mark_completed(&self, id: &str) {
        self.update(id, |j| {
            j.status = JobStatus::Completed;
            j.phase = "completed".into();
            j.progress = 1.0;
            j.completed_at = Some(crate::server::now_iso_public());
        });
        self.pause_flags
            .lock()
            .unwrap()
            .insert(id.to_string(), false);
        self.persist_job(id);
    }
    pub fn mark_failed(&self, id: &str, err: String) {
        self.update(id, |j| {
            j.status = JobStatus::Failed;
            j.phase = "failed".into();
            j.error = Some(err);
            j.completed_at = Some(crate::server::now_iso_public());
        });
        self.pause_flags
            .lock()
            .unwrap()
            .insert(id.to_string(), false);
        self.persist_job(id);
    }
}
