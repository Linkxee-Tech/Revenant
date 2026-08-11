use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// Job priority per §O: a preview click during a deep scan should jump the
/// queue without corrupting the scan itself. Higher variant = higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Scanning = 0,
    Reconstruction = 1,
    Validation = 2,
    PreviewRequest = 3,
}

pub struct Job {
    pub priority: Priority,
    pub seq: u64, // tiebreaker so equal-priority jobs stay FIFO
    pub work: Box<dyn FnOnce() + Send>,
}

impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.seq == other.seq
    }
}
impl Eq for Job {}
impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap; higher priority first, then lower seq
        // (earlier-submitted) first among equal priorities.
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A real bounded-concurrency worker pool: N OS threads pull from a shared
/// priority queue. This is deliberately small and dependency-free (no tokio)
/// since the actual requirement is priority + bounded concurrency + real
/// parallel execution, all three of which this provides and none of which a
/// synchronous mock would prove.
pub struct WorkerPool {
    queue: Arc<Mutex<BinaryHeap<Job>>>,
    seq_counter: Arc<Mutex<u64>>,
    notify_tx: Sender<()>,
}

impl WorkerPool {
    pub fn new(worker_count: usize) -> Self {
        let queue: Arc<Mutex<BinaryHeap<Job>>> = Arc::new(Mutex::new(BinaryHeap::new()));
        let (notify_tx, notify_rx) = channel::<()>();
        let notify_rx = Arc::new(Mutex::new(notify_rx));

        for id in 0..worker_count {
            let queue = Arc::clone(&queue);
            let notify_rx = Arc::clone(&notify_rx);
            thread::spawn(move || loop {
                let job = {
                    let mut q = queue.lock().unwrap();
                    q.pop()
                };
                match job {
                    Some(j) => {
                        (j.work)();
                    }
                    None => {
                        // Nothing queued — block until notified of new work.
                        let rx = notify_rx.lock().unwrap();
                        let _ = rx.recv();
                    }
                }
                let _ = id; // worker id retained for future health-monitoring/logging
            });
        }

        Self {
            queue,
            seq_counter: Arc::new(Mutex::new(0)),
            notify_tx,
        }
    }

    pub fn submit<F: FnOnce() + Send + 'static>(&self, priority: Priority, work: F) {
        let seq = {
            let mut c = self.seq_counter.lock().unwrap();
            *c += 1;
            *c
        };
        self.queue.lock().unwrap().push(Job {
            priority,
            seq,
            work: Box::new(work),
        });
        let _ = self.notify_tx.send(());
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}
