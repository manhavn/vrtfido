//! Log retention: every surface that runs the daemon (desktop CLI, Android app) drops log
//! entries that are older than [`RETENTION_DAYS`], 30 seconds after the service goes up and once
//! per day after that.
//!
//! The schedule is deliberately coarse. A worker thread sleeps on a channel instead of polling, so
//! an idle daemon costs a single `COUNT` per sweep on the local sidecar and never a timer tick or
//! a network round trip: nothing here can keep a phone's CPU awake between sweeps. Rows only leave
//! the database when the cutoff actually matches something, which for a quiet install is rarely.

use crate::db::{timestamp_at, Db};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long an entry stays in `auth_logs` / `debug_logs`.
pub const RETENTION_DAYS: i64 = 7;

/// Delay before the first sweep, counted from the moment the service starts: `vrtfido` on the
/// command line, or the app's service switch going ON. Late enough to stay out of the way of
/// start-up work (sidecars, shadow, binding the port).
pub const FIRST_SWEEP: Duration = Duration::from_secs(30);

/// How often the database is swept after that first pass.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Handle on the retention worker. Dropping it stops the worker, which is what turns the sweep off
/// when the daemon stops: on Android the process outlives the service, so a surviving worker would
/// keep a database handle open behind a daemon the user switched off.
pub struct LogRetention {
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl LogRetention {
    /// Starts the worker with its own clone of the database handle. It reports nothing back: a
    /// failure is written to the debug log and retried on the next sweep.
    pub fn start(db: Db) -> Self {
        let (stop, wake) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("log-retention".to_string())
            .spawn(move || run(db, &wake))
            .ok();
        Self { stop: Some(stop), worker }
    }
}

impl Drop for LogRetention {
    fn drop(&mut self) {
        // Dropping the sender wakes a sleeping worker immediately. The join below then waits only
        // for the statement already in flight, which is a local one: the daemon opens its primary
        // through the resilient backend, so a sweep counts rows in the shadow and queues a single
        // delete for the primary instead of reaching for it directly.
        drop(self.stop.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(db: Db, wake: &mpsc::Receiver<()>) {
    if stopped(wake, FIRST_SWEEP) {
        return;
    }
    loop {
        sweep(&db);
        if stopped(wake, SWEEP_INTERVAL) {
            return;
        }
    }
}

/// Sleeps for `delay`, returning `true` as soon as the owner dropped the handle.
fn stopped(wake: &mpsc::Receiver<()>, delay: Duration) -> bool {
    matches!(wake.recv_timeout(delay), Err(RecvTimeoutError::Disconnected))
}

/// Deletes the log entries that fell out of the retention window and returns how many were removed.
/// Callable on its own: the tests drive it directly instead of waiting for the schedule.
pub fn sweep(db: &Db) -> usize {
    let cutoff = timestamp_at(chrono::Duration::days(-RETENTION_DAYS));
    match db.purge_logs_before(&cutoff) {
        Ok(removed) => {
            if removed > 0 {
                // Left in the log the Web CMS shows, so vanished rows have an explanation. The
                // entry itself is new, so it lives out its own seven days.
                db.log_debug(
                    "INFO",
                    "SYSTEM",
                    &format!("Log retention removed {removed} entries older than {RETENTION_DAYS} days"),
                );
            }
            removed
        }
        Err(err) => {
            db.log_debug("WARN", "SYSTEM", &format!("Log retention failed: {err}"));
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_drops_only_logs_past_the_window() {
        let db = Db::open(":memory:").expect("in-memory database");
        let old = timestamp_at(chrono::Duration::days(-(RETENTION_DAYS + 1)));
        let fresh = timestamp_at(chrono::Duration::days(-(RETENTION_DAYS - 1)));
        db.backend.log_debug("INFO", "TEST", "old debug entry", &old).unwrap();
        db.backend.log_debug("INFO", "TEST", "recent debug entry", &fresh).unwrap();
        db.backend
            .log_auth(None, "rp.test", "MakeCredential", "SUCCESS", "PIN", None, &old)
            .unwrap();
        db.backend
            .log_auth(None, "rp.test", "GetAssertion", "SUCCESS", "PIN", None, &fresh)
            .unwrap();

        assert_eq!(sweep(&db), 2);

        // The sweep's own report entry is a fresh debug row, so the table holds it plus the entry
        // that is still inside the window.
        let debug = db.get_debug_logs(10).unwrap();
        let messages: Vec<&str> = debug.iter().map(|row| row.message.as_str()).collect();
        assert!(messages.contains(&"recent debug entry"), "{messages:?}");
        assert!(!messages.contains(&"old debug entry"), "{messages:?}");
        let auth = db.get_auth_logs(None, 10).unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].operation, "GetAssertion");
    }

    #[test]
    fn sweep_logs_what_it_removed() {
        let db = Db::open(":memory:").expect("in-memory database");
        let old = timestamp_at(chrono::Duration::days(-(RETENTION_DAYS + 1)));
        db.backend.log_debug("ERROR", "TEST", "expired entry", &old).unwrap();

        assert_eq!(sweep(&db), 1);

        let debug = db.get_debug_logs(10).unwrap();
        assert_eq!(debug.len(), 1);
        assert!(debug[0].message.contains("Log retention removed 1 entries"));
        assert_eq!(debug[0].component, "SYSTEM");
    }

    #[test]
    fn a_quiet_sweep_removes_nothing_and_writes_nothing() {
        let db = Db::open(":memory:").expect("in-memory database");
        db.log_debug("INFO", "TEST", "recent entry");

        assert_eq!(sweep(&db), 0);
        assert_eq!(db.get_debug_logs(10).unwrap().len(), 1);
    }
}
