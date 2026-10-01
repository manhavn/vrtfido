//! Persistent offline mirror. Queue rows are appended before changing the shadow;
//! replay is strictly ordered and never advances past a failed row.
//!
//! Deterministic mutations (including absolute sign counts and negative IDs for new
//! offline logs/fingerprints) are safe to retry after a lost acknowledgement. Imported
//! positive IDs retain the existing import overwrite semantics. This cannot provide
//! exactly-once behavior against arbitrary concurrent primary writers or backends
//! which acknowledge a write and subsequently lose it: that needs a transactionally
//! stored idempotency key on the primary. In particular a concurrent primary change
//! to the same credential can be overwritten by an offline absolute-count update.
use sha2::{Digest, Sha256};

use super::{AuthLogRow, CredentialRow, DatabaseExport, Db, DbBackend, DbError, DebugLogRow, FingerprintRow, Result, SecuritySettingsData};
use super::sqlite::SqliteBackend;
use parking_lot::{Condvar, Mutex};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
enum Action {
    DebugLog { id: i64, level: String, component: String, message: String, now: String },
    AuthLog { id: i64, credential_id: Option<String>, rp_id: String, operation: String, status: String, auth_method: String, details: Option<String>, now: String },
    Setting { key: String, value: String },
    DeleteCredential { id: String },
    RenameCredential { id: String, name: String, display_name: String },
    RenameLogCredential { old_id: String, new_id: String },
    Credential(CredentialRow),
    ClearAuthLogs,
    ClearDebugLogs,
    Security(SecuritySettingsData),
    Pin { hash: String, salt: String, now: String },
    RemovePin { now: String },
    RequireUv { require: bool, now: String },
    Fingerprint(FingerprintRow),
    DeleteFingerprint { id: i64 },
    AuthLogFull(AuthLogRow),
    DebugLogFull(DebugLogRow),
}

fn insert_credential(db: &dyn DbBackend, c: &CredentialRow) -> Result<()> {
    db.insert_credential(&c.id, &c.rp_id, &hex::decode(&c.user_id_hex).map_err(|e| DbError::Config(e.to_string()))?,
        &c.user_name, &c.user_display_name,
        &hex::decode(&c.private_key_sec1_hex).map_err(|e| DbError::Config(e.to_string()))?,
        &hex::decode(&c.public_key_cose_hex).map_err(|e| DbError::Config(e.to_string()))?,
        c.sign_count, &c.created_at, &c.last_used_at)
}

impl Action {
    fn apply(&self, db: &dyn DbBackend) -> Result<()> {
        match self {
            Self::DebugLog { id, level, component, message, now } => db.insert_debug_log_full(*id, level, component, message, now),
            Self::AuthLog { id, credential_id, rp_id, operation, status, auth_method, details, now } =>
                db.insert_auth_log_full(*id, credential_id.as_deref(), rp_id, operation, status, auth_method, details.as_deref(), now),
            Self::Setting { key, value } => db.set_app_setting(key, value),
            Self::DeleteCredential { id } => db.delete_credential(id).map(|_| ()),
            Self::RenameCredential { id, name, display_name } => db.update_credential_name(id, name, display_name).map(|_| ()),
            Self::RenameLogCredential { old_id, new_id } => db.update_auth_log_credential_id(old_id, new_id),
            Self::Credential(c) => insert_credential(db, c),
            Self::ClearAuthLogs => db.clear_auth_logs().map(|_| ()),
            Self::ClearDebugLogs => db.clear_debug_logs().map(|_| ()),
            Self::Security(s) => db.set_security_settings_all(s),
            Self::Pin { hash, salt, now } => db.set_pin(hash, salt, now),
            Self::RemovePin { now } => db.remove_pin(now),
            Self::RequireUv { require, now } => db.set_require_uv(*require, now),
            Self::Fingerprint(f) => db.insert_fingerprint_full(f.id, f.slot_index, &f.name, &f.enrolled_at),
            Self::DeleteFingerprint { id } => db.delete_fingerprint(*id).map(|_| ()),
            Self::AuthLogFull(l) => db.insert_auth_log_full(l.id, l.credential_id.as_deref(), &l.rp_id, &l.operation, &l.status, &l.auth_method, l.details.as_deref(), &l.created_at),
            Self::DebugLogFull(l) => db.insert_debug_log_full(l.id, &l.level, &l.component, &l.message, &l.created_at),
        }
    }
}

struct State {
    queue: Connection,
    primary: Option<Arc<dyn DbBackend>>,
    last_snapshot: Option<Instant>,
    wake_reason_write: bool,
}

pub struct ResilientBackend {
    spec: String,
    db_type: Option<String>,
    auth_token: Option<String>,
    client_id: String,
    shadow: SqliteBackend,
    state: Mutex<State>,
    notify: Condvar,
}

fn connection_error(e: &DbError) -> bool {
    let text = e.to_string().to_ascii_lowercase();
    ["connection", "connect", "timeout", "timed out", "network", "unavailable", "refused", "transport", "closed", "broken pipe", "eof", "server selection", "dns", "host", "i/o error", "unable to open database file"].iter().any(|part| text.contains(part))
}

#[cfg(unix)]
fn private_file(path: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new().write(true).create(true).mode(0o600).open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn private_file(path: &str) -> Result<()> {
    std::fs::OpenOptions::new().write(true).create(true).open(path)?;
    Ok(())
}

fn local_primary_path<'a>(spec: &'a str, db_type: Option<&str>) -> Option<&'a str> {
    let remote = match db_type {
        Some(kind) if matches!(kind.to_ascii_lowercase().as_str(), "postgres" | "postgresql" | "mysql" | "mariadb" | "mongodb" | "mongo") => true,
        Some(kind) if matches!(kind.to_ascii_lowercase().as_str(), "libsql" | "turso") =>
            spec.starts_with("libsql://") || spec.starts_with("https://") || spec.starts_with("http://"),
        Some("sqlite") => false,
        _ => spec.contains("://"),
    };
    if remote { return None; }
    let path = spec.strip_prefix("sqlite:").or_else(|| spec.strip_prefix("libsql:")).unwrap_or(spec);
    Some(if path.is_empty() { "authenticator.db" } else { path })
}

fn same_file(a: &str, b: &str) -> Result<bool> {
    if Path::new(a) == Path::new(b) { return Ok(true); }
    Ok(Path::new(a).exists() && Path::new(b).exists()
        && std::fs::canonicalize(a)? == std::fs::canonicalize(b)?)
}

impl ResilientBackend {
    pub fn open(spec: &str, db_type: Option<&str>, auth_token: Option<&str>, shadow_path: &str, queue_path: &str) -> Result<Self> {
        if shadow_path.is_empty() || queue_path.is_empty() ||
            shadow_path == ":memory:" || queue_path == ":memory:" ||
            same_file(shadow_path, queue_path)? {
            return Err(DbError::Config("primary, shadow and queue must be distinct persistent SQLite files".into()));
        }
        if let Some(primary) = local_primary_path(spec.trim(), db_type) {
            if same_file(primary, shadow_path)? || same_file(primary, queue_path)? {
                return Err(DbError::Config("primary, shadow and queue must be distinct persistent SQLite files".into()));
            }
        }
        private_file(shadow_path)?;
        private_file(queue_path)?;
        let shadow = SqliteBackend::open(shadow_path)?;
        let queue = Connection::open(queue_path)?;
        queue.busy_timeout(std::time::Duration::from_secs(5))?;
        // FULL ensures a returned successful offline write has a durable queue record.
        queue.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS pending (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, ready INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS resilient_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
        let identity = hex::encode(Sha256::digest(format!("{}\n{}", db_type.unwrap_or("").to_lowercase(), spec.trim()).as_bytes()));
        let existing: Option<String> = queue.query_row(
            "SELECT value FROM resilient_metadata WHERE key='primary'", [], |r| r.get(0),
        ).optional()?;
        if existing.as_deref().is_some_and(|value| value != identity) {
            return Err(DbError::Config("queue belongs to another primary database".into()));
        }
        shadow.bind_primary(&identity)?;
        queue.execute("INSERT OR IGNORE INTO resilient_metadata(key,value) VALUES('primary',?1)", [&identity])?;
        let generated = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        queue.execute("INSERT OR IGNORE INTO resilient_metadata(key,value) VALUES('client_id',?1)", [&generated])?;
        let client_id: String = queue.query_row(
            "SELECT value FROM resilient_metadata WHERE key='client_id'", [], |r| r.get(0),
        )?;
        let result = Self {
            spec: spec.into(),
            db_type: db_type.map(str::to_owned),
            auth_token: auth_token.map(str::to_owned),
            client_id,
            shadow,
            state: Mutex::new(State {
                queue,
                primary: None,
                last_snapshot: None,
                wake_reason_write: false,
            }),
            notify: Condvar::new(),
        };
        {
            let state = result.state.lock();
            // Re-materialize every still-pending operation: the queue is durable
            // even if a crash happened before the shadow WAL was made durable.
            let staged: Vec<(i64, String)> = {
                let mut stmt = state.queue.prepare("SELECT seq,payload FROM pending ORDER BY seq")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for (seq, payload) in staged {
                if payload.is_empty() {
                    state.queue.execute("DELETE FROM pending WHERE seq=?1", [seq])?;
                    continue;
                }
                let action: Action = serde_json::from_str(&payload)?;
                action.apply(&result.shadow)?;
                state.queue.execute("UPDATE pending SET ready=1 WHERE seq=?1", [seq])?;
            }
        }
        Ok(result)
    }

    /// Open/retry the primary off the request path: connecting can outlast Android's
    /// health-check timeout. Local reads and queued writes stay available meanwhile.
    pub fn start_sync_worker(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        std::thread::spawn(move || {
            let mut reconnect_backoff = Duration::from_millis(200);
            loop {
                let Some(backend) = weak.upgrade() else { break; };

                // 1. Reset backoff if a new write occurred
                {
                    let mut state = backend.state.lock();
                    if state.wake_reason_write {
                        state.wake_reason_write = false;
                        reconnect_backoff = Duration::from_millis(200);
                    }
                }

                // 2. Connect to primary if not currently connected
                if backend.state.lock().primary.is_none() {
                    let open_res = Db::open_with_options(
                        &backend.spec,
                        backend.db_type.as_deref(),
                        backend.auth_token.as_deref(),
                    );
                    match open_res {
                        Ok(db) => {
                            let mut state = backend.state.lock();
                            if state.primary.is_none() {
                                state.primary = Some(db.backend);
                                state.last_snapshot = None;
                                reconnect_backoff = Duration::from_millis(200);
                            }
                        }
                        Err(_) => {
                            let mut state = backend.state.lock();
                            if state.primary.is_none() {
                                let has_pending: bool = state.queue.query_row(
                                    "SELECT 1 FROM pending LIMIT 1", [], |_| Ok(true)
                                ).optional().unwrap_or(Some(true)).unwrap_or(false);

                                let max_backoff = if has_pending {
                                    Duration::from_secs(3)
                                } else {
                                    Duration::from_secs(30)
                                };
                                reconnect_backoff = (reconnect_backoff * 2).min(max_backoff);
                                backend.notify.wait_for(&mut state, reconnect_backoff);
                                continue;
                            }
                        }
                    }
                }

                // 3. Process pending writes and snapshot
                let mut state = backend.state.lock();
                if state.wake_reason_write {
                    state.wake_reason_write = false;
                    reconnect_backoff = Duration::from_millis(200);
                }

                let sync_res = backend.sync(&mut state);
                if let Err(error) = &sync_res {
                    eprintln!("[DB] Pending writes remain queued: {error}");
                }

                if state.primary.is_none() {
                    // Connection lost during sync; loop will retry connecting
                    drop(state);
                    drop(backend);
                    continue;
                }

                let has_pending: bool = state.queue.query_row(
                    "SELECT 1 FROM pending LIMIT 1", [], |_| Ok(true)
                ).optional().unwrap_or(Some(true)).unwrap_or(false);

                // Run snapshot if initial (None) or idle interval (300s) elapsed
                const IDLE_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(300);
                let need_snapshot = state.last_snapshot.map_or(true, |at| at.elapsed() >= IDLE_SNAPSHOT_INTERVAL);

                if sync_res.is_ok() && !has_pending && need_snapshot {
                    if let Err(error) = backend.snapshot(&mut state) {
                        eprintln!("[DB] Snapshot sync error: {error}");
                    }
                }

                if state.primary.is_none() {
                    // Connection lost during snapshot
                    drop(state);
                    drop(backend);
                    continue;
                }

                // 4. Idle wait
                if has_pending {
                    // Unresolved pending writes (e.g. non-connection SQL error); retry after brief pause
                    backend.notify.wait_for(&mut state, Duration::from_secs(1));
                } else {
                    let time_to_next_snapshot = state.last_snapshot.map_or(IDLE_SNAPSHOT_INTERVAL, |at| {
                        IDLE_SNAPSHOT_INTERVAL.saturating_sub(at.elapsed())
                    });
                    let wait_time = time_to_next_snapshot.max(Duration::from_millis(500));
                    backend.notify.wait_for(&mut state, wait_time);
                }
            }
        });
    }

    // Local-generated IDs cannot overlap ordinary positive autoincrement IDs.
    // The persisted random queue namespace also prevents separate clients using
    // the same primary from sharing the same negative IDs.
    fn action_id(&self, seq: i64) -> i64 {
        let digest = Sha256::digest(format!("{}:{seq}", self.client_id).as_bytes());
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        -((i64::from_be_bytes(bytes) & i64::MAX).max(1))
    }


    fn sync(&self, state: &mut State) -> Result<()> {
        let Some(primary) = state.primary.clone() else { return Ok(()); };
        loop {
            let entry: Option<(i64, String)> = state.queue.query_row(
                "SELECT seq,payload FROM pending WHERE ready=1 ORDER BY seq LIMIT 1", [],
                |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            let Some((seq, payload)) = entry else { break; };
            let action: Action = serde_json::from_str(&payload)?;
            match action.apply(primary.as_ref()) {
                Ok(()) => { state.queue.execute("DELETE FROM pending WHERE seq=?1", [seq])?; }
                Err(e) if connection_error(&e) => { state.primary = None; state.last_snapshot = None; return Ok(()); }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn snapshot(&self, state: &mut State) -> Result<()> {
        let Some(primary) = state.primary.clone() else { return Ok(()); };
        // Strict invariant: NEVER snapshot from primary to shadow if ANY task exists in pending queue!
        let has_pending: bool = state.queue.query_row(
            "SELECT 1 FROM pending LIMIT 1", [], |_| Ok(true)
        ).optional()?.unwrap_or(false);
        if has_pending {
            return Ok(());
        }
        let export = (|| -> Result<DatabaseExport> {
            Ok(DatabaseExport {
                version: 1, exported_at: super::current_timestamp(), database_backend: primary.backend_name().to_owned(),
                credentials: primary.get_credentials()?, auth_logs: primary.get_auth_logs(None, i64::MAX as usize)?,
                security_settings: primary.get_security_settings_raw()?, fingerprints: primary.get_fingerprints()?,
                debug_logs: primary.get_debug_logs(i64::MAX as usize)?,
                app_settings: primary.get_app_settings()?.into_iter().collect(),
            })
        })();
        match export {
            Ok(data) => {
                self.shadow.replace_snapshot(&data)?;
                state.last_snapshot = Some(Instant::now());
                Ok(())
            }
            Err(e) if connection_error(&e) => { state.primary = None; state.last_snapshot = None; Ok(()) }
            Err(e) => Err(e),
        }
    }

    fn read<T>(&self, f: impl FnOnce(&SqliteBackend) -> Result<T>) -> Result<T> {
        f(&self.shadow)
    }

    fn write<T>(&self, make: impl FnOnce(&SqliteBackend, i64) -> Result<(Action, T)>) -> Result<T> {
        let mut state = self.state.lock();
        state.queue.execute("INSERT INTO pending(payload,ready) VALUES('',0)", [])?;
        let seq = state.queue.last_insert_rowid();
        let prepared = make(&self.shadow, seq);
        let (action, value) = match prepared {
            Ok(v) => v,
            Err(e) => { state.queue.execute("DELETE FROM pending WHERE seq=?1", [seq])?; return Err(e); }
        };
        let payload = serde_json::to_string(&action)?;
        state.queue.execute("UPDATE pending SET payload=?1 WHERE seq=?2", params![payload, seq])?;
        if let Err(e) = action.apply(&self.shadow) {
            state.queue.execute("DELETE FROM pending WHERE seq=?1", [seq])?;
            return Err(e);
        }
        state.queue.execute("UPDATE pending SET ready=1 WHERE seq=?1", [seq])?;
        if state.primary.is_some() {
            let _ = self.sync(&mut state);
        }
        state.wake_reason_write = true;
        self.notify.notify_one();
        Ok(value)
    }

    pub fn sync_now(&self) -> Result<()> {
        let mut state = self.state.lock();
        if state.primary.is_none() {
            if let Ok(db) = Db::open_with_options(&self.spec, self.db_type.as_deref(), self.auth_token.as_deref()) {
                state.primary = Some(db.backend);
                state.last_snapshot = None;
            }
        }
        self.sync(&mut state)?;
        self.snapshot(&mut state)?;
        state.wake_reason_write = true;
        self.notify.notify_one();
        Ok(())
    }
}

impl DbBackend for ResilientBackend {
    fn backend_name(&self) -> &'static str { "Resilient" }
    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<()> {
        self.write(|_, seq| Ok((Action::DebugLog { id: self.action_id(seq), level: level.into(), component: component.into(), message: message.into(), now: now.into() }, ())))
    }
    fn log_auth(&self, credential_id: Option<&str>, rp_id: &str, operation: &str, status: &str, auth_method: &str, details: Option<&str>, now: &str) -> Result<()> {
        self.write(|_, seq| Ok((Action::AuthLog { id: self.action_id(seq), credential_id: credential_id.map(str::to_owned), rp_id: rp_id.into(), operation: operation.into(), status: status.into(), auth_method: auth_method.into(), details: details.map(str::to_owned), now: now.into() }, ())))
    }
    fn get_app_settings(&self) -> Result<Vec<(String, String)>> { self.read(|s| s.get_app_settings()) }
    fn set_app_setting(&self, key: &str, value: &str) -> Result<()> { self.write(|_, _| Ok((Action::Setting { key: key.into(), value: value.into() }, ()))) }
    fn get_credentials(&self) -> Result<Vec<CredentialRow>> { self.read(|s| s.get_credentials()) }
    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>> { self.read(|s| s.get_credential(id)) }
    fn get_credentials_for_rp(&self, rp: &str) -> Result<Vec<(String, Vec<u8>, String, String)>> { self.read(|s| s.get_credentials_for_rp(rp)) }
    fn delete_credential(&self, id: &str) -> Result<bool> { self.write(|s, _| Ok((Action::DeleteCredential { id: id.into() }, s.get_credential(id)?.is_some()))) }
    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool> {
        self.write(|s, _| Ok((Action::RenameCredential { id: id.into(), name: name.into(), display_name: display_name.into() }, s.get_credential(id)?.is_some())))
    }
    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<()> {
        self.write(|_, _| Ok((Action::RenameLogCredential { old_id: old_id.into(), new_id: new_id.into() }, ())))
    }
    fn insert_credential(&self, id_hex: &str, rp_id: &str, user_id: &[u8], user_name: &str, user_display_name: &str, private_key_sec1: &[u8], public_key_cose: &[u8], sign_count: u32, created_at: &str, last_used_at: &str) -> Result<()> {
        self.write(|_, _| Ok((Action::Credential(CredentialRow { id: id_hex.into(), rp_id: rp_id.into(), user_id_hex: hex::encode(user_id), user_name: user_name.into(), user_display_name: user_display_name.into(), private_key_sec1_hex: hex::encode(private_key_sec1), public_key_cose_hex: hex::encode(public_key_cose), sign_count, created_at: created_at.into(), last_used_at: last_used_at.into() }), ())))
    }
    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32> {
        self.write(|s, _| {
            let mut c = s.get_credential(id)?.ok_or_else(|| DbError::Config(format!("credential {id} not found")))?;
            c.sign_count = c.sign_count.checked_add(1).ok_or_else(|| DbError::Config("sign count overflow".into()))?;
            c.last_used_at = now.into();
            let value = c.sign_count;
            Ok((Action::Credential(c), value))
        })
    }
    fn get_auth_logs(&self, id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>> { self.read(|s| s.get_auth_logs(id, limit)) }
    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>> { self.read(|s| s.get_debug_logs(limit)) }
    fn clear_auth_logs(&self) -> Result<usize> { self.write(|s, _| Ok((Action::ClearAuthLogs, s.get_auth_logs(None, usize::MAX)?.len()))) }
    fn clear_debug_logs(&self) -> Result<usize> { self.write(|s, _| Ok((Action::ClearDebugLogs, s.get_debug_logs(usize::MAX)?.len()))) }
    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData> { self.read(|s| s.get_security_settings_raw()) }
    fn get_fingerprint_count(&self) -> Result<usize> { self.read(|s| s.get_fingerprint_count()) }
    fn set_pin(&self, hash: &str, salt: &str, now: &str) -> Result<()> { self.write(|_, _| Ok((Action::Pin { hash: hash.into(), salt: salt.into(), now: now.into() }, ()))) }
    fn remove_pin(&self, now: &str) -> Result<()> { self.write(|_, _| Ok((Action::RemovePin { now: now.into() }, ()))) }
    fn set_require_uv(&self, require: bool, now: &str) -> Result<()> { self.write(|_, _| Ok((Action::RequireUv { require, now: now.into() }, ()))) }
    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<()> { self.write(|_, _| Ok((Action::Security(settings.clone()), ()))) }
    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>> { self.read(|s| s.get_fingerprints()) }
    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>> { self.read(|s| s.get_fingerprint_by_id(id)) }
    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow> {
        self.write(|s, seq| {
            let id = s.get_fingerprints()?.into_iter()
                .find(|f| f.slot_index == slot_index).map_or_else(|| self.action_id(seq), |f| f.id);
            let fp = FingerprintRow { id, slot_index, name: name.into(), enrolled_at: now.into() };
            Ok((Action::Fingerprint(fp.clone()), fp))
        })
    }
    fn delete_fingerprint(&self, id: i64) -> Result<bool> { self.write(|s, _| Ok((Action::DeleteFingerprint { id }, s.get_fingerprint_by_id(id)?.is_some()))) }
    fn insert_fingerprint_full(&self, id: i64, slot_index: u32, name: &str, enrolled_at: &str) -> Result<()> {
        self.write(|_, _| Ok((Action::Fingerprint(FingerprintRow { id, slot_index, name: name.into(), enrolled_at: enrolled_at.into() }), ())))
    }
    fn insert_auth_log_full(&self, id: i64, credential_id: Option<&str>, rp_id: &str, operation: &str, status: &str, auth_method: &str, details: Option<&str>, created_at: &str) -> Result<()> {
        self.write(|_, _| Ok((Action::AuthLogFull(AuthLogRow { id, credential_id: credential_id.map(str::to_owned), rp_id: rp_id.into(), operation: operation.into(), status: status.into(), auth_method: auth_method.into(), details: details.map(str::to_owned), created_at: created_at.into() }), ())))
    }
    fn insert_debug_log_full(&self, id: i64, level: &str, component: &str, message: &str, created_at: &str) -> Result<()> {
        self.write(|_, _| Ok((Action::DebugLogFull(DebugLogRow { id, level: level.into(), component: component.into(), message: message.into(), created_at: created_at.into() }), ())))
    }
    fn sync_now(&self) -> Result<()> {
        self.sync_now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Workspace(PathBuf);
    impl Workspace {
        fn new() -> Self {
            let id = format!("vrtfido-resilient-{}-{}", std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
            let dir = std::env::temp_dir().join(id);
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self, name: &str) -> String { self.0.join(name).to_str().unwrap().to_owned() }
        fn resilient(&self) -> Db {
            Db::open_resilient(&self.path("primary/database.db"), Some("sqlite"), None,
                &self.path("shadow.db"), &self.path("queue.db")).unwrap()
        }
    }
    impl Drop for Workspace {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn starts_offline_replays_in_order_after_restart_and_keeps_timestamps() {
        let dir = Workspace::new();
        let db = dir.resilient();
        db.set_app_setting("theme", "one").unwrap();
        db.save_credential("key1", "example.test", b"u", "alice", "Alice", b"private", b"public", 1).unwrap();
        assert_eq!(db.increment_sign_count("key1").unwrap(), 2);
        db.set_app_setting("theme", "two").unwrap();
        db.set_pin("hash", "salt").unwrap();
        let fp = db.add_fingerprint(3, "finger").unwrap();
        assert!(db.delete_fingerprint(fp.id).unwrap());
        db.backend.log_auth(Some("key1"), "example.test", "get", "success", "pin", None, "2024-01-02 03:04:05").unwrap();
        assert_eq!(db.get_auth_logs(None, 1).unwrap()[0].created_at, "2024-01-02 03:04:05");
        drop(db);

        let restarted = dir.resilient();
        assert_eq!(restarted.get_app_setting("theme").unwrap().as_deref(), Some("two"));
        assert_eq!(restarted.get_credential("key1").unwrap().unwrap().sign_count, 2);
        assert_eq!(restarted.get_pin_hash_and_salt().unwrap().0.as_deref(), Some("hash"));
        assert!(restarted.get_fingerprints().unwrap().is_empty());
        std::fs::create_dir(dir.0.join("primary")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(12);
        let primary = loop {
            if let Ok(primary) = Db::open(&dir.path("primary/database.db")) {
                if primary.get_app_setting("theme").unwrap().as_deref() == Some("two") {
                    break primary;
                }
            }
            assert!(Instant::now() < deadline, "offline writes were not replayed");
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(restarted.get_app_setting("theme").unwrap().as_deref(), Some("two"));
        assert_eq!(primary.get_app_setting("theme").unwrap().as_deref(), Some("two"));
        assert_eq!(primary.get_credential("key1").unwrap().unwrap().sign_count, 2);
        assert!(primary.get_fingerprints().unwrap().is_empty());
        assert_eq!(primary.get_auth_logs(None, 20).unwrap().len(), 1);
        assert_eq!(primary.get_auth_logs(None, 1).unwrap()[0].created_at, "2024-01-02 03:04:05");
        drop(restarted);
        assert_eq!(dir.resilient().get_auth_logs(None, 20).unwrap().len(), 1);
    }

    #[test]
    fn retains_snapshot_and_local_writes_until_primary_returns() {
        let dir = Workspace::new();
        std::fs::create_dir(dir.0.join("primary")).unwrap();
        let primary = Db::open(&dir.path("primary/database.db")).unwrap();
        primary.set_app_setting("theme", "remote").unwrap();
        primary.save_credential("key1", "example.test", b"u", "alice", "Alice", b"private", b"public", 3).unwrap();
        primary.set_pin("remote-hash", "remote-salt").unwrap();
        let original_fingerprint = primary.add_fingerprint(3, "first").unwrap();
        let backend = Arc::new(ResilientBackend::open(&dir.path("primary/database.db"), Some("sqlite"), None,
            &dir.path("shadow.db"), &dir.path("queue.db")).unwrap());
        backend.start_sync_worker();
        let resilient = Db { backend: backend.clone() };
        let deadline = Instant::now() + Duration::from_secs(8);
        while resilient.get_credential("key1").unwrap().is_none() {
            assert!(Instant::now() < deadline, "initial primary snapshot was not loaded");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(resilient.get_credential("key1").unwrap().unwrap().sign_count, 3);
        assert_eq!(resilient.get_pin_hash_and_salt().unwrap().0.as_deref(), Some("remote-hash"));

        // Move the whole directory (including WAL) and discard the old connection
        // to simulate loss of a remote primary while preserving its on-disk state.
        drop(primary);
        backend.state.lock().primary = None;
        std::fs::rename(dir.0.join("primary"), dir.0.join("disconnected")).unwrap();
        assert_eq!(resilient.get_app_setting("theme").unwrap().as_deref(), Some("remote"));
        resilient.set_app_setting("theme", "offline").unwrap();
        assert_eq!(resilient.increment_sign_count("key1").unwrap(), 4);
        assert_eq!(resilient.add_fingerprint(3, "updated").unwrap().id, original_fingerprint.id);
        assert_eq!(resilient.get_app_setting("theme").unwrap().as_deref(), Some("offline"));
        std::fs::rename(dir.0.join("disconnected"), dir.0.join("primary")).unwrap();
        assert_eq!(resilient.get_app_setting("theme").unwrap().as_deref(), Some("offline"));
        let primary = Db::open(&dir.path("primary/database.db")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while primary.get_credential("key1").unwrap().map_or(0, |c| c.sign_count) != 4 {
            assert!(Instant::now() < deadline, "offline writes were not replayed");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(primary.get_credential("key1").unwrap().unwrap().sign_count, 4);
        assert_eq!(primary.get_fingerprints().unwrap()[0].name, "updated");
    }

    #[test]
    fn offline_replacement_rewrites_logs_and_import_preserves_full_rows() {
        let dir = Workspace::new();
        let source = Db::open(&dir.path("source.db")).unwrap();
        source.save_credential("imported", "other.test", b"uid", "bob", "Bob", b"secret", b"public", 7).unwrap();
        source.set_pin("from-import", "salt").unwrap();
        source.backend.log_auth(Some("imported"), "other.test", "imported", "success", "pin", None,
            "2020-01-02 03:04:05").unwrap();
        let export = source.export_data().unwrap();
        let db = dir.resilient();
        db.import_data(&export).unwrap();
        db.save_credential("old", "example.test", b"one", "alice", "Alice", b"secret1", b"public1", 1).unwrap();
        db.backend.log_auth(Some("old"), "example.test", "old", "success", "pin", None,
            "2021-02-03 04:05:06").unwrap();
        assert!(db.save_credential("new", "example.test", b"one", "alice", "Alice Updated",
            b"secret2", b"public2", 1).unwrap());
        assert!(db.get_credential("old").unwrap().is_none());
        drop(db);
        std::fs::create_dir(dir.0.join("primary")).unwrap();
        let recovered = dir.resilient();
        assert_eq!(recovered.get_credentials().unwrap().len(), 2);
        assert!(recovered.get_credential("old").unwrap().is_none());
        assert_eq!(recovered.get_credential("new").unwrap().unwrap().user_display_name, "Alice Updated");
        assert_eq!(recovered.get_auth_logs(Some("new"), 20).unwrap().len(), 1);
        assert_eq!(recovered.get_auth_logs(Some("imported"), 20).unwrap()[0].created_at, "2020-01-02 03:04:05");
        assert_eq!(recovered.get_pin_hash_and_salt().unwrap().0.as_deref(), Some("from-import"));
        let primary = Db::open(&dir.path("primary/database.db")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while primary.get_auth_logs(None, 20).unwrap().len() != 2 {
            assert!(Instant::now() < deadline, "imported logs were not replayed");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn replays_pending_writes_without_another_request() {
        let dir = Workspace::new();
        let db = dir.resilient();
        db.set_app_setting("language", "vi").unwrap();
        std::fs::create_dir(dir.0.join("primary")).unwrap();
        let primary = Db::open(&dir.path("primary/database.db")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if primary.get_app_setting("language").unwrap().as_deref() == Some("vi") {
                break;
            }
            assert!(Instant::now() < deadline, "queued write was not replayed while idle");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn rejects_database_identity_change_and_shared_paths() {
        let dir = Workspace::new();
        let primary = dir.path("primary/database.db");
        let shadow = dir.path("shadow.db");
        let queue = dir.path("queue.db");
        assert!(Db::open_resilient(&primary, Some("sqlite"), None, &shadow, &shadow).is_err());
        assert!(Db::open_resilient(&primary, Some("sqlite"), None, &primary, &queue).is_err());
        assert!(Db::open_resilient(&primary, Some("sqlite"), None, &shadow, &primary).is_err());
        drop(dir.resilient());
        assert!(Db::open_resilient("another.db", Some("sqlite"), None, &shadow, &queue).is_err());
    }

    #[test]
    fn refuses_local_write_when_queue_or_shadow_is_unwritable() {
        let dir = Workspace::new();
        let resilient = ResilientBackend::open(&dir.path("primary/database.db"), Some("sqlite"), None,
            &dir.path("shadow.db"), &dir.path("queue.db")).unwrap();
        resilient.state.lock().queue.execute_batch("PRAGMA query_only=ON").unwrap();
        assert!(resilient.set_app_setting("key", "value").is_err());
        assert!(resilient.get_app_settings().unwrap().is_empty());
        resilient.state.lock().queue.execute_batch("PRAGMA query_only=OFF").unwrap();
        Connection::open(dir.path("shadow.db")).unwrap().execute_batch(
            "CREATE TRIGGER reject_setting BEFORE INSERT ON app_settings
             BEGIN SELECT RAISE(ABORT, 'shadow unavailable'); END;").unwrap();
        assert!(resilient.set_app_setting("key", "value").is_err());
        assert!(resilient.get_app_settings().unwrap().is_empty());
        let pending: i64 = resilient.state.lock().queue.query_row("SELECT count(*) FROM pending", [], |r| r.get(0)).unwrap();
        assert_eq!(pending, 0);
    }

    #[test]
    fn sync_now_forces_immediate_primary_pull() {
        let dir = Workspace::new();
        std::fs::create_dir(dir.0.join("primary")).unwrap();
        let primary = Db::open(&dir.path("primary/database.db")).unwrap();
        primary.set_app_setting("theme", "initial").unwrap();
        let resilient = dir.resilient();

        // Resilient DB initially synced "initial"
        let deadline = Instant::now() + Duration::from_secs(8);
        while resilient.get_app_setting("theme").unwrap().as_deref() != Some("initial") {
            assert!(Instant::now() < deadline, "initial primary snapshot was not loaded");
            std::thread::sleep(Duration::from_millis(50));
        }

        // External change on primary behind resilient's back
        primary.set_app_setting("theme", "externally_updated").unwrap();
        // Since periodic polling is idle (5 minutes), shadow still has "initial"
        assert_eq!(resilient.get_app_setting("theme").unwrap().as_deref(), Some("initial"));

        // On-demand sync_now must immediately pull the update
        resilient.sync_now().unwrap();
        assert_eq!(resilient.get_app_setting("theme").unwrap().as_deref(), Some("externally_updated"));
    }
}
