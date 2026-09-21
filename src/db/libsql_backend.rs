use super::{
    AuthLogRow, CredentialRow, DbBackend, DbError, DebugLogRow, FingerprintRow,
    SecuritySettingsData,
};
use std::sync::mpsc;
use std::sync::Arc;

struct AsyncWorker {
    sender: mpsc::Sender<Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>>,
}

impl AsyncWorker {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create dedicated tokio runtime for LibSQL");
            while let Ok(job) = rx.recv() {
                job(&rt);
            }
        });
        Self { sender: tx }
    }

    fn run<R: Send + 'static, F: FnOnce(&tokio::runtime::Runtime) -> R + Send + 'static>(&self, f: F) -> R {
        let (res_tx, res_rx) = mpsc::channel();
        let _ = self.sender.send(Box::new(move |rt| {
            let r = f(rt);
            let _ = res_tx.send(r);
        }));
        res_rx.recv().expect("Worker thread panicked or dropped channel")
    }
}

pub struct LibSqlBackend {
    worker: Arc<AsyncWorker>,
    conn: Arc<libsql::Connection>,
}

impl LibSqlBackend {
    pub fn open(url_or_path: &str, auth_token: Option<&str>) -> Result<Self, DbError> {
        let worker = Arc::new(AsyncWorker::new());
        let url_owned = url_or_path.to_string();
        let token_owned = auth_token.map(|t| t.to_string());

        let conn = worker.run(move |rt| {
            rt.block_on(async move {
                let token = token_owned.unwrap_or_default();
                let remote_url = if url_owned.starts_with("libsql://") {
                    format!("https://{}", &url_owned["libsql://".len()..])
                } else {
                    url_owned
                };
                let db = libsql::Builder::new_remote(remote_url, token)
                    .build()
                    .await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;

                let conn = db.connect().map_err(|e| DbError::LibSql(e.to_string()))?;

                // Initialize tables
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS credentials (
                         id TEXT PRIMARY KEY,
                         rp_id TEXT NOT NULL,
                         user_id BLOB NOT NULL,
                         user_name TEXT NOT NULL,
                         user_display_name TEXT NOT NULL,
                         private_key_sec1 BLOB NOT NULL,
                         public_key_cose BLOB NOT NULL,
                         sign_count INTEGER NOT NULL DEFAULT 1,
                         created_at TEXT NOT NULL,
                         last_used_at TEXT NOT NULL
                     );

                     CREATE TABLE IF NOT EXISTS auth_logs (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         credential_id TEXT,
                         rp_id TEXT NOT NULL,
                         operation TEXT NOT NULL,
                         status TEXT NOT NULL,
                         auth_method TEXT NOT NULL,
                         details TEXT,
                         created_at TEXT NOT NULL
                     );

                     CREATE TABLE IF NOT EXISTS security_settings (
                         id INTEGER PRIMARY KEY CHECK (id = 1),
                         pin_hash TEXT,
                         pin_salt TEXT,
                         pin_enabled INTEGER NOT NULL DEFAULT 0,
                         fp_enabled INTEGER NOT NULL DEFAULT 1,
                         require_uv INTEGER NOT NULL DEFAULT 1,
                         updated_at TEXT NOT NULL
                     );

                     CREATE TABLE IF NOT EXISTS fingerprints (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         slot_index INTEGER NOT NULL UNIQUE,
                         name TEXT NOT NULL,
                         enrolled_at TEXT NOT NULL
                     );

                     CREATE TABLE IF NOT EXISTS debug_logs (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         level TEXT NOT NULL,
                         component TEXT NOT NULL,
                         message TEXT NOT NULL,
                         created_at TEXT NOT NULL
                     );

                     INSERT OR IGNORE INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
                     VALUES (1, NULL, NULL, 0, 1, 1, datetime('now'));

                     CREATE INDEX IF NOT EXISTS idx_credentials_rp_user ON credentials(rp_id, user_name);"
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                Ok::<_, DbError>(conn)
            })
        })?;

        Ok(Self {
            worker,
            conn: Arc::new(conn),
        })
    }
}

impl DbBackend for LibSqlBackend {
    fn backend_name(&self) -> &'static str {
        "LibSQL"
    }

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let level = level.to_string();
        let component = component.to_string();
        let message = message.to_string();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let _ = conn.execute(
                    "INSERT INTO debug_logs (level, component, message, created_at) VALUES (?1, ?2, ?3, ?4)",
                    libsql::params![level, component, message, now],
                ).await;
                Ok(())
            })
        })
    }

    fn log_auth(
        &self,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
        now: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let cid = credential_id.map(|s| s.to_string());
        let rp_id = rp_id.to_string();
        let operation = operation.to_string();
        let status = status.to_string();
        let auth_method = auth_method.to_string();
        let details = details.map(|s| s.to_string());
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let _ = conn.execute(
                    "INSERT INTO auth_logs (credential_id, rp_id, operation, status, auth_method, details, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    libsql::params![cid, rp_id, operation, status, auth_method, details, now],
                ).await;
                Ok(())
            })
        })
    }

    fn get_credentials(&self) -> Result<Vec<CredentialRow>, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                            hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
                     FROM credentials ORDER BY datetime(last_used_at) DESC",
                    (),
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let mut list = Vec::new();
                while let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    list.push(CredentialRow {
                        id: row.get(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        rp_id: row.get(1).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_id_hex: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_name: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_display_name: row.get(4).map_err(|e| DbError::LibSql(e.to_string()))?,
                        private_key_sec1_hex: row.get(5).map_err(|e| DbError::LibSql(e.to_string()))?,
                        public_key_cose_hex: row.get(6).map_err(|e| DbError::LibSql(e.to_string()))?,
                        sign_count: row.get::<i64>(7).map_err(|e| DbError::LibSql(e.to_string()))? as u32,
                        created_at: row.get(8).map_err(|e| DbError::LibSql(e.to_string()))?,
                        last_used_at: row.get(9).map_err(|e| DbError::LibSql(e.to_string()))?,
                    });
                }
                Ok(list)
            })
        })
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, DbError> {
        let conn = self.conn.clone();
        let id_owned = id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                            hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
                     FROM credentials WHERE id = ?1",
                    libsql::params![id_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    Ok(Some(CredentialRow {
                        id: row.get(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        rp_id: row.get(1).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_id_hex: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_name: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                        user_display_name: row.get(4).map_err(|e| DbError::LibSql(e.to_string()))?,
                        private_key_sec1_hex: row.get(5).map_err(|e| DbError::LibSql(e.to_string()))?,
                        public_key_cose_hex: row.get(6).map_err(|e| DbError::LibSql(e.to_string()))?,
                        sign_count: row.get::<i64>(7).map_err(|e| DbError::LibSql(e.to_string()))? as u32,
                        created_at: row.get(8).map_err(|e| DbError::LibSql(e.to_string()))?,
                        last_used_at: row.get(9).map_err(|e| DbError::LibSql(e.to_string()))?,
                    }))
                } else {
                    Ok(None)
                }
            })
        })
    }

    fn get_credentials_for_rp(&self, rp_id: &str) -> Result<Vec<(String, Vec<u8>, String, String)>, DbError> {
        let conn = self.conn.clone();
        let rp_id_owned = rp_id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, user_id, user_name, created_at FROM credentials WHERE rp_id = ?1 COLLATE NOCASE",
                    libsql::params![rp_id_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let mut list = Vec::new();
                while let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    let id: String = row.get(0).map_err(|e| DbError::LibSql(e.to_string()))?;
                    let user_id: Vec<u8> = row.get(1).map_err(|e| DbError::LibSql(e.to_string()))?;
                    let user_name: String = row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?;
                    let created_at: String = row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?;
                    list.push((id, user_id, user_name, created_at));
                }
                Ok(list)
            })
        })
    }

    fn delete_credential(&self, id: &str) -> Result<bool, DbError> {
        let conn = self.conn.clone();
        let id_owned = id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let count = conn.execute("DELETE FROM credentials WHERE id = ?1", libsql::params![id_owned])
                    .await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(count > 0)
            })
        })
    }

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool, DbError> {
        let conn = self.conn.clone();
        let id_owned = id.to_string();
        let name_owned = name.to_string();
        let display_name_owned = display_name.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let count = conn.execute(
                    "UPDATE credentials SET user_name = ?1, user_display_name = ?2 WHERE id = ?3",
                    libsql::params![name_owned, display_name_owned, id_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(count > 0)
            })
        })
    }

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let old_id_owned = old_id.to_string();
        let new_id_owned = new_id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let _ = conn.execute(
                    "UPDATE auth_logs SET credential_id = ?1 WHERE credential_id = ?2",
                    libsql::params![new_id_owned, old_id_owned],
                ).await;
                Ok(())
            })
        })
    }

    fn insert_credential(
        &self,
        id_hex: &str,
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        private_key_sec1: &[u8],
        public_key_cose: &[u8],
        sign_count: u32,
        created_at: &str,
        last_used_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let id_hex = id_hex.to_string();
        let rp_id = rp_id.to_string();
        let user_id = user_id.to_vec();
        let user_name = user_name.to_string();
        let user_display_name = user_display_name.to_string();
        let private_key_sec1 = private_key_sec1.to_vec();
        let public_key_cose = public_key_cose.to_vec();
        let created_at = created_at.to_string();
        let last_used_at = last_used_at.to_string();

        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                              private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    libsql::params![
                        id_hex,
                        rp_id,
                        user_id,
                        user_name,
                        user_display_name,
                        private_key_sec1,
                        public_key_cose,
                        sign_count as i64,
                        created_at,
                        last_used_at,
                    ],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32, DbError> {
        let conn = self.conn.clone();
        let id_owned = id.to_string();
        let now_owned = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "UPDATE credentials SET sign_count = sign_count + 1, last_used_at = ?2 WHERE id = ?1",
                    libsql::params![id_owned.clone(), now_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let mut rows = conn.query(
                    "SELECT sign_count FROM credentials WHERE id = ?1",
                    libsql::params![id_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    let count: i64 = row.get(0).map_err(|e| DbError::LibSql(e.to_string()))?;
                    Ok(count as u32)
                } else {
                    Err(DbError::LibSql("Credential not found".into()))
                }
            })
        })
    }

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>, DbError> {
        let conn = self.conn.clone();
        let cid = credential_id.map(|s| s.to_string());
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = if let Some(c) = cid {
                    conn.query(
                        "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                         FROM auth_logs WHERE credential_id = ?1 ORDER BY id DESC LIMIT ?2",
                        libsql::params![c, limit as i64],
                    ).await.map_err(|e| DbError::LibSql(e.to_string()))?
                } else {
                    conn.query(
                        "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                         FROM auth_logs ORDER BY id DESC LIMIT ?1",
                        libsql::params![limit as i64],
                    ).await.map_err(|e| DbError::LibSql(e.to_string()))?
                };

                let mut list = Vec::new();
                while let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    list.push(AuthLogRow {
                        id: row.get::<i64>(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        credential_id: row.get(1).ok(),
                        rp_id: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        operation: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                        status: row.get(4).map_err(|e| DbError::LibSql(e.to_string()))?,
                        auth_method: row.get(5).map_err(|e| DbError::LibSql(e.to_string()))?,
                        details: row.get(6).ok(),
                        created_at: row.get(7).map_err(|e| DbError::LibSql(e.to_string()))?,
                    });
                }
                Ok(list)
            })
        })
    }

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, level, component, message, created_at
                     FROM debug_logs ORDER BY id DESC LIMIT ?1",
                    libsql::params![limit as i64],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let mut list = Vec::new();
                while let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    list.push(DebugLogRow {
                        id: row.get::<i64>(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        level: row.get(1).map_err(|e| DbError::LibSql(e.to_string()))?,
                        component: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        message: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                        created_at: row.get(4).map_err(|e| DbError::LibSql(e.to_string()))?,
                    });
                }
                Ok(list)
            })
        })
    }

    fn clear_auth_logs(&self) -> Result<usize, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let count = conn
                    .execute("DELETE FROM auth_logs", ())
                    .await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(count as usize)
            })
        })
    }

    fn clear_debug_logs(&self) -> Result<usize, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let count = conn
                    .execute("DELETE FROM debug_logs", ())
                    .await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(count as usize)
            })
        })
    }

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at FROM security_settings WHERE id = 1",
                    (),
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    let pin_hash: Option<String> = row.get(0).ok();
                    let pin_salt: Option<String> = row.get(1).ok();
                    let pin_enabled: i64 = row.get::<i64>(2).unwrap_or(0);
                    let fp_enabled: i64 = row.get::<i64>(3).unwrap_or(1);
                    let require_uv: i64 = row.get::<i64>(4).unwrap_or(1);
                    let updated_at: String = row.get(5).map_err(|e| DbError::LibSql(e.to_string()))?;

                    Ok(SecuritySettingsData {
                        pin_hash,
                        pin_salt,
                        pin_enabled: pin_enabled != 0,
                        fp_enabled: fp_enabled != 0,
                        require_uv: require_uv != 0,
                        updated_at,
                    })
                } else {
                    Err(DbError::LibSql("Security settings row not found".into()))
                }
            })
        })
    }

    fn get_fingerprint_count(&self) -> Result<usize, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query("SELECT count(*) FROM fingerprints", ()).await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;
                if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    let c: i64 = row.get(0).map_err(|e| DbError::LibSql(e.to_string()))?;
                    Ok(c as usize)
                } else {
                    Ok(0)
                }
            })
        })
    }

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let pin_hash = pin_hash.to_string();
        let pin_salt = pin_salt.to_string();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "UPDATE security_settings
                     SET pin_hash = ?1, pin_salt = ?2, pin_enabled = 1, updated_at = ?3
                     WHERE id = 1",
                    libsql::params![pin_hash, pin_salt, now],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn remove_pin(&self, now: &str) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "UPDATE security_settings
                     SET pin_hash = NULL, pin_salt = NULL, pin_enabled = 0, updated_at = ?1
                     WHERE id = 1",
                    libsql::params![now],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn set_require_uv(&self, require: bool, now: &str) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let require_val: i64 = if require { 1 } else { 0 };
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "UPDATE security_settings SET require_uv = ?1, updated_at = ?2 WHERE id = 1",
                    libsql::params![require_val, now],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let pin_hash = settings.pin_hash.clone();
        let pin_salt = settings.pin_salt.clone();
        let pin_enabled: i64 = if settings.pin_enabled { 1 } else { 0 };
        let fp_enabled: i64 = if settings.fp_enabled { 1 } else { 0 };
        let require_uv: i64 = if settings.require_uv { 1 } else { 0 };
        let updated_at = settings.updated_at.clone();

        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(id) DO UPDATE SET
                         pin_hash = excluded.pin_hash,
                         pin_salt = excluded.pin_salt,
                         pin_enabled = excluded.pin_enabled,
                         fp_enabled = excluded.fp_enabled,
                         require_uv = excluded.require_uv,
                         updated_at = excluded.updated_at",
                    libsql::params![
                        pin_hash,
                        pin_salt,
                        pin_enabled,
                        fp_enabled,
                        require_uv,
                        updated_at,
                    ],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, slot_index, name, enrolled_at FROM fingerprints ORDER BY slot_index ASC",
                    (),
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let mut list = Vec::new();
                while let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    list.push(FingerprintRow {
                        id: row.get::<i64>(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        slot_index: row.get::<i64>(1).map_err(|e| DbError::LibSql(e.to_string()))? as u32,
                        name: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        enrolled_at: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                    });
                }
                Ok(list)
            })
        })
    }

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let mut rows = conn.query(
                    "SELECT id, slot_index, name, enrolled_at FROM fingerprints WHERE id = ?1",
                    libsql::params![id],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    Ok(Some(FingerprintRow {
                        id: row.get::<i64>(0).map_err(|e| DbError::LibSql(e.to_string()))?,
                        slot_index: row.get::<i64>(1).map_err(|e| DbError::LibSql(e.to_string()))? as u32,
                        name: row.get(2).map_err(|e| DbError::LibSql(e.to_string()))?,
                        enrolled_at: row.get(3).map_err(|e| DbError::LibSql(e.to_string()))?,
                    }))
                } else {
                    Ok(None)
                }
            })
        })
    }

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow, DbError> {
        let conn = self.conn.clone();
        let slot = slot_index as i64;
        let name_owned = name.to_string();
        let now_owned = now.to_string();

        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT INTO fingerprints (slot_index, name, enrolled_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(slot_index) DO UPDATE SET name = excluded.name, enrolled_at = excluded.enrolled_at",
                    libsql::params![slot, name_owned.clone(), now_owned.clone()],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                // Get ID
                let mut rows = conn.query(
                    "SELECT id FROM fingerprints WHERE slot_index = ?1",
                    libsql::params![slot],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;

                let id = if let Some(row) = rows.next().await.map_err(|e| DbError::LibSql(e.to_string()))? {
                    row.get::<i64>(0).unwrap_or(0)
                } else {
                    0
                };

                Ok(FingerprintRow {
                    id,
                    slot_index,
                    name: name_owned,
                    enrolled_at: now_owned,
                })
            })
        })
    }

    fn delete_fingerprint(&self, id: i64) -> Result<bool, DbError> {
        let conn = self.conn.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let count = conn.execute("DELETE FROM fingerprints WHERE id = ?1", libsql::params![id])
                    .await
                    .map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(count > 0)
            })
        })
    }

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let name_owned = name.to_string();
        let enrolled_at_owned = enrolled_at.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT INTO fingerprints (id, slot_index, name, enrolled_at) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET slot_index = excluded.slot_index, name = excluded.name, enrolled_at = excluded.enrolled_at",
                    libsql::params![id, slot_index as i64, name_owned, enrolled_at_owned],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn insert_auth_log_full(
        &self,
        id: i64,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
        created_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let cid = credential_id.map(|s| s.to_string());
        let rp_id = rp_id.to_string();
        let operation = operation.to_string();
        let status = status.to_string();
        let auth_method = auth_method.to_string();
        let details = details.map(|s| s.to_string());
        let created_at = created_at.to_string();

        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT OR REPLACE INTO auth_logs (id, credential_id, rp_id, operation, status, auth_method, details, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    libsql::params![id, cid, rp_id, operation, status, auth_method, details, created_at],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }

    fn insert_debug_log_full(
        &self,
        id: i64,
        level: &str,
        component: &str,
        message: &str,
        created_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.clone();
        let level = level.to_string();
        let component = component.to_string();
        let message = message.to_string();
        let created_at = created_at.to_string();

        self.worker.run(move |rt| {
            rt.block_on(async move {
                conn.execute(
                    "INSERT OR REPLACE INTO debug_logs (id, level, component, message, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    libsql::params![id, level, component, message, created_at],
                ).await.map_err(|e| DbError::LibSql(e.to_string()))?;
                Ok(())
            })
        })
    }
}
