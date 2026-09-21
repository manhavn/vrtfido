use super::{
    AuthLogRow, CredentialRow, DbBackend, DbError, DebugLogRow, FingerprintRow,
    SecuritySettingsData,
};
use postgres::{Client, NoTls};
use std::sync::mpsc;
use std::sync::Arc;

fn pg_err(e: postgres::Error) -> DbError {
    if let Some(d) = e.as_db_error() {
        let mut msg = format!("db error: {}", d.message());
        if let Some(detail) = d.detail() {
            msg.push_str(&format!(" [detail: {}]", detail));
        }
        if let Some(hint) = d.hint() {
            msg.push_str(&format!(" [hint: {}]", hint));
        }
        if let Some(table) = d.table() {
            msg.push_str(&format!(" [table: {}]", table));
        }
        if let Some(column) = d.column() {
            msg.push_str(&format!(" [column: {}]", column));
        }
        if let Some(constraint) = d.constraint() {
            msg.push_str(&format!(" [constraint: {}]", constraint));
        }
        DbError::Postgres(msg)
    } else if let Some(source) = std::error::Error::source(&e) {
        DbError::Postgres(format!("{}: {}", e, source))
    } else {
        DbError::Postgres(e.to_string())
    }
}

struct PgWorker {
    sender: mpsc::Sender<Box<dyn FnOnce(&mut Client) + Send>>,
}

impl PgWorker {
    fn new(url: &str) -> Result<Self, DbError> {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce(&mut Client) + Send>>();
        let (init_tx, init_rx) = mpsc::channel();
        let url_owned = url.to_string();

        std::thread::spawn(move || {
            let mut client = match Client::connect(&url_owned, NoTls) {
                Ok(c) => c,
                Err(e) => {
                    let _ = init_tx.send(Err(pg_err(e)));
                    return;
                }
            };

            let init_res = client.batch_execute(
                "CREATE TABLE IF NOT EXISTS credentials (
                     id VARCHAR(255) PRIMARY KEY,
                     rp_id VARCHAR(255) NOT NULL,
                     user_id BYTEA NOT NULL,
                     user_name VARCHAR(255) NOT NULL,
                     user_display_name VARCHAR(255) NOT NULL,
                     private_key_sec1 BYTEA NOT NULL,
                     public_key_cose BYTEA NOT NULL,
                     sign_count BIGINT NOT NULL DEFAULT 1,
                     created_at VARCHAR(64) NOT NULL,
                     last_used_at VARCHAR(64) NOT NULL
                 );

                 CREATE TABLE IF NOT EXISTS auth_logs (
                     id BIGSERIAL PRIMARY KEY,
                     credential_id VARCHAR(255),
                     rp_id VARCHAR(255) NOT NULL,
                     operation VARCHAR(64) NOT NULL,
                     status VARCHAR(64) NOT NULL,
                     auth_method VARCHAR(64) NOT NULL,
                     details TEXT,
                     created_at VARCHAR(64) NOT NULL
                 );

                 CREATE TABLE IF NOT EXISTS security_settings (
                     id INT PRIMARY KEY CHECK (id = 1),
                     pin_hash TEXT,
                     pin_salt TEXT,
                     pin_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                     fp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                     require_uv BOOLEAN NOT NULL DEFAULT TRUE,
                     updated_at VARCHAR(64) NOT NULL
                 );

                 CREATE TABLE IF NOT EXISTS fingerprints (
                     id BIGSERIAL PRIMARY KEY,
                     slot_index INT NOT NULL UNIQUE,
                     name VARCHAR(255) NOT NULL,
                     enrolled_at VARCHAR(64) NOT NULL
                 );

                 CREATE TABLE IF NOT EXISTS debug_logs (
                     id BIGSERIAL PRIMARY KEY,
                     level VARCHAR(32) NOT NULL,
                     component VARCHAR(64) NOT NULL,
                     message TEXT NOT NULL,
                     created_at VARCHAR(64) NOT NULL
                 );

                 INSERT INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
                 VALUES (1, NULL, NULL, FALSE, TRUE, TRUE, to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS'))
                 ON CONFLICT (id) DO NOTHING;

                 CREATE INDEX IF NOT EXISTS idx_credentials_rp_user ON credentials(rp_id, user_name);"
            );
            if let Err(e) = init_res {
                let _ = init_tx.send(Err(pg_err(e)));
                return;
            }

            let _ = init_tx.send(Ok(()));

            while let Ok(job) = rx.recv() {
                job(&mut client);
            }
        });

        init_rx.recv().map_err(|_| DbError::Postgres("Worker thread terminated unexpectedly".into()))??;

        Ok(Self { sender: tx })
    }

    fn run<R: Send + 'static, F: FnOnce(&mut Client) -> R + Send + 'static>(&self, f: F) -> R {
        let (res_tx, res_rx) = mpsc::channel();
        let _ = self.sender.send(Box::new(move |client| {
            let r = f(client);
            let _ = res_tx.send(r);
        }));
        res_rx.recv().expect("Postgres worker thread dropped channel")
    }
}

pub struct PostgresBackend {
    worker: Arc<PgWorker>,
}

impl PostgresBackend {
    pub fn open(url: &str) -> Result<Self, DbError> {
        let worker = PgWorker::new(url)?;
        Ok(Self {
            worker: Arc::new(worker),
        })
    }
}

impl DbBackend for PostgresBackend {
    fn backend_name(&self) -> &'static str {
        "PostgreSQL"
    }

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<(), DbError> {
        let level = level.to_string();
        let component = component.to_string();
        let message = message.to_string();
        let now = now.to_string();
        self.worker.run(move |client| {
            let _ = client.execute(
                "INSERT INTO debug_logs (level, component, message, created_at) VALUES ($1, $2, $3, $4)",
                &[&level, &component, &message, &now],
            );
            Ok(())
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
        let cid = credential_id.map(|s| s.to_string());
        let rp_id = rp_id.to_string();
        let operation = operation.to_string();
        let status = status.to_string();
        let auth_method = auth_method.to_string();
        let details = details.map(|s| s.to_string());
        let now = now.to_string();
        self.worker.run(move |client| {
            let _ = client.execute(
                "INSERT INTO auth_logs (credential_id, rp_id, operation, status, auth_method, details, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[&cid, &rp_id, &operation, &status, &auth_method, &details, &now],
            );
            Ok(())
        })
    }

    fn get_credentials(&self) -> Result<Vec<CredentialRow>, DbError> {
        self.worker.run(|client| {
            let rows = client.query(
                "SELECT id, rp_id, user_id, user_name, user_display_name,
                        private_key_sec1, public_key_cose, sign_count, created_at, last_used_at
                 FROM credentials ORDER BY last_used_at DESC",
                &[],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            let mut list = Vec::new();
            for r in rows {
                let uid_bytes: Vec<u8> = r.get(2);
                let sec1_bytes: Vec<u8> = r.get(5);
                let cose_bytes: Vec<u8> = r.get(6);
                let sc: i64 = r.get(7);

                list.push(CredentialRow {
                    id: r.get(0),
                    rp_id: r.get(1),
                    user_id_hex: hex::encode(uid_bytes),
                    user_name: r.get(3),
                    user_display_name: r.get(4),
                    private_key_sec1_hex: hex::encode(sec1_bytes),
                    public_key_cose_hex: hex::encode(cose_bytes),
                    sign_count: sc as u32,
                    created_at: r.get(8),
                    last_used_at: r.get(9),
                });
            }
            Ok(list)
        })
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, DbError> {
        let id = id.to_string();
        self.worker.run(move |client| {
            let rows = client.query(
                "SELECT id, rp_id, user_id, user_name, user_display_name,
                        private_key_sec1, public_key_cose, sign_count, created_at, last_used_at
                 FROM credentials WHERE id = $1",
                &[&id],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            if let Some(r) = rows.into_iter().next() {
                let uid_bytes: Vec<u8> = r.get(2);
                let sec1_bytes: Vec<u8> = r.get(5);
                let cose_bytes: Vec<u8> = r.get(6);
                let sc: i64 = r.get(7);

                Ok(Some(CredentialRow {
                    id: r.get(0),
                    rp_id: r.get(1),
                    user_id_hex: hex::encode(uid_bytes),
                    user_name: r.get(3),
                    user_display_name: r.get(4),
                    private_key_sec1_hex: hex::encode(sec1_bytes),
                    public_key_cose_hex: hex::encode(cose_bytes),
                    sign_count: sc as u32,
                    created_at: r.get(8),
                    last_used_at: r.get(9),
                }))
            } else {
                Ok(None)
            }
        })
    }

    fn get_credentials_for_rp(&self, rp_id: &str) -> Result<Vec<(String, Vec<u8>, String, String)>, DbError> {
        let rp_id = rp_id.to_string();
        self.worker.run(move |client| {
            let rows = client.query(
                "SELECT id, user_id, user_name, created_at FROM credentials WHERE LOWER(rp_id) = LOWER($1)",
                &[&rp_id],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            let mut list = Vec::new();
            for r in rows {
                let id: String = r.get(0);
                let user_id: Vec<u8> = r.get(1);
                let user_name: String = r.get(2);
                let created_at: String = r.get(3);
                list.push((id, user_id, user_name, created_at));
            }
            Ok(list)
        })
    }

    fn delete_credential(&self, id: &str) -> Result<bool, DbError> {
        let id = id.to_string();
        self.worker.run(move |client| {
            let rows = client.execute("DELETE FROM credentials WHERE id = $1", &[&id])
                .map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(rows > 0)
        })
    }

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool, DbError> {
        let id = id.to_string();
        let name = name.to_string();
        let display_name = display_name.to_string();
        self.worker.run(move |client| {
            let rows = client.execute(
                "UPDATE credentials SET user_name = $1, user_display_name = $2 WHERE id = $3",
                &[&name, &display_name, &id],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(rows > 0)
        })
    }

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<(), DbError> {
        let old_id = old_id.to_string();
        let new_id = new_id.to_string();
        self.worker.run(move |client| {
            let _ = client.execute(
                "UPDATE auth_logs SET credential_id = $1 WHERE credential_id = $2",
                &[&new_id, &old_id],
            );
            Ok(())
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
        let id_hex = id_hex.to_string();
        let rp_id = rp_id.to_string();
        let user_id = user_id.to_vec();
        let user_name = user_name.to_string();
        let user_display_name = user_display_name.to_string();
        let private_key_sec1 = private_key_sec1.to_vec();
        let public_key_cose = public_key_cose.to_vec();
        let sc = sign_count as i64;
        let created_at = created_at.to_string();
        let last_used_at = last_used_at.to_string();

        self.worker.run(move |client| {
            client.execute(
                "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                          private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (id) DO UPDATE SET
                     rp_id = EXCLUDED.rp_id,
                     user_id = EXCLUDED.user_id,
                     user_name = EXCLUDED.user_name,
                     user_display_name = EXCLUDED.user_display_name,
                     private_key_sec1 = EXCLUDED.private_key_sec1,
                     public_key_cose = EXCLUDED.public_key_cose,
                     sign_count = EXCLUDED.sign_count,
                     created_at = EXCLUDED.created_at,
                     last_used_at = EXCLUDED.last_used_at",
                &[
                    &id_hex,
                    &rp_id,
                    &user_id,
                    &user_name,
                    &user_display_name,
                    &private_key_sec1,
                    &public_key_cose,
                    &sc,
                    &created_at,
                    &last_used_at,
                ],
            ).map_err(pg_err)?;
            Ok(())
        })
    }

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32, DbError> {
        let id = id.to_string();
        let now = now.to_string();
        self.worker.run(move |client| {
            client.execute(
                "UPDATE credentials SET sign_count = sign_count + 1, last_used_at = $2 WHERE id = $1",
                &[&id, &now],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            let rows = client.query("SELECT sign_count FROM credentials WHERE id = $1", &[&id])
                .map_err(|e| DbError::Postgres(e.to_string()))?;

            if let Some(r) = rows.into_iter().next() {
                let count: i64 = r.get(0);
                Ok(count as u32)
            } else {
                Err(DbError::Postgres("Credential not found".into()))
            }
        })
    }

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>, DbError> {
        let cid = credential_id.map(|s| s.to_string());
        self.worker.run(move |client| {
            let rows = match (cid.as_deref(), limit == usize::MAX) {
                (Some(c), false) => client.query(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs WHERE credential_id = $1 ORDER BY id DESC LIMIT $2",
                    &[&c, &(limit.min(i64::MAX as usize) as i64)],
                ),
                (Some(c), true) => client.query(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs WHERE credential_id = $1 ORDER BY id DESC",
                    &[&c],
                ),
                (None, false) => client.query(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs ORDER BY id DESC LIMIT $1",
                    &[&(limit.min(i64::MAX as usize) as i64)],
                ),
                (None, true) => client.query(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs ORDER BY id DESC",
                    &[],
                ),
            }.map_err(|e| DbError::Postgres(e.to_string()))?;

            let mut list = Vec::new();
            for r in rows {
                list.push(AuthLogRow {
                    id: r.get(0),
                    credential_id: r.get(1),
                    rp_id: r.get(2),
                    operation: r.get(3),
                    status: r.get(4),
                    auth_method: r.get(5),
                    details: r.get(6),
                    created_at: r.get(7),
                });
            }
            Ok(list)
        })
    }

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>, DbError> {
        self.worker.run(move |client| {
            let rows = if limit == usize::MAX {
                client.query(
                    "SELECT id, level, component, message, created_at FROM debug_logs ORDER BY id DESC",
                    &[],
                )
            } else {
                client.query(
                    "SELECT id, level, component, message, created_at FROM debug_logs ORDER BY id DESC LIMIT $1",
                    &[&(limit.min(i64::MAX as usize) as i64)],
                )
            }.map_err(|e| DbError::Postgres(e.to_string()))?;

            let mut list = Vec::new();
            for r in rows {
                list.push(DebugLogRow {
                    id: r.get(0),
                    level: r.get(1),
                    component: r.get(2),
                    message: r.get(3),
                    created_at: r.get(4),
                });
            }
            Ok(list)
        })
    }

    fn clear_auth_logs(&self) -> Result<usize, DbError> {
        self.worker.run(|client| {
            let rows = client
                .execute("DELETE FROM auth_logs", &[])
                .map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(rows as usize)
        })
    }

    fn clear_debug_logs(&self) -> Result<usize, DbError> {
        self.worker.run(|client| {
            let rows = client
                .execute("DELETE FROM debug_logs", &[])
                .map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(rows as usize)
        })
    }

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData, DbError> {
        self.worker.run(|client| {
            let rows = client.query(
                "SELECT pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at FROM security_settings WHERE id = 1",
                &[],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            if let Some(r) = rows.into_iter().next() {
                Ok(SecuritySettingsData {
                    pin_hash: r.get(0),
                    pin_salt: r.get(1),
                    pin_enabled: r.get(2),
                    fp_enabled: r.get(3),
                    require_uv: r.get(4),
                    updated_at: r.get(5),
                })
            } else {
                Err(DbError::Postgres("Security settings row not found".into()))
            }
        })
    }

    fn get_fingerprint_count(&self) -> Result<usize, DbError> {
        self.worker.run(|client| {
            let rows = client.query("SELECT count(*) FROM fingerprints", &[])
                .map_err(|e| DbError::Postgres(e.to_string()))?;
            if let Some(r) = rows.into_iter().next() {
                let count: i64 = r.get(0);
                Ok(count as usize)
            } else {
                Ok(0)
            }
        })
    }

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<(), DbError> {
        let pin_hash = pin_hash.to_string();
        let pin_salt = pin_salt.to_string();
        let now = now.to_string();
        self.worker.run(move |client| {
            client.execute(
                "UPDATE security_settings
                 SET pin_hash = $1, pin_salt = $2, pin_enabled = TRUE, updated_at = $3
                 WHERE id = 1",
                &[&pin_hash, &pin_salt, &now],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(())
        })
    }

    fn remove_pin(&self, now: &str) -> Result<(), DbError> {
        let now = now.to_string();
        self.worker.run(move |client| {
            client.execute(
                "UPDATE security_settings
                 SET pin_hash = NULL, pin_salt = NULL, pin_enabled = FALSE, updated_at = $1
                 WHERE id = 1",
                &[&now],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(())
        })
    }

    fn set_require_uv(&self, require: bool, now: &str) -> Result<(), DbError> {
        let now = now.to_string();
        self.worker.run(move |client| {
            client.execute(
                "UPDATE security_settings SET require_uv = $1, updated_at = $2 WHERE id = 1",
                &[&require, &now],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(())
        })
    }

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<(), DbError> {
        let settings = settings.clone();
        self.worker.run(move |client| {
            client.execute(
                "INSERT INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
                 VALUES (1, $1, $2, $3, $4, $5, $6)
                 ON CONFLICT(id) DO UPDATE SET
                     pin_hash = EXCLUDED.pin_hash,
                     pin_salt = EXCLUDED.pin_salt,
                     pin_enabled = EXCLUDED.pin_enabled,
                     fp_enabled = EXCLUDED.fp_enabled,
                     require_uv = EXCLUDED.require_uv,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &settings.pin_hash,
                    &settings.pin_salt,
                    &settings.pin_enabled,
                    &settings.fp_enabled,
                    &settings.require_uv,
                    &settings.updated_at,
                ],
            ).map_err(pg_err)?;
            Ok(())
        })
    }

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>, DbError> {
        self.worker.run(|client| {
            let rows = client.query(
                "SELECT id, slot_index, name, enrolled_at FROM fingerprints ORDER BY slot_index ASC",
                &[],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            let mut list = Vec::new();
            for r in rows {
                let id: i64 = r.get(0);
                let slot: i32 = r.get(1);
                list.push(FingerprintRow {
                    id,
                    slot_index: slot as u32,
                    name: r.get(2),
                    enrolled_at: r.get(3),
                });
            }
            Ok(list)
        })
    }

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>, DbError> {
        self.worker.run(move |client| {
            let rows = client.query(
                "SELECT id, slot_index, name, enrolled_at FROM fingerprints WHERE id = $1",
                &[&id],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            if let Some(r) = rows.into_iter().next() {
                let fid: i64 = r.get(0);
                let slot: i32 = r.get(1);
                Ok(Some(FingerprintRow {
                    id: fid,
                    slot_index: slot as u32,
                    name: r.get(2),
                    enrolled_at: r.get(3),
                }))
            } else {
                Ok(None)
            }
        })
    }

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow, DbError> {
        let slot = slot_index as i32;
        let name_owned = name.to_string();
        let now_owned = now.to_string();

        self.worker.run(move |client| {
            let rows = client.query(
                "INSERT INTO fingerprints (slot_index, name, enrolled_at) VALUES ($1, $2, $3)
                 ON CONFLICT(slot_index) DO UPDATE SET name = EXCLUDED.name, enrolled_at = EXCLUDED.enrolled_at
                 RETURNING id",
                &[&slot, &name_owned, &now_owned],
            ).map_err(|e| DbError::Postgres(e.to_string()))?;

            let id: i64 = rows.first().map(|r| r.get(0)).unwrap_or(0);

            Ok(FingerprintRow {
                id,
                slot_index,
                name: name_owned,
                enrolled_at: now_owned,
            })
        })
    }

    fn delete_fingerprint(&self, id: i64) -> Result<bool, DbError> {
        self.worker.run(move |client| {
            let rows = client.execute("DELETE FROM fingerprints WHERE id = $1", &[&id])
                .map_err(|e| DbError::Postgres(e.to_string()))?;
            Ok(rows > 0)
        })
    }

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<(), DbError> {
        let slot = slot_index as i32;
        let name = name.to_string();
        let enrolled_at = enrolled_at.to_string();
        self.worker.run(move |client| {
            let _ = client.execute("DELETE FROM fingerprints WHERE slot_index = $1 OR id = $2", &[&slot, &id]);
            client.execute(
                "INSERT INTO fingerprints (id, slot_index, name, enrolled_at) VALUES ($1, $2, $3, $4)",
                &[&id, &slot, &name, &enrolled_at],
            ).map_err(pg_err)?;
            let _ = client.execute(
                "SELECT setval(pg_get_serial_sequence('fingerprints', 'id'), coalesce((SELECT max(id) FROM fingerprints), 1))",
                &[],
            );
            Ok(())
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
        let cid = credential_id.map(|s| s.to_string());
        let rp_id = rp_id.to_string();
        let operation = operation.to_string();
        let status = status.to_string();
        let auth_method = auth_method.to_string();
        let details = details.map(|s| s.to_string());
        let created_at = created_at.to_string();

        self.worker.run(move |client| {
            client.execute(
                "INSERT INTO auth_logs (id, credential_id, rp_id, operation, status, auth_method, details, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) DO UPDATE SET
                     credential_id = EXCLUDED.credential_id,
                     rp_id = EXCLUDED.rp_id,
                     operation = EXCLUDED.operation,
                     status = EXCLUDED.status,
                     auth_method = EXCLUDED.auth_method,
                     details = EXCLUDED.details,
                     created_at = EXCLUDED.created_at",
                &[&id, &cid, &rp_id, &operation, &status, &auth_method, &details, &created_at],
            ).map_err(pg_err)?;
            let _ = client.execute(
                "SELECT setval(pg_get_serial_sequence('auth_logs', 'id'), coalesce((SELECT max(id) FROM auth_logs), 1))",
                &[],
            );
            Ok(())
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
        let level = level.to_string();
        let component = component.to_string();
        let message = message.to_string();
        let created_at = created_at.to_string();

        self.worker.run(move |client| {
            client.execute(
                "INSERT INTO debug_logs (id, level, component, message, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (id) DO UPDATE SET
                     level = EXCLUDED.level,
                     component = EXCLUDED.component,
                     message = EXCLUDED.message,
                     created_at = EXCLUDED.created_at",
                &[&id, &level, &component, &message, &created_at],
            ).map_err(pg_err)?;
            let _ = client.execute(
                "SELECT setval(pg_get_serial_sequence('debug_logs', 'id'), coalesce((SELECT max(id) FROM debug_logs), 1))",
                &[],
            );
            Ok(())
        })
    }
}
