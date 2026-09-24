use super::{
    AuthLogRow, CredentialRow, DbBackend, DbError, DebugLogRow, FingerprintRow,
    SecuritySettingsData,
};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::sync::Arc;

pub struct SqliteBackend {
    conn: Arc<Mutex<Connection>>,
    name: &'static str,
}

impl SqliteBackend {
    pub fn open(path: &str) -> Result<Self, DbError> {
        Self::open_with_name(path, "SQLite")
    }

    pub fn open_with_name(path: &str, name: &'static str) -> Result<Self, DbError> {
        let conn = Connection::open(path).map_err(DbError::Sqlite)?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS credentials (
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

             CREATE TABLE IF NOT EXISTS app_settings (
                setting_key TEXT PRIMARY KEY,
                value TEXT NOT NULL
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

             -- Clean up prior duplicates (if any), keep newest by last_used_at/created_at
             DELETE FROM credentials
             WHERE id NOT IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                         PARTITION BY LOWER(rp_id), LOWER(user_name)
                         ORDER BY datetime(last_used_at) DESC, datetime(created_at) DESC
                     ) as rn
                     FROM credentials
                 ) WHERE rn = 1
             );

             DELETE FROM credentials
             WHERE user_id != X'00000000000000000000000000000000'
               AND length(user_id) > 0
               AND id NOT IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                         PARTITION BY LOWER(rp_id), user_id
                         ORDER BY datetime(last_used_at) DESC, datetime(created_at) DESC
                     ) as rn
                     FROM credentials
                     WHERE user_id != X'00000000000000000000000000000000' AND length(user_id) > 0
                 ) WHERE rn = 1
             );

             CREATE INDEX IF NOT EXISTS idx_credentials_rp_user ON credentials(rp_id, user_name);"
        ).map_err(DbError::Sqlite)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            name,
        })
    }
}

impl DbBackend for SqliteBackend {
    fn backend_name(&self) -> &'static str {
        self.name
    }

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO debug_logs (level, component, message, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![level, component, message, now],
        );
        Ok(())
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
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO auth_logs (credential_id, rp_id, operation, status, auth_method, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![credential_id, rp_id, operation, status, auth_method, details, now],
        );
        Ok(())
    }

    fn get_app_settings(&self) -> Result<Vec<(String, String)>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT setting_key, value FROM app_settings ORDER BY setting_key")
            .map_err(DbError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(DbError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(DbError::Sqlite)
    }

    fn set_app_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO app_settings (setting_key, value) VALUES (?1, ?2)
             ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn get_credentials(&self) -> Result<Vec<CredentialRow>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                    hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
             FROM credentials ORDER BY datetime(last_used_at) DESC"
        ).map_err(DbError::Sqlite)?;

        let rows = stmt.query_map([], |row| {
            Ok(CredentialRow {
                id: row.get(0)?,
                rp_id: row.get(1)?,
                user_id_hex: row.get(2)?,
                user_name: row.get(3)?,
                user_display_name: row.get(4)?,
                private_key_sec1_hex: row.get(5)?,
                public_key_cose_hex: row.get(6)?,
                sign_count: row.get(7)?,
                created_at: row.get(8)?,
                last_used_at: row.get(9)?,
            })
        }).map_err(DbError::Sqlite)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(DbError::Sqlite)?);
        }
        Ok(list)
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                    hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
             FROM credentials WHERE id = ?1"
        ).map_err(DbError::Sqlite)?;

        let mut rows = stmt.query_map([id], |row| {
            Ok(CredentialRow {
                id: row.get(0)?,
                rp_id: row.get(1)?,
                user_id_hex: row.get(2)?,
                user_name: row.get(3)?,
                user_display_name: row.get(4)?,
                private_key_sec1_hex: row.get(5)?,
                public_key_cose_hex: row.get(6)?,
                sign_count: row.get(7)?,
                created_at: row.get(8)?,
                last_used_at: row.get(9)?,
            })
        }).map_err(DbError::Sqlite)?;

        if let Some(r) = rows.next() {
            Ok(Some(r.map_err(DbError::Sqlite)?))
        } else {
            Ok(None)
        }
    }

    fn get_credentials_for_rp(&self, rp_id: &str) -> Result<Vec<(String, Vec<u8>, String, String)>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, user_name, created_at FROM credentials WHERE rp_id = ?1 COLLATE NOCASE"
        ).map_err(DbError::Sqlite)?;

        let rows = stmt.query_map([rp_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }).map_err(DbError::Sqlite)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(DbError::Sqlite)?);
        }
        Ok(list)
    }

    fn delete_credential(&self, id: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM credentials WHERE id = ?1", [id]).map_err(DbError::Sqlite)?;
        Ok(rows > 0)
    }

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE credentials SET user_name = ?1, user_display_name = ?2 WHERE id = ?3",
            params![name, display_name, id],
        ).map_err(DbError::Sqlite)?;
        Ok(rows > 0)
    }

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "UPDATE auth_logs SET credential_id = ?1 WHERE credential_id = ?2",
            params![new_id, old_id],
        );
        Ok(())
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
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                      private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                 rp_id = excluded.rp_id,
                 user_id = excluded.user_id,
                 user_name = excluded.user_name,
                 user_display_name = excluded.user_display_name,
                 private_key_sec1 = excluded.private_key_sec1,
                 public_key_cose = excluded.public_key_cose,
                 sign_count = excluded.sign_count,
                 created_at = excluded.created_at,
                 last_used_at = excluded.last_used_at",
            params![
                id_hex,
                rp_id,
                user_id,
                user_name,
                user_display_name,
                private_key_sec1,
                public_key_cose,
                sign_count,
                created_at,
                last_used_at,
            ],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32, DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE credentials SET sign_count = sign_count + 1, last_used_at = ?2 WHERE id = ?1",
            params![id, now],
        ).map_err(DbError::Sqlite)?;
        let mut stmt = conn.prepare("SELECT sign_count FROM credentials WHERE id = ?1").map_err(DbError::Sqlite)?;
        let count: u32 = stmt.query_row([id], |r| r.get(0)).map_err(DbError::Sqlite)?;
        Ok(count)
    }

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>, DbError> {
        let conn = self.conn.lock();
        let map_fn = |row: &rusqlite::Row| -> rusqlite::Result<AuthLogRow> {
            Ok(AuthLogRow {
                id: row.get(0)?,
                credential_id: row.get(1)?,
                rp_id: row.get(2)?,
                operation: row.get(3)?,
                status: row.get(4)?,
                auth_method: row.get(5)?,
                details: row.get(6)?,
                created_at: row.get(7)?,
            })
        };

        let mut list = Vec::new();
        if let Some(cid) = credential_id {
            let mut stmt = conn.prepare(
                "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                 FROM auth_logs WHERE credential_id = ?1 ORDER BY id DESC LIMIT ?2",
            ).map_err(DbError::Sqlite)?;
            let rows = stmt.query_map(params![cid, limit as i64], map_fn).map_err(DbError::Sqlite)?;
            for r in rows {
                list.push(r.map_err(DbError::Sqlite)?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                 FROM auth_logs ORDER BY id DESC LIMIT ?1",
            ).map_err(DbError::Sqlite)?;
            let rows = stmt.query_map(params![limit as i64], map_fn).map_err(DbError::Sqlite)?;
            for r in rows {
                list.push(r.map_err(DbError::Sqlite)?);
            }
        }
        Ok(list)
    }

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, level, component, message, created_at
             FROM debug_logs ORDER BY id DESC LIMIT ?1"
        ).map_err(DbError::Sqlite)?;

        let rows = stmt.query_map([limit as i64], |row| {
            Ok(DebugLogRow {
                id: row.get(0)?,
                level: row.get(1)?,
                component: row.get(2)?,
                message: row.get(3)?,
                created_at: row.get(4)?,
            })
        }).map_err(DbError::Sqlite)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(DbError::Sqlite)?);
        }
        Ok(list)
    }

    fn clear_auth_logs(&self) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM auth_logs", []).map_err(DbError::Sqlite)?;
        Ok(rows)
    }

    fn clear_debug_logs(&self) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM debug_logs", []).map_err(DbError::Sqlite)?;
        Ok(rows)
    }

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at FROM security_settings WHERE id = 1"
        ).map_err(DbError::Sqlite)?;
        let (pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at): (
            Option<String>, Option<String>, bool, bool, bool, String
        ) = stmt.query_row([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        }).map_err(DbError::Sqlite)?;

        Ok(SecuritySettingsData {
            pin_hash,
            pin_salt,
            pin_enabled,
            fp_enabled,
            require_uv,
            updated_at,
        })
    }

    fn get_fingerprint_count(&self) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let mut fp_stmt = conn.prepare("SELECT count(*) FROM fingerprints").map_err(DbError::Sqlite)?;
        let fp_count_i64: i64 = fp_stmt.query_row([], |r| r.get(0)).map_err(DbError::Sqlite)?;
        Ok(fp_count_i64 as usize)
    }

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings
             SET pin_hash = ?1, pin_salt = ?2, pin_enabled = 1, updated_at = ?3
             WHERE id = 1",
            params![pin_hash, pin_salt, now],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn remove_pin(&self, now: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings
             SET pin_hash = NULL, pin_salt = NULL, pin_enabled = 0, updated_at = ?1
             WHERE id = 1",
            [now],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn set_require_uv(&self, require: bool, now: &str) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings SET require_uv = ?1, updated_at = ?2 WHERE id = 1",
            params![require, now],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<(), DbError> {
        let conn = self.conn.lock();
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
            params![
                settings.pin_hash,
                settings.pin_salt,
                settings.pin_enabled,
                settings.fp_enabled,
                settings.require_uv,
                settings.updated_at,
            ],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, slot_index, name, enrolled_at FROM fingerprints ORDER BY slot_index ASC"
        ).map_err(DbError::Sqlite)?;

        let rows = stmt.query_map([], |row| {
            Ok(FingerprintRow {
                id: row.get(0)?,
                slot_index: row.get(1)?,
                name: row.get(2)?,
                enrolled_at: row.get(3)?,
            })
        }).map_err(DbError::Sqlite)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(DbError::Sqlite)?);
        }
        Ok(list)
    }

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>, DbError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, slot_index, name, enrolled_at FROM fingerprints WHERE id = ?1"
        ).map_err(DbError::Sqlite)?;

        let mut rows = stmt.query_map([id], |row| {
            Ok(FingerprintRow {
                id: row.get(0)?,
                slot_index: row.get(1)?,
                name: row.get(2)?,
                enrolled_at: row.get(3)?,
            })
        }).map_err(DbError::Sqlite)?;

        if let Some(r) = rows.next() {
            Ok(Some(r.map_err(DbError::Sqlite)?))
        } else {
            Ok(None)
        }
    }

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow, DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO fingerprints (slot_index, name, enrolled_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(slot_index) DO UPDATE SET name = excluded.name, enrolled_at = excluded.enrolled_at",
            params![slot_index, name, now],
        ).map_err(DbError::Sqlite)?;
        let id = conn.last_insert_rowid();

        Ok(FingerprintRow {
            id,
            slot_index,
            name: name.to_string(),
            enrolled_at: now.to_string(),
        })
    }

    fn delete_fingerprint(&self, id: i64) -> Result<bool, DbError> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM fingerprints WHERE id = ?1", [id]).map_err(DbError::Sqlite)?;
        Ok(rows > 0)
    }

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO fingerprints (id, slot_index, name, enrolled_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET slot_index = excluded.slot_index, name = excluded.name, enrolled_at = excluded.enrolled_at",
            params![id, slot_index, name, enrolled_at],
        ).map_err(DbError::Sqlite)?;
        Ok(())
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
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO auth_logs (id, credential_id, rp_id, operation, status, auth_method, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, credential_id, rp_id, operation, status, auth_method, details, created_at],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }

    fn insert_debug_log_full(
        &self,
        id: i64,
        level: &str,
        component: &str,
        message: &str,
        created_at: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO debug_logs (id, level, component, message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, level, component, message, created_at],
        ).map_err(DbError::Sqlite)?;
        Ok(())
    }
}
