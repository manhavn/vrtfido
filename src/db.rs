use parking_lot::Mutex;
use rusqlite::{params, Connection, Result};
use std::sync::Arc;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CredentialRow {
    pub id: String, // hex
    pub rp_id: String,
    pub user_id_hex: String,
    pub user_name: String,
    pub user_display_name: String,
    pub private_key_sec1_hex: String,
    pub public_key_cose_hex: String,
    pub sign_count: u32,
    pub created_at: String,
    pub last_used_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AuthLogRow {
    pub id: i64,
    pub credential_id: Option<String>,
    pub rp_id: String,
    pub operation: String, // MakeCredential, GetAssertion, PinVerify, FpVerify, etc.
    pub status: String,    // SUCCESS, FAILED, REJECTED, PENDING
    pub auth_method: String, // PIN, FINGERPRINT, NONE
    pub details: Option<String>,
    pub created_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SecuritySettings {
    pub pin_enabled: bool,
    pub fp_enabled: bool,
    pub require_uv: bool,
    pub fp_count: usize,
    pub max_fp_slots: usize,
    pub updated_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct FingerprintRow {
    pub id: i64,
    pub slot_index: u32,
    pub name: String,
    pub enrolled_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DebugLogRow {
    pub id: i64,
    pub level: String,
    pub component: String,
    pub message: String,
    pub created_at: String,
}
#[allow(dead_code)]
impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
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

             CREATE TABLE IF NOT EXISTS debug_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 level TEXT NOT NULL,
                 component TEXT NOT NULL,
                 message TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );

             INSERT OR IGNORE INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
             VALUES (1, NULL, NULL, 0, 1, 1, datetime('now'));"
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn log_debug(&self, level: &str, component: &str, message: &str) {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO debug_logs (level, component, message, created_at) VALUES (?1, ?2, ?3, datetime('now'))",
            params![level, component, message],
        );
    }

    pub fn log_auth(
        &self,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
    ) {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO auth_logs (credential_id, rp_id, operation, status, auth_method, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))",
            params![credential_id, rp_id, operation, status, auth_method, details],
        );
    }

    pub fn get_credentials(&self) -> Result<Vec<CredentialRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                    hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
             FROM credentials ORDER BY datetime(last_used_at) DESC"
        )?;

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
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, rp_id, hex(user_id), user_name, user_display_name,
                    hex(private_key_sec1), hex(public_key_cose), sign_count, created_at, last_used_at
             FROM credentials WHERE id = ?1"
        )?;

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
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn save_credential(
        &self,
        id_hex: &str,
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        private_key_sec1: &[u8],
        public_key_cose: &[u8],
        sign_count: u32,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                      private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), datetime('now'))
             ON CONFLICT(id) DO UPDATE SET
                sign_count = excluded.sign_count,
                last_used_at = datetime('now')",
            params![
                id_hex,
                rp_id,
                user_id,
                user_name,
                user_display_name,
                private_key_sec1,
                public_key_cose,
                sign_count
            ],
        )?;
        Ok(())
    }

    pub fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE credentials SET user_name = ?1, user_display_name = ?2 WHERE id = ?3",
            params![name, display_name, id],
        )?;
        Ok(rows > 0)
    }

    pub fn delete_credential(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM credentials WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }

    pub fn increment_sign_count(&self, id: &str) -> Result<u32> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE credentials SET sign_count = sign_count + 1, last_used_at = datetime('now') WHERE id = ?1",
            [id],
        )?;
        let mut stmt = conn.prepare("SELECT sign_count FROM credentials WHERE id = ?1")?;
        let count: u32 = stmt.query_row([id], |r| r.get(0))?;
        Ok(count)
    }

    pub fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>> {
        let conn = self.conn.lock();
        let map_fn = |row: &rusqlite::Row| -> Result<AuthLogRow> {
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
            )?;
            let rows = stmt.query_map(params![cid, limit as i64], map_fn)?;
            for r in rows {
                list.push(r?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                 FROM auth_logs ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], map_fn)?;
            for r in rows {
                list.push(r?);
            }
        }
        Ok(list)
    }

    pub fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, level, component, message, created_at
             FROM debug_logs ORDER BY id DESC LIMIT ?1"
        )?;

        let rows = stmt.query_map([limit as i64], |row| {
            Ok(DebugLogRow {
                id: row.get(0)?,
                level: row.get(1)?,
                component: row.get(2)?,
                message: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_security_settings(&self) -> Result<SecuritySettings> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT pin_enabled, fp_enabled, require_uv, updated_at FROM security_settings WHERE id = 1"
        )?;
        let (pin_enabled, fp_enabled, require_uv, updated_at): (bool, bool, bool, String) =
            stmt.query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;

        let mut fp_stmt = conn.prepare("SELECT count(*) FROM fingerprints")?;
        let fp_count_i64: i64 = fp_stmt.query_row([], |r| r.get(0))?;
        let fp_count = fp_count_i64 as usize;
        Ok(SecuritySettings {
            pin_enabled,
            fp_enabled,
            require_uv,
            fp_count,
            max_fp_slots: 10,
            updated_at,
        })
    }

    pub fn get_pin_hash_and_salt(&self) -> Result<(Option<String>, Option<String>)> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT pin_hash, pin_salt FROM security_settings WHERE id = 1")?;
        stmt.query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
    }

    pub fn set_pin(&self, pin_hash: &str, pin_salt: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings
             SET pin_hash = ?1, pin_salt = ?2, pin_enabled = 1, updated_at = datetime('now')
             WHERE id = 1",
            params![pin_hash, pin_salt],
        )?;
        Ok(())
    }

    pub fn remove_pin(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings
             SET pin_hash = NULL, pin_salt = NULL, pin_enabled = 0, updated_at = datetime('now')
             WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    pub fn set_require_uv(&self, require: bool) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE security_settings SET require_uv = ?1, updated_at = datetime('now') WHERE id = 1",
            [require],
        )?;
        Ok(())
    }

    pub fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, slot_index, name, enrolled_at FROM fingerprints ORDER BY slot_index ASC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(FingerprintRow {
                id: row.get(0)?,
                slot_index: row.get(1)?,
                name: row.get(2)?,
                enrolled_at: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT id, slot_index, name, enrolled_at FROM fingerprints WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], |row| {
            Ok(FingerprintRow {
                id: row.get(0)?,
                slot_index: row.get(1)?,
                name: row.get(2)?,
                enrolled_at: row.get(3)?,
            })
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn add_fingerprint(&self, slot_index: u32, name: &str) -> Result<FingerprintRow> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO fingerprints (slot_index, name, enrolled_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(slot_index) DO UPDATE SET name = excluded.name, enrolled_at = datetime('now')",
            params![slot_index, name],
        )?;
        let id = conn.last_insert_rowid();

        Ok(FingerprintRow {
            id,
            slot_index,
            name: name.to_string(),
            enrolled_at: "Vừa xong".to_string(),
        })
    }

    pub fn delete_fingerprint(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM fingerprints WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }
}
