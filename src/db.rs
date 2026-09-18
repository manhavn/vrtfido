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
    pub max_fp_slots: Option<usize>,
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
             VALUES (1, NULL, NULL, 0, 1, 1, datetime('now'));

             -- Dọn dẹp bản ghi trùng lặp trước đó (nếu có), chỉ giữ lại bản ghi mới nhất theo lần dùng/ngày tạo
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
    ) -> Result<bool> {
        let conn = self.conn.lock();

        // 1. Quét các credential hiện có của RP để kiểm tra trùng tài khoản
        let mut stmt = conn.prepare(
            "SELECT id, user_id, user_name, created_at FROM credentials WHERE rp_id = ?1 COLLATE NOCASE"
        )?;

        let rows = stmt.query_map([rp_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let dummy_id = [0u8; 16];
        let new_uid_valid = !user_id.is_empty() && user_id != dummy_id;
        let new_name_clean = user_name.trim();

        let mut matching_ids = Vec::new();
        let mut earliest_created_at: Option<String> = None;

        for r in rows {
            let (exist_id, exist_uid, exist_name, created_at) = r?;
            let exist_uid_valid = !exist_uid.is_empty() && exist_uid.as_slice() != dummy_id;
            let exist_name_clean = exist_name.trim();

            let mut is_match = false;

            // Kiểm tra trùng user_id (nếu cả 2 đều hợp lệ và khác dummy 16 byte 0)
            if new_uid_valid && exist_uid_valid && exist_uid.as_slice() == user_id {
                is_match = true;
            }

            // Hoặc kiểm tra trùng user_name (không phân biệt hoa thường)
            if !is_match && !new_name_clean.is_empty() && !exist_name_clean.is_empty() {
                if exist_name_clean.eq_ignore_ascii_case(new_name_clean) {
                    // Nếu cả 2 đều là placeholder "User" nhưng user_id thực sự khác nhau thì là 2 tài khoản khác
                    if !(new_name_clean.eq_ignore_ascii_case("User")
                        && new_uid_valid
                        && exist_uid_valid
                        && exist_uid.as_slice() != user_id)
                    {
                        is_match = true;
                    }
                }
            }

            if is_match {
                matching_ids.push(exist_id);
                if earliest_created_at.is_none() {
                    earliest_created_at = Some(created_at);
                }
            }
        }

        let is_update = !matching_ids.is_empty();

        // 2. Nếu đã tồn tại bản ghi cùng tài khoản, xóa data cũ và cập nhật audit log sang ID mới
        for old_id in &matching_ids {
            let _ = conn.execute("DELETE FROM credentials WHERE id = ?1", [old_id]);
            let _ = conn.execute(
                "UPDATE auth_logs SET credential_id = ?1 WHERE credential_id = ?2",
                params![id_hex, old_id],
            );
        }

        // 3. Ghi đè / thêm mới bản ghi với dữ liệu mới nhất (giữ created_at ban đầu nếu là ghi đè)
        if let Some(created_at_val) = earliest_created_at {
            conn.execute(
                "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                          private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))",
                params![
                    id_hex,
                    rp_id,
                    user_id,
                    user_name,
                    user_display_name,
                    private_key_sec1,
                    public_key_cose,
                    sign_count,
                    created_at_val,
                ],
            )?;
        } else {
            conn.execute(
                "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                          private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), datetime('now'))",
                params![
                    id_hex,
                    rp_id,
                    user_id,
                    user_name,
                    user_display_name,
                    private_key_sec1,
                    public_key_cose,
                    sign_count,
                ],
            )?;
        }

        Ok(is_update)
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

    pub fn get_security_settings(&self, unlimited_fps: bool) -> Result<SecuritySettings> {
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
            max_fp_slots: if unlimited_fps { None } else { Some(10) },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Db {
        Db::open(":memory:").expect("Failed to open in-memory db")
    }

    #[test]
    fn test_duplicate_same_username_same_rp_overwrites() {
        let db = create_test_db();

        // Đăng ký lần 1
        let res1 = db.save_credential(
            "id_1",
            "webauthn.io",
            b"uid_1",
            "testuser",
            "User Display 1",
            b"sec1_key_1",
            b"cose_key_1",
            1,
        ).unwrap();
        assert!(!res1, "Lần đầu tiên đăng ký không phải là update");

        let creds1 = db.get_credentials().unwrap();
        assert_eq!(creds1.len(), 1);
        assert_eq!(creds1[0].id, "id_1");
        assert_eq!(creds1[0].user_name, "testuser");
        assert_eq!(creds1[0].user_display_name, "User Display 1");

        // Đăng ký lần 2 cùng rp_id và user_name
        let res2 = db.save_credential(
            "id_2",
            "webauthn.io",
            b"uid_1",
            "testuser",
            "User Display 2",
            b"sec1_key_2",
            b"cose_key_2",
            1,
        ).unwrap();
        assert!(res2, "Lần thứ hai đăng ký cùng tài khoản phải là update");

        // Kiểm tra không sinh thêm bản ghi mới, chỉ có đúng 1 bản ghi
        let creds2 = db.get_credentials().unwrap();
        assert_eq!(creds2.len(), 1, "Chỉ được phép có 1 bản ghi duy nhất cho cùng một tài khoản của 1 trang web");
        assert_eq!(creds2[0].id, "id_2", "ID phải được cập nhật sang ID mới");
        assert_eq!(creds2[0].user_display_name, "User Display 2", "Data phải được cập nhật mới");
        assert_eq!(hex::decode(&creds2[0].private_key_sec1_hex).unwrap(), b"sec1_key_2", "Private key mới");
    }

    #[test]
    fn test_duplicate_case_insensitive_username() {
        let db = create_test_db();

        db.save_credential(
            "id_1",
            "webauthn.io",
            b"uid_1",
            "alice",
            "Alice",
            b"key1",
            b"cose1",
            1,
        ).unwrap();

        // Đăng ký lại với chữ hoa "Alice"
        let is_update = db.save_credential(
            "id_2",
            "webauthn.io",
            b"uid_different",
            "Alice",
            "Alice New",
            b"key2",
            b"cose2",
            1,
        ).unwrap();
        assert!(is_update, "Tên tài khoản không phân biệt hoa thường phải nhận diện trùng");

        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, "id_2");
    }

    #[test]
    fn test_duplicate_same_user_id_different_username() {
        let db = create_test_db();

        db.save_credential(
            "id_1",
            "webauthn.io",
            b"unique_user_id_123",
            "old_name",
            "Old Display",
            b"key1",
            b"cose1",
            1,
        ).unwrap();

        // Đổi username nhưng cùng user_id
        let is_update = db.save_credential(
            "id_2",
            "webauthn.io",
            b"unique_user_id_123",
            "new_name",
            "New Display",
            b"key2",
            b"cose2",
            1,
        ).unwrap();
        assert!(is_update, "Cùng user_id phải nhận diện là cùng một tài khoản và ghi đè");

        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, "id_2");
        assert_eq!(creds[0].user_name, "new_name");
    }

    #[test]
    fn test_different_accounts_same_rp_creates_multiple() {
        let db = create_test_db();

        let res1 = db.save_credential(
            "id_1",
            "webauthn.io",
            b"uid_alice",
            "alice",
            "Alice",
            b"key1",
            b"cose1",
            1,
        ).unwrap();
        assert!(!res1);

        let res2 = db.save_credential(
            "id_2",
            "webauthn.io",
            b"uid_bob",
            "bob",
            "Bob",
            b"key2",
            b"cose2",
            1,
        ).unwrap();
        assert!(!res2);

        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 2, "Hai tài khoản khác nhau trên cùng RP phải được lưu độc lập");
    }

    #[test]
    fn test_same_username_different_rp_creates_multiple() {
        let db = create_test_db();

        db.save_credential(
            "id_1",
            "webauthn.io",
            b"uid_1",
            "alice",
            "Alice",
            b"key1",
            b"cose1",
            1,
        ).unwrap();

        db.save_credential(
            "id_2",
            "github.com",
            b"uid_1",
            "alice",
            "Alice",
            b"key2",
            b"cose2",
            1,
        ).unwrap();

        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 2, "Cùng username nhưng khác trang web phải được lưu độc lập");
    }

    #[test]
    fn test_auth_logs_updated_to_new_credential_id() {
        let db = create_test_db();

        db.save_credential(
            "id_old",
            "webauthn.io",
            b"uid_1",
            "testuser",
            "User",
            b"key1",
            b"cose1",
            1,
        ).unwrap();

        // Tạo auth log liên kết với id_old
        db.log_auth(
            Some("id_old"),
            "webauthn.io",
            "GetAssertion",
            "SUCCESS",
            "PIN",
            Some("Old log"),
        );

        let logs_before = db.get_auth_logs(Some("id_old"), 10).unwrap();
        assert_eq!(logs_before.len(), 1);

        // Đăng ký lại ghi đè sang id_new
        db.save_credential(
            "id_new",
            "webauthn.io",
            b"uid_1",
            "testuser",
            "User New",
            b"key2",
            b"cose2",
            1,
        ).unwrap();

        // Logs của id_old phải được chuyển sang id_new
        let logs_old = db.get_auth_logs(Some("id_old"), 10).unwrap();
        assert_eq!(logs_old.len(), 0);

        let logs_new = db.get_auth_logs(Some("id_new"), 10).unwrap();
        assert_eq!(logs_new.len(), 1);
        assert_eq!(logs_new[0].credential_id.as_deref(), Some("id_new"));
    }

    #[test]
    fn test_db_startup_deduplication() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("vrtfido_test_dedup_{}.db", rand::random::<u32>()));
        let path_str = db_path.to_str().unwrap();

        // Tạo database và chèn thủ công 3 bản ghi trùng lặp (mô phỏng dữ liệu cũ)
        {
            let conn = Connection::open(path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE credentials (
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
                 INSERT INTO credentials VALUES ('id1', 'webauthn.io', X'01', 'testuser', 'User', X'00', X'00', 1, '2026-09-18 10:00:00', '2026-09-18 10:10:00');
                 INSERT INTO credentials VALUES ('id2', 'webauthn.io', X'01', 'testuser', 'User', X'00', X'00', 1, '2026-09-18 10:00:00', '2026-09-18 10:20:00');
                 INSERT INTO credentials VALUES ('id3', 'webauthn.io', X'01', 'testuser', 'User', X'00', X'00', 1, '2026-09-18 10:00:00', '2026-09-18 10:30:00');"
            ).unwrap();
        }

        // Mở qua Db::open -> Phải tự động dọn dẹp các bản ghi trùng cũ, chỉ giữ lại bản ghi mới nhất ('id3')
        let db = Db::open(path_str).unwrap();
        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 1, "Chỉ giữ lại 1 bản ghi mới nhất sau khi mở DB");
        assert_eq!(creds[0].id, "id3");

        let _ = std::fs::remove_file(db_path);
    }
}
