pub mod libsql_backend;
pub mod mysql_backend;
pub mod postgres_backend;
pub mod sqlite;

use chrono::Utc;
use std::fmt;
use std::sync::Arc;

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    LibSql(String),
    Postgres(String),
    MySql(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    #[allow(dead_code)]
    Config(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Sqlite(e) => write!(f, "SQLite error: {}", e),
            DbError::LibSql(e) => write!(f, "LibSQL error: {}", e),
            DbError::Postgres(e) => write!(f, "PostgreSQL error: {}", e),
            DbError::MySql(e) => write!(f, "MySQL error: {}", e),
            DbError::Io(e) => write!(f, "I/O error: {}", e),
            DbError::Json(e) => write!(f, "JSON error: {}", e),
            DbError::Config(e) => write!(f, "Database config error: {}", e),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e)
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        DbError::Io(e)
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        DbError::Json(e)
    }
}

pub type Result<T, E = DbError> = std::result::Result<T, E>;

fn current_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
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
    pub operation: String,
    pub status: String,
    pub auth_method: String,
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
pub struct SecuritySettingsData {
    pub pin_hash: Option<String>,
    pub pin_salt: Option<String>,
    pub pin_enabled: bool,
    pub fp_enabled: bool,
    pub require_uv: bool,
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DatabaseExport {
    pub version: u32,
    pub exported_at: String,
    pub database_backend: String,
    pub credentials: Vec<CredentialRow>,
    pub auth_logs: Vec<AuthLogRow>,
    pub security_settings: SecuritySettingsData,
    pub fingerprints: Vec<FingerprintRow>,
    pub debug_logs: Vec<DebugLogRow>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct ImportStats {
    pub credentials_imported: usize,
    pub auth_logs_imported: usize,
    pub fingerprints_imported: usize,
    pub debug_logs_imported: usize,
    pub security_settings_updated: bool,
}

pub trait DbBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<()>;

    fn log_auth(
        &self,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
        now: &str,
    ) -> Result<()>;

    fn get_credentials(&self) -> Result<Vec<CredentialRow>>;

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>>;

    fn get_credentials_for_rp(&self, rp_id: &str) -> Result<Vec<(String, Vec<u8>, String, String)>>;

    fn delete_credential(&self, id: &str) -> Result<bool>;

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool>;

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<()>;

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
    ) -> Result<()>;

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32>;

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>>;

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>>;

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData>;

    fn get_fingerprint_count(&self) -> Result<usize>;

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<()>;

    fn remove_pin(&self, now: &str) -> Result<()>;

    fn set_require_uv(&self, require: bool, now: &str) -> Result<()>;

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<()>;

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>>;

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>>;

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow>;

    fn delete_fingerprint(&self, id: i64) -> Result<bool>;

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<()>;

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
    ) -> Result<()>;

    fn insert_debug_log_full(
        &self,
        id: i64,
        level: &str,
        component: &str,
        message: &str,
        created_at: &str,
    ) -> Result<()>;
}

#[derive(Clone)]
pub struct Db {
    backend: Arc<dyn DbBackend>,
}

#[allow(dead_code)]
impl Db {
    pub fn open(path_or_url: &str) -> Result<Self> {
        Self::open_with_options(path_or_url, None, None)
    }

    pub fn open_with_options(
        spec: &str,
        db_type: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<Self> {
        let effective_type = db_type.map(|t| t.to_lowercase());
        let trimmed_spec = spec.trim();

        let backend: Arc<dyn DbBackend> = match effective_type.as_deref() {
            Some("postgres") | Some("postgresql") => {
                Arc::new(postgres_backend::PostgresBackend::open(trimmed_spec)?)
            }
            Some("mysql") | Some("mariadb") => {
                Arc::new(mysql_backend::MySqlBackend::open(trimmed_spec)?)
            }
            Some("libsql") | Some("turso") => {
                if trimmed_spec.starts_with("libsql://")
                    || trimmed_spec.starts_with("http://")
                    || trimmed_spec.starts_with("https://")
                {
                    Arc::new(libsql_backend::LibSqlBackend::open(trimmed_spec, auth_token)?)
                } else {
                    let clean_path = trimmed_spec.strip_prefix("libsql:").unwrap_or(trimmed_spec);
                    let path = if clean_path.is_empty() { "authenticator.db" } else { clean_path };
                    Arc::new(sqlite::SqliteBackend::open_with_name(path, "LibSQL")?)
                }
            }
            Some("sqlite") => {
                let clean_path = trimmed_spec.strip_prefix("sqlite:").unwrap_or(trimmed_spec);
                let path = if clean_path.is_empty() { "authenticator.db" } else { clean_path };
                Arc::new(sqlite::SqliteBackend::open(path)?)
            }
            _ => {
                // Auto-detect based on URL prefix or format
                if trimmed_spec.starts_with("postgres://") || trimmed_spec.starts_with("postgresql://") {
                    Arc::new(postgres_backend::PostgresBackend::open(trimmed_spec)?)
                } else if trimmed_spec.starts_with("mysql://") || trimmed_spec.starts_with("mariadb://") {
                    Arc::new(mysql_backend::MySqlBackend::open(trimmed_spec)?)
                } else if trimmed_spec.starts_with("libsql://")
                    || trimmed_spec.starts_with("http://")
                    || trimmed_spec.starts_with("https://")
                {
                    Arc::new(libsql_backend::LibSqlBackend::open(trimmed_spec, auth_token)?)
                } else {
                    let clean_path = trimmed_spec.strip_prefix("sqlite:").unwrap_or(trimmed_spec);
                    let path = if clean_path.is_empty() { "authenticator.db" } else { clean_path };
                    Arc::new(sqlite::SqliteBackend::open(path)?)
                }
            }
        };

        Ok(Self { backend })
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    pub fn log_debug(&self, level: &str, component: &str, message: &str) {
        let now = current_timestamp();
        let _ = self.backend.log_debug(level, component, message, &now);
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
        let now = current_timestamp();
        let _ = self.backend.log_auth(credential_id, rp_id, operation, status, auth_method, details, &now);
    }

    pub fn get_credentials(&self) -> Result<Vec<CredentialRow>> {
        self.backend.get_credentials()
    }

    pub fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>> {
        self.backend.get_credential(id)
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
        // 1. Quét các credential hiện có của RP để kiểm tra trùng tài khoản
        let existing = self.backend.get_credentials_for_rp(rp_id)?;

        let dummy_id = [0u8; 16];
        let new_uid_valid = !user_id.is_empty() && user_id != dummy_id;
        let new_name_clean = user_name.trim();

        let mut matching_ids = Vec::new();
        let mut earliest_created_at: Option<String> = None;

        for (exist_id, exist_uid, exist_name, created_at) in existing {
            let exist_uid_valid = !exist_uid.is_empty() && exist_uid.as_slice() != dummy_id;
            let exist_name_clean = exist_name.trim();

            let mut is_match = false;

            if new_uid_valid && exist_uid_valid && exist_uid.as_slice() == user_id {
                is_match = true;
            }

            if !is_match && !new_name_clean.is_empty() && !exist_name_clean.is_empty() {
                if exist_name_clean.eq_ignore_ascii_case(new_name_clean) {
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
            let _ = self.backend.delete_credential(old_id);
            let _ = self.backend.update_auth_log_credential_id(old_id, id_hex);
        }

        // 3. Ghi đè / thêm mới bản ghi với dữ liệu mới nhất
        let now = current_timestamp();
        let created_at_val = earliest_created_at.unwrap_or_else(|| now.clone());

        self.backend.insert_credential(
            id_hex,
            rp_id,
            user_id,
            user_name,
            user_display_name,
            private_key_sec1,
            public_key_cose,
            sign_count,
            &created_at_val,
            &now,
        )?;

        Ok(is_update)
    }

    pub fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool> {
        self.backend.update_credential_name(id, name, display_name)
    }

    pub fn delete_credential(&self, id: &str) -> Result<bool> {
        self.backend.delete_credential(id)
    }

    pub fn increment_sign_count(&self, id: &str) -> Result<u32> {
        let now = current_timestamp();
        self.backend.increment_sign_count(id, &now)
    }

    pub fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>> {
        self.backend.get_auth_logs(credential_id, limit)
    }

    pub fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>> {
        self.backend.get_debug_logs(limit)
    }

    pub fn get_security_settings(&self, unlimited_fps: bool) -> Result<SecuritySettings> {
        let raw = self.backend.get_security_settings_raw()?;
        let fp_count = self.backend.get_fingerprint_count()?;

        Ok(SecuritySettings {
            pin_enabled: raw.pin_enabled,
            fp_enabled: raw.fp_enabled,
            require_uv: raw.require_uv,
            fp_count,
            max_fp_slots: if unlimited_fps { None } else { Some(10) },
            updated_at: raw.updated_at,
        })
    }

    pub fn get_pin_hash_and_salt(&self) -> Result<(Option<String>, Option<String>)> {
        let raw = self.backend.get_security_settings_raw()?;
        Ok((raw.pin_hash, raw.pin_salt))
    }

    pub fn set_pin(&self, pin_hash: &str, pin_salt: &str) -> Result<()> {
        let now = current_timestamp();
        self.backend.set_pin(pin_hash, pin_salt, &now)
    }

    pub fn remove_pin(&self) -> Result<()> {
        let now = current_timestamp();
        self.backend.remove_pin(&now)
    }

    pub fn set_require_uv(&self, require: bool) -> Result<()> {
        let now = current_timestamp();
        self.backend.set_require_uv(require, &now)
    }

    pub fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>> {
        self.backend.get_fingerprints()
    }

    pub fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>> {
        self.backend.get_fingerprint_by_id(id)
    }

    pub fn add_fingerprint(&self, slot_index: u32, name: &str) -> Result<FingerprintRow> {
        let now = current_timestamp();
        self.backend.add_fingerprint(slot_index, name, &now)
    }

    pub fn delete_fingerprint(&self, id: i64) -> Result<bool> {
        self.backend.delete_fingerprint(id)
    }

    pub fn export_data(&self) -> Result<DatabaseExport> {
        let credentials = self.backend.get_credentials()?;
        let auth_logs = self.backend.get_auth_logs(None, usize::MAX)?;
        let security_settings = self.backend.get_security_settings_raw()?;
        let fingerprints = self.backend.get_fingerprints()?;
        let debug_logs = self.backend.get_debug_logs(usize::MAX)?;

        Ok(DatabaseExport {
            version: 1,
            exported_at: current_timestamp(),
            database_backend: self.backend.backend_name().to_string(),
            credentials,
            auth_logs,
            security_settings,
            fingerprints,
            debug_logs,
        })
    }

    pub fn import_data(&self, data: &DatabaseExport) -> Result<ImportStats> {
        let mut stats = ImportStats::default();

        // 1. Import security settings (PIN, UV, etc.)
        self.backend.set_security_settings_all(&data.security_settings)?;
        stats.security_settings_updated = true;

        // 2. Import credentials
        for c in &data.credentials {
            let uid = hex::decode(&c.user_id_hex).unwrap_or_default();
            let sec1 = hex::decode(&c.private_key_sec1_hex).unwrap_or_default();
            let cose = hex::decode(&c.public_key_cose_hex).unwrap_or_default();
            self.backend.insert_credential(
                &c.id,
                &c.rp_id,
                &uid,
                &c.user_name,
                &c.user_display_name,
                &sec1,
                &cose,
                c.sign_count,
                &c.created_at,
                &c.last_used_at,
            )?;
            stats.credentials_imported += 1;
        }

        // 3. Import fingerprints
        for fp in &data.fingerprints {
            self.backend.insert_fingerprint_full(fp.id, fp.slot_index, &fp.name, &fp.enrolled_at)?;
            stats.fingerprints_imported += 1;
        }

        // 4. Import auth logs
        for log in &data.auth_logs {
            self.backend.insert_auth_log_full(
                log.id,
                log.credential_id.as_deref(),
                &log.rp_id,
                &log.operation,
                &log.status,
                &log.auth_method,
                log.details.as_deref(),
                &log.created_at,
            )?;
            stats.auth_logs_imported += 1;
        }

        // 5. Import debug logs
        for log in &data.debug_logs {
            self.backend.insert_debug_log_full(
                log.id,
                &log.level,
                &log.component,
                &log.message,
                &log.created_at,
            )?;
            stats.debug_logs_imported += 1;
        }

        Ok(stats)
    }

    pub fn export_to_file(&self, path: &str) -> Result<()> {
        let export = self.export_data()?;
        let json = serde_json::to_string_pretty(&export).map_err(DbError::Json)?;
        std::fs::write(path, json).map_err(DbError::Io)?;
        Ok(())
    }

    pub fn import_from_file(&self, path: &str) -> Result<ImportStats> {
        let json = std::fs::read_to_string(path).map_err(DbError::Io)?;
        let export: DatabaseExport = serde_json::from_str(&json).map_err(DbError::Json)?;
        self.import_data(&export)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

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

    #[test]
    fn test_export_import_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let export_path = temp_dir.join(format!("vrtfido_test_export_{}.json", rand::random::<u32>()));
        let export_path_str = export_path.to_str().unwrap();

        let db1 = create_test_db();
        // 1. Setup rich data
        db1.save_credential(
            "cred_1",
            "example.com",
            b"user_123",
            "bob",
            "Bob Smith",
            b"priv_key_bytes",
            b"pub_key_bytes",
            5,
        ).unwrap();

        db1.set_pin("hash_pin_123", "salt_456").unwrap();
        db1.add_fingerprint(1, "Right Index").unwrap();
        db1.add_fingerprint(2, "Left Thumb").unwrap();
        db1.log_auth(Some("cred_1"), "example.com", "GetAssertion", "SUCCESS", "PIN", Some("Test auth"));
        db1.log_debug("INFO", "TEST", "Testing export import");

        // 2. Export to file
        db1.export_to_file(export_path_str).expect("Failed to export");

        // 3. Create fresh DB2 and import
        let db2 = create_test_db();
        let stats = db2.import_from_file(export_path_str).expect("Failed to import");

        assert_eq!(stats.credentials_imported, 1);
        assert_eq!(stats.fingerprints_imported, 2);
        assert_eq!(stats.auth_logs_imported, 1);
        assert_eq!(stats.debug_logs_imported, 1);
        assert!(stats.security_settings_updated);

        // 4. Verify 100% data fidelity in DB2
        let creds = db2.get_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, "cred_1");
        assert_eq!(creds[0].rp_id, "example.com");
        assert_eq!(creds[0].user_name, "bob");
        assert_eq!(creds[0].user_display_name, "Bob Smith");
        assert_eq!(creds[0].sign_count, 5);
        assert_eq!(hex::decode(&creds[0].user_id_hex).unwrap(), b"user_123");
        assert_eq!(hex::decode(&creds[0].private_key_sec1_hex).unwrap(), b"priv_key_bytes");
        assert_eq!(hex::decode(&creds[0].public_key_cose_hex).unwrap(), b"pub_key_bytes");

        let (hash, salt) = db2.get_pin_hash_and_salt().unwrap();
        assert_eq!(hash.as_deref(), Some("hash_pin_123"));
        assert_eq!(salt.as_deref(), Some("salt_456"));

        let fps = db2.get_fingerprints().unwrap();
        assert_eq!(fps.len(), 2);
        assert_eq!(fps[0].slot_index, 1);
        assert_eq!(fps[0].name, "Right Index");
        assert_eq!(fps[1].slot_index, 2);
        assert_eq!(fps[1].name, "Left Thumb");

        let auth_logs = db2.get_auth_logs(None, 10).unwrap();
        assert_eq!(auth_logs.len(), 1);
        assert_eq!(auth_logs[0].credential_id.as_deref(), Some("cred_1"));
        assert_eq!(auth_logs[0].operation, "GetAssertion");

        let debug_logs = db2.get_debug_logs(10).unwrap();
        assert_eq!(debug_logs.len(), 1);
        assert_eq!(debug_logs[0].component, "TEST");
        assert_eq!(debug_logs[0].message, "Testing export import");

        let _ = std::fs::remove_file(export_path);
    }

    #[test]
    fn test_libsql_local_backend() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("vrtfido_test_libsql_{}.db", rand::random::<u32>()));
        let path_str = db_path.to_str().unwrap();

        let db = Db::open_with_options(path_str, Some("libsql"), None).expect("Failed to open libsql db");
        assert_eq!(db.backend_name(), "LibSQL");

        db.save_credential(
            "libsql_cred_1",
            "example.org",
            b"libsql_user",
            "libsql_test",
            "LibSQL User",
            b"priv_sec1",
            b"pub_cose",
            1,
        ).unwrap();

        let creds = db.get_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, "libsql_cred_1");
        assert_eq!(creds[0].user_name, "libsql_test");

        db.set_pin("libsql_pin", "libsql_salt").unwrap();
        let (pin, salt) = db.get_pin_hash_and_salt().unwrap();
        assert_eq!(pin.as_deref(), Some("libsql_pin"));
        assert_eq!(salt.as_deref(), Some("libsql_salt"));

        let count = db.increment_sign_count("libsql_cred_1").unwrap();
        assert_eq!(count, 2);

        let del_ok = db.delete_credential("libsql_cred_1").unwrap();
        assert!(del_ok);
        assert_eq!(db.get_credentials().unwrap().len(), 0);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_live_postgres_backend() {
        let pg_url = "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres";
        let db = match Db::open(pg_url) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("PostgreSQL not reachable or auth failed: {}, skipping", e);
                return;
            }
        };
        assert_eq!(db.backend_name(), "PostgreSQL");

        let test_id = format!("pg_test_{}", rand::random::<u32>());
        db.save_credential(
            &test_id,
            "postgres.test",
            b"pg_uid",
            "pg_user",
            "Postgres User",
            b"pg_sec1",
            b"pg_cose",
            1,
        ).expect("Failed to save credential in Postgres");

        let cred = db.get_credential(&test_id).expect("Failed to get credential").expect("Credential not found");
        assert_eq!(cred.id, test_id);
        assert_eq!(cred.user_name, "pg_user");
        assert_eq!(hex::decode(&cred.user_id_hex).unwrap(), b"pg_uid");

        let count = db.increment_sign_count(&test_id).expect("Failed to increment sign count");
        assert_eq!(count, 2);

        db.log_debug("INFO", "PG_TEST", "Postgres backend works!");
        let debug_logs = db.get_debug_logs(5).expect("Failed to get debug logs");
        assert!(!debug_logs.is_empty());

        let export = db.export_data().expect("Failed to export from Postgres");
        assert_eq!(export.database_backend, "PostgreSQL");
        assert!(export.credentials.iter().any(|c| c.id == test_id));

        let del = db.delete_credential(&test_id).expect("Failed to delete credential");
        assert!(del);
    }
}
