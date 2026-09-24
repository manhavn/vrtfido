use super::{
    AuthLogRow, CredentialRow, DbBackend, DbError, DebugLogRow, FingerprintRow,
    SecuritySettingsData,
};
use mysql::prelude::Queryable;
use mysql::{Opts, Pool};
use std::sync::Arc;

pub struct MySqlBackend {
    pool: Arc<Pool>,
}

impl MySqlBackend {
    pub fn open(url: &str) -> Result<Self, DbError> {
        let clean_url = if url.starts_with("mariadb://") {
            format!("mysql://{}", &url["mariadb://".len()..])
        } else {
            url.to_string()
        };

        let opts = Opts::from_url(&clean_url).map_err(|e| DbError::MySql(e.to_string()))?;
        let pool = Pool::new(opts).map_err(|e| DbError::MySql(e.to_string()))?;

        let mut conn = pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS credentials (
                 id VARCHAR(255) PRIMARY KEY,
                 rp_id VARCHAR(255) NOT NULL,
                 user_id VARBINARY(1024) NOT NULL,
                 user_name VARCHAR(255) NOT NULL,
                 user_display_name VARCHAR(255) NOT NULL,
                 private_key_sec1 VARBINARY(1024) NOT NULL,
                 public_key_cose VARBINARY(1024) NOT NULL,
                 sign_count INT UNSIGNED NOT NULL DEFAULT 1,
                 created_at VARCHAR(64) NOT NULL,
                 last_used_at VARCHAR(64) NOT NULL,
                 INDEX idx_credentials_rp_user (rp_id, user_name)
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS auth_logs (
                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                 credential_id VARCHAR(255),
                 rp_id VARCHAR(255) NOT NULL,
                 operation VARCHAR(64) NOT NULL,
                 status VARCHAR(64) NOT NULL,
                 auth_method VARCHAR(64) NOT NULL,
                 details TEXT,
                 created_at VARCHAR(64) NOT NULL
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS security_settings (
                 id INT PRIMARY KEY,
                 pin_hash TEXT,
                 pin_salt TEXT,
                 pin_enabled TINYINT(1) NOT NULL DEFAULT 0,
                 fp_enabled TINYINT(1) NOT NULL DEFAULT 1,
                 require_uv TINYINT(1) NOT NULL DEFAULT 1,
                 updated_at VARCHAR(64) NOT NULL
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS fingerprints (
                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                 slot_index INT NOT NULL UNIQUE,
                 name VARCHAR(255) NOT NULL,
                 enrolled_at VARCHAR(64) NOT NULL
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS app_settings (
                setting_key VARCHAR(128) PRIMARY KEY,
                value TEXT NOT NULL
            )",
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS debug_logs (
                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                 level VARCHAR(32) NOT NULL,
                 component VARCHAR(64) NOT NULL,
                 message TEXT NOT NULL,
                 created_at VARCHAR(64) NOT NULL
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        conn.query_drop(
            "INSERT IGNORE INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
             VALUES (1, NULL, NULL, 0, 1, 1, DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s'));"
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }
}

impl DbBackend for MySqlBackend {
    fn backend_name(&self) -> &'static str {
        "MySQL/MariaDB"
    }

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let _ = conn.exec_drop(
            "INSERT INTO debug_logs (level, component, message, created_at) VALUES (?, ?, ?, ?)",
            (level, component, message, now),
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
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let _ = conn.exec_drop(
            "INSERT INTO auth_logs (credential_id, rp_id, operation, status, auth_method, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            (credential_id, rp_id, operation, status, auth_method, details, now),
        );
        Ok(())
    }

    fn get_app_settings(&self) -> Result<Vec<(String, String)>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(String, String)> = conn
            .query("SELECT setting_key, value FROM app_settings ORDER BY setting_key")
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(rows)
    }

    fn set_app_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO app_settings (setting_key, value) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE value = VALUES(value)",
            (key, value),
        )
        .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn get_credentials(&self) -> Result<Vec<CredentialRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(
            String, String, Vec<u8>, String, String,
            Vec<u8>, Vec<u8>, u32, String, String
        )> = conn.query(
            "SELECT id, rp_id, user_id, user_name, user_display_name,
                    private_key_sec1, public_key_cose, sign_count, created_at, last_used_at
             FROM credentials ORDER BY last_used_at DESC",
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        let mut list = Vec::new();
        for (id, rp_id, uid, u_name, u_disp, sec1, cose, sign_count, created_at, last_used_at) in rows {
            list.push(CredentialRow {
                id,
                rp_id,
                user_id_hex: hex::encode(uid),
                user_name: u_name,
                user_display_name: u_disp,
                private_key_sec1_hex: hex::encode(sec1),
                public_key_cose_hex: hex::encode(cose),
                sign_count,
                created_at,
                last_used_at,
            });
        }
        Ok(list)
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let row: Option<(
            String, String, Vec<u8>, String, String,
            Vec<u8>, Vec<u8>, u32, String, String
        )> = conn.exec_first(
            "SELECT id, rp_id, user_id, user_name, user_display_name,
                    private_key_sec1, public_key_cose, sign_count, created_at, last_used_at
             FROM credentials WHERE id = ?",
            (id,),
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        if let Some((id, rp_id, uid, u_name, u_disp, sec1, cose, sign_count, created_at, last_used_at)) = row {
            Ok(Some(CredentialRow {
                id,
                rp_id,
                user_id_hex: hex::encode(uid),
                user_name: u_name,
                user_display_name: u_disp,
                private_key_sec1_hex: hex::encode(sec1),
                public_key_cose_hex: hex::encode(cose),
                sign_count,
                created_at,
                last_used_at,
            }))
        } else {
            Ok(None)
        }
    }

    fn get_credentials_for_rp(&self, rp_id: &str) -> Result<Vec<(String, Vec<u8>, String, String)>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(String, Vec<u8>, String, String)> = conn.exec(
            "SELECT id, user_id, user_name, created_at FROM credentials WHERE LOWER(rp_id) = LOWER(?)",
            (rp_id,),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(rows)
    }

    fn delete_credential(&self, id: &str) -> Result<bool, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop("DELETE FROM credentials WHERE id = ?", (id,))
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(conn.affected_rows() > 0)
    }

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "UPDATE credentials SET user_name = ?, user_display_name = ? WHERE id = ?",
            (name, display_name, id),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(conn.affected_rows() > 0)
    }

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let _ = conn.exec_drop(
            "UPDATE auth_logs SET credential_id = ? WHERE credential_id = ?",
            (new_id, old_id),
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
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO credentials (id, rp_id, user_id, user_name, user_display_name,
                                      private_key_sec1, public_key_cose, sign_count, created_at, last_used_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                 rp_id = VALUES(rp_id),
                 user_id = VALUES(user_id),
                 user_name = VALUES(user_name),
                 user_display_name = VALUES(user_display_name),
                 private_key_sec1 = VALUES(private_key_sec1),
                 public_key_cose = VALUES(public_key_cose),
                 sign_count = VALUES(sign_count),
                 created_at = VALUES(created_at),
                 last_used_at = VALUES(last_used_at)",
            (
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
            ),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "UPDATE credentials SET sign_count = sign_count + 1, last_used_at = ? WHERE id = ?",
            (now, id),
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        let count: Option<u32> = conn.exec_first(
            "SELECT sign_count FROM credentials WHERE id = ?",
            (id,),
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        if let Some(c) = count {
            Ok(c)
        } else {
            Err(DbError::MySql("Credential not found".into()))
        }
    }

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(i64, Option<String>, String, String, String, String, Option<String>, String)> =
            match (credential_id, limit == usize::MAX) {
                (Some(cid), false) => conn.exec(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs WHERE credential_id = ? ORDER BY id DESC LIMIT ?",
                    (cid, limit as u64),
                ).map_err(|e| DbError::MySql(e.to_string()))?,
                (Some(cid), true) => conn.exec(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs WHERE credential_id = ? ORDER BY id DESC",
                    (cid,),
                ).map_err(|e| DbError::MySql(e.to_string()))?,
                (None, false) => conn.exec(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs ORDER BY id DESC LIMIT ?",
                    (limit as u64,),
                ).map_err(|e| DbError::MySql(e.to_string()))?,
                (None, true) => conn.query(
                    "SELECT id, credential_id, rp_id, operation, status, auth_method, details, created_at
                     FROM auth_logs ORDER BY id DESC",
                ).map_err(|e| DbError::MySql(e.to_string()))?,
            };

        let mut list = Vec::new();
        for (id, cid, rp_id, operation, status, auth_method, details, created_at) in rows {
            list.push(AuthLogRow {
                id,
                credential_id: cid,
                rp_id,
                operation,
                status,
                auth_method,
                details,
                created_at,
            });
        }
        Ok(list)
    }

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(i64, String, String, String, String)> = if limit == usize::MAX {
            conn.query(
                "SELECT id, level, component, message, created_at FROM debug_logs ORDER BY id DESC",
            ).map_err(|e| DbError::MySql(e.to_string()))?
        } else {
            conn.exec(
                "SELECT id, level, component, message, created_at FROM debug_logs ORDER BY id DESC LIMIT ?",
                (limit as u64,),
            ).map_err(|e| DbError::MySql(e.to_string()))?
        };

        let mut list = Vec::new();
        for (id, level, component, message, created_at) in rows {
            list.push(DebugLogRow {
                id,
                level,
                component,
                message,
                created_at,
            });
        }
        Ok(list)
    }

    fn clear_auth_logs(&self) -> Result<usize, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop("DELETE FROM auth_logs", ())
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(conn.affected_rows() as usize)
    }

    fn clear_debug_logs(&self) -> Result<usize, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop("DELETE FROM debug_logs", ())
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(conn.affected_rows() as usize)
    }

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let row: Option<(Option<String>, Option<String>, i8, i8, i8, String)> = conn.query_first(
            "SELECT pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at FROM security_settings WHERE id = 1",
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        if let Some((pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)) = row {
            Ok(SecuritySettingsData {
                pin_hash,
                pin_salt,
                pin_enabled: pin_enabled != 0,
                fp_enabled: fp_enabled != 0,
                require_uv: require_uv != 0,
                updated_at,
            })
        } else {
            Err(DbError::MySql("Security settings row not found".into()))
        }
    }

    fn get_fingerprint_count(&self) -> Result<usize, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let count: Option<i64> = conn.query_first("SELECT count(*) FROM fingerprints")
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(count.unwrap_or(0) as usize)
    }

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "UPDATE security_settings
             SET pin_hash = ?, pin_salt = ?, pin_enabled = 1, updated_at = ?
             WHERE id = 1",
            (pin_hash, pin_salt, now),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn remove_pin(&self, now: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "UPDATE security_settings
             SET pin_hash = NULL, pin_salt = NULL, pin_enabled = 0, updated_at = ?
             WHERE id = 1",
            (now,),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn set_require_uv(&self, require: bool, now: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let req_val: i8 = if require { 1 } else { 0 };
        conn.exec_drop(
            "UPDATE security_settings SET require_uv = ?, updated_at = ? WHERE id = 1",
            (req_val, now),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let p_en: i8 = if settings.pin_enabled { 1 } else { 0 };
        let fp_en: i8 = if settings.fp_enabled { 1 } else { 0 };
        let r_uv: i8 = if settings.require_uv { 1 } else { 0 };

        conn.exec_drop(
            "INSERT INTO security_settings (id, pin_hash, pin_salt, pin_enabled, fp_enabled, require_uv, updated_at)
             VALUES (1, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                 pin_hash = VALUES(pin_hash),
                 pin_salt = VALUES(pin_salt),
                 pin_enabled = VALUES(pin_enabled),
                 fp_enabled = VALUES(fp_enabled),
                 require_uv = VALUES(require_uv),
                 updated_at = VALUES(updated_at)",
            (
                &settings.pin_hash,
                &settings.pin_salt,
                p_en,
                fp_en,
                r_uv,
                &settings.updated_at,
            ),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let rows: Vec<(i64, u32, String, String)> = conn.query(
            "SELECT id, slot_index, name, enrolled_at FROM fingerprints ORDER BY slot_index ASC",
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        let mut list = Vec::new();
        for (id, slot_index, name, enrolled_at) in rows {
            list.push(FingerprintRow {
                id,
                slot_index,
                name,
                enrolled_at,
            });
        }
        Ok(list)
    }

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        let row: Option<(i64, u32, String, String)> = conn.exec_first(
            "SELECT id, slot_index, name, enrolled_at FROM fingerprints WHERE id = ?",
            (id,),
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        if let Some((fid, slot_index, name, enrolled_at)) = row {
            Ok(Some(FingerprintRow {
                id: fid,
                slot_index,
                name,
                enrolled_at,
            }))
        } else {
            Ok(None)
        }
    }

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO fingerprints (slot_index, name, enrolled_at) VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE name = VALUES(name), enrolled_at = VALUES(enrolled_at)",
            (slot_index, name, now),
        ).map_err(|e| DbError::MySql(e.to_string()))?;

        let id = conn.last_insert_id() as i64;

        Ok(FingerprintRow {
            id,
            slot_index,
            name: name.to_string(),
            enrolled_at: now.to_string(),
        })
    }

    fn delete_fingerprint(&self, id: i64) -> Result<bool, DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop("DELETE FROM fingerprints WHERE id = ?", (id,))
            .map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(conn.affected_rows() > 0)
    }

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<(), DbError> {
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO fingerprints (id, slot_index, name, enrolled_at) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE slot_index = VALUES(slot_index), name = VALUES(name), enrolled_at = VALUES(enrolled_at)",
            (id, slot_index, name, enrolled_at),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
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
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "REPLACE INTO auth_logs (id, credential_id, rp_id, operation, status, auth_method, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (id, credential_id, rp_id, operation, status, auth_method, details, created_at),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
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
        let mut conn = self.pool.get_conn().map_err(|e| DbError::MySql(e.to_string()))?;
        conn.exec_drop(
            "REPLACE INTO debug_logs (id, level, component, message, created_at)
             VALUES (?, ?, ?, ?, ?)",
            (id, level, component, message, created_at),
        ).map_err(|e| DbError::MySql(e.to_string()))?;
        Ok(())
    }
}
