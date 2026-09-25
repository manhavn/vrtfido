use crate::db::Db;
use crate::security::SecurityEngine;
use axum::{
    extract::{Path, State},
    http::header,
    response::{Html, IntoResponse},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub security: SecurityEngine,
    pub debug_mode: Arc<AtomicBool>,
    pub uhid_connected: Arc<AtomicBool>,
    pub unlimited_fps: bool,
    pub port: u16,
}
#[derive(Serialize)]
pub struct SystemStatus {
    pub app_name: &'static str,
    pub version: &'static str,
    pub port: u16,
    pub uhid_connected: bool,
    pub usb_sensor_connected: bool,
    pub debug_mode: bool,
    pub credentials_count: usize,
    pub pin_configured: bool,
    pub fp_count: usize,
    pub unlimited_fingerprints: bool,
    pub database_backend: &'static str,
}

#[derive(Deserialize)]
pub struct UpdateCredentialRequest {
    pub user_name: String,
    pub user_display_name: String,
}

#[derive(Deserialize)]
pub struct SetPinRequest {
    pub pin: String,
    pub old_pin: Option<String>,
}

#[derive(Deserialize)]
pub struct RemovePinRequest {
    pub current_pin: String,
}

#[derive(Deserialize)]
pub struct AddFingerprintRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct ApproveVerifyRequest {
    pub request_id: u64,
    pub method: String,
    pub pin: Option<String>,
    pub credential_id: Option<String>,
}
#[derive(Deserialize)]
pub struct SelectAccountRequest {
    pub request_id: u64,
    pub credential_id: String,
}


#[derive(Deserialize)]
pub struct RejectVerifyRequest {
    pub request_id: u64,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/favicon.ico", get(favicon_ico))
        .route("/api/status", get(get_status))
        .route("/api/credentials", get(list_credentials))
        .route("/api/credentials/{id}", put(update_credential))
        .route("/api/credentials/{id}", delete(delete_credential))
        .route("/api/credentials/{id}/logs", get(get_credential_logs))
        .route("/api/logs", get(list_auth_logs).delete(clear_auth_logs))
        .route("/api/debug-logs", get(list_debug_logs).delete(clear_debug_logs))
        .route("/api/logs/clean", post(clean_all_logs).delete(clean_all_logs))
        .route("/api/security", get(get_security))
        .route("/api/security/pin", post(set_pin))
        .route("/api/security/pin", delete(remove_pin))
        .route("/api/security/fingerprints", post(add_fingerprint))
        .route("/api/security/fingerprints/enroll/start", post(start_enroll_fingerprint))
        .route("/api/security/fingerprints/enroll/status", get(get_enroll_status))
        .route("/api/security/fingerprints/enroll/cancel", post(cancel_enroll))
        .route("/api/security/fingerprints/{id}", delete(delete_fingerprint))
        .route("/api/verify/pending", get(get_pending_verify))
        .route("/api/verify/select", post(select_verify_account))
        .route("/api/verify/approve", post(approve_verify))
        .route("/api/verify/reject", post(reject_verify))
        .route("/api/settings", get(get_settings))
        .route("/api/settings", post(update_settings))
        .route("/api/database/export", get(export_database))
        .route("/api/database/import", post(import_database))
        .route("/api/passkey/candidates", post(passkey_candidates))
        .route("/api/passkey/create", post(passkey_create))
        .route("/api/passkey/get", post(passkey_get))
        .with_state(state)
}

async fn get_status(State(state): State<AppState>) -> Json<ApiResponse<SystemStatus>> {
    let creds = state.db.get_credentials().unwrap_or_default();
    let sec = state.db.get_security_settings(state.unlimited_fps).unwrap_or(crate::db::SecuritySettings {
        pin_enabled: false,
        fp_enabled: true,
        require_uv: true,
        fp_count: 0,
        max_fp_slots: if state.unlimited_fps { None } else { Some(10) },
        updated_at: "".into(),
    });

    Json(ApiResponse::ok(SystemStatus {
        app_name: "VrtFido",
        version: env!("CARGO_PKG_VERSION"),
        port: state.port,
        uhid_connected: state.uhid_connected.load(Ordering::SeqCst),
        usb_sensor_connected: crate::sensor::UsbSensor::is_hardware_plugged(),
        debug_mode: state.debug_mode.load(Ordering::SeqCst),
        credentials_count: creds.len(),
        pin_configured: sec.pin_enabled,
        fp_count: sec.fp_count,
        unlimited_fingerprints: state.unlimited_fps,
        database_backend: state.db.backend_name(),
    }))
}

async fn list_credentials(State(state): State<AppState>) -> Json<ApiResponse<Vec<crate::db::CredentialRow>>> {
    match state.db.get_credentials() {
        Ok(creds) => Json(ApiResponse::ok(creds)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn update_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateCredentialRequest>,
) -> Json<ApiResponse<bool>> {
    match state.db.update_credential_name(&id, &payload.user_name, &payload.user_display_name) {
        Ok(ok) => {
            state.db.log_auth(
                Some(&id),
                "CMS",
                "CredentialUpdate",
                "SUCCESS",
                "CMS",
                Some(&format!("Update credential name: {}", payload.user_name)),
            );
            Json(ApiResponse::ok(ok))
        }
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn delete_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<bool>> {
    match state.db.delete_credential(&id) {
        Ok(ok) => {
            state.db.log_auth(
                Some(&id),
                "CMS",
                "CredentialDelete",
                "SUCCESS",
                "CMS",
                Some("Delete credential from store"),
            );
            Json(ApiResponse::ok(ok))
        }
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn get_credential_logs(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<Vec<crate::db::AuthLogRow>>> {
    match state.db.get_auth_logs(Some(&id), 100) {
        Ok(logs) => Json(ApiResponse::ok(logs)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn list_auth_logs(State(state): State<AppState>) -> Json<ApiResponse<Vec<crate::db::AuthLogRow>>> {
    match state.db.get_auth_logs(None, 200) {
        Ok(logs) => Json(ApiResponse::ok(logs)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn list_debug_logs(State(state): State<AppState>) -> Json<ApiResponse<Vec<crate::db::DebugLogRow>>> {
    match state.db.get_debug_logs(200) {
        Ok(logs) => Json(ApiResponse::ok(logs)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

#[derive(Serialize)]
pub struct CleanLogsResult {
    pub auth_logs_deleted: usize,
    pub debug_logs_deleted: usize,
}

async fn clear_auth_logs(State(state): State<AppState>) -> Json<ApiResponse<usize>> {
    match state.db.clear_auth_logs() {
        Ok(count) => Json(ApiResponse::ok(count)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn clear_debug_logs(State(state): State<AppState>) -> Json<ApiResponse<usize>> {
    match state.db.clear_debug_logs() {
        Ok(count) => Json(ApiResponse::ok(count)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn clean_all_logs(State(state): State<AppState>) -> Json<ApiResponse<CleanLogsResult>> {
    match state.db.clear_all_logs() {
        Ok((auth, debug)) => {
            let daemon_log_path = std::env::temp_dir().join("vrtfido.log");
            if daemon_log_path.exists() {
                let _ = std::fs::write(&daemon_log_path, "");
            }
            Json(ApiResponse::ok(CleanLogsResult {
                auth_logs_deleted: auth,
                debug_logs_deleted: debug,
            }))
        }
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

#[derive(Serialize)]
pub struct SecurityView {
    pub settings: crate::db::SecuritySettings,
    pub fingerprints: Vec<crate::db::FingerprintRow>,
}

async fn get_security(State(state): State<AppState>) -> Json<ApiResponse<SecurityView>> {
    let settings = match state.db.get_security_settings(state.unlimited_fps) {
        Ok(s) => s,
        Err(e) => return Json(ApiResponse::err(e.to_string())),
    };
    let fps = state.db.get_fingerprints().unwrap_or_default();
    Json(ApiResponse::ok(SecurityView {
        settings,
        fingerprints: fps,
    }))
}

async fn set_pin(
    State(state): State<AppState>,
    Json(payload): Json<SetPinRequest>,
) -> Json<ApiResponse<bool>> {
    let res = if let Some(old) = payload.old_pin {
        state.security.change_pin(&old, &payload.pin)
    } else {
        state.security.set_pin(&payload.pin)
    };

    match res {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn remove_pin(
    State(state): State<AppState>,
    Json(payload): Json<RemovePinRequest>,
) -> Json<ApiResponse<bool>> {
    match state.security.remove_pin(&payload.current_pin) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn start_enroll_fingerprint(
    State(state): State<AppState>,
    Json(payload): Json<AddFingerprintRequest>,
) -> Json<ApiResponse<bool>> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Json(ApiResponse::err("Fingerprint label cannot be empty"));
    }
    // Answer with the real reason (sensor unplugged, slot limit, busy) so the modal cannot sit
    // on "connecting" forever while a background task waits for a sensor that is not there.
    if let Err(e) = state.security.can_enroll_fingerprint() {
        return Json(ApiResponse::err(e));
    }
    let sec = state.security.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = sec.enroll_fingerprint(&name) {
            // The 6-stage scan reports its own failure through the enroll progress the modal
            // polls; this line keeps the daemon log complete for a failed attempt.
            eprintln!("[CMS] Fingerprint enrollment failed: {}", e);
        }
    });
    Json(ApiResponse::ok(true))
}

async fn get_enroll_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<crate::sensor::EnrollProgress>> {
    let p = state.security.sensor().get_enroll_progress();
    Json(ApiResponse::ok(p))
}

async fn cancel_enroll(
    State(state): State<AppState>,
) -> Json<ApiResponse<bool>> {
    state.security.sensor().cancel_current_op();
    Json(ApiResponse::ok(true))
}

async fn add_fingerprint(
    State(state): State<AppState>,
    Json(payload): Json<AddFingerprintRequest>,
) -> Json<ApiResponse<crate::db::FingerprintRow>> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Json(ApiResponse::err("Fingerprint label cannot be empty"));
    }
    let sec = state.security.clone();
    let res = tokio::task::spawn_blocking(move || sec.enroll_fingerprint(&name)).await;
    match res {
        Ok(Ok(row)) => Json(ApiResponse::ok(row)),
        Ok(Err(e)) => Json(ApiResponse::err(e)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn delete_fingerprint(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<bool>> {
    match state.security.delete_fingerprint(id) {
        Ok(ok) => Json(ApiResponse::ok(ok)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn get_pending_verify(
    State(state): State<AppState>,
) -> Json<ApiResponse<Option<crate::security::PendingPrompt>>> {
    let p = state.security.get_pending_prompt();
    Json(ApiResponse::ok(p))
}

async fn approve_verify(
    State(state): State<AppState>,
    Json(payload): Json<ApproveVerifyRequest>,
) -> Json<ApiResponse<bool>> {
    match state.security.approve_pending(
        payload.request_id,
        &payload.method,
        payload.pin.as_deref(),
        payload.credential_id,
    ) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn select_verify_account(
    State(state): State<AppState>,
    Json(payload): Json<SelectAccountRequest>,
) -> Json<ApiResponse<bool>> {
    match state.security.select_account(payload.request_id, &payload.credential_id) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn reject_verify(
    State(state): State<AppState>,
    Json(payload): Json<RejectVerifyRequest>,
) -> Json<ApiResponse<bool>> {
    let reason = payload.reason.unwrap_or_else(|| "User rejected operation".into());
    match state.security.reject_pending(payload.request_id, &reason) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

/// Supported UI languages; anything else is rejected so a bad client cannot brick the UI.
const SUPPORTED_LANGUAGES: [&str; 2] = ["en", "vi"];
const DEFAULT_LANGUAGE: &str = "en";
/// Port used when the app has no stored daemon configuration yet.
const DEFAULT_DAEMON_PORT: u16 = 10209;

#[derive(Deserialize, Default)]
pub struct DaemonSettingsUpdate {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub db_type: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub debug: Option<bool>,
    #[serde(default)]
    pub unlimited_fingerprints: Option<bool>,
    #[serde(default)]
    pub running: Option<bool>,
}

#[derive(Deserialize, Default)]
pub struct SettingsUpdate {
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub daemon: Option<DaemonSettingsUpdate>,
}

fn settings_map(db: &crate::db::Db) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    map.insert("language".to_string(), DEFAULT_LANGUAGE.to_string());
    map.insert("daemon.port".to_string(), DEFAULT_DAEMON_PORT.to_string());
    map.insert("daemon.debug".to_string(), "false".to_string());
    map.insert("daemon.unlimited_fingerprints".to_string(), "false".to_string());
    map.insert("daemon.running".to_string(), "false".to_string());
    for (key, value) in db.get_app_settings().unwrap_or_default() {
        map.insert(key, value);
    }
    map
}

async fn get_settings(State(state): State<AppState>) -> Json<ApiResponse<std::collections::BTreeMap<String, String>>> {
    let stored = match state.db.get_app_settings() {
        Ok(values) => values,
        Err(e) => return Json(ApiResponse::err(e.to_string())),
    };
    let mut map = settings_map(&state.db);
    map.extend(stored);
    Json(ApiResponse::ok(map))
}

async fn update_settings(
    State(state): State<AppState>,
    Json(payload): Json<SettingsUpdate>,
) -> Json<ApiResponse<std::collections::BTreeMap<String, String>>> {
    let mut writes: Vec<(&str, String)> = Vec::new();

    if let Some(language) = payload.language.as_deref() {
        let language = language.trim().to_lowercase();
        if !SUPPORTED_LANGUAGES.contains(&language.as_str()) {
            return Json(ApiResponse::err(format!(
                "Unsupported language '{language}', expected one of: {}",
                SUPPORTED_LANGUAGES.join(", ")
            )));
        }
        writes.push(("language", language));
    }

    if let Some(daemon) = payload.daemon.as_ref() {
        if let Some(host) = daemon.host.as_deref() {
            let host = host.trim();
            if host.is_empty() {
                return Json(ApiResponse::err("Daemon host must not be empty"));
            }
            writes.push(("daemon.host", host.to_string()));
        }
        if let Some(port) = daemon.port {
            if port == 0 {
                return Json(ApiResponse::err("Daemon port must be between 1 and 65535"));
            }
            writes.push(("daemon.port", port.to_string()));
        }
        if let Some(database) = daemon.database.as_deref() {
            let database = database.trim();
            if database.is_empty() {
                return Json(ApiResponse::err("Daemon database must not be empty"));
            }
            writes.push(("daemon.database", database.to_string()));
        }
        if let Some(db_type) = daemon.db_type.as_deref() {
            writes.push(("daemon.db_type", db_type.trim().to_string()));
        }
        if let Some(auth_token) = daemon.auth_token.as_deref() {
            writes.push(("daemon.auth_token", auth_token.trim().to_string()));
        }
        if let Some(debug) = daemon.debug {
            writes.push(("daemon.debug", debug.to_string()));
        }
        if let Some(unlimited) = daemon.unlimited_fingerprints {
            writes.push(("daemon.unlimited_fingerprints", unlimited.to_string()));
        }
        if let Some(running) = daemon.running {
            writes.push(("daemon.running", running.to_string()));
        }
    }

    for (key, value) in writes {
        if let Err(e) = state.db.set_app_setting(key, &value) {
            return Json(ApiResponse::err(e.to_string()));
        }
    }

    let mut map = settings_map(&state.db);
    map.extend(state.db.get_app_settings().unwrap_or_default());
    Json(ApiResponse::ok(map))
}

async fn export_database(
    State(state): State<AppState>,
) -> Json<ApiResponse<crate::db::DatabaseExport>> {
    match state.db.export_data() {
        Ok(data) => Json(ApiResponse::ok(data)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn import_database(
    State(state): State<AppState>,
    Json(payload): Json<crate::db::DatabaseExport>,
) -> Json<ApiResponse<crate::db::ImportStats>> {
    match state.db.import_data(&payload) {
        Ok(stats) => {
            state.db.log_auth(
                None,
                "CMS",
                "DatabaseImport",
                "SUCCESS",
                "NONE",
                Some(&format!(
                    "Imported {} credentials, {} fingerprints",
                    stats.credentials_imported, stats.fingerprints_imported
                )),
            );
            Json(ApiResponse::ok(stats))
        }
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn passkey_candidates(
    State(state): State<AppState>,
    Json(payload): Json<crate::passkey::CandidatesRequest>,
) -> Json<ApiResponse<Vec<crate::passkey::CandidateItem>>> {
    let items = crate::passkey::get_candidates(&state.db, &payload);
    Json(ApiResponse::ok(items))
}

async fn passkey_create(
    State(state): State<AppState>,
    Json(payload): Json<crate::passkey::PasskeyCreateRequest>,
) -> Json<ApiResponse<crate::passkey::PasskeyCreateResponseData>> {
    match crate::passkey::create_passkey(&state.db, &state.security, payload).await {
        Ok(res) => Json(ApiResponse::ok(res)),
        Err(err) => Json(ApiResponse::err(err)),
    }
}

async fn passkey_get(
    State(state): State<AppState>,
    Json(payload): Json<crate::passkey::PasskeyGetRequest>,
) -> Json<ApiResponse<crate::passkey::PasskeyGetResponseData>> {
    match crate::passkey::get_passkey(&state.db, &state.security, payload).await {
        Ok(res) => Json(ApiResponse::ok(res)),
        Err(err) => Json(ApiResponse::err(err)),
    }
}

async fn index_html() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VrtFido - Virtual FIDO2 & Passkey Manager</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #182234;
            --bg-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #334155;
            --radius: 10px;
            --gap: 1rem;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        html { -webkit-text-size-adjust: 100%; }
        body { background-color: var(--bg-primary); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
        img, svg, table { max-width: 100%; }

        /* ---------- Header ---------- */
        header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 0.85rem 1.5rem; display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; position: sticky; top: 0; z-index: 50; }
        .logo { display: flex; align-items: center; gap: 0.75rem; font-size: 1.2rem; font-weight: 700; color: var(--accent); min-width: 0; }
        .logo span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .status-group { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; justify-content: flex-end; }
        .badge-status { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; white-space: nowrap; }
        .badge-online { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-debug { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }

        .lang-toggle { display: inline-flex; align-items: center; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 9999px; padding: 2px; }
        .lang-btn { background: none; border: none; color: var(--text-muted); font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; padding: 0.25rem 0.7rem; border-radius: 9999px; cursor: pointer; transition: background-color 0.15s, color 0.15s; min-height: 28px; }
        .lang-btn:hover { color: var(--text-main); }
        .lang-btn.active { background: var(--accent); color: #020617; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; flex: 0 0 auto; }

        .container { max-width: 1280px; width: 100%; margin: 0 auto; padding: 1.75rem 1.5rem 3rem; flex: 1; }

        /* ---------- Tabs ---------- */
        .tabs { display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border); margin-bottom: 1.75rem; overflow-x: auto; scrollbar-width: none; }
        .tabs::-webkit-scrollbar { display: none; }
        .tab-btn { background: none; border: none; color: var(--text-muted); padding: 0.75rem 1.25rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; transition: color 0.2s, border-color 0.2s; display: flex; align-items: center; gap: 0.5rem; white-space: nowrap; flex: 0 0 auto; }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* ---------- Cards ---------- */
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.5rem; }
        .card-header { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .card-title { font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
        .card-subtitle { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; }

        /* ---------- Action bars ---------- */
        .action-bar, .form-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
        .input-row { display: flex; gap: 0.5rem; align-items: stretch; flex-wrap: wrap; }
        .input-row .form-control { flex: 1 1 12rem; min-width: 0; }
        .search-input { flex: 1 1 16rem; max-width: 22rem; min-width: 0; }
        /* The search box and Refresh share the header row; the action bar claims the space the
           title leaves over so the input grows to 22rem instead of wrapping above the button. */
        #tab-creds .card-header .action-bar { flex: 1 1 auto; justify-content: flex-end; }

        /* ---------- Tables ---------- */
        .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        .table-wrap.scroll-y { max-height: 400px; overflow-y: auto; }
        /* Fixed layout plus per-column budgets keeps long domains, usernames and log messages
           inside the card instead of stretching the table; the value itself is clipped with an
           ellipsis by .cell-value and the full text is exposed through a title tooltip. */
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; table-layout: fixed; }
        th { padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); background: var(--bg-secondary); white-space: nowrap; position: sticky; top: 0; z-index: 1; overflow: hidden; text-overflow: ellipsis; }
        td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(51, 65, 85, 0.5); vertical-align: middle; }
        tbody tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(51, 65, 85, 0.2); }
        .cell-value { display: block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .actions-cell { white-space: normal; }
        .actions-cell .btn + .btn { margin-left: 0.4rem; }
        .empty-row td { text-align: center; color: var(--text-muted); padding: 2rem 1rem; }

        /* Column budgets. These percentages are only the pre-JS fallback: sizeTableColumns()
           measures the rigid columns (timestamps, badges, buttons) and hands the remaining width
           to the columns marked .col-flex, so long domains, usernames and log messages are the
           only values that ever get clipped. */
        .table-creds th:nth-child(1) { width: 16%; }
        .table-creds th:nth-child(2) { width: 11%; }
        .table-creds th:nth-child(3) { width: 11%; }
        .table-creds th:nth-child(4) { width: 12%; }
        .table-creds th:nth-child(5) { width: 15%; }
        .table-creds th:nth-child(6) { width: 15%; }
        .table-creds th:nth-child(7) { width: 20%; }
        .table-fp th:nth-child(1) { width: 18%; }
        .table-fp th:nth-child(2) { width: 21%; }
        .table-fp th:nth-child(3) { width: 34%; }
        .table-fp th:nth-child(4) { width: 27%; }
        .table-logs th:nth-child(1) { width: 18%; }
        .table-logs th:nth-child(2) { width: 19%; }
        .table-logs th:nth-child(3) { width: 14%; }
        .table-logs th:nth-child(4) { width: 13%; }
        .table-logs th:nth-child(5) { width: 14%; }
        .table-logs th:nth-child(6) { width: 22%; }
        .table-debug th:nth-child(1) { width: 18%; }
        .table-debug th:nth-child(2) { width: 13%; }
        .table-debug th:nth-child(3) { width: 21%; }
        .table-debug th:nth-child(4) { width: 48%; }

        /* ---------- Buttons ---------- */
        .btn { padding: 0.55rem 1rem; border-radius: 8px; font-weight: 600; font-size: 0.85rem; cursor: pointer; border: 1px solid transparent; transition: background-color 0.15s, color 0.15s, border-color 0.15s; display: inline-flex; align-items: center; justify-content: center; gap: 0.4rem; min-height: 40px; line-height: 1.1; }
        .btn-primary { background: var(--accent); color: #020617; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border-color: rgba(239, 68, 68, 0.3); }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-secondary { background: var(--bg-hover); color: var(--text-main); }
        .btn-secondary:hover { background: #475569; }
        .btn-sm { padding: 0.4rem 0.7rem; font-size: 0.8rem; min-height: 34px; }

        /* ---------- Forms ---------- */
        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; color: var(--text-muted); }
        .form-control { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 0.85rem; color: var(--text-main); font-size: 0.9rem; outline: none; min-height: 40px; }
        .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1.5rem; }
        .future-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: 1rem; }
        .future-item { background: var(--bg-secondary); padding: 1rem; border-radius: 8px; border: 1px dashed var(--border); }
        .future-item .ico { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .future-item .name { font-weight: 600; }
        .future-item .meta { font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem; }

        /* ---------- Modals ---------- */
        .modal-overlay { position: fixed; inset: 0; background: rgba(2, 6, 23, 0.85); backdrop-filter: blur(8px); display: none; justify-content: center; align-items: center; z-index: 100; padding: 1rem; animation: fadeIn 0.2s; }
        .modal-box { background: var(--bg-card); border: 2px solid var(--accent); border-radius: 12px; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto; padding: 1.75rem; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 0 50px var(--accent-glow); text-align: center; }
        .modal-icon { font-size: 3rem; margin-bottom: 1rem; }
        .modal-title { font-size: 1.3rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--accent); }
        .modal-rp { font-size: 1.05rem; font-weight: 600; color: var(--text-main); background: var(--bg-secondary); padding: 0.5rem 1rem; border-radius: 8px; display: inline-block; margin: 0.75rem 0; word-break: break-word; }

        .tag-op { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .tag-make { background: rgba(56, 189, 248, 0.15); color: var(--accent); }
        .tag-get { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .tag-status-success { color: var(--success); font-weight: 600; }
        .tag-status-rejected { color: var(--danger); font-weight: 600; }

        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        /* ---------- Desktop / mobile split ----------
           Layout is chosen from the viewport width, never from the user agent, so resizing a
           window, rotating a phone or using a tablet all behave consistently. */
        @media (min-width: 861px) {
            .mobile-only { display: none !important; }
        }

        @media (max-width: 860px) {
            .desktop-only { display: none !important; }

            header { padding: 0.75rem 1rem; }
            .logo { font-size: 1.05rem; }
            .container { padding: 1rem 0.85rem 2.5rem; }
            .card { padding: 1.1rem 1rem; margin-bottom: 1rem; border-radius: 12px; }
            .card-header { align-items: flex-start; }
            .card-title { font-size: 1rem; }
            .grid-2 { grid-template-columns: 1fr; gap: 1rem; }
            .tabs { margin-bottom: 1.25rem; }

            /* Full-width actions read better than a cramped inline row on a phone. */
            .action-bar { width: 100%; }
            .action-bar .btn { flex: 1 1 auto; }
            .action-bar .search-input { flex: 1 1 100%; max-width: none; }
            .form-actions .btn, .input-row .btn { flex: 1 1 100%; }
            .modal-box { padding: 1.25rem 1rem; }

            /* Tables become stacked cards; labels come from data-label, set by decorateTables(). */
            .table-wrap, .table-wrap.scroll-y { overflow: visible; max-height: none; }
            table { display: block; font-size: 0.88rem; }
            table thead { display: none; }
            table tbody { display: block; }
            table tr { display: block; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 0.75rem; padding: 0.25rem 0.25rem; }
            table tr:hover td { background: transparent; }
            table td { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.85rem; border-bottom: 1px dashed rgba(51, 65, 85, 0.6); padding: 0.55rem 0.7rem; text-align: right; min-width: 0; }
            table tr td:last-child { border-bottom: none; }
            table td::before { content: attr(data-label); color: var(--text-muted); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; text-align: left; flex: 0 0 40%; }
            table td:not([data-label])::before, table td[colspan]::before { content: none; }
            /* The value must be allowed to shrink below its content width for the ellipsis to work.
               On a phone there is no hover, so a value is wrapped instead of being clipped after a
               single line: three lines are shown at most, which keeps the card compact while still
               revealing most of a long domain, username or log message. */
            table td > .cell-value { flex: 1 1 auto; min-width: 0; white-space: normal; overflow-wrap: anywhere; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3; }
            table td[colspan] { display: block; text-align: center; }
            table td.empty-row-cell { display: block; }
            .actions-cell { white-space: normal; }
            .actions-cell .btn { flex: 1 1 auto; }
            .actions-cell .btn + .btn { margin-left: 0; }
            .actions-cell .btn:first-of-type { margin-left: auto; }
        }
    </style>
    </style>
</head>
<body>

    <header>
        <div class="logo">
            <span>🛡️</span>
            <span>VrtFido - WebAuthn CMS</span>
        </div>
        <div class="status-group">
            <div id="uhidStatus" class="badge-status badge-offline desktop-only">
                <span class="dot"></span>
                <span id="uhidText">UHID Connecting...</span>
            </div>
            <div id="usbSensorStatus" class="badge-status badge-offline desktop-only">
                <span class="dot"></span>
                <span id="usbSensorText">USB Sensor 3274:8012</span>
            </div>
            <div id="unlimitedFpStatus" class="badge-status" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); display: none;">
                ♾️ Fingerprints: Unlimited
            </div>
            <div id="debugStatus" class="badge-status badge-debug" style="display: none;" data-i18n="status.debug">
                CLI DEBUG ACTIVE
            </div>
            <div class="lang-toggle" role="group" aria-label="Language / Ngôn ngữ">
                <button class="lang-btn" data-lang="en" onclick="setLanguage('en')">EN</button>
                <button class="lang-btn" data-lang="vi" onclick="setLanguage('vi')">VI</button>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Navigation -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-creds')"><span data-i18n="tab.creds">🔑 Passkey Credentials</span> (<span id="credCount">0</span>)</button>
            <button class="tab-btn desktop-only" onclick="switchTab('tab-security')"><span data-i18n="tab.security">🛡️ Security & Biometrics</span></button>
            <button class="tab-btn" onclick="switchTab('tab-logs')"><span data-i18n="tab.logs">📜 Audit Trail</span></button>
            <button class="tab-btn" onclick="switchTab('tab-debug')"><span data-i18n="tab.debug">🐞 Debug Logs</span></button>
        </div>

        <!-- TAB 1: CREDENTIALS -->
        <div id="tab-creds" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <div class="card-title" data-i18n="creds.title">Registered WebAuthn Credentials</div>
                    <div class="action-bar">
                        <input type="search" id="credSearchInput" class="form-control search-input" autocomplete="off"
                               placeholder="Search domain, username, display name" data-i18n-placeholder="creds.searchPh"
                               oninput="onCredSearch()">
                        <button class="btn btn-secondary btn-sm" onclick="loadCredentials()" data-i18n="btn.refresh">🔄 Refresh</button>
                    </div>
                </div>
                <div class="table-wrap">
                    <table class="table-creds">
                        <thead>
                            <tr>
                                <th class="col-flex" data-i18n="creds.h.rp">Relying Party (Domain)</th>
                                <th class="col-flex" data-i18n="creds.h.user">Username</th>
                                <th class="col-flex" data-i18n="creds.h.display">Display Name</th>
                                <th data-i18n="creds.h.signCount">Sign Count</th>
                                <th data-i18n="creds.h.created">Created At</th>
                                <th data-i18n="creds.h.lastUsed">Last Used</th>
                                <th data-i18n="creds.h.actions">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="credTableBody">
                            <tr><td colspan="7" class="empty-row-cell" style="text-align: center; color: var(--text-muted);" data-i18n="common.loading">Loading data...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: SECURITY & BIOMETRICS -->
        <div id="tab-security" class="tab-content desktop-only">
            <div class="grid-2">
                <!-- 6-Digit PIN -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title" data-i18n="sec.pin.title">🔢 Passkey PIN (6 Digits)</div>
                        <span id="pinBadge" class="badge-status badge-offline" data-i18n="sec.pin.notConfigured">Not Configured</span>
                    </div>
                    <p class="card-subtitle" data-i18n="sec.pin.desc">
                        A single 6-digit numeric PIN (0-9) used for rapid user verification when accessing websites.
                    </p>
                    <div id="pinFormArea">
                        <div class="form-group" id="oldPinGroup" style="display: none;">
                            <label class="form-label" data-i18n="sec.pin.current">Current PIN:</label>
                            <input type="password" maxlength="6" id="oldPinInput" class="form-control" placeholder="Current 6 digits" data-i18n-placeholder="sec.pin.currentPh">
                        </div>
                        <div class="form-group">
                            <label class="form-label" id="newPinLabel" data-i18n="sec.pin.new">Enter New 6-Digit PIN:</label>
                            <input type="password" maxlength="6" id="newPinInput" class="form-control" placeholder="6 digits (e.g. 123456)" data-i18n-placeholder="sec.pin.newPh">
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-primary" onclick="submitPin()" data-i18n="sec.pin.save">💾 Save PIN</button>
                            <button class="btn btn-danger" id="removePinBtn" style="display: none;" onclick="removePin()" data-i18n="sec.pin.remove">🗑️ Remove PIN</button>
                        </div>
                    </div>
                </div>

                <!-- Fingerprint Biometrics (Max 10) -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title"><span data-i18n="sec.fp.title">🖐️ Fingerprint Management</span> (<span id="fpCount">0</span><span id="fpLimitText">/10</span>)</div>
                    </div>
                    <p class="card-subtitle" data-i18n="sec.fp.desc">
                        Enroll up to 10 fingerprints. Click add and touch the USB sensor 6 times when prompted.
                    </p>
                    <div class="form-group input-row">
                        <input type="text" id="fpNameInput" class="form-control" placeholder="Label (e.g. Right Index, Left Thumb...)" data-i18n-placeholder="sec.fp.labelPh">
                        <button class="btn btn-primary" id="addFpBtn" onclick="addFingerprint()" data-i18n="sec.fp.add">➕ Add Fingerprint</button>
                    </div>
                    <div class="table-wrap scroll-y">
                        <table class="table-fp">
                            <thead>
                                <tr>
                                    <th data-i18n="sec.fp.h.slot">Slot</th>
                                    <th class="col-flex" data-i18n="sec.fp.h.name">Fingerprint Name</th>
                                    <th data-i18n="sec.fp.h.enrolled">Enrolled At</th>
                                    <th data-i18n="sec.fp.h.action">Action</th>
                                </tr>
                            </thead>
                            <tbody id="fpTableBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-title" data-i18n="sec.future.title">🚀 Extended Biometrics (Future Technologies)</div>
                </div>
                <div class="future-grid">
                    <div class="future-item">
                        <div class="ico">👤</div>
                        <div class="name" data-i18n="sec.future.face">Facial Recognition (Face ID)</div>
                        <div class="meta" data-i18n="sec.future.ready">[Module Ready]</div>
                    </div>
                    <div class="future-item">
                        <div class="ico">👁️</div>
                        <div class="name" data-i18n="sec.future.iris">Iris Scanner</div>
                        <div class="meta">[Module Ready]</div>
                    </div>
                    <div class="future-item">
                        <div class="ico">🎙️</div>
                        <div class="name" data-i18n="sec.future.voice">Voiceprint Biometrics</div>
                        <div class="meta">[Module Ready]</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: AUDIT LOGS -->
        <div id="tab-logs" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title" data-i18n="logs.title">📜 Operational Audit Trail</div>
                    <div class="action-bar">
                        <button class="btn btn-danger btn-sm" onclick="cleanAuditLogs()" data-i18n="btn.clearLogs">🗑️ Clear Logs</button>
                        <button class="btn btn-secondary btn-sm" onclick="cleanAllLogs()" data-i18n="btn.clearAll">🧹 Clear All</button>
                        <button class="btn btn-secondary btn-sm" onclick="loadAuditLogs()" data-i18n="btn.refresh">🔄 Refresh</button>
                    </div>
                </div>
                <div class="table-wrap">
                    <table class="table-logs">
                        <thead>
                            <tr>
                                <th data-i18n="logs.h.time">Timestamp</th>
                                <th class="col-flex" data-i18n="logs.h.rp">Relying Party</th>
                                <th data-i18n="logs.h.op">Operation</th>
                                <th data-i18n="logs.h.method">Method</th>
                                <th data-i18n="logs.h.status">Status</th>
                                <th class="col-flex" data-i18n="logs.h.details">Details</th>
                            </tr>
                        </thead>
                        <tbody id="auditTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: DEBUG LOGS -->
        <div id="tab-debug" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title" data-i18n="debug.title">🐞 System Debug Logs & Errors</div>
                    <div class="action-bar">
                        <button class="btn btn-danger btn-sm" onclick="cleanDebugLogs()" data-i18n="btn.clearLogs">🗑️ Clear Logs</button>
                        <button class="btn btn-secondary btn-sm" onclick="cleanAllLogs()" data-i18n="btn.clearAll">🧹 Clear All</button>
                        <button class="btn btn-secondary btn-sm" onclick="loadDebugLogs()" data-i18n="btn.refresh">🔄 Refresh</button>
                    </div>
                </div>
                <div class="table-wrap scroll-y">
                    <table class="table-debug">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th data-i18n="debug.h.level">Level</th>
                                <th data-i18n="debug.h.component">Component</th>
                                <th class="col-flex" data-i18n="debug.h.message">Message</th>
                            </tr>
                        </thead>
                        <tbody id="debugTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- 6-STAGE USB FINGERPRINT ENROLLMENT MODAL -->
    <div id="enrollModal" class="modal-overlay">
        <div class="modal-box" style="max-width: 440px;">
            <div class="modal-icon" id="enrollIcon" style="font-size: 3.5rem;">🖐️</div>
            <div class="modal-title" id="enrollModalTitle" data-i18n="enroll.title">Scanning USB Fingerprint</div>
            <p id="enrollStepDesc" style="font-size: 1.25rem; font-weight: 700; color: var(--accent); margin: 0.5rem 0;">Stage 1 / 6</p>
            <p id="enrollActionPrompt" style="font-size: 0.95rem; color: var(--text-main); margin-bottom: 1.5rem;" data-i18n="enroll.prompt">Please place your finger on the USB sensor...</p>
            
            <div style="background: var(--bg-secondary); border-radius: 9999px; height: 12px; width: 100%; overflow: hidden; margin-bottom: 1.5rem; border: 1px solid var(--border);">
                <div id="enrollProgressBar" style="background: var(--accent); height: 100%; width: 16%; transition: width 0.3s;"></div>
            </div>

            <button class="btn btn-danger" onclick="cancelEnrollment()" data-i18n="common.cancel">❌ Cancel</button>
        </div>
    </div>

    <!-- REAL-TIME WEBAUTHN VERIFICATION PROMPT MODAL -->
    <div id="verifyModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-icon" id="modalIcon">🛡️</div>
            <div class="modal-title" id="modalTitle" data-i18n="verify.title">WebAuthn Verification Request</div>
            <p style="font-size: 0.9rem; color: var(--text-muted);" data-i18n="verify.desc">A website is requesting your security key:</p>
            <div>
                <span class="modal-rp" id="modalRpId">webauthn.io</span>
            </div>
            <p id="modalUserDesc" style="font-size: 0.85rem; margin-bottom: 0.5rem; color: var(--text-muted);"></p>

            <!-- MULTI-ACCOUNT SELECTION (WHEN USER NOT PROVIDED BY RP) -->
            <div id="modalAccountSelectionArea" style="display: none; text-align: left; margin: 0.75rem 0 1rem 0; background: var(--bg-secondary); padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid var(--border);">
                <label class="form-label" style="font-size: 0.8rem; margin-bottom: 0.35rem; color: var(--accent);" data-i18n="verify.select">👤 Select Account to Authenticate:</label>
                <select id="modalAccountSelect" class="form-control" style="font-weight: 600; cursor: pointer;">
                </select>
                <div id="modalAccountNote" style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.35rem;" data-i18n="verify.note">
                    Defaulted to latest used/added account.
                </div>
            </div>

            <div id="modalSetupView" style="display: none; margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <p style="font-size: 0.9rem; color: var(--warning); margin-bottom: 0.75rem; font-weight: 600;">
                    <span data-i18n="verify.setup">⚠️ Security is not configured. Please create a 6-digit PIN to activate:</span>
                </p>
                <input type="password" maxlength="6" id="setupPinInput" class="form-control" data-i18n-placeholder="verify.setupPh" placeholder="Enter 6 digits" style="text-align: center; font-size: 1.25rem; letter-spacing: 0.5rem; margin-bottom: 1rem;">
                <div style="display: flex; gap: 0.5rem; justify-content: center;">
                    <button class="btn btn-primary" onclick="submitModalApproval('SETUP')" data-i18n="verify.activate">Activate & Approve</button>
                    <button class="btn btn-danger" onclick="submitModalReject()" data-i18n="common.reject">Reject</button>
                </div>
            </div>

            <div id="modalVerifyView" style="display: none; margin-top: 1rem;">
                <p style="font-size: 0.85rem; color: var(--accent); margin-bottom: 0.5rem; font-weight: 600;">
                    <span data-i18n="verify.prompt">💡 Touch the USB fingerprint sensor now or enter your PIN:</span>
                </p>
                <input type="password" maxlength="6" id="verifyPinInput" class="form-control" data-i18n-placeholder="verify.pinPh" placeholder="Enter 6-digit PIN" style="text-align: center; font-size: 1.25rem; letter-spacing: 0.5rem; margin-bottom: 1rem;" autofocus>
                
                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                    <div style="display: flex; gap: 0.5rem; justify-content: center;">
                        <button class="btn btn-primary" onclick="submitModalApproval('PIN')" data-i18n="verify.withPin">🔑 Verify with PIN</button>
                        <button class="btn btn-secondary" onclick="submitModalApproval('FINGERPRINT')" data-i18n="verify.withSensor">🖐️ Touch USB Sensor</button>
                    </div>
                    <button class="btn btn-danger" style="margin-top: 0.5rem;" onclick="submitModalReject()" data-i18n="verify.reject">❌ Reject Request</button>
                </div>
            </div>
        </div>
    </div>

    <!-- MAIN SCRIPT -->
    <script>
        let currentPromptId = null;
        let enrollInterval = null;

        // Layout breakpoint shared with the stylesheet: 860px and below is treated as mobile.
        const MOBILE_QUERY = window.matchMedia('(max-width: 860px)');
        const isMobile = () => MOBILE_QUERY.matches;

        // Desktop keeps the real table headers; mobile renders each row as a card, so every cell
        // needs its column name. Deriving it from <thead> keeps the render functions untouched.
        function decorateTables(root, force) {
            (root || document).querySelectorAll('table').forEach(table => {
                const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
                if (!headers.length) return;
                table.querySelectorAll('tbody tr').forEach(row => {
                    Array.from(row.children).forEach((cell, index) => {
                        if (cell.tagName !== 'TD') return;
                        if (cell.hasAttribute('colspan')) return;
                        if (force) delete cell.dataset.label;
                        if (cell.dataset.label) return;
                        const label = headers[index];
                        if (label) cell.dataset.label = label;
                    });
                });
            });
        }

        // Long values must not widen the table: each value cell gets a .cell-value wrapper that
        // the stylesheet clips with an ellipsis. The wrapper is appended to the existing markup so
        // <strong>/<code>/badge styling inside the cell survives.
        function wrapCellValues(root) {
            (root || document).querySelectorAll('table tbody td').forEach(td => {
                if (td.hasAttribute('colspan')) return;
                if (td.classList.contains('actions-cell') || td.classList.contains('empty-row-cell')) return;
                if (td.childElementCount === 1 && td.firstElementChild.classList.contains('cell-value')) return;
                if (!td.textContent.trim()) return;
                const span = document.createElement('span');
                span.className = 'cell-value';
                while (td.firstChild) span.appendChild(td.firstChild);
                td.appendChild(span);
            });
        }

        // A title is only attached where something is actually hidden - horizontally through the
        // ellipsis, or vertically where the mobile line clamp cuts a wrapped value off - so short
        // cells do not get a pointless tooltip. Hidden tabs report no layout, so they are skipped
        // and picked up again once their panel becomes visible (switchTab -> refreshTableLayout).
        function syncCellTitles(root) {
            (root || document).querySelectorAll('table thead th, table tbody td > .cell-value').forEach(el => {
                const visible = el.offsetParent !== null;
                const clipped = visible && (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1);
                if (clipped) {
                    const text = el.textContent.trim();
                    if (text) el.title = text;
                } else {
                    el.removeAttribute('title');
                }
            });
        }

        function refreshTableLayout(root, force) {
            decorateTables(root, force);
            wrapCellValues(root);
            sizeTableColumns(root);
            syncCellTitles(root);
        }

        // Fixed table-layout needs explicit widths. The stylesheet percentages are only a first-paint
        // fallback and cannot work on their own: a timestamp or a pair of buttons needs its content
        // width while a domain or a debug message does not, and the labels change with the language.
        // So rigid columns are measured on their full content and the leftover width is shared out
        // between the .col-flex columns - the ones whose long values the ellipsis may clip.
        function sizeTableColumns(root) {
            const MIN_FLEX = 56;      // a flexible column never collapses below this
            const RIGID_SHARE = 0.75; // rigid columns may claim at most this much of the table
            (root || document).querySelectorAll('table').forEach(table => {
                const ths = Array.from(table.querySelectorAll('thead th'));
                if (!ths.length) return;
                if (isMobile() || table.offsetParent === null) {
                    ths.forEach(th => { th.style.width = ''; });
                    return;
                }
                const flex = ths.map(th => th.classList.contains('col-flex'));
                if (!flex.some(Boolean)) return;

                // A Range rect reports the natural width of the content even while the box clips it,
                // so each pass measures the value rather than the width the previous pass assigned.
                // Wrapping is suppressed while measuring: a wrapped cell (the action buttons, for
                // example) would otherwise report the width of its widest line and stay wrapped.
                const needed = ths.map(() => 0);
                const range = document.createRange();
                const cells = ths.slice();
                table.querySelectorAll('tbody tr').forEach(row => cells.push(...row.children));
                const restoreWrap = cells.map(cell => [cell, cell.style.whiteSpace]);
                cells.forEach(cell => { cell.style.whiteSpace = 'nowrap'; });
                const measure = (cell, index) => {
                    if (index >= needed.length) return;
                    if (cell.tagName !== 'TH' && cell.hasAttribute('colspan')) return;
                    const inner = (cell.childElementCount === 1 && cell.firstElementChild.classList.contains('cell-value'))
                        ? cell.firstElementChild : cell;
                    range.selectNodeContents(inner);
                    const cs = getComputedStyle(cell);
                    const width = Math.ceil(range.getBoundingClientRect().width + parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight));
                    needed[index] = Math.max(needed[index], width);
                };
                ths.forEach(measure);
                table.querySelectorAll('tbody tr').forEach(row => Array.from(row.children).forEach(measure));
                restoreWrap.forEach(([cell, whiteSpace]) => { cell.style.whiteSpace = whiteSpace; });

                const avail = table.clientWidth;
                if (!avail) return;
                const rigidIndexes = flex.map((isFlex, i) => isFlex ? -1 : i).filter(i => i >= 0);
                const rigidNeeded = rigidIndexes.reduce((sum, i) => sum + needed[i], 0);
                const rigidBudget = Math.min(rigidNeeded, avail * RIGID_SHARE);
                const rigidScale = rigidNeeded > 0 ? rigidBudget / rigidNeeded : 1;

                const widths = ths.map(() => 0);
                rigidIndexes.forEach(i => { widths[i] = needed[i] * rigidScale; });

                // Water-fill the flexible columns proportionally to their content, capping each one at
                // what it actually needs so a short value does not steal space from a long one.
                let remaining = avail - rigidBudget;
                let pending = flex.map((isFlex, i) => isFlex ? i : -1).filter(i => i >= 0);
                while (pending.length) {
                    const weight = pending.reduce((sum, i) => sum + Math.max(needed[i], MIN_FLEX), 0);
                    const share = i => remaining * Math.max(needed[i], MIN_FLEX) / weight;
                    const satisfied = pending.filter(i => needed[i] > 0 && share(i) >= needed[i]);
                    if (satisfied.length) {
                        satisfied.forEach(i => { widths[i] = needed[i]; remaining -= needed[i]; });
                        pending = pending.filter(i => !satisfied.includes(i));
                        continue;
                    }
                    const starving = pending.filter(i => share(i) < MIN_FLEX);
                    if (starving.length && remaining >= MIN_FLEX * starving.length) {
                        starving.forEach(i => { widths[i] = MIN_FLEX; remaining -= MIN_FLEX; });
                        pending = pending.filter(i => !starving.includes(i));
                        continue;
                    }
                    pending.forEach(i => { widths[i] = share(i); });
                    pending = [];
                }
                ths.forEach((th, i) => { th.style.width = Math.max(0, Math.floor(widths[i])) + 'px'; });
            });
        }

        let decorateScheduled = false;
        const tableObserver = new MutationObserver(() => {
            if (decorateScheduled) return;
            decorateScheduled = true;
            requestAnimationFrame(() => {
                decorateScheduled = false;
                refreshTableLayout();
            });
        });
        tableObserver.observe(document.body, { childList: true, subtree: true });

        let resizeScheduled = false;
        window.addEventListener('resize', () => {
            if (resizeScheduled) return;
            resizeScheduled = true;
            requestAnimationFrame(() => {
                resizeScheduled = false;
                refreshTableLayout();
            });
        });

        // ---------------------------------------------------------------------------
        // i18n: English is the default; the choice is stored server-side in the database
        // (POST /api/settings) so the web CMS and the Android app share one language.
        // ---------------------------------------------------------------------------
        const I18N = {
            en: {
                'tab.creds': '🔑 Passkey Credentials',
                'tab.security': '🛡️ Security & Biometrics',
                'tab.logs': '📜 Audit Trail',
                'tab.debug': '🐞 Debug Logs',
                'creds.title': 'Registered WebAuthn Credentials',
                'creds.h.rp': 'Relying Party (Domain)',
                'creds.h.user': 'Username',
                'creds.h.display': 'Display Name',
                'creds.h.signCount': 'Sign Count',
                'creds.h.created': 'Created At',
                'creds.h.lastUsed': 'Last Used',
                'creds.h.actions': 'Actions',
                'creds.empty': 'No passkey credentials stored yet. Open webauthn.io to register!',
                'creds.searchPh': 'Search domain, username or display name...',
                'creds.noMatch': 'No credentials match your search.',
                'creds.promptUser': 'Enter new username:',
                'creds.promptDisplay': 'Enter new display name:',
                'creds.confirmDelete': "Are you sure you want to delete the credential for domain '{rp}'?",
                'sec.pin.title': '🔢 Passkey PIN (6 Digits)',
                'sec.pin.desc': 'A single 6-digit numeric PIN (0-9) used for rapid user verification when accessing websites.',
                'sec.pin.active': 'Active',
                'sec.pin.notConfigured': 'Not Configured',
                'sec.pin.current': 'Current PIN:',
                'sec.pin.new': 'Enter New 6-Digit PIN:',
                'sec.pin.replace': 'Enter replacement 6-digit PIN:',
                'sec.pin.currentPh': 'Current 6 digits',
                'sec.pin.newPh': '6 digits (e.g. 123456)',
                'sec.pin.save': '💾 Save PIN',
                'sec.pin.remove': '🗑️ Remove PIN',
                'sec.fp.title': '🖐️ Fingerprint Management',
                'sec.fp.desc': 'Enroll up to 10 fingerprints. Click add and touch the USB sensor 6 times when prompted.',
                'sec.fp.labelPh': 'Label (e.g. Right Index, Left Thumb...)',
                'sec.fp.add': '➕ Add Fingerprint',
                'sec.fp.h.slot': 'Slot',
                'sec.fp.h.name': 'Fingerprint Name',
                'sec.fp.h.enrolled': 'Enrolled At',
                'sec.fp.h.action': 'Action',
                'sec.fp.slot': 'Slot {n}',
                'sec.fp.empty': 'No fingerprints enrolled yet. Up to 10 fingerprints.',
                'sec.fp.limit': '/10',
                'sec.fp.unlimited': ' - Unlimited',
                'sec.future.title': '🚀 Extended Biometrics (Future Technologies)',
                'sec.future.face': 'Facial Recognition (Face ID)',
                'sec.future.iris': 'Iris Scanner',
                'sec.future.voice': 'Voiceprint Biometrics',
                'sec.future.ready': '[Module Ready]',
                'logs.title': '📜 Operational Audit Trail',
                'logs.h.time': 'Timestamp',
                'logs.h.rp': 'Relying Party',
                'logs.h.op': 'Operation',
                'logs.h.method': 'Method',
                'logs.h.status': 'Status',
                'logs.h.details': 'Details',
                'logs.empty': 'No audit logs yet.',
                'logs.confirmClear': 'Delete all audit logs?',
                'logs.confirmClearAll': 'Delete audit logs, debug logs and the audit trail? This cannot be undone.',
                'debug.title': '🐞 System Debug Logs & Errors',
                'debug.h.time': 'Timestamp',
                'debug.h.level': 'Level',
                'debug.h.component': 'Component',
                'debug.h.message': 'Message',
                'debug.empty': 'No debug logs yet (enable the --debug flag to capture packets).',
                'debug.confirmClear': 'Delete all debug logs?',
                'btn.refresh': '🔄 Refresh',
                'btn.clearLogs': '🗑️ Clear Logs',
                'btn.clearAll': '🧹 Clear All',
                'status.uhidOnline': 'UHID FIDO2 Online',
                'status.uhidOffline': 'UHID Offline',
                'status.usbReady': 'USB 3274:8012 Ready',
                'status.usbDisconnected': 'USB 3274:8012 Disconnected',
                'status.unlimited': '♾️ Fingerprints: Unlimited',
                'status.debug': 'CLI DEBUG ACTIVE',
                'common.loading': 'Loading data...',
                'common.delete': '🗑️ Delete',
                'common.edit': '✏️ Edit',
                'common.cancel': '❌ Cancel',
                'common.reject': 'Reject',
                'common.error': 'Error',
                'common.errorLoading': 'Error loading data',
                'common.errorLoadingLogs': 'Error loading logs',
                'common.languageSaved': 'Language saved',
                'enroll.title': 'Scanning USB Fingerprint',
                'enroll.stage': 'Stage {n} / 6',
                'enroll.prompt': 'Please place your finger on the USB sensor...',
                'verify.title': 'WebAuthn Verification Request',
                'verify.desc': 'A website is requesting your security key:',
                'verify.select': '👤 Select Account to Authenticate:',
                'verify.note': 'Defaulted to the latest used/added account.',
                'verify.setup': '⚠️ Security is not configured. Please create a 6-digit PIN to activate:',
                'verify.setupPh': 'Enter 6 digits',
                'verify.activate': 'Activate & Approve',
                'verify.prompt': '💡 Touch the USB fingerprint sensor now or enter your PIN:',
                'verify.pinPh': 'Enter 6-digit PIN',
                'verify.withPin': '🔑 Verify with PIN',
                'verify.withSensor': '🖐️ Touch USB Sensor',
                'verify.reject': '❌ Reject Request',
                'enroll.initializing': 'Initializing...',
                'enroll.connecting': 'Connecting to USB sensor...',
                'enroll.success': 'Success!',
                'enroll.captured': 'Captured 6 stages and saved to USB chip!',
                'enroll.failed': 'Failed',
                'enroll.error': 'An error occurred',
                'fp.deleteConfirm': 'Delete this fingerprint?',
                'fp.nameRequired': 'Please enter a name for the fingerprint!',
                'pin.invalid': 'PIN must be exactly 6 numeric digits (0-9)!',
                'pin.saved': 'PIN updated successfully!',
                'pin.removed': 'PIN removed successfully!',
                'pin.confirmRemoval': 'Please enter the current PIN to confirm removal:',
                'logs.cleared': 'Logs cleared',
                'debug.cleared': 'Debug logs cleared',
                'all.cleared': 'All logs cleared',
                'logs.clearConfirm': 'Clear all audit logs?',
                'debug.clearConfirm': 'Clear all debug logs?',
                'all.clearConfirm': 'Clear audit logs, debug logs and the audit trail? This cannot be undone.',
                'common.errorClearing': 'Error clearing logs',
                'common.confirm': 'Confirm'
            },
            vi: {
                'tab.creds': '🔑 Khoá Passkey',
                'tab.security': '🛡️ Bảo mật & Sinh trắc học',
                'tab.logs': '📜 Nhật ký hoạt động',
                'tab.debug': '🐞 Nhật ký gỡ lỗi',
                'creds.title': 'Khoá WebAuthn đã đăng ký',
                'creds.h.rp': 'Tên miền (Relying Party)',
                'creds.h.user': 'Tên tài khoản',
                'creds.h.display': 'Tên hiển thị',
                'creds.h.signCount': 'Số lần ký',
                'creds.h.created': 'Ngày tạo',
                'creds.h.lastUsed': 'Dùng lần cuối',
                'creds.h.actions': 'Thao tác',
                'creds.empty': 'Chưa có khoá passkey nào. Mở webauthn.io để đăng ký!',
                'creds.searchPh': 'Tìm tên miền, tên tài khoản hoặc tên hiển thị...',
                'creds.noMatch': 'Không có khoá nào khớp với tìm kiếm.',
                'creds.promptUser': 'Nhập tên tài khoản mới:',
                'creds.promptDisplay': 'Nhập tên hiển thị mới:',
                'creds.confirmDelete': "Xoá khoá của tên miền '{rp}'?",
                'sec.pin.title': '🔢 Mã PIN Passkey (6 số)',
                'sec.pin.desc': 'Một mã PIN 6 số (0-9) dùng để xác minh nhanh khi truy cập website.',
                'sec.pin.active': 'Đang bật',
                'sec.pin.notConfigured': 'Chưa thiết lập',
                'sec.pin.current': 'PIN hiện tại:',
                'sec.pin.new': 'Nhập PIN 6 số mới:',
                'sec.pin.replace': 'Nhập PIN 6 số thay thế:',
                'sec.pin.currentPh': '6 số hiện tại',
                'sec.pin.newPh': '6 số (ví dụ 123456)',
                'sec.pin.save': '💾 Lưu PIN',
                'sec.pin.remove': '🗑️ Xoá PIN',
                'sec.fp.title': '🖐️ Quản lý vân tay',
                'sec.fp.desc': 'Đăng ký tối đa 10 vân tay. Bấm thêm và chạm cảm biến USB 6 lần theo hướng dẫn.',
                'sec.fp.labelPh': 'Nhãn (ví dụ Ngón trỏ phải, Ngón cái trái...)',
                'sec.fp.add': '➕ Thêm vân tay',
                'sec.fp.h.slot': 'Khe',
                'sec.fp.h.name': 'Tên vân tay',
                'sec.fp.h.enrolled': 'Ngày đăng ký',
                'sec.fp.h.action': 'Thao tác',
                'sec.fp.slot': 'Khe {n}',
                'sec.fp.empty': 'Chưa đăng ký vân tay nào. Tối đa 10 vân tay.',
                'sec.fp.limit': '/10',
                'sec.fp.unlimited': ' - Không giới hạn',
                'sec.future.title': '🚀 Sinh trắc học mở rộng (công nghệ tương lai)',
                'sec.future.face': 'Nhận diện khuôn mặt (Face ID)',
                'sec.future.iris': 'Quét mống mắt',
                'sec.future.voice': 'Sinh trắc học giọng nói',
                'sec.future.ready': '[Sẵn sàng]',
                'logs.title': '📜 Nhật ký hoạt động',
                'logs.h.time': 'Thời gian',
                'logs.h.rp': 'Tên miền',
                'logs.h.op': 'Hành động',
                'logs.h.method': 'Phương thức',
                'logs.h.status': 'Trạng thái',
                'logs.h.details': 'Chi tiết',
                'logs.empty': 'Chưa có nhật ký hoạt động.',
                'logs.confirmClear': 'Xoá toàn bộ nhật ký hoạt động?',
                'logs.confirmClearAll': 'Xoá nhật ký hoạt động và nhật ký gỡ lỗi? Không thể hoàn tác.',
                'debug.title': '🐞 Nhật ký gỡ lỗi & lỗi hệ thống',
                'debug.h.time': 'Thời gian',
                'debug.h.level': 'Mức',
                'debug.h.component': 'Thành phần',
                'debug.h.message': 'Nội dung',
                'debug.empty': 'Chưa có nhật ký gỡ lỗi (bật cờ --debug để ghi gói tin).',
                'debug.confirmClear': 'Xoá toàn bộ nhật ký gỡ lỗi?',
                'btn.refresh': '🔄 Làm mới',
                'btn.clearLogs': '🗑️ Xoá nhật ký',
                'btn.clearAll': '🧹 Xoá tất cả',
                'status.uhidOnline': 'UHID FIDO2 trực tuyến',
                'status.uhidOffline': 'UHID ngoại tuyến',
                'status.usbReady': 'USB 3274:8012 sẵn sàng',
                'status.usbDisconnected': 'USB 3274:8012 chưa kết nối',
                'status.unlimited': '♾️ Vân tay: không giới hạn',
                'status.debug': 'ĐANG BẬT GỠ LỖI CLI',
                'common.loading': 'Đang tải dữ liệu...',
                'common.delete': '🗑️ Xoá',
                'common.edit': '✏️ Sửa',
                'common.cancel': '❌ Huỷ',
                'common.reject': 'Từ chối',
                'common.error': 'Lỗi',
                'common.errorLoading': 'Lỗi khi tải dữ liệu',
                'common.errorLoadingLogs': 'Lỗi khi tải nhật ký',
                'common.languageSaved': 'Đã lưu ngôn ngữ',
                'enroll.title': 'Đang quét vân tay USB',
                'enroll.stage': 'Bước {n} / 6',
                'enroll.prompt': 'Vui lòng đặt ngón tay lên cảm biến USB...',
                'verify.title': 'Yêu cầu xác thực WebAuthn',
                'verify.desc': 'Một website đang yêu cầu khoá bảo mật của bạn:',
                'verify.select': '👤 Chọn tài khoản để xác thực:',
                'verify.note': 'Mặc định dùng tài khoản dùng/thêm gần nhất.',
                'verify.setup': '⚠️ Chưa thiết lập bảo mật. Hãy tạo mã PIN 6 số để kích hoạt:',
                'verify.setupPh': 'Nhập 6 số',
                'verify.activate': 'Kích hoạt & Chấp nhận',
                'verify.prompt': '💡 Chạm cảm biến vân tay USB hoặc nhập mã PIN:',
                'verify.pinPh': 'Nhập PIN 6 số',
                'verify.withPin': '🔑 Xác thực bằng PIN',
                'verify.withSensor': '🖐️ Chạm cảm biến USB',
                'verify.reject': '❌ Từ chối yêu cầu',
                'enroll.initializing': 'Đang khởi tạo...',
                'enroll.connecting': 'Đang kết nối cảm biến USB...',
                'enroll.success': 'Thành công!',
                'enroll.captured': 'Đã ghi 6 bước và lưu vào chip USB!',
                'enroll.failed': 'Thất bại',
                'enroll.error': 'Đã xảy ra lỗi',
                'fp.deleteConfirm': 'Xoá vân tay này?',
                'fp.nameRequired': 'Vui lòng nhập tên cho vân tay!',
                'pin.invalid': 'PIN phải gồm đúng 6 chữ số (0-9)!',
                'pin.saved': 'Đã cập nhật PIN!',
                'pin.removed': 'Đã xoá PIN!',
                'pin.confirmRemoval': 'Nhập PIN hiện tại để xác nhận xoá:',
                'logs.cleared': 'Đã xoá nhật ký',
                'debug.cleared': 'Đã xoá nhật ký gỡ lỗi',
                'all.cleared': 'Đã xoá toàn bộ nhật ký',
                'logs.clearConfirm': 'Xoá toàn bộ nhật ký hoạt động?',
                'debug.clearConfirm': 'Xoá toàn bộ nhật ký gỡ lỗi?',
                'all.clearConfirm': 'Xoá nhật ký hoạt động và nhật ký gỡ lỗi? Không thể hoàn tác.',
                'common.errorClearing': 'Lỗi khi xoá nhật ký',
                'common.confirm': 'Xác nhận'
            }
        };

        let currentLang = 'en';

        function t(key, vars) {
            const dict = I18N[currentLang] || I18N.en;
            let text = dict[key] || I18N.en[key] || key;
            if (vars) Object.keys(vars).forEach(k => { text = text.replace(`{${k}}`, vars[k]); });
            return text;
        }

        function applyLanguage(lang) {
            currentLang = I18N[lang] ? lang : 'en';
            document.documentElement.lang = currentLang;
            document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
            document.querySelectorAll('.lang-btn').forEach(b => b.classList.toggle('active', b.dataset.lang === currentLang));
            refreshTableLayout(document, true);
        }

        async function loadSettings() {
            let language = 'en';
            try {
                const res = await fetch('/api/settings');
                const json = await res.json();
                if (json.success && json.data && json.data.language) language = json.data.language;
            } catch (e) {
                console.warn('settings unavailable, using default language', e);
            }
            applyLanguage(language);
            return language;
        }

        async function setLanguage(lang) {
            applyLanguage(lang);
            try {
                await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ language: currentLang })
                });
            } catch (e) {
                console.warn('could not persist language', e);
            }
            // Texts rendered by script (status, toggles, fingerprint suffix) refresh here.
            fetchStatus();
            loadCredentials();
        }

        function switchTab(tabId, btn) {
            const panel = document.getElementById(tabId);
            // A panel hidden for this viewport must never take over the screen.
            if (panel && panel.classList.contains('desktop-only') && isMobile()) {
                tabId = 'tab-creds';
                btn = null;
            }
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            const targetBtn = btn || (typeof event !== 'undefined' && event && event.target) || document.querySelector(`[onclick*="${tabId}"]`);
            if (targetBtn && targetBtn.classList) targetBtn.classList.add('active');
            const targetContent = document.getElementById(tabId);
            if (targetContent) targetContent.classList.add('active');
            // Cells clipped while the panel was hidden can only be measured now.
            requestAnimationFrame(() => refreshTableLayout(targetContent));
            if (tabId === 'tab-creds') loadCredentials();
            if (tabId === 'tab-security') loadSecurity();
            if (tabId === 'tab-logs') loadAuditLogs();
            if (tabId === 'tab-debug') loadDebugLogs();
        }

        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const json = await res.json();
                if (json.success) {
                    const s = json.data;
                    // Toggle state classes instead of replacing className, so layout classes
                    // such as desktop-only survive the status refresh.
                    const uhidEl = document.getElementById('uhidStatus');
                    const uhidTxt = document.getElementById('uhidText');
                    uhidEl.classList.toggle('badge-online', !!s.uhid_connected);
                    uhidEl.classList.toggle('badge-offline', !s.uhid_connected);
                    uhidTxt.innerText = t(s.uhid_connected ? 'status.uhidOnline' : 'status.uhidOffline');

                    const usbEl = document.getElementById('usbSensorStatus');
                    const usbTxt = document.getElementById('usbSensorText');
                    usbEl.classList.toggle('badge-online', !!s.usb_sensor_connected);
                    usbEl.classList.toggle('badge-offline', !s.usb_sensor_connected);
                    usbTxt.innerText = t(s.usb_sensor_connected ? 'status.usbReady' : 'status.usbDisconnected');

                    if (document.getElementById('debugStatus')) {
                        document.getElementById('debugStatus').style.display = s.debug_mode ? 'inline-flex' : 'none';
                    }
                    if (document.getElementById('unlimitedFpStatus')) {
                        document.getElementById('unlimitedFpStatus').style.display = s.unlimited_fingerprints ? 'inline-flex' : 'none';
                    }
                    if (document.getElementById('fpLimitText')) {
                        document.getElementById('fpLimitText').innerText = t(s.unlimited_fingerprints ? 'sec.fp.limit' : 'sec.fp.limit');
                    }
                    if (document.getElementById('credCount')) {
                        document.getElementById('credCount').innerText = s.credentials_count;
                    }
                }
            } catch (e) {
                console.error(e);
            }
        }

        // Credentials are fetched in full, so filtering happens in the browser: typing in the
        // search box never hits the API and never loses the current result set ordering. The query
        // is read from the input at render time, so browser form-restore cannot desync the list.
        let credCache = [];

        function onCredSearch() {
            renderCredentials();
        }

        function renderCredentials() {
            const tbody = document.getElementById('credTableBody');
            const input = document.getElementById('credSearchInput');
            const q = (input ? input.value : '').trim().toLowerCase();
            const rows = q
                ? credCache.filter(c => [c.rp_id, c.user_name, c.user_display_name].some(v => (v || '').toLowerCase().includes(q)))
                : credCache;
            if (rows.length === 0) {
                const key = credCache.length === 0 ? 'creds.empty' : 'creds.noMatch';
                tbody.innerHTML = `<tr><td colspan="7" class="empty-row-cell" style="text-align: center; color: var(--text-muted); padding: 2rem;">${escapeHtml(t(key))}</td></tr>`;
                return;
            }
            tbody.innerHTML = rows.map(c => {
                const idAttr = escapeHtml(c.id);
                const uNameAttr = escapeHtml(c.user_name);
                const uDisplayAttr = escapeHtml(c.user_display_name);
                const rpIdAttr = escapeHtml(c.rp_id);
                return `
                    <tr>
                        <td><strong>${rpIdAttr}</strong></td>
                        <td>${uNameAttr}</td>
                        <td>${uDisplayAttr}</td>
                        <td><span style="font-weight:700; color:var(--accent);">${c.sign_count}</span></td>
                        <td style="color:var(--text-muted);">${c.created_at}</td>
                        <td style="color:var(--text-muted);">${c.last_used_at}</td>
                        <td class="actions-cell">
                            <button class="btn btn-secondary btn-sm btn-edit" data-id="${idAttr}" data-username="${uNameAttr}" data-displayname="${uDisplayAttr}">${escapeHtml(t('common.edit'))}</button>
                            <button class="btn btn-danger btn-sm btn-delete" data-id="${idAttr}" data-rpid="${rpIdAttr}">${escapeHtml(t('common.delete'))}</button>
                        </td>
                    </tr>
                `;
            }).join('');
            tbody.querySelectorAll('.btn-edit').forEach(btn => {
                btn.onclick = () => editCredential(btn.dataset.id, btn.dataset.username, btn.dataset.displayname);
            });
            tbody.querySelectorAll('.btn-delete').forEach(btn => {
                btn.onclick = () => deleteCredential(btn.dataset.id, btn.dataset.rpid);
            });
        }

        async function loadCredentials() {
            const tbody = document.getElementById('credTableBody');
            try {
                const res = await fetch('/api/credentials');
                const json = await res.json();
                if (json.success && Array.isArray(json.data)) {
                    credCache = json.data;
                    renderCredentials();
                } else {
                    credCache = [];
                    tbody.innerHTML = `<tr><td colspan="7" class="empty-row-cell" style="color:var(--danger);">${escapeHtml(t('common.errorLoading'))}: ${escapeHtml(json.error || '')}</td></tr>`;
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="7" class="empty-row-cell" style="color:var(--danger);">${escapeHtml(t('common.errorLoading'))}: ${e}</td></tr>`;
            }
        }

        async function editCredential(id, oldName, oldDisplay) {
            const newName = prompt(t('creds.promptUser'), oldName);
            if (newName === null) return;
            const newDisplay = prompt(t('creds.promptDisplay'), oldDisplay);
            if (newDisplay === null) return;

            const res = await fetch(`/api/credentials/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_name: newName, user_display_name: newDisplay })
            });
            const json = await res.json();
            if (json.success) {
                loadCredentials();
            } else {
                alert(t('common.error') + ': ' + json.error);
            }
        }

        async function deleteCredential(id, rpId) {
            if (!confirm(t('creds.confirmDelete', { rp: rpId }))) return;
            const res = await fetch(`/api/credentials/${id}`, { method: 'DELETE' });
            const json = await res.json();
            if (json.success) {
                loadCredentials();
            } else {
                alert(t('common.error') + ': ' + json.error);
            }
        }

        async function loadSecurity() {
            try {
                const res = await fetch('/api/security');
                const json = await res.json();
                if (json.success) {
                    const sec = json.data.settings;
                    const fps = json.data.fingerprints;

                    const pinBadge = document.getElementById('pinBadge');
                    const oldGroup = document.getElementById('oldPinGroup');
                    const removeBtn = document.getElementById('removePinBtn');
                    const newPinLabel = document.getElementById('newPinLabel');

                    if (sec.pin_enabled) {
                        pinBadge.classList.remove('badge-offline');
                        pinBadge.classList.add('badge-online');
                        pinBadge.innerText = t('sec.pin.active');
                        oldGroup.style.display = 'block';
                        removeBtn.style.display = 'inline-flex';
                        newPinLabel.innerText = t('sec.pin.replace');
                    } else {
                        pinBadge.classList.remove('badge-online');
                        pinBadge.classList.add('badge-offline');
                        pinBadge.innerText = t('sec.pin.notConfigured');
                        oldGroup.style.display = 'none';
                        removeBtn.style.display = 'none';
                        newPinLabel.innerText = t('sec.pin.new');
                    }

                    document.getElementById('fpCount').innerText = fps.length;
                    const fpTbody = document.getElementById('fpTableBody');
                    if (fps.length > 0) {
                        fpTbody.innerHTML = fps.map(f => `
                            <tr>
                                <td>${escapeHtml(t('sec.fp.slot', { n: f.slot_index }))}</td>
                                <td><strong>${escapeHtml(f.name)}</strong></td>
                                <td style="color:var(--text-muted);">${f.enrolled_at}</td>
                                <td class="actions-cell"><button class="btn btn-danger btn-sm" onclick="deleteFp(${f.id})">${escapeHtml(t('common.delete'))}</button></td>
                            </tr>
                        `).join('');
                    } else {
                        fpTbody.innerHTML = `<tr><td colspan="4" class="empty-row-cell" style="text-align: center; color: var(--text-muted);">${escapeHtml(t('sec.fp.empty'))}</td></tr>`;
                    }
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function submitPin() {
            const pin = document.getElementById('newPinInput').value.trim();
            const oldPin = document.getElementById('oldPinInput').value.trim();

            if (pin.length !== 6 || !/^\d+$/.test(pin)) {
                alert(t('pin.invalid'));
                return;
            }

            const payload = { pin };
            if (document.getElementById('oldPinGroup').style.display !== 'none') {
                payload.old_pin = oldPin;
            }

            const res = await fetch('/api/security/pin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const json = await res.json();
            if (json.success) {
                alert(t('pin.saved'));
                document.getElementById('newPinInput').value = '';
                document.getElementById('oldPinInput').value = '';
                loadSecurity();
            } else {
                alert(t('common.error') + ': ' + json.error);
            }
        }

        async function removePin() {
            const current_pin = prompt(t('pin.confirmRemoval'));
            if (!current_pin) return;

            const res = await fetch('/api/security/pin', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current_pin })
            });
            const json = await res.json();
            if (json.success) {
                alert(t('pin.removed'));
                loadSecurity();
            } else {
                alert(t('common.error') + ': ' + json.error);
            }
        }

        // START 6-STAGE USB FINGERPRINT ENROLLMENT (NON-BLOCKING)
        async function addFingerprint() {
            const nameInput = document.getElementById('fpNameInput');
            const name = nameInput.value.trim();
            if (!name) {
                alert(t('fp.nameRequired'));
                return;
            }

            document.getElementById('enrollModal').style.display = 'flex';
            document.getElementById('enrollStepDesc').innerText = t('enroll.initializing');
            document.getElementById('enrollActionPrompt').innerText = t('enroll.connecting');
            document.getElementById('enrollProgressBar').style.width = '10%';
            document.getElementById('enrollIcon').innerText = '🖐️';

            const res = await fetch('/api/security/fingerprints/enroll/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const json = await res.json();
            if (!json.success) {
                alert(t('common.error') + ': ' + json.error);
                document.getElementById('enrollModal').style.display = 'none';
                return;
            }

            if (enrollInterval) clearInterval(enrollInterval);
            enrollInterval = setInterval(pollEnrollProgress, 250);
        }

        async function pollEnrollProgress() {
            try {
                const res = await fetch('/api/security/fingerprints/enroll/status');
                const json = await res.json();
                if (json.success && json.data) {
                    const p = json.data;
                    if (p.active) {
                        const pct = Math.round((p.stage / p.total_stages) * 100);
                        document.getElementById('enrollProgressBar').style.width = pct + '%';
                        document.getElementById('enrollStepDesc').innerText = t('enroll.stage', { n: p.stage });
                        document.getElementById('enrollActionPrompt').innerText = p.message;
                        document.getElementById('enrollIcon').innerText = p.status === 'finger_lift' ? '👆' : '🖐️';
                    } else if (p.status === 'completed') {
                        clearInterval(enrollInterval);
                        enrollInterval = null;
                        document.getElementById('enrollProgressBar').style.width = '100%';
                        document.getElementById('enrollIcon').innerText = '✅';
                        document.getElementById('enrollStepDesc').innerText = t('enroll.success');
                        document.getElementById('enrollActionPrompt').innerText = t('enroll.captured');
                        setTimeout(() => {
                            document.getElementById('enrollModal').style.display = 'none';
                            document.getElementById('fpNameInput').value = '';
                            loadSecurity();
                        }, 1200);
                    } else if (p.status === 'error') {
                        clearInterval(enrollInterval);
                        enrollInterval = null;
                        document.getElementById('enrollIcon').innerText = '❌';
                        document.getElementById('enrollStepDesc').innerText = t('enroll.failed');
                        document.getElementById('enrollActionPrompt').innerText = p.error || t('enroll.error');
                        setTimeout(() => {
                            document.getElementById('enrollModal').style.display = 'none';
                        }, 2500);
                    }
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function cancelEnrollment() {
            if (enrollInterval) {
                clearInterval(enrollInterval);
                enrollInterval = null;
            }
            await fetch('/api/security/fingerprints/enroll/cancel', { method: 'POST' });
            document.getElementById('enrollModal').style.display = 'none';
        }

        async function deleteFp(id) {
            if (!confirm(t('fp.deleteConfirm'))) return;
            const res = await fetch(`/api/security/fingerprints/${id}`, { method: 'DELETE' });
            const json = await res.json();
            if (json.success) {
                loadSecurity();
            } else {
                alert(t('common.error') + ': ' + json.error);
            }
        }

        async function loadAuditLogs() {
            const tbody = document.getElementById('auditTableBody');
            try {
                const res = await fetch('/api/logs');
                const json = await res.json();
                if (json.success && json.data.length > 0) {
                    tbody.innerHTML = json.data.map(l => {
                        const statusClass = l.status === 'SUCCESS' ? 'tag-status-success' : 'tag-status-rejected';
                        const opClass = l.operation.includes('Make') ? 'tag-op tag-make' : 'tag-op tag-get';
                        return `
                            <tr>
                                <td style="color:var(--text-muted); font-size:0.8rem;">${l.created_at}</td>
                                <td><strong>${escapeHtml(l.rp_id)}</strong></td>
                                <td><span class="${opClass}">${escapeHtml(l.operation)}</span></td>
                                <td><code>${escapeHtml(l.auth_method)}</code></td>
                                <td><span class="${statusClass}">${l.status}</span></td>
                                <td style="color:var(--text-muted);">${escapeHtml(l.details || '')}</td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="6" class="empty-row-cell" style="text-align:center; color:var(--text-muted);">${escapeHtml(t('logs.empty'))}</td></tr>`;
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" class="empty-row-cell" style="color:var(--danger);">${escapeHtml(t('common.errorLoadingLogs'))}: ${e}</td></tr>`;
            }
        }

        async function loadDebugLogs() {
            const tbody = document.getElementById('debugTableBody');
            try {
                const res = await fetch('/api/debug-logs');
                const json = await res.json();
                if (json.success && json.data.length > 0) {
                    tbody.innerHTML = json.data.map(d => `
                        <tr>
                            <td style="color:var(--text-muted); font-size:0.8rem;">${d.created_at}</td>
                            <td><span class="badge-status" style="background:rgba(56,189,248,0.15); color:var(--accent);">${d.level}</span></td>
                            <td><strong>${escapeHtml(d.component)}</strong></td>
                            <td><code style="word-break:break-all;">${escapeHtml(d.message)}</code></td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="4" class="empty-row-cell" style="text-align:center; color:var(--text-muted);">${escapeHtml(t('debug.empty'))}</td></tr>`;
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="4" class="empty-row-cell" style="color:var(--danger);">${escapeHtml(t('common.error'))}: ${e}</td></tr>`;
            }
        }

        async function cleanAuditLogs() {
            if (!confirm(t('logs.clearConfirm'))) return;
            try {
                const res = await fetch('/api/logs', { method: 'DELETE' });
                const json = await res.json();
                if (json.success) {
                    loadAuditLogs();
                } else {
                    alert(t('common.errorClearing') + ': ' + json.error);
                }
            } catch (e) {
                alert("Error: " + e);
            }
        }

        async function cleanDebugLogs() {
            if (!confirm("Are you sure you want to clear all Debug Logs?")) return;
            try {
                const res = await fetch('/api/debug-logs', { method: 'DELETE' });
                const json = await res.json();
                if (json.success) {
                    loadDebugLogs();
                } else {
                    alert("Error clearing debug logs: " + json.error);
                }
            } catch (e) {
                alert("Error: " + e);
            }
        }

        async function cleanAllLogs() {
            if (!confirm("Are you sure you want to clear ALL logs (both Audit and Debug)?")) return;
            try {
                const res = await fetch('/api/logs/clean', { method: 'POST' });
                const json = await res.json();
                if (json.success) {
                    loadAuditLogs();
                    loadDebugLogs();
                } else {
                    alert(t('common.errorClearing') + ': ' + json.error);
                }
            } catch (e) {
                alert("Error: " + e);
            }
        }

        // --- POLLING REAL-TIME WEBAUTHN REQUEST MODAL ---
        async function pollPendingVerification() {
            try {
                const res = await fetch('/api/verify/pending');
                const json = await res.json();
                if (json.success && json.data) {
                    const p = json.data;
                    const isNewPrompt = (currentPromptId !== p.request_id);
                    currentPromptId = p.request_id;

                    document.getElementById('modalRpId').innerText = p.rp_id;
                    const opText = p.operation === 'MakeCredential' ? 'Register New Passkey' : 'Authenticate Sign-in';
                    document.getElementById('modalTitle').innerText = opText;

                    const accountSelectArea = document.getElementById('modalAccountSelectionArea');
                    const accountSelect = document.getElementById('modalAccountSelect');

                    if (p.accounts && p.accounts.length > 1) {
                        accountSelectArea.style.display = 'block';
                        document.getElementById('modalUserDesc').innerText = '';

                        if (isNewPrompt) {
                            accountSelect.innerHTML = '';
                            p.accounts.forEach(acc => {
                                const opt = document.createElement('option');
                                opt.value = acc.id;
                                const displayName = acc.user_display_name && acc.user_display_name !== acc.user_name 
                                    ? ` (${acc.user_display_name})` 
                                    : '';
                                opt.text = `${acc.user_name}${displayName}`;
                                accountSelect.appendChild(opt);
                            });
                            if (p.selected_credential_id) {
                                accountSelect.value = p.selected_credential_id;
                            } else if (p.accounts.length > 0) {
                                accountSelect.value = p.accounts[0].id;
                            }

                            accountSelect.onchange = async () => {
                                if (currentPromptId && accountSelect.value) {
                                    await fetch('/api/verify/select', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({
                                            request_id: currentPromptId,
                                            credential_id: accountSelect.value
                                        })
                                    });
                                }
                            };
                        }
                    } else {
                        accountSelectArea.style.display = 'none';
                        accountSelect.innerHTML = '';
                        document.getElementById('modalUserDesc').innerText = p.user_name ? `Account: ${p.user_name}` : '';
                    }

                    if (!p.is_security_setup) {
                        document.getElementById('modalSetupView').style.display = 'block';
                        document.getElementById('modalVerifyView').style.display = 'none';
                    } else {
                        document.getElementById('modalSetupView').style.display = 'none';
                        document.getElementById('modalVerifyView').style.display = 'block';
                        if (isNewPrompt) {
                            setTimeout(() => {
                                if (document.activeElement !== accountSelect) {
                                    document.getElementById('verifyPinInput').focus();
                                }
                            }, 100);
                        }
                    }

                    if (isNewPrompt) {
                        document.getElementById('verifyModal').style.display = 'flex';
                    }
                } else {
                    if (currentPromptId !== null) {
                        document.getElementById('verifyModal').style.display = 'none';
                        currentPromptId = null;
                        loadCredentials();
                        loadAuditLogs();
                    }
                }
            } catch (e) {
                // Ignore network errors in poll
            }
        }

        async function submitModalApproval(method) {
            if (!currentPromptId) return;
            let pin = null;

            if (method === 'SETUP') {
                pin = document.getElementById('setupPinInput').value.trim();
                if (pin.length !== 6 || !/^\d+$/.test(pin)) {
                    alert("Activation PIN must be exactly 6 digits!");
                    return;
                }
            } else if (method === 'PIN') {
                pin = document.getElementById('verifyPinInput').value.trim();
                if (pin.length !== 6 || !/^\d+$/.test(pin)) {
                    alert("PIN must be exactly 6 digits!");
                    return;
                }
            }

            const accountSelect = document.getElementById('modalAccountSelect');
            const credential_id = (accountSelect && accountSelect.value) ? accountSelect.value : null;

            const res = await fetch('/api/verify/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: currentPromptId, method, pin, credential_id })
            });
            const json = await res.json();
            if (json.success) {
                document.getElementById('verifyModal').style.display = 'none';
                document.getElementById('verifyPinInput').value = '';
                document.getElementById('setupPinInput').value = '';
                currentPromptId = null;
                setTimeout(() => { loadCredentials(); loadAuditLogs(); }, 500);
            } else {
                alert("Authentication error: " + json.error);
            }
        }
        async function submitModalReject() {
            if (!currentPromptId) return;
            await fetch('/api/verify/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: currentPromptId, reason: "Rejected on Web CMS" })
            });
            document.getElementById('verifyModal').style.display = 'none';
            currentPromptId = null;
            loadAuditLogs();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // Init: resolve the stored language first so the first paint is already localized.
        (async () => {
            await loadSettings();
            refreshTableLayout();
            MOBILE_QUERY.addEventListener('change', () => requestAnimationFrame(() => refreshTableLayout()));
            fetchStatus();
            loadCredentials();
        })();
        setInterval(fetchStatus, 3000);
        setInterval(pollPendingVerification, 1000);
    </script>
</body>
</html>
"#)
}

async fn favicon_ico() -> impl IntoResponse {
    const FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");
    ([(header::CONTENT_TYPE, "image/x-icon")], FAVICON)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityEngine;
    use crate::sensor::UsbSensor;

    fn create_test_state() -> AppState {
        let db = Db::open(":memory:").expect("Failed to open test db");
        let sensor = UsbSensor::new();
        let security = SecurityEngine::new(db.clone(), sensor, false);
        AppState {
            db,
            security,
            debug_mode: Arc::new(AtomicBool::new(false)),
            uhid_connected: Arc::new(AtomicBool::new(false)),
            unlimited_fps: false,
            port: 10209,
        }
    }

    #[tokio::test]
    async fn test_settings_default_language_and_persistence() {
        let state = create_test_state();

        let initial = get_settings(State(state.clone())).await.0;
        assert!(initial.success);
        let defaults = initial.data.expect("settings payload");
        assert_eq!(defaults.get("language").map(String::as_str), Some("en"));
        assert_eq!(defaults.get("daemon.port").map(String::as_str), Some("10209"));

        let updated = update_settings(
            State(state.clone()),
            Json(SettingsUpdate {
                language: Some("vi".into()),
                ..Default::default()
            }),
        )
        .await
        .0;
        assert!(updated.success);
        assert_eq!(
            updated.data.as_ref().and_then(|m| m.get("language")).map(String::as_str),
            Some("vi")
        );
        assert_eq!(state.db.get_app_setting("language").unwrap().as_deref(), Some("vi"));

        // Unknown languages are rejected instead of being persisted.
        let rejected = update_settings(
            State(state.clone()),
            Json(SettingsUpdate {
                language: Some("fr".into()),
                ..Default::default()
            }),
        )
        .await
        .0;
        assert!(!rejected.success);
        assert_eq!(state.db.get_app_setting("language").unwrap().as_deref(), Some("vi"));
    }

    #[tokio::test]
    async fn test_settings_store_daemon_parameters() {
        let state = create_test_state();

        let stored = update_settings(
            State(state.clone()),
            Json(SettingsUpdate {
                language: None,
                daemon: Some(DaemonSettingsUpdate {
                    host: Some("127.0.0.1".into()),
                    port: Some(11223),
                    database: Some("vault.db".into()),
                    debug: Some(true),
                    unlimited_fingerprints: Some(true),
                    running: Some(true),
                    ..Default::default()
                }),
            }),
        )
        .await
        .0;
        assert!(stored.success, "{:?}", stored.error);
        let map = stored.data.expect("settings payload");
        assert_eq!(map.get("daemon.host").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(map.get("daemon.port").map(String::as_str), Some("11223"));
        assert_eq!(map.get("daemon.database").map(String::as_str), Some("vault.db"));
        assert_eq!(map.get("daemon.debug").map(String::as_str), Some("true"));
        assert_eq!(map.get("daemon.running").map(String::as_str), Some("true"));

        // Invalid values must not be written.
        let bad_port = update_settings(
            State(state.clone()),
            Json(SettingsUpdate {
                daemon: Some(DaemonSettingsUpdate {
                    port: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .await
        .0;
        assert!(!bad_port.success);
        let bad_host = update_settings(
            State(state.clone()),
            Json(SettingsUpdate {
                daemon: Some(DaemonSettingsUpdate {
                    host: Some("   ".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .await
        .0;
        assert!(!bad_host.success);
        assert_eq!(state.db.get_app_setting("daemon.port").unwrap().as_deref(), Some("11223"));
    }

    #[tokio::test]
    async fn test_web_clear_auth_logs() {
        let state = create_test_state();
        state.db.log_auth(None, "example.com", "MakeCredential", "SUCCESS", "PIN", None);
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 1);

        let res = clear_auth_logs(State(state.clone())).await;
        assert!(res.0.success);
        assert_eq!(res.0.data, Some(1));
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_web_clear_debug_logs() {
        let state = create_test_state();
        state.db.log_debug("INFO", "TEST", "Debug message");
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 1);

        let res = clear_debug_logs(State(state.clone())).await;
        assert!(res.0.success);
        assert_eq!(res.0.data, Some(1));
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_web_clean_all_logs() {
        let state = create_test_state();
        state.db.log_auth(None, "example.com", "GetAssertion", "SUCCESS", "FP", None);
        state.db.log_debug("WARN", "TEST", "Debug warning");
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 1);
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 1);

        let res = clean_all_logs(State(state.clone())).await;
        assert!(res.0.success);
        let result = res.0.data.unwrap();
        assert_eq!(result.auth_logs_deleted, 1);
        assert_eq!(result.debug_logs_deleted, 1);
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 0);
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 0);
    }

    async fn send_http_request(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, addr, body.len(), body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await.unwrap();
        let sep = b"\r\n\r\n";
        if let Some(pos) = response_bytes.windows(sep.len()).position(|w| w == sep) {
            let header = String::from_utf8_lossy(&response_bytes[..pos]).to_string();
            let body = String::from_utf8_lossy(&response_bytes[pos + sep.len()..]).to_string();
            (header, body)
        } else {
            (String::from_utf8_lossy(&response_bytes).to_string(), String::new())
        }
    }

    #[tokio::test]
    async fn test_web_routes_http_e2e() {
        let state = create_test_state();
        state.db.log_auth(None, "example.com", "GetAssertion", "SUCCESS", "FP", None);
        state.db.log_debug("WARN", "TEST", "Debug warning");

        let app = create_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Test GET /
        let (status, body) = send_http_request(addr, "GET", "/", "").await;
        assert!(status.contains("200 OK"));
        assert!(body.contains("cleanAuditLogs()"));
        assert!(body.contains("cleanDebugLogs()"));
        assert!(body.contains("cleanAllLogs()"));
        assert!(body.contains("🗑️ Clear Logs"));
        assert!(body.contains("🧹 Clear All"));

        // Test DELETE /api/logs
        let (status, body) = send_http_request(addr, "DELETE", "/api/logs", "").await;
        assert!(status.contains("200 OK"));
        assert!(body.contains("\"success\":true"));
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 0);

        // Seed auth log again
        state.db.log_auth(None, "example.com", "GetAssertion", "SUCCESS", "FP", None);

        // Test DELETE /api/debug-logs
        let (status, body) = send_http_request(addr, "DELETE", "/api/debug-logs", "").await;
        assert!(status.contains("200 OK"));
        assert!(body.contains("\"success\":true"));
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 0);

        // Seed debug log again
        state.db.log_debug("ERROR", "TEST", "Another debug error");

        // Test POST /api/logs/clean
        let (status, body) = send_http_request(addr, "POST", "/api/logs/clean", "").await;
        assert!(status.contains("200 OK"));
        assert!(body.contains("\"success\":true"));
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 0);
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 0);

        // Seed both again
        state.db.log_auth(None, "example.com", "GetAssertion", "SUCCESS", "FP", None);
        state.db.log_debug("ERROR", "TEST", "Another debug error");

        // Test DELETE /api/logs/clean
        let (status, body) = send_http_request(addr, "DELETE", "/api/logs/clean", "").await;
        assert!(status.contains("200 OK"));
        assert!(body.contains("\"success\":true"));
        assert_eq!(state.db.get_auth_logs(None, 10).unwrap().len(), 0);
        assert_eq!(state.db.get_debug_logs(10).unwrap().len(), 0);

        // Test GET /favicon.ico
        let (status, _body) = send_http_request(addr, "GET", "/favicon.ico", "").await;
        assert!(status.contains("200 OK"));
        assert!(status.contains("image/x-icon"));
    }

    #[tokio::test]
    async fn test_verify_pending_with_accounts_selection() {
        let state = create_test_state();
        state.security.set_pin("123456").unwrap();

        let accounts = vec![
            crate::security::PendingAccountOption {
                id: "cred_1".into(),
                user_name: "alice".into(),
                user_display_name: "Alice A".into(),
                last_used_at: "2026-09-22 10:00:00".into(),
                created_at: "2026-09-20 10:00:00".into(),
            },
            crate::security::PendingAccountOption {
                id: "cred_2".into(),
                user_name: "bob".into(),
                user_display_name: "Bob B".into(),
                last_used_at: "2026-09-21 10:00:00".into(),
                created_at: "2026-09-20 11:00:00".into(),
            },
        ];

        let sec_clone = state.security.clone();
        let verify_task = tokio::spawn(async move {
            sec_clone
                .request_user_verification_with_accounts(
                    "example.com",
                    "GetAssertion",
                    "alice",
                    accounts,
                    Some("cred_1".into()),
                )
                .await
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let pending_res = get_pending_verify(State(state.clone())).await;
        assert!(pending_res.0.success);
        let prompt = pending_res.0.data.unwrap().unwrap();
        assert_eq!(prompt.accounts.len(), 2);
        assert_eq!(prompt.selected_credential_id, Some("cred_1".into()));

        // Test POST /api/verify/select (change selected account)
        let select_req = SelectAccountRequest {
            request_id: prompt.request_id,
            credential_id: "cred_2".into(),
        };
        let select_res = select_verify_account(State(state.clone()), axum::Json(select_req)).await;
        assert!(select_res.0.success);

        // Verify prompt state updated
        let pending_res2 = get_pending_verify(State(state.clone())).await;
        let prompt2 = pending_res2.0.data.unwrap().unwrap();
        assert_eq!(prompt2.selected_credential_id, Some("cred_2".into()));

        // Approve choosing cred_2
        let approve_req = ApproveVerifyRequest {
            request_id: prompt.request_id,
            method: "PIN".into(),
            pin: Some("123456".into()),
            credential_id: Some("cred_2".into()),
        };
        let approve_res = approve_verify(State(state.clone()), axum::Json(approve_req)).await;
        assert!(approve_res.0.success);

        let result = verify_task.await.unwrap().unwrap();
        assert_eq!(result.method, "PIN");
        assert_eq!(result.selected_credential_id, Some("cred_2".into()));
    }

    #[tokio::test]
    async fn test_web_passkey_endpoints() {
        let state = create_test_state();

        // 1. Create passkey via API
        let create_req = crate::passkey::PasskeyCreateRequest {
            rp: crate::passkey::RpEntity {
                id: "github.com".to_string(),
                name: Some("GitHub".to_string()),
            },
            user: crate::passkey::UserEntity {
                id: crate::passkey::b64url_encode(b"gh_user_42"),
                name: "dev@github.com".to_string(),
                display_name: Some("Dev User".to_string()),
            },
            challenge: Some(crate::passkey::b64url_encode(b"random_challenge")),
            client_data_json: None,
            client_data_hash: None,
            user_verification: Some("ANDROID_BIOMETRIC".to_string()),
            pin: None,
        };

        let create_res = passkey_create(State(state.clone()), axum::Json(create_req)).await;
        assert!(create_res.0.success);
        let cred_data = create_res.0.data.unwrap();
        assert_eq!(cred_data.cred_type, "public-key");

        // 2. Query candidates via API
        let cand_req = crate::passkey::CandidatesRequest {
            rp_id: "github.com".to_string(),
            allow_credentials: vec![],
        };
        let cand_res = passkey_candidates(State(state.clone()), axum::Json(cand_req)).await;
        assert!(cand_res.0.success);
        let cands = cand_res.0.data.unwrap();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].user_name, "dev@github.com");

        // 3. Get assertion via API
        let get_req = crate::passkey::PasskeyGetRequest {
            rp_id: "github.com".to_string(),
            credential_id: Some(cred_data.id.clone()),
            challenge: Some(crate::passkey::b64url_encode(b"gh_login_challenge")),
            client_data_json: None,
            client_data_hash: None,
            user_verification: Some("ANDROID_BIOMETRIC".to_string()),
            pin: None,
        };
        let get_res = passkey_get(State(state.clone()), axum::Json(get_req)).await;
        assert!(get_res.0.success);
        let get_data = get_res.0.data.unwrap();
        assert_eq!(get_data.id, cred_data.id);
    }

    /// Enrolling without the 3274:8012 sensor used to answer `success: true` and still write a
    /// slot row, so the dashboard listed a "fingerprint" that could never match — the chip holds
    /// no template for it. The pre-flight check must refuse and record nothing.
    #[tokio::test]
    async fn test_enrollment_without_sensor_is_refused_and_records_no_slot() {
        if crate::sensor::UsbSensor::is_hardware_plugged() {
            // Only reproducible where the dongle is absent; on a machine that has it attached the
            // enrollment would really run against the hardware.
            return;
        }

        let state = create_test_state();
        let res = start_enroll_fingerprint(
            State(state.clone()),
            Json(AddFingerprintRequest { name: "ghost".into() }),
        )
        .await
        .0;

        assert!(!res.success, "enrolling without the sensor must fail");
        assert!(res.error.unwrap_or_default().contains("not connected"));
        assert!(
            state.db.get_fingerprints().unwrap().is_empty(),
            "no image was captured, so no slot may be recorded"
        );
    }

    /// Approving a request with the FINGERPRINT method while the sensor is unplugged must not
    /// fall through to success: the old code skipped the biometric check entirely, so clicking
    /// "Fingerprint" on the dashboard approved the WebAuthn request without any verification.
    #[tokio::test]
    async fn test_fingerprint_approval_requires_the_sensor() {
        if crate::sensor::UsbSensor::is_hardware_plugged() {
            return;
        }

        let state = create_test_state();
        state.db.add_fingerprint(0, "T1").unwrap();

        let sec = state.security.clone();
        let verify_task = tokio::spawn(async move {
            sec.request_user_verification("example.com", "GetAssertion", "alice").await
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let prompt = get_pending_verify(State(state.clone()))
            .await
            .0
            .data
            .unwrap()
            .expect("a verification request must be pending");

        let approved = approve_verify(
            State(state.clone()),
            Json(ApproveVerifyRequest {
                request_id: prompt.request_id,
                method: "FINGERPRINT".into(),
                pin: None,
                credential_id: None,
            }),
        )
        .await
        .0;

        assert!(!approved.success, "fingerprint approval must fail without the sensor");
        assert!(approved.error.unwrap_or_default().contains("not connected"));
        assert!(
            get_pending_verify(State(state.clone())).await.0.data.unwrap().is_some(),
            "the request must stay pending so the user can fall back to the PIN"
        );
        verify_task.abort();
    }
}
