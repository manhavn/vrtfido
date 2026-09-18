use crate::db::Db;
use crate::security::SecurityEngine;
use axum::{
    extract::{Path, State},
    response::Html,
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
        .route("/api/status", get(get_status))
        .route("/api/credentials", get(list_credentials))
        .route("/api/credentials/{id}", put(update_credential))
        .route("/api/credentials/{id}", delete(delete_credential))
        .route("/api/credentials/{id}/logs", get(get_credential_logs))
        .route("/api/logs", get(list_auth_logs))
        .route("/api/debug-logs", get(list_debug_logs))
        .route("/api/security", get(get_security))
        .route("/api/security/pin", post(set_pin))
        .route("/api/security/pin", delete(remove_pin))
        .route("/api/security/fingerprints", post(add_fingerprint))
        .route("/api/security/fingerprints/enroll/start", post(start_enroll_fingerprint))
        .route("/api/security/fingerprints/enroll/status", get(get_enroll_status))
        .route("/api/security/fingerprints/enroll/cancel", post(cancel_enroll))
        .route("/api/security/fingerprints/{id}", delete(delete_fingerprint))
        .route("/api/verify/pending", get(get_pending_verify))
        .route("/api/verify/approve", post(approve_verify))
        .route("/api/verify/reject", post(reject_verify))
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
        app_name: "vrtfido",
        version: "1.0.0",
        port: 10209,
        uhid_connected: state.uhid_connected.load(Ordering::SeqCst),
        usb_sensor_connected: crate::sensor::UsbSensor::is_hardware_plugged(),
        debug_mode: state.debug_mode.load(Ordering::SeqCst),
        credentials_count: creds.len(),
        pin_configured: sec.pin_enabled,
        fp_count: sec.fp_count,
        unlimited_fingerprints: state.unlimited_fps,
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
                Some(&format!("Cập nhật tên tài khoản: {}", payload.user_name)),
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
                Some("Xóa tài khoản khỏi bộ nhớ"),
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
        return Json(ApiResponse::err("Tên gợi nhớ vân tay không được để trống"));
    }
    let sec = state.security.clone();
    tokio::task::spawn_blocking(move || {
        let _ = sec.enroll_fingerprint(&name);
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
        return Json(ApiResponse::err("Tên gợi nhớ vân tay không được để trống"));
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
    match state.security.approve_pending(payload.request_id, &payload.method, payload.pin.as_deref()) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn reject_verify(
    State(state): State<AppState>,
    Json(payload): Json<RejectVerifyRequest>,
) -> Json<ApiResponse<bool>> {
    let reason = payload.reason.unwrap_or_else(|| "Người dùng từ chối thao tác".into());
    match state.security.reject_pending(payload.request_id, &reason) {
        Ok(_) => Json(ApiResponse::ok(true)),
        Err(e) => Json(ApiResponse::err(e)),
    }
}

async fn index_html() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>vrtfido - Virtual FIDO2 & Passkey Manager</title>
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
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-primary); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }
        
        header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
        .logo { display: flex; align-items: center; gap: 0.75rem; font-size: 1.25rem; font-weight: 700; color: var(--accent); }
        .badge-status { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; }
        .badge-online { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-debug { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); margin-left: 0.5rem; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }

        .container { max-width: 1200px; width: 100%; margin: 0 auto; padding: 2rem; flex: 1; }

        .tabs { display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
        .tab-btn { background: none; border: none; color: var(--text-muted); padding: 0.75rem 1.25rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; display: flex; align-items: center; gap: 0.5rem; }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.5rem; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .card-title { font-size: 1.15rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }

        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th { padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); background: var(--bg-secondary); }
        td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(51, 65, 85, 0.5); }
        tr:hover td { background: rgba(51, 65, 85, 0.2); }

        .btn { padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; font-size: 0.85rem; cursor: pointer; border: 1px solid transparent; transition: all 0.15s; display: inline-flex; align-items: center; gap: 0.4rem; }
        .btn-primary { background: var(--accent); color: #020617; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border-color: rgba(239, 68, 68, 0.3); }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-secondary { background: var(--bg-hover); color: var(--text-main); }
        .btn-secondary:hover { background: #475569; }
        .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8rem; }

        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; color: var(--text-muted); }
        .form-control { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.85rem; color: var(--text-main); font-size: 0.9rem; outline: none; }
        .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }

        .modal-overlay { position: fixed; inset: 0; background: rgba(2, 6, 23, 0.85); backdrop-filter: blur(8px); display: none; justify-content: center; align-items: center; z-index: 100; animation: fadeIn 0.2s; }
        .modal-box { background: var(--bg-card); border: 2px solid var(--accent); border-radius: 12px; width: 90%; max-width: 500px; padding: 2rem; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 0 50px var(--accent-glow); text-align: center; }
        .modal-icon { font-size: 3rem; margin-bottom: 1rem; }
        .modal-title { font-size: 1.35rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--accent); }
        .modal-rp { font-size: 1.1rem; font-weight: 600; color: var(--text-main); background: var(--bg-secondary); padding: 0.5rem 1rem; border-radius: 6px; display: inline-block; margin: 0.75rem 0; }

        .tag-op { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .tag-make { background: rgba(56, 189, 248, 0.15); color: var(--accent); }
        .tag-get { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .tag-status-success { color: var(--success); font-weight: 600; }
        .tag-status-rejected { color: var(--danger); font-weight: 600; }

        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    </style>
</head>
<body>

    <header>
        <div class="logo">
            <span>🛡️</span>
            <span>vrtfido - WebAuthn CMS</span>
        </div>
        <div style="display: flex; align-items: center;">
            <div id="uhidStatus" class="badge-status badge-offline">
                <span class="dot"></span>
                <span id="uhidText">UHID Đang kết nối...</span>
            </div>
            <div id="usbSensorStatus" class="badge-status badge-offline" style="margin-left: 0.5rem;">
                <span class="dot"></span>
                <span id="usbSensorText">USB Sensor 3274:8012</span>
            </div>
            <div id="unlimitedFpStatus" class="badge-status" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); margin-left: 0.5rem; display: none;">
                ♾️ Vân tay: Không giới hạn
            </div>
            <div id="debugStatus" class="badge-status badge-debug" style="display: none;">
        </div>
    </header>

    <div class="container">
        <!-- Navigation -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-creds')">🔑 Tài khoản Passkey (<span id="credCount">0</span>)</button>
            <button class="tab-btn" onclick="switchTab('tab-security')">🛡️ Cài đặt Bảo mật & Sinh trắc</button>
            <button class="tab-btn" onclick="switchTab('tab-logs')">📜 Nhật ký Truy vết (Audit)</button>
            <button class="tab-btn" onclick="switchTab('tab-debug')">🐞 Logs Debug & Lỗi</button>
        </div>

        <!-- TAB 1: CREDENTIALS -->
        <div id="tab-creds" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Tài khoản WebAuthn đã đăng ký</div>
                    <button class="btn btn-secondary btn-sm" onclick="loadCredentials()">🔄 Làm mới</button>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Relying Party (Domain)</th>
                                <th>Tên người dùng</th>
                                <th>Tên hiển thị</th>
                                <th>Số lần ký</th>
                                <th>Ngày tạo</th>
                                <th>Dùng lần cuối</th>
                                <th>Thao tác</th>
                            </tr>
                        </thead>
                        <tbody id="credTableBody">
                            <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Đang tải dữ liệu...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: SECURITY & BIOMETRICS -->
        <div id="tab-security" class="tab-content">
            <div class="grid-2">
                <!-- Mã PIN 6 số -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🔢 Mật khẩu Passkey (Mã PIN 6 số)</div>
                        <span id="pinBadge" class="badge-status badge-offline">Chưa thiết lập</span>
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
                        Chỉ cho phép duy nhất 1 mã PIN gồm đúng 6 chữ số (0-9) dùng để xác thực nhanh khi truy cập website.
                    </p>
                    <div id="pinFormArea">
                        <div class="form-group" id="oldPinGroup" style="display: none;">
                            <label class="form-label">Mã PIN hiện tại:</label>
                            <input type="password" maxlength="6" id="oldPinInput" class="form-control" placeholder="6 chữ số cũ">
                        </div>
                        <div class="form-group">
                            <label class="form-label" id="newPinLabel">Nhập mã PIN 6 số mới:</label>
                            <input type="password" maxlength="6" id="newPinInput" class="form-control" placeholder="6 chữ số (vd: 123456)">
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <button class="btn btn-primary" onclick="submitPin()">💾 Lưu mã PIN</button>
                            <button class="btn btn-danger" id="removePinBtn" style="display: none;" onclick="removePin()">🗑️ Xóa mã PIN</button>
                        </div>
                    </div>
                </div>

                <!-- Sinh trắc học Vân tay (Max 10) -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🖐️ Quản lý Vân tay (<span id="fpCount">0</span><span id="fpLimitText">/10</span>)</div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
                        Đăng ký tối đa 10 dấu vân tay. Khi bấm thêm, hệ thống sẽ chờ bạn chạm ngón tay 6 lần vào đầu đọc USB.
                    </p>
                    <div class="form-group" style="display: flex; gap: 0.5rem;">
                        <input type="text" id="fpNameInput" class="form-control" placeholder="Tên gợi nhớ (vd: Ngón trỏ phải, Ngón cái trái...)">
                        <button class="btn btn-primary" id="addFpBtn" onclick="addFingerprint()">➕ Thêm vân tay</button>
                    </div>
                    <div style="max-height: 250px; overflow-y: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Slot</th>
                                    <th>Tên vân tay</th>
                                    <th>Ngày thêm</th>
                                    <th>Xóa</th>
                                </tr>
                            </thead>
                            <tbody id="fpTableBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-title">🚀 Chế độ Sinh trắc học mở rộng (Future Technologies)</div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 8px; border: 1px dashed var(--border);">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">👤</div>
                        <div style="font-weight: 600;">Nhận diện khuôn mặt (FaceID)</div>
                        <div style="font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem;">[Sẵn sàng Module]</div>
                    </div>
                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 8px; border: 1px dashed var(--border);">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">👁️</div>
                        <div style="font-weight: 600;">Quét mống mắt (Iris Scan)</div>
                        <div style="font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem;">[Sẵn sàng Module]</div>
                    </div>
                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 8px; border: 1px dashed var(--border);">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🎙️</div>
                        <div style="font-weight: 600;">Sinh trắc giọng nói (Voiceprint)</div>
                        <div style="font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem;">[Sẵn sàng Module]</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: AUDIT LOGS -->
        <div id="tab-logs" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📜 Nhật ký Truy vết Thao tác (Audit Trail)</div>
                    <button class="btn btn-secondary btn-sm" onclick="loadAuditLogs()">🔄 Làm mới</button>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Thời gian</th>
                                <th>Relying Party</th>
                                <th>Thao tác</th>
                                <th>Phương thức</th>
                                <th>Trạng thái</th>
                                <th>Chi tiết</th>
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
                    <div class="card-title">🐞 Logs Lỗi & Debug Hệ thống</div>
                    <button class="btn btn-secondary btn-sm" onclick="loadDebugLogs()">🔄 Làm mới</button>
                </div>
                <div style="overflow-x: auto; max-height: 400px;">
                    <table>
                        <thead>
                            <tr>
                                <th>Thời gian</th>
                                <th>Level</th>
                                <th>Component</th>
                                <th>Nội dung Log</th>
                            </tr>
                        </thead>
                        <tbody id="debugTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL TIẾN TRÌNH QUÉT VÂN TAY 6 LẦN TRÊN USB -->
    <div id="enrollModal" class="modal-overlay">
        <div class="modal-box" style="max-width: 440px;">
            <div class="modal-icon" id="enrollIcon" style="font-size: 3.5rem;">🖐️</div>
            <div class="modal-title" id="enrollModalTitle">Đang quét vân tay USB</div>
            <p id="enrollStepDesc" style="font-size: 1.25rem; font-weight: 700; color: var(--accent); margin: 0.5rem 0;">Lần 1 / 6</p>
            <p id="enrollActionPrompt" style="font-size: 0.95rem; color: var(--text-main); margin-bottom: 1.5rem;">Vui lòng chạm ngón tay vào cảm biến USB...</p>
            
            <div style="background: var(--bg-secondary); border-radius: 9999px; height: 12px; width: 100%; overflow: hidden; margin-bottom: 1.5rem; border: 1px solid var(--border);">
                <div id="enrollProgressBar" style="background: var(--accent); height: 100%; width: 16%; transition: width 0.3s;"></div>
            </div>

            <button class="btn btn-danger" onclick="cancelEnrollment()">❌ Hủy bỏ</button>
        </div>
    </div>

    <!-- MODAL XÁC THỰC WEBAUTHN TỰ ĐỘNG BẬT KHI CÓ REQUEST -->
    <div id="verifyModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-icon" id="modalIcon">🛡️</div>
            <div class="modal-title" id="modalTitle">Yêu cầu xác thực WebAuthn</div>
            <p style="font-size: 0.9rem; color: var(--text-muted);">Website đang yêu cầu khóa bảo mật của bạn:</p>
            <div>
                <span class="modal-rp" id="modalRpId">webauthn.io</span>
            </div>
            <p id="modalUserDesc" style="font-size: 0.85rem; margin-bottom: 1rem; color: var(--text-muted);"></p>

            <div id="modalSetupView" style="display: none; margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <p style="font-size: 0.9rem; color: var(--warning); margin-bottom: 0.75rem; font-weight: 600;">
                    ⚠️ Bạn chưa cài đặt bảo mật. Vui lòng tạo mã PIN 6 số để kích hoạt:
                </p>
                <input type="password" maxlength="6" id="setupPinInput" class="form-control" placeholder="Nhập 6 chữ số" style="text-align: center; font-size: 1.25rem; letter-spacing: 0.5rem; margin-bottom: 1rem;">
                <div style="display: flex; gap: 0.5rem; justify-content: center;">
                    <button class="btn btn-primary" onclick="submitModalApproval('SETUP')">Kích hoạt & Duyệt</button>
                    <button class="btn btn-danger" onclick="submitModalReject()">Từ chối</button>
                </div>
            </div>

            <div id="modalVerifyView" style="display: none; margin-top: 1rem;">
                <p style="font-size: 0.85rem; color: var(--accent); margin-bottom: 0.5rem; font-weight: 600;">
                    💡 Bạn có thể chạm ngón tay vào cảm biến USB ngay bây giờ hoặc nhập mã PIN:
                </p>
                <input type="password" maxlength="6" id="verifyPinInput" class="form-control" placeholder="Nhập mã PIN 6 số" style="text-align: center; font-size: 1.25rem; letter-spacing: 0.5rem; margin-bottom: 1rem;" autofocus>
                
                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                    <div style="display: flex; gap: 0.5rem; justify-content: center;">
                        <button class="btn btn-primary" onclick="submitModalApproval('PIN')">🔑 Xác thực bằng PIN</button>
                        <button class="btn btn-secondary" onclick="submitModalApproval('FINGERPRINT')">🖐️ Chạm Vân tay USB</button>
                    </div>
                    <button class="btn btn-danger" style="margin-top: 0.5rem;" onclick="submitModalReject()">❌ Từ chối yêu cầu</button>
                </div>
            </div>
        </div>
    </div>

    <!-- SCRIPT CHÍNH -->
    <script>
        let currentPromptId = null;
        let enrollInterval = null;

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
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
                    const uhidEl = document.getElementById('uhidStatus');
                    const uhidTxt = document.getElementById('uhidText');
                    if (s.uhid_connected) {
                        uhidEl.className = 'badge-status badge-online';
                        uhidTxt.innerText = 'UHID FIDO2 Online';
                    } else {
                        uhidEl.className = 'badge-status badge-offline';
                        uhidTxt.innerText = 'UHID Offline';
                    }

                    const usbEl = document.getElementById('usbSensorStatus');
                    const usbTxt = document.getElementById('usbSensorText');
                    if (s.usb_sensor_connected) {
                        usbEl.className = 'badge-status badge-online';
                        usbTxt.innerText = 'USB 3274:8012 Sẵn sàng';
                    } else {
                        usbEl.className = 'badge-status badge-offline';
                        usbTxt.innerText = 'USB 3274:8012 Chưa cắm';
                    }

                    document.getElementById('debugStatus').style.display = s.debug_mode ? 'inline-flex' : 'none';
                    document.getElementById('unlimitedFpStatus').style.display = s.unlimited_fingerprints ? 'inline-flex' : 'none';
                    document.getElementById('fpLimitText').innerText = s.unlimited_fingerprints ? ' - Không giới hạn' : '/10';
                    document.getElementById('credCount').innerText = s.credentials_count;
            } catch (e) {
                console.error(e);
            }
        }

        async function loadCredentials() {
            const tbody = document.getElementById('credTableBody');
            try {
                const res = await fetch('/api/credentials');
                const json = await res.json();
                if (json.success && json.data.length > 0) {
                    tbody.innerHTML = json.data.map(c => `
                        <tr>
                            <td><strong>${escapeHtml(c.rp_id)}</strong></td>
                            <td>${escapeHtml(c.user_name)}</td>
                            <td>${escapeHtml(c.user_display_name)}</td>
                            <td><span style="font-weight:700; color:var(--accent);">${c.sign_count}</span></td>
                            <td style="color:var(--text-muted);">${c.created_at}</td>
                            <td style="color:var(--text-muted);">${c.last_used_at}</td>
                            <td>
                                <button class="btn btn-secondary btn-sm" onclick="editCredential('${c.id}', '${escapeHtml(c.user_name)}', '${escapeHtml(c.user_display_name)}')">✏️ Sửa</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteCredential('${c.id}', '${escapeHtml(c.rp_id)}')">🗑️ Xóa</button>
                            </td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">Chưa có tài khoản Passkey nào được lưu. Hãy mở webauthn.io để đăng ký!</td></tr>';
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="7" style="color:var(--danger);">Lỗi tải dữ liệu: ${e}</td></tr>`;
            }
        }

        async function editCredential(id, oldName, oldDisplay) {
            const newName = prompt("Nhập tên đăng nhập mới:", oldName);
            if (newName === null) return;
            const newDisplay = prompt("Nhập tên hiển thị mới:", oldDisplay);
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
                alert("Lỗi: " + json.error);
            }
        }

        async function deleteCredential(id, rpId) {
            if (!confirm(`Bạn có chắc chắn muốn xóa khóa bảo mật của domain '${rpId}'?`)) return;
            const res = await fetch(`/api/credentials/${id}`, { method: 'DELETE' });
            const json = await res.json();
            if (json.success) {
                loadCredentials();
            } else {
                alert("Lỗi: " + json.error);
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
                        pinBadge.className = 'badge-status badge-online';
                        pinBadge.innerText = 'Đã kích hoạt';
                        oldGroup.style.display = 'block';
                        removeBtn.style.display = 'inline-flex';
                        newPinLabel.innerText = 'Nhập mã PIN 6 số thay thế:';
                    } else {
                        pinBadge.className = 'badge-status badge-offline';
                        pinBadge.innerText = 'Chưa thiết lập';
                        oldGroup.style.display = 'none';
                        removeBtn.style.display = 'none';
                        newPinLabel.innerText = 'Nhập mã PIN 6 số mới:';
                    }

                    document.getElementById('fpCount').innerText = fps.length;
                    const fpTbody = document.getElementById('fpTableBody');
                    if (fps.length > 0) {
                        fpTbody.innerHTML = fps.map(f => `
                            <tr>
                                <td>Slot ${f.slot_index}</td>
                                <td><strong>${escapeHtml(f.name)}</strong></td>
                                <td style="color:var(--text-muted);">${f.enrolled_at}</td>
                                <td><button class="btn btn-danger btn-sm" onclick="deleteFp(${f.id})">Xóa</button></td>
                            </tr>
                        `).join('');
                    } else {
                        fpTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Chưa có vân tay nào. Tối đa 10 vân tay.</td></tr>';
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
                alert("Mã PIN bắt buộc phải gồm đúng 6 chữ số (0-9)!");
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
                alert("Cập nhật mã PIN thành công!");
                document.getElementById('newPinInput').value = '';
                document.getElementById('oldPinInput').value = '';
                loadSecurity();
            } else {
                alert("Lỗi: " + json.error);
            }
        }

        async function removePin() {
            const current_pin = prompt("Vui lòng nhập mã PIN hiện tại để xác nhận xóa:");
            if (!current_pin) return;

            const res = await fetch('/api/security/pin', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current_pin })
            });
            const json = await res.json();
            if (json.success) {
                alert("Đã xóa mã PIN bảo mật!");
                loadSecurity();
            } else {
                alert("Lỗi: " + json.error);
            }
        }

        // BẮT ĐẦU QUY TRÌNH QUÉT VÂN TAY 6 LẦN TRÊN USB (NON-BLOCKING)
        async function addFingerprint() {
            const nameInput = document.getElementById('fpNameInput');
            const name = nameInput.value.trim();
            if (!name) {
                alert("Vui lòng nhập tên cho dấu vân tay!");
                return;
            }

            document.getElementById('enrollModal').style.display = 'flex';
            document.getElementById('enrollStepDesc').innerText = 'Khởi tạo...';
            document.getElementById('enrollActionPrompt').innerText = 'Đang kết nối cảm biến USB...';
            document.getElementById('enrollProgressBar').style.width = '10%';
            document.getElementById('enrollIcon').innerText = '🖐️';

            const res = await fetch('/api/security/fingerprints/enroll/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const json = await res.json();
            if (!json.success) {
                alert("Lỗi: " + json.error);
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
                        document.getElementById('enrollStepDesc').innerText = `Lần ${p.stage} / ${p.total_stages}`;
                        document.getElementById('enrollActionPrompt').innerText = p.message;
                        document.getElementById('enrollIcon').innerText = p.status === 'finger_lift' ? '👆' : '🖐️';
                    } else if (p.status === 'completed') {
                        clearInterval(enrollInterval);
                        enrollInterval = null;
                        document.getElementById('enrollProgressBar').style.width = '100%';
                        document.getElementById('enrollIcon').innerText = '✅';
                        document.getElementById('enrollStepDesc').innerText = 'Thành công!';
                        document.getElementById('enrollActionPrompt').innerText = 'Đã quét đủ 6 mẫu và lưu vào chip USB!';
                        setTimeout(() => {
                            document.getElementById('enrollModal').style.display = 'none';
                            document.getElementById('fpNameInput').value = '';
                            loadSecurity();
                        }, 1200);
                    } else if (p.status === 'error') {
                        clearInterval(enrollInterval);
                        enrollInterval = null;
                        document.getElementById('enrollIcon').innerText = '❌';
                        document.getElementById('enrollStepDesc').innerText = 'Thất bại';
                        document.getElementById('enrollActionPrompt').innerText = p.error || 'Có lỗi xảy ra';
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
            if (!confirm("Xóa vân tay này?")) return;
            const res = await fetch(`/api/security/fingerprints/${id}`, { method: 'DELETE' });
            const json = await res.json();
            if (json.success) {
                loadSecurity();
            } else {
                alert("Lỗi: " + json.error);
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
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Chưa có nhật ký nào.</td></tr>';
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" style="color:var(--danger);">Lỗi tải logs: ${e}</td></tr>`;
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
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">Không có debug log nào (Bật flag --debug khi chạy để xem).</td></tr>';
                }
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="4" style="color:var(--danger);">Lỗi: ${e}</td></tr>`;
            }
        }

        // --- POLLING REAL-TIME WEBAUTHN REQUEST MODAL ---
        async function pollPendingVerification() {
            try {
                const res = await fetch('/api/verify/pending');
                const json = await res.json();
                if (json.success && json.data) {
                    const p = json.data;
                    currentPromptId = p.request_id;

                    document.getElementById('modalRpId').innerText = p.rp_id;
                    const opText = p.operation === 'MakeCredential' ? 'Đăng ký Passkey mới' : 'Xác thực Đăng nhập';
                    document.getElementById('modalTitle').innerText = opText;
                    document.getElementById('modalUserDesc').innerText = p.user_name ? `Tài khoản: ${p.user_name}` : '';

                    if (!p.is_security_setup) {
                        document.getElementById('modalSetupView').style.display = 'block';
                        document.getElementById('modalVerifyView').style.display = 'none';
                    } else {
                        document.getElementById('modalSetupView').style.display = 'none';
                        document.getElementById('modalVerifyView').style.display = 'block';
                        setTimeout(() => document.getElementById('verifyPinInput').focus(), 100);
                    }

                    document.getElementById('verifyModal').style.display = 'flex';
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
                    alert("Mã PIN kích hoạt phải có đúng 6 chữ số!");
                    return;
                }
            } else if (method === 'PIN') {
                pin = document.getElementById('verifyPinInput').value.trim();
                if (pin.length !== 6 || !/^\d+$/.test(pin)) {
                    alert("Mã PIN phải có đúng 6 chữ số!");
                    return;
                }
            }

            const res = await fetch('/api/verify/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: currentPromptId, method, pin })
            });
            const json = await res.json();
            if (json.success) {
                document.getElementById('verifyModal').style.display = 'none';
                document.getElementById('verifyPinInput').value = '';
                document.getElementById('setupPinInput').value = '';
                currentPromptId = null;
                setTimeout(() => { loadCredentials(); loadAuditLogs(); }, 500);
            } else {
                alert("Lỗi xác thực: " + json.error);
            }
        }

        async function submitModalReject() {
            if (!currentPromptId) return;
            await fetch('/api/verify/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: currentPromptId, reason: "Từ chối trên Web CMS" })
            });
            document.getElementById('verifyModal').style.display = 'none';
            currentPromptId = null;
            loadAuditLogs();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Init
        fetchStatus();
        loadCredentials();
        setInterval(fetchStatus, 3000);
        setInterval(pollPendingVerification, 1000);
    </script>
</body>
</html>
"#)
}
