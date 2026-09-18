use crate::db::Db;
use crate::sensor::UsbSensor;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiometricModality {
    Fingerprint,
    Face,
    Iris,
    Voice,
    Palm,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PendingPrompt {
    pub request_id: u64,
    pub rp_id: String,
    pub operation: String,
    pub user_name: String,
    pub is_security_setup: bool,
    pub pin_configured: bool,
    pub fp_count: usize,
    pub hardware_sensor_available: bool,
    pub available_modalities: Vec<BiometricModality>,
    pub created_at_secs: u64,
    pub timeout_seconds: u64,
}

pub struct ActiveVerification {
    pub prompt: PendingPrompt,
    pub start_time: Instant,
    pub responder: Option<oneshot::Sender<Result<String, String>>>,
}

#[derive(Clone)]
pub struct SecurityEngine {
    db: Db,
    sensor: UsbSensor,
    pending: Arc<Mutex<Option<ActiveVerification>>>,
    req_counter: Arc<AtomicU64>,
}

impl SecurityEngine {
    pub fn new(db: Db, sensor: UsbSensor) -> Self {
        Self {
            db,
            sensor,
            pending: Arc::new(Mutex::new(None)),
            req_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn sensor(&self) -> &UsbSensor {
        &self.sensor
    }

    pub fn validate_pin_format(pin: &str) -> Result<(), &'static str> {
        if pin.len() != 6 {
            return Err("Mã passkey PIN phải có đúng 6 chữ số");
        }
        if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err("Mã passkey PIN chỉ được chứa các ký tự số (0-9)");
        }
        Ok(())
    }

    pub fn hash_pin(pin: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(pin.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), &'static str> {
        Self::validate_pin_format(pin)?;
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let hash = Self::hash_pin(pin, &salt);
        self.db.set_pin(&hash, &salt).map_err(|_| "Lỗi lưu PIN vào database")?;
        self.db.log_auth(None, "SYSTEM", "PinSet", "SUCCESS", "PIN", Some("Đã thiết lập mã PIN 6 số"));
        Ok(())
    }

    pub fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<(), &'static str> {
        Self::validate_pin_format(new_pin)?;
        self.verify_pin(old_pin)?;
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let hash = Self::hash_pin(new_pin, &salt);
        self.db.set_pin(&hash, &salt).map_err(|_| "Lỗi cập nhật PIN vào database")?;
        self.db.log_auth(None, "SYSTEM", "PinChanged", "SUCCESS", "PIN", Some("Đã đổi mã PIN 6 số thành công"));
        Ok(())
    }

    pub fn remove_pin(&self, current_pin: &str) -> Result<(), &'static str> {
        self.verify_pin(current_pin)?;
        self.db.remove_pin().map_err(|_| "Lỗi xóa PIN khỏi database")?;
        self.db.log_auth(None, "SYSTEM", "PinRemoved", "SUCCESS", "PIN", Some("Đã xóa mã PIN 6 số"));
        Ok(())
    }

    pub fn verify_pin(&self, pin: &str) -> Result<bool, &'static str> {
        let (stored_hash, stored_salt) = self.db.get_pin_hash_and_salt().map_err(|_| "Lỗi đọc cấu hình bảo mật")?;
        match (stored_hash, stored_salt) {
            (Some(hash), Some(salt)) => {
                let computed = Self::hash_pin(pin, &salt);
                if computed == hash {
                    Ok(true)
                } else {
                    Err("Mã PIN không chính xác")
                }
            }
            _ => Err("Chưa thiết lập mã PIN bảo mật"),
        }
    }

    /// Thêm vân tay: Quét thực tế từ thiết bị USB Microarray MAFP
    pub fn enroll_fingerprint<F>(&self, name: &str, progress_cb: F) -> Result<crate::db::FingerprintRow, String>
    where
        F: FnMut(u32, u32, &str),
    {
        // 1. Kiểm tra giới hạn 10 vân tay trước
        let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
        if fps.len() >= 10 {
            return Err("Đã đạt giới hạn tối đa 10 vân tay".into());
        }

        // Tìm slot tiếp theo
        let existing_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
        let mut target_slot = 0u32;
        for s in 0..10 {
            if !existing_slots.contains(&s) {
                target_slot = s;
                break;
            }
        }

        // 2. Thử kết nối và quét trực tiếp từ USB
        if UsbSensor::is_hardware_plugged() {
            println!("[SECURITY] Bắt đầu chu trình quét vân tay thật trên USB cho slot {}...", target_slot);
            self.sensor.enroll_fingerprint(target_slot, progress_cb)?;
        } else {
            println!("[SECURITY] Không phát hiện USB vân tay, lưu slot ảo.");
        }

        // 3. Lưu thông tin vào SQLite
        let row = self.db.add_fingerprint(name).map_err(|e| e.to_string())?;
        self.db.log_auth(
            None,
            "SYSTEM",
            "FingerprintEnrolled",
            "SUCCESS",
            "FINGERPRINT",
            Some(&format!("Đã quét và lưu vân tay '{}' vào USB & DB slot {}", row.name, row.slot_index)),
        );
        Ok(row)
    }

    pub fn delete_fingerprint(&self, id: i64) -> Result<bool, String> {
        let ok = self.db.delete_fingerprint(id).map_err(|e| e.to_string())?;
        if ok {
            self.db.log_auth(
                None,
                "SYSTEM",
                "FingerprintDeleted",
                "SUCCESS",
                "FINGERPRINT",
                Some(&format!("Đã xóa vân tay id {}", id)),
            );
        }
        Ok(ok)
    }

    pub fn get_pending_prompt(&self) -> Option<PendingPrompt> {
        let mut guard = self.pending.lock();
        if let Some(active) = guard.as_ref() {
            if active.start_time.elapsed() > Duration::from_secs(active.prompt.timeout_seconds) {
                *guard = None;
                None
            } else {
                Some(active.prompt.clone())
            }
        } else {
            None
        }
    }

    pub async fn request_user_verification(
        &self,
        rp_id: &str,
        operation: &str,
        user_name: &str,
    ) -> Result<String, String> {
        let settings = self.db.get_security_settings().map_err(|e| e.to_string())?;
        let is_security_setup = settings.pin_enabled || settings.fp_count > 0;
        let sensor_ok = UsbSensor::is_hardware_plugged();

        let req_id = self.req_counter.fetch_add(1, Ordering::SeqCst);
        let prompt = PendingPrompt {
            request_id: req_id,
            rp_id: rp_id.to_string(),
            operation: operation.to_string(),
            user_name: user_name.to_string(),
            is_security_setup,
            pin_configured: settings.pin_enabled,
            fp_count: settings.fp_count,
            hardware_sensor_available: sensor_ok,
            available_modalities: vec![
                BiometricModality::Fingerprint,
                BiometricModality::Face,
            ],
            created_at_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            timeout_seconds: 60,
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock();
            *guard = Some(ActiveVerification {
                prompt,
                start_time: Instant::now(),
                responder: Some(tx),
            });
        }

        println!(
            "\n[SECURITY] >>> YÊU CẦU XÁC THỰC MỚI (Request #{} - RP: '{}', Thao tác: '{}') <<<",
            req_id, rp_id, operation
        );
        if sensor_ok {
            println!("[SECURITY] >>> Bạn có thể chạm ngón tay vào cảm biến USB hoặc dùng Web CMS <<<");
        } else {
            println!("[SECURITY] >>> Mở Web CMS http://localhost:10209 để duyệt hoặc từ chối <<<");
        }

        // Tự động lắng nghe chạm cảm biến vân tay song song nếu USB đang cắm!
        let sensor_clone = self.sensor.clone();
        let pending_ref = self.pending.clone();
        let db_clone = self.db.clone();
        let rp_id_owned = rp_id.to_string();
        let op_owned = operation.to_string();

        let fp_listener = tokio::task::spawn_blocking(move || {
            if !UsbSensor::is_hardware_plugged() {
                return;
            }
            // Lắng nghe chạm ngón tay trong tối đa 55s
            if let Ok(true) = sensor_clone.wait_for_finger_press(55) {
                let mut guard = pending_ref.lock();
                if let Some(mut active) = guard.take() {
                    if active.prompt.request_id == req_id {
                        if let Some(responder) = active.responder.take() {
                            let _ = responder.send(Ok("USB_FINGERPRINT_HARDWARE".to_string()));
                        }
                        db_clone.log_auth(
                            None,
                            &rp_id_owned,
                            &op_owned,
                            "SUCCESS",
                            "FINGERPRINT_USB",
                            Some("Xác thực thành công bằng chạm cảm biến USB phần cứng"),
                        );
                    } else {
                        *guard = Some(active);
                    }
                }
            }
        });

        let result = match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(res)) => {
                let mut guard = self.pending.lock();
                *guard = None;
                res
            }
            Ok(Err(_)) => {
                let mut guard = self.pending.lock();
                *guard = None;
                Err("Phiên xác thực bị hủy bỏ".to_string())
            }
            Err(_) => {
                let mut guard = self.pending.lock();
                *guard = None;
                Err("Hết thời gian chờ xác thực (Timeout 60s)".to_string())
            }
        };

        fp_listener.abort();
        result
    }

    pub fn approve_pending(&self, req_id: u64, method: &str, input_pin: Option<&str>) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Mã yêu cầu không khớp".to_string());
            }

            match method {
                "PIN" => {
                    let pin = input_pin.ok_or_else(|| "Chưa nhập mã PIN".to_string())?;
                    self.verify_pin(pin)?;
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok("PIN".to_string()));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "PIN",
                        Some("Xác thực PIN 6 số thành công qua Web CMS"),
                    );
                    Ok(())
                }
                "FINGERPRINT" => {
                    // Nếu USB cắm, chờ người dùng chạm ngón tay thật trong 15s
                    if UsbSensor::is_hardware_plugged() {
                        println!("[SECURITY] Đang chờ bạn chạm ngón tay vào cảm biến USB...");
                        if let Err(e) = self.sensor.wait_for_finger_press(15) {
                            *guard = Some(active);
                            return Err(format!("Chưa phát hiện chạm vân tay trên USB: {}", e));
                        }
                    }

                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok("FINGERPRINT".to_string()));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "FINGERPRINT",
                        Some("Xác thực cảm biến vân tay thành công"),
                    );
                    Ok(())
                }
                "SETUP" => {
                    if let Some(pin) = input_pin {
                        self.set_pin(pin)?;
                    }
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok("SETUP".to_string()));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "SETUP",
                        Some("Khởi tạo phương thức bảo mật mới thành công"),
                    );
                    Ok(())
                }
                _ => {
                    *guard = Some(active);
                    Err("Phương thức xác thực không hợp lệ".to_string())
                }
            }
        } else {
            Err("Không có yêu cầu xác thực nào đang chờ".to_string())
        }
    }

    pub fn reject_pending(&self, req_id: u64, reason: &str) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Mã yêu cầu không khớp".to_string());
            }

            if let Some(responder) = active.responder.take() {
                let _ = responder.send(Err(format!("Từ chối bởi người dùng: {}", reason)));
            }
            self.db.log_auth(
                None,
                &active.prompt.rp_id,
                &active.prompt.operation,
                "REJECTED",
                "NONE",
                Some(reason),
            );
            Ok(())
        } else {
            Err("Không có yêu cầu xác thực nào đang chờ".to_string())
        }
    }
}
