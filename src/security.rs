use crate::db::Db;
use crate::sensor::{SensorBusyMode, UsbSensor};
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

    /// Thêm vân tay: Quét 6 lần thực tế từ thiết bị USB Microarray MAFP
    pub fn enroll_fingerprint(&self, name: &str) -> Result<crate::db::FingerprintRow, String> {
        let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
        if fps.len() >= 10 {
            return Err("Đã đạt giới hạn tối đa 10 vân tay".into());
        }

        let existing_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
        let mut target_slot = 0u32;
        for s in 0..10 {
            if !existing_slots.contains(&s) {
                target_slot = s;
                break;
            }
        }

        // Quét mẫu 6 lần trên phần cứng thật
        let actual_fid = if UsbSensor::is_hardware_plugged() {
            println!("[SECURITY] Bắt đầu chu trình quét vân tay 6 mẫu trên USB...");
            self.sensor.enroll_fingerprint_pipeline(target_slot)?
        } else {
            target_slot as u16
        };

        let row = self.db.add_fingerprint(name).map_err(|e| e.to_string())?;
        self.db.log_auth(
            None,
            "SYSTEM",
            "FingerprintEnrolled",
            "SUCCESS",
            "FINGERPRINT",
            Some(&format!("Đã quét đủ 6 mẫu và lưu vân tay '{}' vào USB slot {}", row.name, actual_fid)),
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

            // Nếu xóa hết vân tay trong DB, dọn sạch flash chip USB
            let remaining = self.db.get_fingerprints().map_err(|e| e.to_string())?;
            if remaining.is_empty() && UsbSensor::is_hardware_plugged() {
                let _ = self.sensor.clear_chip_templates();
            }
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

        // Lấy danh sách các slot vân tay đã đăng ký
        let fps = self.db.get_fingerprints().unwrap_or_default();
        let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();

        // Lắng nghe chạm ngón tay trên USB nếu có vân tay đăng ký
        let sensor_clone = self.sensor.clone();
        let pending_ref = self.pending.clone();
        let db_clone = self.db.clone();
        let rp_id_owned = rp_id.to_string();
        let op_owned = operation.to_string();

        let fp_listener = tokio::task::spawn_blocking(move || {
            if !UsbSensor::is_hardware_plugged() || enrolled_slots.is_empty() {
                return;
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(55) {
                if sensor_clone.busy_mode() == SensorBusyMode::Idle {
                    // Chờ và so khớp vân tay THẬT!
                    match sensor_clone.verify_fingerprint(&enrolled_slots, 2) {
                        Ok(true) => {
                            // ĐÚNG VÂN TAY ĐÃ ĐĂNG KÝ!
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
                                        Some("Xác thực thành công bằng cảm biến vân tay USB (Trùng khớp template)"),
                                    );
                                    return;
                                } else {
                                    *guard = Some(active);
                                }
                            }
                        }
                        Ok(false) => {
                            // SAI VÂN TAY! NGÓN TAY KHÁC!
                            println!("[SECURITY] [REJECT] Ngón tay không trùng khớp với các mẫu đã cài đặt! TỪ CHỐI!");
                            db_clone.log_auth(
                                None,
                                &rp_id_owned,
                                &op_owned,
                                "REJECTED",
                                "FINGERPRINT_USB",
                                Some("Thử xác thực bằng ngón tay không trùng khớp (Bị từ chối)"),
                            );
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(300));
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
                    let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
                    let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
                    if enrolled_slots.is_empty() {
                        *guard = Some(active);
                        return Err("Chưa có vân tay nào được đăng ký trong hệ thống".into());
                    }

                    if UsbSensor::is_hardware_plugged() {
                        println!("[SECURITY] Đang chờ bạn chạm đúng ngón tay vào cảm biến USB...");
                        match self.sensor.verify_fingerprint(&enrolled_slots, 15) {
                            Ok(true) => {
                                println!("[SECURITY] Xác thực vân tay thành công!");
                            }
                            Ok(false) => {
                                *guard = Some(active);
                                return Err("Vân tay KHÔNG TRÙNG KHỚP với bất kỳ mẫu nào đã cài đặt! Yêu cầu bị từ chối.".into());
                            }
                            Err(e) => {
                                *guard = Some(active);
                                return Err(format!("Lỗi cảm biến vân tay: {}", e));
                            }
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
                        Some("Xác thực cảm biến vân tay thành công (Khớp template)"),
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
