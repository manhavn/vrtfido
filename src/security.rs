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
pub struct PendingAccountOption {
    pub id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub last_used_at: String,
    pub created_at: String,
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
    pub accounts: Vec<PendingAccountOption>,
    pub selected_credential_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VerificationSuccess {
    pub method: String,
    pub selected_credential_id: Option<String>,
}

pub struct ActiveVerification {
    pub prompt: PendingPrompt,
    pub start_time: Instant,
    pub responder: Option<oneshot::Sender<Result<VerificationSuccess, String>>>,
}


#[derive(Clone)]
pub struct SecurityEngine {
    db: Db,
    sensor: UsbSensor,
    pending: Arc<Mutex<Option<ActiveVerification>>>,
    req_counter: Arc<AtomicU64>,
    unlimited_fps: bool,
}

impl SecurityEngine {
    pub fn new(db: Db, sensor: UsbSensor, unlimited_fps: bool) -> Self {
        Self {
            db,
            sensor,
            pending: Arc::new(Mutex::new(None)),
            req_counter: Arc::new(AtomicU64::new(1)),
            unlimited_fps,
        }
    }

    pub fn sensor(&self) -> &UsbSensor {
        &self.sensor
    }

    pub fn validate_pin_format(pin: &str) -> Result<(), &'static str> {
        if pin.len() != 6 {
            return Err("Passkey PIN must be exactly 6 digits");
        }
        if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err("Passkey PIN may only contain numeric digits (0-9)");
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
        self.db.set_pin(&hash, &salt).map_err(|_| "Failed to save PIN to database")?;
        self.db.log_auth(None, "SYSTEM", "PinSet", "SUCCESS", "PIN", Some("Configured 6-digit PIN"));
        Ok(())
    }

    pub fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<(), &'static str> {
        Self::validate_pin_format(new_pin)?;
        self.verify_pin(old_pin)?;
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let hash = Self::hash_pin(new_pin, &salt);
        self.db.set_pin(&hash, &salt).map_err(|_| "Failed to update PIN in database")?;
        self.db.log_auth(None, "SYSTEM", "PinChanged", "SUCCESS", "PIN", Some("Changed 6-digit PIN successfully"));
        Ok(())
    }

    pub fn remove_pin(&self, current_pin: &str) -> Result<(), &'static str> {
        self.verify_pin(current_pin)?;
        self.db.remove_pin().map_err(|_| "Failed to delete PIN from database")?;
        self.db.log_auth(None, "SYSTEM", "PinRemoved", "SUCCESS", "PIN", Some("Removed 6-digit PIN"));
        Ok(())
    }

    pub fn verify_pin(&self, pin: &str) -> Result<bool, &'static str> {
        let (stored_hash, stored_salt) = self.db.get_pin_hash_and_salt().map_err(|_| "Failed to read security settings")?;
        match (stored_hash, stored_salt) {
            (Some(hash), Some(salt)) => {
                let computed = Self::hash_pin(pin, &salt);
                if computed == hash {
                    Ok(true)
                } else {
                    Err("Incorrect PIN")
                }
            }
            _ => Err("Security PIN not configured"),
        }
    }

    /// Enroll fingerprint: Scan 6 times via USB Microarray MAFP sensor
    pub fn enroll_fingerprint(&self, name: &str) -> Result<crate::db::FingerprintRow, String> {
        let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
        if !self.unlimited_fps && fps.len() >= 10 {
            return Err("Maximum 10 fingerprints reached (Use --unlimited-fps to remove limit)".into());
        }

        let existing_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
        let max_slots = if self.unlimited_fps { 30 } else { 10 };
        let mut target_slot = 0u32;
        for s in 0..max_slots {
            if !existing_slots.contains(&s) {
                target_slot = s;
                break;
            }
        }

        // Scan 6 stages on physical hardware
        let actual_fid = if UsbSensor::is_hardware_plugged() {
            println!("[SECURITY] Starting 6-stage USB fingerprint enrollment...");
            self.sensor.enroll_fingerprint_pipeline(target_slot)?
        } else {
            target_slot as u16
        };

        let row = self.db.add_fingerprint(actual_fid as u32, name).map_err(|e| e.to_string())?;
        self.db.log_auth(
            None,
            "SYSTEM",
            "FingerprintEnrolled",
            "SUCCESS",
            "FINGERPRINT",
            Some(&format!("Enrolled 6 stages for fingerprint '{}' saved to USB & DB slot {}", row.name, actual_fid)),
        );
        Ok(row)
    }

    pub fn delete_fingerprint(&self, id: i64) -> Result<bool, String> {
        if let Ok(Some(fp)) = self.db.get_fingerprint_by_id(id) {
            let slot = fp.slot_index;
            if UsbSensor::is_hardware_plugged() {
                println!("[SECURITY] Deleting template slot {} from USB chip...", slot);
                let _ = self.sensor.delete_slot(slot);
            }
        }

        let ok = self.db.delete_fingerprint(id).map_err(|e| e.to_string())?;
        if ok {
            self.db.log_auth(
                None,
                "SYSTEM",
                "FingerprintDeleted",
                "SUCCESS",
                "FINGERPRINT",
                Some(&format!("Deleted fingerprint id {} and template from USB chip", id)),
            );

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
        let res = self
            .request_user_verification_with_accounts(rp_id, operation, user_name, Vec::new(), None)
            .await?;
        Ok(res.method)
    }

    pub async fn request_user_verification_with_accounts(
        &self,
        rp_id: &str,
        operation: &str,
        user_name: &str,
        accounts: Vec<PendingAccountOption>,
        default_selected_cred_id: Option<String>,
    ) -> Result<VerificationSuccess, String> {
        let settings = self.db.get_security_settings(self.unlimited_fps).map_err(|e| e.to_string())?;
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
            accounts,
            selected_credential_id: default_selected_cred_id,
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
            "\n[SECURITY] >>> NEW VERIFICATION REQUEST (Request #{} - RP: '{}', Operation: '{}') <<<",
            req_id, rp_id, operation
        );

        // Retrieve list of enrolled fingerprint slots
        let fps = self.db.get_fingerprints().unwrap_or_default();
        let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();

        // Listen for finger touch on USB if fingerprints are enrolled
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
                    // Wait and verify real fingerprint
                    match sensor_clone.verify_fingerprint(&enrolled_slots, 2) {
                        Ok(true) => {
                            // MATCH FOUND
                            let mut guard = pending_ref.lock();
                            if let Some(mut active) = guard.take() {
                                if active.prompt.request_id == req_id {
                                    let chosen_id = active.prompt.selected_credential_id.clone();
                                    if let Some(responder) = active.responder.take() {
                                        let _ = responder.send(Ok(VerificationSuccess {
                                            method: "USB_FINGERPRINT_HARDWARE".to_string(),
                                            selected_credential_id: chosen_id,
                                        }));
                                    }
                                    db_clone.log_auth(
                                        None,
                                        &rp_id_owned,
                                        &op_owned,
                                        "SUCCESS",
                                        "FINGERPRINT_USB",
                                        Some("Authenticated successfully via USB fingerprint sensor (Template match)"),
                                    );
                                    return;
                                } else {
                                    *guard = Some(active);
                                }
                            }
                        }
                        Ok(false) => {
                            // MISMATCH
                            println!("[SECURITY] [REJECT] Fingerprint does not match any enrolled template! REJECTED!");
                            db_clone.log_auth(
                                None,
                                &rp_id_owned,
                                &op_owned,
                                "REJECTED",
                                "FINGERPRINT_USB",
                                Some("Fingerprint verification mismatch (Rejected)"),
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
                Err("Verification session cancelled".to_string())
            }
            Err(_) => {
                let mut guard = self.pending.lock();
                *guard = None;
                Err("Verification timed out (Timeout 60s)".to_string())
            }
        };

        fp_listener.abort();
        result
    }

    pub fn approve_pending(
        &self,
        req_id: u64,
        method: &str,
        input_pin: Option<&str>,
        selected_credential_id: Option<String>,
    ) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            let chosen_cred_id = selected_credential_id.or_else(|| active.prompt.selected_credential_id.clone());

            match method {
                "PIN" => {
                    let pin = input_pin.ok_or_else(|| "PIN not provided".to_string())?;
                    self.verify_pin(pin)?;
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "PIN".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "PIN",
                        Some("Verified 6-digit PIN successfully via Web CMS"),
                    );
                    Ok(())
                }
                "FINGERPRINT" => {
                    let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
                    let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
                    if enrolled_slots.is_empty() {
                        *guard = Some(active);
                        return Err("No fingerprints enrolled in the system".into());
                    }

                    if UsbSensor::is_hardware_plugged() {
                        println!("[SECURITY] Waiting for finger press on USB sensor...");
                        match self.sensor.verify_fingerprint(&enrolled_slots, 15) {
                            Ok(true) => {
                                println!("[SECURITY] Fingerprint verified successfully!");
                            }
                            Ok(false) => {
                                *guard = Some(active);
                                return Err("Fingerprint DOES NOT MATCH any enrolled template! Request rejected.".into());
                            }
                            Err(e) => {
                                *guard = Some(active);
                                return Err(format!("Fingerprint sensor error: {}", e));
                            }
                        }
                    }

                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "FINGERPRINT".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "FINGERPRINT",
                        Some("Fingerprint sensor verified successfully (Template match)"),
                    );
                    Ok(())
                }
                "SETUP" => {
                    if let Some(pin) = input_pin {
                        self.set_pin(pin)?;
                    }
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "SETUP".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "SETUP",
                        Some("Initialized new security settings successfully"),
                    );
                    Ok(())
                }

                _ => {
                    *guard = Some(active);
                    Err("Invalid verification method".to_string())
                }
            }
        } else {
            Err("No pending verification request".to_string())
        }
    }

    pub fn select_account(&self, req_id: u64, credential_id: &str) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            active.prompt.selected_credential_id = Some(credential_id.to_string());
            *guard = Some(active);
            Ok(())
        } else {
            Err("No pending verification request".to_string())
        }
    }

    pub fn reject_pending(&self, req_id: u64, reason: &str) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            if let Some(responder) = active.responder.take() {
                let _ = responder.send(Err(format!("Rejected by user: {}", reason)));
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
            Err("No pending verification request".to_string())
        }
    }
}
