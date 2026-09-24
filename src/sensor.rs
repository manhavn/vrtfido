use parking_lot::Mutex;
use rusb::{DeviceHandle, GlobalContext};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub const VENDOR_ID: u16 = 0x3274;
pub const PRODUCT_ID: u16 = 0x8012;

const EP_OUT: u8 = 0x03;
const EP_IN: u8 = 0x83;

const CMD_GET_IMAGE: u8 = 0x01;
const CMD_GEN_CHAR: u8 = 0x02;
const CMD_REG_MODEL: u8 = 0x05;
const CMD_STORE_CHAR: u8 = 0x06;
const CMD_EMPTY: u8 = 0x0D;
const CMD_DELETE_CHAR: u8 = 0x0C;
const CMD_READ_INDEX: u8 = 0x1F;
const CMD_SEARCH: u8 = 0x66;

pub const ENROLL_TOTAL_STAGES: u32 = 6;
pub const MAX_STAGE_RETRIES: u32 = 10;

static HANDSHAKE_PKT: &[u8] = &[
    0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x00, 0x02, 0x23, 0xA2,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SensorBusyMode {
    Idle,
    Enrolling,
    Verifying,
}

#[derive(Serialize, Clone, Debug)]
pub struct EnrollProgress {
    pub active: bool,
    pub stage: u32,
    pub total_stages: u32,
    pub status: String,
    pub message: String,
    pub error: Option<String>,
}

impl Default for EnrollProgress {
    fn default() -> Self {
        Self {
            active: false,
            stage: 0,
            total_stages: ENROLL_TOTAL_STAGES,
            status: "idle".into(),
            message: "".into(),
            error: None,
        }
    }
}

#[derive(Clone)]
pub struct UsbSensor {
    inner: Arc<Mutex<Option<DeviceHandle<GlobalContext>>>>,
    busy_mode: Arc<Mutex<SensorBusyMode>>,
    cancel_requested: Arc<AtomicBool>,
    enroll_progress: Arc<Mutex<EnrollProgress>>,
}

#[allow(dead_code)]
impl UsbSensor {
    pub fn new() -> Self {
        let sensor = Self {
            inner: Arc::new(Mutex::new(None)),
            busy_mode: Arc::new(Mutex::new(SensorBusyMode::Idle)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            enroll_progress: Arc::new(Mutex::new(EnrollProgress::default())),
        };
        #[cfg(not(target_os = "android"))]
        let _ = sensor.try_connect();
        sensor
    }

    pub fn is_hardware_plugged() -> bool {
        #[cfg(target_os = "android")]
        return false;
        #[cfg(not(target_os = "android"))]
        {
            if let Ok(devices) = rusb::devices() {
                for dev in devices.iter() {
                    if let Ok(desc) = dev.device_descriptor() {
                        if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }

    pub fn busy_mode(&self) -> SensorBusyMode {
        *self.busy_mode.lock()
    }

    pub fn cancel_current_op(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let mut p = self.enroll_progress.lock();
        p.active = false;
        p.status = "error".into();
        p.error = Some("Operation cancelled".into());
    }

    pub fn get_enroll_progress(&self) -> EnrollProgress {
        self.enroll_progress.lock().clone()
    }

    pub fn try_connect(&self) -> Result<(), String> {
        let mut guard = self.inner.lock();
        if guard.is_some() {
            return Ok(());
        }

        let devices = rusb::devices().map_err(|e| format!("Failed to list USB devices: {}", e))?;
        let mut target = None;
        for dev in devices.iter() {
            if let Ok(desc) = dev.device_descriptor() {
                if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                    target = Some(dev);
                    break;
                }
            }
        }

        let dev = target.ok_or_else(|| "USB fingerprint sensor (3274:8012) not found".to_string())?;
        let handle = dev.open().map_err(|e| format!("Failed to open USB device: {}", e))?;

        if let Ok(active) = handle.kernel_driver_active(0) {
            if active {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0).map_err(|e| format!("Failed to claim interface 0: {}", e))?;

        let _ = handle.write_bulk(EP_OUT, HANDSHAKE_PKT, Duration::from_millis(500));
        let mut resp_buf = [0u8; 64];
        let _ = handle.read_bulk(EP_IN, &mut resp_buf, Duration::from_millis(500));

        *guard = Some(handle);
        println!("[SENSOR] Connected successfully to Microarray MAFP USB sensor (3274:8012)!");
        Ok(())
    }

    fn build_packet(cmd: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF]);
        pkt.push(0x01);
        let len = (cmd.len() + 2) as u16;
        pkt.push((len >> 8) as u8);
        pkt.push((len & 0xFF) as u8);
        pkt.extend_from_slice(cmd);

        let mut csum: u16 = 0x01 + (len >> 8) + (len & 0xFF);
        for &b in cmd {
            csum = csum.wrapping_add(b as u16);
        }
        pkt.push((csum >> 8) as u8);
        pkt.push((csum & 0xFF) as u8);
        pkt
    }

    fn send_command(&self, cmd: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        let mut guard = self.inner.lock();
        if guard.is_none() {
            drop(guard);
            self.try_connect()?;
            guard = self.inner.lock();
        }

        let handle = guard.as_mut().ok_or_else(|| "USB device not connected".to_string())?;
        let pkt = Self::build_packet(cmd);

        handle
            .write_bulk(EP_OUT, &pkt, timeout)
            .map_err(|e| format!("USB write error: {}", e))?;

        let mut resp_buf = [0u8; 64];
        let bytes_read = handle
            .read_bulk(EP_IN, &mut resp_buf, timeout)
            .map_err(|e| format!("USB read error: {}", e))?;

        if bytes_read < 11 {
            return Err("Response packet too short".into());
        }
        if resp_buf[0] != 0xEF || resp_buf[1] != 0x01 || resp_buf[6] != 0x07 {
            return Err("Invalid response packet".into());
        }

        let payload_len = (((resp_buf[7] as u16) << 8) | (resp_buf[8] as u16)) as usize;
        if payload_len < 2 || 9 + payload_len > bytes_read {
            return Err("Invalid payload length".into());
        }

        let data = &resp_buf[9..9 + payload_len - 2];
        Ok(data.to_vec())
    }

    pub fn is_finger_present(&self) -> bool {
        match self.send_command(&[CMD_GET_IMAGE], Duration::from_millis(300)) {
            Ok(data) => !data.is_empty() && data[0] == 0x00,
            Err(_) => false,
        }
    }

    pub fn wait_for_finger_press(&self, timeout_secs: u64) -> Result<bool, String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Operation cancelled".into());
            }
            if self.is_finger_present() {
                return Ok(true);
            }
            sleep(Duration::from_millis(100));
        }
        Err("Finger touch timed out".into())
    }

    pub fn wait_for_finger_lift(&self, timeout_secs: u64) -> Result<(), String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Operation cancelled".into());
            }
            if !self.is_finger_present() {
                return Ok(());
            }
            sleep(Duration::from_millis(80));
        }
        Ok(())
    }

    pub fn find_free_fid_slot(&self) -> Result<u16, String> {
        let resp = self.send_command(&[CMD_READ_INDEX, 0x00], Duration::from_millis(1000))?;
        if !resp.is_empty() && resp[0] == 0x00 && resp.len() >= 5 {
            let bitmap = &resp[1..5];
            for byte_idx in 0..4 {
                let b = bitmap[byte_idx];
                for bit in 0..8 {
                    let slot = (byte_idx * 8 + bit) as u16;
                    if slot < 30 && (b & (1 << bit)) == 0 {
                        return Ok(slot);
                    }
                }
            }
        }
        println!("[SENSOR] USB chip memory full, clearing via CMD 0x0D (Empty)...");
        let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
        Ok(0)
    }

    pub fn delete_slot(&self, slot: u32) -> Result<(), String> {
        let fid = (slot & 0x1F) as u16;
        let del_cmd = [CMD_DELETE_CHAR, (fid >> 8) as u8, (fid & 0xFF) as u8, 0x00, 0x01];
        let res = self.send_command(&del_cmd, Duration::from_millis(1500))?;
        if !res.is_empty() && res[0] == 0x00 {
            println!("[SENSOR] [+] Deleted template slot {} from USB chip successfully!", fid);
            Ok(())
        } else {
            Err(format!("Error deleting template slot {} from chip: {:?}", fid, res))
        }
    }

    pub fn clear_chip_templates(&self) -> Result<(), String> {
        let res = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500))?;
        if !res.is_empty() && res[0] == 0x00 {
            println!("[SENSOR] [+] Cleared all templates from USB chip!");
            Ok(())
        } else {
            Err(format!("Error clearing chip memory: {:?}", res))
        }
    }

    pub fn enroll_fingerprint_pipeline(&self, preferred_slot: u32) -> Result<u16, String> {
        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("USB sensor busy with another operation".into());
            }
            *busy = SensorBusyMode::Enrolling;
        }
        self.cancel_requested.store(false, Ordering::SeqCst);

        {
            let mut p = self.enroll_progress.lock();
            p.active = true;
            p.stage = 1;
            p.total_stages = ENROLL_TOTAL_STAGES;
            p.status = "waiting_touch".into();
            p.message = format!("Stage 1/{}: Please place finger on USB sensor...", ENROLL_TOTAL_STAGES);
            p.error = None;
        }

        let run_result = self.execute_enroll_stages(preferred_slot);

        {
            let mut p = self.enroll_progress.lock();
            match &run_result {
                Ok(fid) => {
                    p.active = false;
                    p.status = "completed".into();
                    p.message = format!("Captured 6 stages and saved to USB chip slot {}!", fid);
                    p.error = None;
                }
                Err(err) => {
                    p.active = false;
                    p.status = "error".into();
                    p.error = Some(err.clone());
                }
            }
            let mut busy = self.busy_mode.lock();
            *busy = SensorBusyMode::Idle;
        }

        run_result
    }

    /// 6-stage enrollment loop: IF ANY STAGE FAILS, KEEP STAGE AND ALLOW RETRY!
    fn execute_enroll_stages(&self, preferred_slot: u32) -> Result<u16, String> {
        let _ = self.send_command(&[0x23], Duration::from_millis(500));
        sleep(Duration::from_millis(100));

        let fid = match self.find_free_fid_slot() {
            Ok(s) => s,
            Err(_) => (preferred_slot & 0x1F) as u16,
        };
        println!("[SENSOR] Enrollment slot on USB chip: {}", fid);

        let mut current_stage = 1u32;
        let mut retry_count = 0u32;

        while current_stage <= ENROLL_TOTAL_STAGES {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Fingerprint enrollment cancelled".into());
            }

            // Update waiting for finger press state
            {
                let mut p = self.enroll_progress.lock();
                p.stage = current_stage;
                p.status = "waiting_touch".into();
                if retry_count > 0 {
                    p.message = format!(
                        "Stage {}/{}: Image unclear, please place finger flat on sensor again...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                } else {
                    p.message = format!(
                        "Stage {}/{}: Place finger on USB sensor...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }
            }
            println!(
                "[ENROLL] Stage {}/{}: Waiting for finger touch (Attempt {}/{})...",
                current_stage, ENROLL_TOTAL_STAGES, retry_count + 1, MAX_STAGE_RETRIES
            );

            // Wait for finger touch (30s timeout per attempt)
            match self.wait_for_finger_press(30) {
                Ok(true) => {}
                _ => {
                    if self.cancel_requested.load(Ordering::SeqCst) {
                        return Err("Cancelled".into());
                    }
                    println!("[ENROLL] No finger touch detected, continuing to wait...");
                    continue;
                }
            }

            // Extract GenChar features into corresponding slot
            let gen_res = self.send_command(&[CMD_GEN_CHAR, current_stage as u8], Duration::from_millis(1000));
            let is_success = match &gen_res {
                Ok(res) => !res.is_empty() && res[0] == 0x00,
                Err(_) => false,
            };

            if is_success {
                // Stage succeeded -> advance to next stage!
                {
                    let mut p = self.enroll_progress.lock();
                    p.status = "finger_lift".into();
                    p.message = format!(
                        "Captured stage {}/{}! Please lift your finger...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }
                println!(
                    "[ENROLL] [+] Stage {}/{}: Stage captured successfully! Waiting for finger lift...",
                    current_stage, ENROLL_TOTAL_STAGES
                );

                self.wait_for_finger_lift(15)?;
                sleep(Duration::from_millis(250));

                current_stage += 1;
                retry_count = 0;
            } else {
                // Sample error -> DO NOT EXIT! Keep current stage and retry!
                // (due to skewed finger, lifting too fast, or sensor blur)
                retry_count += 1;
                println!(
                    "[ENROLL] [RETRY] Stage {}/{}: Quality insufficient (Code: {:?}). Waiting for finger lift to retry...",
                    current_stage, ENROLL_TOTAL_STAGES, gen_res
                );

                {
                    let mut p = self.enroll_progress.lock();
                    p.status = "finger_lift".into();
                    p.message = format!(
                        "Image unclear or finger moved! Please lift finger to retry stage {}/{}...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }

                self.wait_for_finger_lift(10)?;
                sleep(Duration::from_millis(300));

                if retry_count >= MAX_STAGE_RETRIES {
                    return Err(format!(
                        "Failed to recognize stage {} after {} attempts. Please try again.",
                        current_stage, MAX_STAGE_RETRIES
                    ));
                }
            }
        }

        // Collected all 6 stages -> Synthesize RegModel (CMD 0x05)
        {
            let mut p = self.enroll_progress.lock();
            p.status = "waiting_touch".into();
            p.message = "Collected 6 stages! Synthesizing fingerprint model on chip...".into();
        }
        println!("[ENROLL] Collected 6 stages! Sending RegModel command (CMD 0x05)...");
        let reg_res = self.send_command(&[CMD_REG_MODEL], Duration::from_millis(1500))?;
        if reg_res.is_empty() || reg_res[0] != 0x00 {
            return Err("Failed to synthesize fingerprint model from 6 stages on chip".into());
        }

        // Store into flash memory on chip (StoreChar)
        let store_cmd = [CMD_STORE_CHAR, 0x01, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let store_res = self.send_command(&store_cmd, Duration::from_millis(1500))?;

        if store_res.is_empty() || store_res[0] != 0x00 {
            println!("[SENSOR] [RETRY] StoreChar returned code {:?}, cleaning chip and storing in slot 0...", store_res);
            let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
            let retry_store = [CMD_STORE_CHAR, 0x01, 0x00, 0x00];
            let retry_res = self.send_command(&retry_store, Duration::from_millis(1500))?;
            if retry_res.is_empty() || retry_res[0] != 0x00 {
                return Err(format!("Failed to write template to USB chip (code: {:?})", retry_res));
            }
            println!("[SENSOR] [+] Completed fingerprint enrollment to USB chip slot 0!");
            return Ok(0);
        }

        println!("[SENSOR] [+] Completed fingerprint enrollment to USB chip slot {}!", fid);
        Ok(fid)
    }

    /// Verify fingerprint against list of enrolled slots
    pub fn verify_fingerprint(&self, enrolled_slots: &[u32], timeout_secs: u64) -> Result<bool, String> {
        if enrolled_slots.is_empty() {
            return Err("No fingerprints enrolled in the system".into());
        }

        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("USB sensor busy".into());
            }
            *busy = SensorBusyMode::Verifying;
        }

        let res = self.execute_verification(enrolled_slots, timeout_secs);

        {
            let mut busy = self.busy_mode.lock();
            *busy = SensorBusyMode::Idle;
        }
        res
    }

    fn execute_verification(&self, enrolled_slots: &[u32], timeout_secs: u64) -> Result<bool, String> {
        self.wait_for_finger_press(timeout_secs)?;

        // Extract touched finger features into char-buf slot 1
        let gen_res = self.send_command(&[CMD_GEN_CHAR, 0x01], Duration::from_millis(1000))?;
        if gen_res.is_empty() || gen_res[0] != 0x00 {
            let _ = self.wait_for_finger_lift(5);
            return Err("Failed to capture fingerprint image (Please place finger flat on sensor)".into());
        }

        // Match against ALL enrolled slots with CMD_SEARCH (0x66)
        for &slot_u32 in enrolled_slots {
            let slot = (slot_u32 & 0x1F) as u16;
            let search_cmd = [CMD_SEARCH, (slot >> 8) as u8, (slot & 0xFF) as u8];
            if let Ok(res) = self.send_command(&search_cmd, Duration::from_millis(800)) {
                if !res.is_empty() && res[0] == 0x00 {
                    println!("[SENSOR] [MATCH] >>> FINGERPRINT MATCHED SLOT {} ON USB CHIP! <<<", slot);
                    let _ = self.wait_for_finger_lift(5);
                    return Ok(true);
                } else {
                    println!("[SENSOR] [SEARCH] Slot {}: No match (response code: {:?})", slot, res);
                }
            }
        }

        // IF ALL SLOTS MISMATCH -> REJECT!
        println!("[SENSOR] [REJECT] >>> FINGERPRINT DOES NOT MATCH ANY ENROLLED TEMPLATE! REJECTED! <<<");
        let _ = self.wait_for_finger_lift(5);
        Ok(false)
    }
}
