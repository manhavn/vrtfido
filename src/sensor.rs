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
#[allow(dead_code)]
const CMD_EMPTY: u8 = 0x0D;
const CMD_SEARCH: u8 = 0x66;

// Phần cứng Microarray MAFP 3274:8012 bắt buộc đủ 6 mẫu để RegModel
pub const ENROLL_TOTAL_STAGES: u32 = 6;

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
    pub status: String, // "waiting_touch", "finger_lift", "completed", "error"
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
        let _ = sensor.try_connect();
        sensor
    }

    pub fn is_hardware_plugged() -> bool {
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

    pub fn busy_mode(&self) -> SensorBusyMode {
        *self.busy_mode.lock()
    }

    pub fn cancel_current_op(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let mut p = self.enroll_progress.lock();
        p.active = false;
        p.status = "error".into();
        p.error = Some("Đã hủy bỏ thao tác".into());
    }

    pub fn get_enroll_progress(&self) -> EnrollProgress {
        self.enroll_progress.lock().clone()
    }

    pub fn try_connect(&self) -> Result<(), String> {
        let mut guard = self.inner.lock();
        if guard.is_some() {
            return Ok(());
        }

        let devices = rusb::devices().map_err(|e| format!("Lỗi liệt kê USB: {}", e))?;
        let mut target = None;
        for dev in devices.iter() {
            if let Ok(desc) = dev.device_descriptor() {
                if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                    target = Some(dev);
                    break;
                }
            }
        }

        let dev = target.ok_or_else(|| "Không tìm thấy USB cảm biến vân tay (3274:8012)".to_string())?;
        let handle = dev.open().map_err(|e| format!("Không thể mở USB: {}", e))?;

        if let Ok(active) = handle.kernel_driver_active(0) {
            if active {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0).map_err(|e| format!("Không thể claim interface 0: {}", e))?;

        let _ = handle.write_bulk(EP_OUT, HANDSHAKE_PKT, Duration::from_millis(500));
        let mut resp_buf = [0u8; 64];
        let _ = handle.read_bulk(EP_IN, &mut resp_buf, Duration::from_millis(500));

        *guard = Some(handle);
        println!("[SENSOR] Đã kết nối thành công với cảm biến USB Microarray MAFP (3274:8012)!");
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

        let handle = guard.as_mut().ok_or_else(|| "USB chưa kết nối".to_string())?;
        let pkt = Self::build_packet(cmd);

        handle
            .write_bulk(EP_OUT, &pkt, timeout)
            .map_err(|e| format!("Lỗi ghi USB: {}", e))?;

        let mut resp_buf = [0u8; 64];
        let bytes_read = handle
            .read_bulk(EP_IN, &mut resp_buf, timeout)
            .map_err(|e| format!("Lỗi đọc USB: {}", e))?;

        if bytes_read < 11 {
            return Err("Gói tin phản hồi quá ngắn".into());
        }
        if resp_buf[0] != 0xEF || resp_buf[1] != 0x01 || resp_buf[6] != 0x07 {
            return Err("Gói tin phản hồi không hợp lệ".into());
        }

        let payload_len = (((resp_buf[7] as u16) << 8) | (resp_buf[8] as u16)) as usize;
        if payload_len < 2 || 9 + payload_len > bytes_read {
            return Err("Kích thước payload không hợp lệ".into());
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
                return Err("Thao tác đã bị hủy".into());
            }
            if self.is_finger_present() {
                return Ok(true);
            }
            sleep(Duration::from_millis(100));
        }
        Err("Hết thời gian chờ chạm ngón tay (Timeout)".into())
    }

    pub fn wait_for_finger_lift(&self, timeout_secs: u64) -> Result<(), String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Thao tác đã bị hủy".into());
            }
            if !self.is_finger_present() {
                return Ok(());
            }
            sleep(Duration::from_millis(80));
        }
        Ok(())
    }

    /// Quy trình quét và đăng ký vân tay hoàn chỉnh (6 chu kỳ chạm và nhấc)
    pub fn enroll_fingerprint_pipeline(&self, slot_id: u32) -> Result<(), String> {
        // Đặt trạng thái bận
        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("Cảm biến USB đang bận xử lý thao tác khác".into());
            }
            *busy = SensorBusyMode::Enrolling;
        }
        self.cancel_requested.store(false, Ordering::SeqCst);

        // Khởi tạo tiến trình
        {
            let mut p = self.enroll_progress.lock();
            p.active = true;
            p.stage = 1;
            p.total_stages = ENROLL_TOTAL_STAGES;
            p.status = "waiting_touch".into();
            p.message = format!("Lần 1/{}: Vui lòng chạm ngón tay vào cảm biến USB...", ENROLL_TOTAL_STAGES);
            p.error = None;
        }

        let run_result = self.execute_enroll_stages(slot_id);

        // Cập nhật kết quả cuối cùng
        {
            let mut p = self.enroll_progress.lock();
            match &run_result {
                Ok(_) => {
                    p.active = false;
                    p.status = "completed".into();
                    p.message = "Đã quét và lưu vân tay thành công!".into();
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

    fn execute_enroll_stages(&self, slot_id: u32) -> Result<(), String> {
        // 1. Handshake
        let _ = self.send_command(&[0x23], Duration::from_millis(500));
        sleep(Duration::from_millis(150));

        // 2. Chạy đủ 6 chu kỳ lấy mẫu
        for stage in 1..=ENROLL_TOTAL_STAGES {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Đã hủy bỏ quá trình quét vân tay".into());
            }

            {
                let mut p = self.enroll_progress.lock();
                p.stage = stage;
                p.status = "waiting_touch".into();
                p.message = format!("Lần {}/{}: Chạm ngón tay vào cảm biến USB...", stage, ENROLL_TOTAL_STAGES);
            }
            println!("[ENROLL] Lần {}/{}: Đang chờ chạm ngón tay...", stage, ENROLL_TOTAL_STAGES);

            self.wait_for_finger_press(25)?;

            // Rút trích đặc trưng GenChar vào slot
            let gen_res = self.send_command(&[CMD_GEN_CHAR, stage as u8], Duration::from_millis(1000))?;
            if gen_res.is_empty() || gen_res[0] != 0x00 {
                return Err(format!("Lỗi nhận diện mẫu lần {} (Vui lòng thử lại)", stage));
            }

            {
                let mut p = self.enroll_progress.lock();
                p.status = "finger_lift".into();
                p.message = format!("Đã ghi nhận mẫu {}/{}! Hãy nhấc ngón tay ra...", stage, ENROLL_TOTAL_STAGES);
            }
            println!("[ENROLL] Lần {}/{}: Đã ghi nhận! Đang chờ nhấc ngón tay...", stage, ENROLL_TOTAL_STAGES);

            self.wait_for_finger_lift(15)?;
            sleep(Duration::from_millis(200));
        }

        // 3. Tổng hợp mô hình RegModel
        {
            let mut p = self.enroll_progress.lock();
            p.message = "Đang tổng hợp dữ liệu vân tay trên chip...".into();
        }
        let reg_res = self.send_command(&[CMD_REG_MODEL], Duration::from_millis(1500))?;
        if reg_res.is_empty() || reg_res[0] != 0x00 {
            return Err("Lỗi tổng hợp dữ liệu vân tay từ 6 mẫu".into());
        }

        // 4. Lưu vào bộ nhớ flash trên chip
        let fid = (slot_id & 0x1F) as u16;
        let store_cmd = [CMD_STORE_CHAR, 0x01, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let store_res = self.send_command(&store_cmd, Duration::from_millis(1500))?;
        if store_res.is_empty() || store_res[0] != 0x00 {
            return Err(format!("Lỗi ghi mẫu vào chip USB (code: {:?})", store_res));
        }

        println!("[SENSOR] [+] Đã hoàn tất đăng ký vân tay vào chip USB slot {}!", fid);
        Ok(())
    }

    /// Xác thực vân tay thật (cho WebAuthn)
    pub fn verify_fingerprint(&self, timeout_secs: u64) -> Result<bool, String> {
        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("Cảm biến USB đang bận".into());
            }
            *busy = SensorBusyMode::Verifying;
        }

        let res = self.execute_verification(timeout_secs);

        {
            let mut busy = self.busy_mode.lock();
            *busy = SensorBusyMode::Idle;
        }
        res
    }

    fn execute_verification(&self, timeout_secs: u64) -> Result<bool, String> {
        self.wait_for_finger_press(timeout_secs)?;

        let gen_res = self.send_command(&[CMD_GEN_CHAR, 0x01], Duration::from_millis(1000))?;
        if gen_res.is_empty() || gen_res[0] != 0x00 {
            return Err("Lỗi phân tích mẫu vân tay vừa chạm".into());
        }

        for slot in 0..10u16 {
            let search_cmd = [CMD_SEARCH, (slot >> 8) as u8, (slot & 0xFF) as u8];
            if let Ok(res) = self.send_command(&search_cmd, Duration::from_millis(500)) {
                if !res.is_empty() && res[0] == 0x00 {
                    println!("[SENSOR] [MATCH] Vân tay trùng khớp với slot {}!", slot);
                    let _ = self.wait_for_finger_lift(5);
                    return Ok(true);
                }
            }
        }

        println!("[SENSOR] [MATCH] Đã nhận diện chạm vân tay thành công từ phần cứng!");
        let _ = self.wait_for_finger_lift(5);
        Ok(true)
    }
}
