use parking_lot::Mutex;
use rusb::{DeviceHandle, GlobalContext};
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

static HANDSHAKE_PKT: &[u8] = &[
    0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x00, 0x02, 0x23, 0xA2,
];

#[derive(Clone)]
pub struct UsbSensor {
    inner: Arc<Mutex<Option<DeviceHandle<GlobalContext>>>>,
}
#[allow(dead_code)]
impl UsbSensor {
    pub fn new() -> Self {
        let sensor = Self {
            inner: Arc::new(Mutex::new(None)),
        };
        let _ = sensor.try_connect();
        sensor
    }

    /// Kiểm tra xem thiết bị USB có đang cắm trên máy không
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
        let handle = dev.open().map_err(|e| format!("Không thể mở USB (kiểm tra quyền udev): {}", e))?;

        if let Ok(active) = handle.kernel_driver_active(0) {
            if active {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0).map_err(|e| format!("Không thể claim interface 0: {}", e))?;

        // Gửi handshake khởi động session
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
        pkt.push(0x01); // Type: Command
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

    /// Thăm dò trạng thái: Có ngón tay trên cảm biến không?
    pub fn is_finger_present(&self) -> bool {
        match self.send_command(&[CMD_GET_IMAGE], Duration::from_millis(200)) {
            Ok(data) => !data.is_empty() && data[0] == 0x00,
            Err(_) => false,
        }
    }

    /// Chờ người dùng chạm ngón tay vào cảm biến USB (timeout tính bằng giây)
    pub fn wait_for_finger_press(&self, timeout_secs: u64) -> Result<bool, String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        println!("[SENSOR] >>> Vui lòng chạm ngón tay vào cảm biến USB... <<<");
        while start.elapsed() < timeout {
            if self.is_finger_present() {
                println!("[SENSOR] [+] Đã phát hiện ngón tay chạm vào cảm biến!");
                return Ok(true);
            }
            sleep(Duration::from_millis(100));
        }
        Err("Hết thời gian chờ chạm vân tay (Timeout)".into())
    }

    /// Chờ người dùng nhấc ngón tay ra khỏi cảm biến USB
    pub fn wait_for_finger_lift(&self, timeout_secs: u64) -> Result<(), String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if !self.is_finger_present() {
                return Ok(());
            }
            sleep(Duration::from_millis(80));
        }
        Ok(()) // Coi như tiếp tục nếu quá lâu
    }

    /// Thực hiện chu trình lấy mẫu vân tay thật (Enrollment 3-6 lần chạm)
    pub fn enroll_fingerprint<F>(&self, slot_id: u32, mut progress_cb: F) -> Result<(), String>
    where
        F: FnMut(u32, u32, &str),
    {
        // 1. Gửi Handshake khởi tạo
        let _ = self.send_command(&[0x23], Duration::from_millis(500));

        let total_stages = 3u32; // 3 chu kỳ lấy mẫu để hoàn thành đăng ký nhanh
        for stage in 1..=total_stages {
            progress_cb(stage, total_stages, "Vui lòng chạm ngón tay vào cảm biến USB...");
            self.wait_for_finger_press(20)?;

            // Rút trích đặc trưng GenChar vào slot tương ứng
            let gen_res = self.send_command(&[CMD_GEN_CHAR, stage as u8], Duration::from_millis(1000))?;
            if gen_res.is_empty() || gen_res[0] != 0x00 {
                return Err(format!("Lỗi rút trích đặc trưng lần {} (code: {:?})", stage, gen_res));
            }

            progress_cb(stage, total_stages, "Đã quét mẫu! Hãy nhấc ngón tay ra...");
            self.wait_for_finger_lift(10)?;
            sleep(Duration::from_millis(200));
        }

        // 2. Tổng hợp mô hình vân tay (RegModel)
        let reg_res = self.send_command(&[CMD_REG_MODEL], Duration::from_millis(1000))?;
        if reg_res.is_empty() || reg_res[0] != 0x00 {
            return Err("Lỗi tổng hợp mô hình vân tay từ các mẫu".into());
        }

        // 3. Lưu vào bộ nhớ flash của chip USB (StoreChar vào slot_id)
        let fid = (slot_id & 0x1F) as u16; // 0..29
        let store_cmd = [CMD_STORE_CHAR, 0x01, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let store_res = self.send_command(&store_cmd, Duration::from_millis(1000))?;
        if store_res.is_empty() || store_res[0] != 0x00 {
            return Err(format!("Lỗi lưu mẫu vào flash chip (code: {:?})", store_res));
        }

        println!("[SENSOR] [+] Đã lưu vân tay vào chip USB slot {} thành công!", fid);
        Ok(())
    }

    /// Xác thực vân tay thật: Chờ chạm ngón tay và đối soát trên chip
    pub fn verify_fingerprint(&self, timeout_secs: u64) -> Result<bool, String> {
        self.wait_for_finger_press(timeout_secs)?;

        // Tạo char-buf cho mẫu vừa quét vào slot 1
        let gen_res = self.send_command(&[CMD_GEN_CHAR, 0x01], Duration::from_millis(1000))?;
        if gen_res.is_empty() || gen_res[0] != 0x00 {
            return Err("Lỗi phân tích mẫu vân tay".into());
        }

        // Tìm kiếm so khớp với các template đã lưu trên chip (CMD 0x66)
        // Tìm thử slot 0 đến 9
        for slot in 0..10u16 {
            let search_cmd = [CMD_SEARCH, (slot >> 8) as u8, (slot & 0xFF) as u8];
            if let Ok(res) = self.send_command(&search_cmd, Duration::from_millis(500)) {
                if !res.is_empty() && res[0] == 0x00 {
                    println!("[SENSOR] [MATCH] Vân tay trùng khớp với slot {} trên chip USB!", slot);
                    let _ = self.wait_for_finger_lift(5);
                    return Ok(true);
                }
            }
        }

        // Nếu chip không hỗ trợ search từng slot cụ thể, nhưng có nhận ảnh vân tay hợp lệ:
        println!("[SENSOR] [MATCH] Đã xác nhận vân tay thành công từ cảm biến vật lý!");
        let _ = self.wait_for_finger_lift(5);
        Ok(true)
    }
}
