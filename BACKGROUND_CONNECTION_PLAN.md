# Kế Hoạch Khắc Phục Lỗi Mất Kết Nối Database Khi Thu Nhỏ App (vrtfido)

Tài liệu này tổng hợp bài học và giải pháp thực tế đã thực hiện trên ứng dụng **Universal Data Relay (`udr-gui`)** (đã kiểm chứng qua ADB trên Android 16 Vivo), phân tích nguyên nhân sự cố tương tự trên **vrtfido** và vạch ra lộ trình khắc phục toàn diện.

---

## 1. Bài Học Thực Tế & Kết Quả Từ `udr-gui`

Trong quá trình debug ứng dụng `udr-gui` trên thiết bị thật (Vivo MT6991, Android 16), các hiện tượng sau đã được làm rõ:

1. **Hiểu lầm về "tiến trình đặc biệt":**
   - Android không cung cấp cơ chế "tiến trình bất tử" riêng cho app người dùng.
   - Giải pháp chuẩn và bền bỉ nhất của Android là **Foreground Service** đi kèm thông báo cố định (`ongoing / NO_CLEAR`) và giữ `PARTIAL_WAKE_LOCK`.
2. **Cơ chế ngắt kết nối thực sự khi thu nhỏ màn hình:**
   - Dù tiến trình (`PID`) và Foreground Service vẫn đang chạy bình thường, các kết nối TCP/UDP ra ngoài Internet (QUIC tunnel, database sockets) vẫn bị ngắt khi app vào nền nếu:
     - Hệ thống kích hoạt chế độ **Doze** (tắt màn hình, hạn chế mạng nền).
     - Cơ chế quản lý pin độc quyền của nhà sản xuất (như **Funtouch OS / Vivo**) chặn socket mạng nền của app.
3. **Cơ chế thông báo không thể bỏ qua:**
   - Cần khai báo quyền `POST_NOTIFICATIONS` và xin cấp quyền runtime (Android 13+).
   - Khi thông báo được ghim cố định với `setOngoing(true)` và flag `NO_CLEAR`, người dùng không thể vuốt để tắt thông báo giống như trình phát media.
4. **Giải pháp xử lý triệt để đã triển khai:**
   - Chuyển app vào danh sách **Battery Optimization Exemption (Doze Whitelist)**.
   - Bật tùy chọn pin ngầm của hãng: **Kiểm soát pin dưới nền → Cho phép sử dụng pin ngầm**.
   - Tắt tính năng **Tạm dừng hoạt động ứng dụng nếu không dùng** (*Pause app activity if unused*).
   - Tích hợp các nút mở nhanh trang cài đặt pin và thông báo ngay trong ứng dụng để người dùng chủ động kiểm tra và bật.

---

## 2. Phân Tích Hiện Trạng Trên `vrtfido` (Nguyên Nhân Gây Mất Kết Nối Database)

Qua rà soát mã nguồn `vrtfido/android` và tầng Rust database backend:

### A. Vấn đề tại tầng Android (`VrtfidoService.kt` & `MainActivity.kt`)
1. **Watchdog tự sát khi vào nền:**
   - Trong `VrtfidoService.kt`:
     ```kotlin
     while (isActive) {
         delay(2000)
         if (!VrtfidoClient.isRunning(this@VrtfidoService)) {
             lastError = "Máy chủ tại ${binding.localUrl} đã dừng"
             isRunning = false
             broadcastStatus(false)
             stopSelf() // <--- Tự động tắt dịch vụ!
             break
         }
     }
     ```
   - Khi app thu nhỏ, `VrtfidoClient.isRunning()` thực hiện HTTP call tới `http://127.0.0.1:port/api/health` với timeout ngắn. Nếu hệ thống Android/OEM tạm dừng mạng hoặc freeze luồng, chỉ cần 1 lần thất bại là `VrtfidoService` gọi `stopSelf()`, kéo theo toàn bộ daemon Rust và kết nối database bị hủy bỏ.
2. **Thiếu CPU WakeLock:**
   - `VrtfidoService` không giữ `PowerManager.WakeLock`. Khi màn hình tắt, CPU bị sleep dẫn đến các luồng background worker sync database bị đóng băng hoặc socket timeout.
3. **Thiếu hỗ trợ gỡ bỏ tối ưu pin (Doze / OEM):**
   - Ứng dụng chưa có kiểm tra `isIgnoringBatteryOptimizations` và không có nút dẫn người dùng đến trang cài đặt pin để cấp quyền chạy ngầm (đặc biệt quan trọng với PostgreSQL / MySQL / MongoDB / LibSQL remote).
4. **Cấu hình Foreground Service:**
   - Đang dùng `foregroundServiceType="specialUse"`. Trên một số phiên bản Android 14+, kiểu này bị giám sát chặt chẽ và có thể bị hệ thống can thiệp hạn chế mạng nền nếu không có ngoại lệ pin.

### B. Vấn đề tại tầng Database Backend (Rust)
1. **PostgreSQL Worker luồng đơn không tự reconnect socket:**
   - Trong `src/db/postgres_backend.rs`, `PgWorker` kết nối một lần duy nhất qua `postgres::Client::connect`. Khi socket bị hệ điều hành đóng (do Doze hoặc rớt Wi-Fi khi thu nhỏ), mọi câu lệnh sau đó sẽ ném lỗi `Broken pipe` hoặc `connection closed` mà không tự mở lại connection client.
2. **`ResilientBackend` offline sync phụ thuộc vào vòng lặp 5s:**
   - Cơ chế fallback `resilient.rs` chuyển sang `shadow` SQLite khi gặp `connection_error`. Tuy nhiên, nếu service Android bị `stopSelf()` như ở mục (A), luồng đồng bộ này cũng chết theo.

---

## 3. Lộ Trình & Kế Hoạch Triển Khai Cho `vrtfido`

### Giai Đoạn 1: Sửa Vòng Đời & Loại Bỏ Watchdog Gây Tắt Service (Android)
- [x] **Khắc phục Watchdog:**
  - Đã bổ sung hàm JNI `isDaemonRunning()` trực tiếp kiểm tra trạng thái luồng native daemon trong bộ nhớ (0ms latency, không loopback timeout).
  - Bỏ hoàn toàn việc gọi `stopSelf()` dựa trên HTTP health check; service chỉ tự dừng khi tiến trình daemon thực sự kết thúc/crash.
- [x] **Giữ CPU WakeLock khi Daemon Chạy:**
  - Đã khai báo quyền `android.permission.WAKE_LOCK` trong `AndroidManifest.xml`.
  - `VrtfidoService`: acquire `PARTIAL_WAKE_LOCK` (`vrtfido:daemon`) khi bắt đầu daemon và release an toàn khi `stopDaemon()` / `onDestroy()`.
- [x] **Tối ưu Foreground Notification:**
  - Notification giữ cờ `setOngoing(true)`, `setAutoCancel(false)`.
  - Đã bổ sung nút hành động **Dừng máy chủ (Stop Server)** trực tiếp trên thông báo bên cạnh **Mở Web Dashboard**.
### Giai Đoạn 2: Tích Hợp Kiểm Soát Tối Ưu Pin & Thông Báo Cho Người Dùng
- [x] **Kiểm tra trạng thái Battery Optimization:**
  - Đã viết helper kiểm tra `PowerManager.isIgnoringBatteryOptimizations(packageName)`.
  - Đã thêm card cảnh báo nổi bật trên `MainActivity` khi chưa bỏ qua tối ưu pin (`card_battery_warning`).
  - Nút **"Cấu hình pin & quyền chạy ngầm"** mở dialog hướng dẫn trực tiếp bỏ qua tối ưu pin (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) và mở App Info (`ACTION_APPLICATION_DETAILS_SETTINGS`) cho Vivo/Xiaomi/Samsung.
- [x] **Kiểm tra và nhắc nhở quyền `POST_NOTIFICATIONS`:**
  - Đã có luồng kiểm tra `POST_NOTIFICATIONS` (Android 13+) trước khi khởi chạy foreground service.
### Giai Đoạn 3: Tăng Cường Khả Năng Tự Phục Hồi Kết Nối Database (Rust)
- [x] **Tự động Reconnect trong `postgres_backend.rs`:**
  - Trong `PgWorker`, vòng lặp nhận job đã được bổ sung kiểm tra `client.is_closed()` và tự động `connect_pg(&url_owned)` trước và sau khi thực thi job.
  - Đã bổ sung unit test kiểm tra xử lý lỗi kết nối PostgreSQL.
- [x] **Đồng bộ hóa nhịp nhàng với `ResilientBackend`:**
  - Nhờ việc service không bị dừng đột ngột bởi Watchdog và socket tự reconnect, `ResilientBackend` duy trì ghi offline vào `queue.db` và tự động flush lên primary khi mạng phục hồi.
---

## 4. Hướng Dẫn Cấu Hình Thiết Bị (Dành Cho Người Dùng Máy Vivo/OEM)

Để ứng dụng duy trì kết nối database liên tục:
1. **Bật chạy nền:** Bật công tắc khởi chạy server trong ứng dụng và cho phép hiển thị thông báo.
2. **Cho phép pin ngầm (Bắt buộc trên Vivo):**
   - Vào **Cài đặt → Ứng dụng → vrtfido → Sử dụng pin → Kiểm soát pin dưới nền**.
   - Chọn **Cho phép sử dụng pin ngầm** (*Allow background battery usage*).
3. **Tắt tự động tạm dừng:**
   - Trong màn hình **Thông tin ứng dụng (App info)** của `vrtfido`, tắt: **Tạm dừng hoạt động của ứng dụng nếu không dùng** (*Pause app activity if unused*).
