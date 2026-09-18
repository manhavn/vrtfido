# vrtfido

**vrtfido** là ứng dụng giả lập khóa bảo mật phần cứng **Virtual FIDO2 / WebAuthn Authenticator** chạy trên Linux thông qua kernel character device `/dev/uhid`. 

Ứng dụng tích hợp sẵn **Web CMS Dashboard** trên cổng **10209**, lưu trữ cơ sở dữ liệu **SQLite**, hỗ trợ chính sách xác thực đa lớp (Mã PIN passkey 6 số, quản lý tối đa 10 dấu vân tay, và mở rộng sinh trắc học khuôn mặt/mống mắt).

---

## 🌟 Tính năng chính

1. **Kernel Virtual HID (`/dev/uhid`):**
   - Tự tạo một thiết bị USB HID ảo với FIDO Usage Page (`0xF1D0`).
   - Mọi trình duyệt (Chrome, Chromium, Firefox, Edge) tự động nhận diện như một USB Security Key vật lý cắm vào máy.
   - Hỗ trợ đầy đủ các lệnh CTAP2: `authenticatorGetInfo`, `authenticatorMakeCredential` (Đăng ký Passkey), `authenticatorGetAssertion` (Đăng nhập WebAuthn).

2. **Cửa sổ Phê duyệt Tương tác (Interactive Verification Modal):**
   - Khi website (ví dụ: `webauthn.io`, GitHub, Google) gửi yêu cầu xác thực WebAuthn, Web CMS tự động bật modal xác thực thời gian thực.
   - Nếu chưa cài đặt bảo mật: Tự động yêu cầu khởi tạo mã PIN 6 số.
   - Nếu đã cài đặt: Cho phép xác thực bằng mã PIN 6 số hoặc Chạm cảm biến vân tay.

3. **Chính sách Quản lý Bảo mật:**
   - **Mã PIN 6 số (Mật khẩu Passkey):** Kiểm tra định dạng 6 chữ số, băm mật mã SHA-256 kèm muối (salt). Chỉ cho phép duy nhất 1 mã PIN (Thêm / Đổi cần PIN cũ / Xóa).
   - **Quản lý Vân tay:** Đăng ký tối đa 10 dấu vân tay (slot 0 đến 9), có đặt tên gợi nhớ và xóa slot.
   - **Mở rộng đa sinh trắc học tương lai:** Cấu trúc module hỗ trợ mở rộng FaceID, Iris, Voiceprint.

4. **Web Management CMS (Cổng 10209):**
   - Giao diện Dark theme hiện đại, nhẹ, nhúng trực tiếp vào binary (không phụ thuộc Node/npm).
   - Quản lý danh sách tài khoản Passkey đã lưu (Relying Party domain, username, số lần ký, ngày tạo, lần dùng cuối).
   - Cho phép chỉnh sửa tên hiển thị hoặc xóa tài khoản.
   - **Nhật ký Truy vết (Audit Trail):** Lưu vết toàn bộ lịch sử thao tác với thông tin chi tiết từng tài khoản.
   - **Logs Debug & Lỗi:** Bảng hiển thị logs hệ thống và gói tin CTAP2.

5. **Chế độ Debug qua CLI:**
   - Mặc định tắt debug để giữ log sạch.
   - Kích hoạt qua cờ `--debug` hoặc `-d` để in chi tiết các gói tin CTAPHID và lưu vào bảng `debug_logs`.

---

## 🚀 Cài đặt & Sử dụng

### 1. Cấp quyền truy cập `/dev/uhid`
Do Linux kernel bảo vệ file ký tự `/dev/uhid`, bạn cần cấp quyền:

```bash
# Cách 1: Cấp quyền tạm thời
sudo chmod 666 /dev/uhid

# Cách 2: Cấu hình udev rule vĩnh viễn
echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 2. Biên dịch & Chạy

```bash
# Biên dịch phiên bản Release
cargo build --release

# Chạy ứng dụng thông thường
./target/release/vrtfido

# Hoặc chạy với chế độ debug chi tiết
./target/release/vrtfido --debug
```

### 3. Trải nghiệm

1. Mở trình duyệt truy cập Web CMS: **http://localhost:10209**
2. Mở tab mới truy cập trang kiểm thử: **https://webauthn.io/**
3. Nhập tên tài khoản bất kỳ $\rightarrow$ Bấm **Register** hoặc **Authenticate**.
4. Cửa sổ popup trên Web CMS sẽ xuất hiện để bạn nhập PIN 6 số hoặc bấm xác thực vân tay.

---

## 📂 Cơ sở dữ liệu SQLite

File cơ sở dữ liệu mặc định là `authenticator.db` gồm các bảng:
* `credentials`: Lưu private key (P-256 SEC1), public key (COSE), sign counter và thông tin RP.
* `auth_logs`: Lưu vết toàn bộ thao tác xác thực và đăng ký.
* `security_settings`: Lưu trạng thái PIN và chính sách xác thực.
* `fingerprints`: Quản lý 10 slot vân tay.
* `debug_logs`: Lưu vết lỗi và gói tin CTAPHID/CTAP2 khi bật debug.

---

## 📜 License
MIT
