# vrtfido

**vrtfido** là ứng dụng giả lập khóa bảo mật phần cứng **Virtual FIDO2 / WebAuthn Authenticator** chạy trên Linux thông qua kernel character device `/dev/uhid`. 

Ứng dụng tích hợp sẵn **Web CMS Dashboard** trên cổng **10209**, hỗ trợ lưu trữ linh hoạt đa cơ sở dữ liệu (**SQLite**, **PostgreSQL**, **LibSQL/Turso**, **MySQL**, **MariaDB**) cùng tính năng **Export / Import 100% dữ liệu sang JSON** để chuyển đổi server dễ dàng, hỗ trợ chính sách xác thực đa lớp (Mã PIN passkey 6 số, quản lý tối đa 10 dấu vân tay, và mở rộng sinh trắc học khuôn mặt/mống mắt).

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


6. **Hỗ trợ Đa Cơ sở Dữ liệu & Chuyển dịch Dữ liệu (100% Data Migration):**
   - Kết nối linh hoạt với **SQLite**, **PostgreSQL**, **LibSQL (Turso Cloud)**, **MySQL** và **MariaDB**.
   - Xuất (Export) và Nhập (Import) 100% dữ liệu (Credentials, PIN, Vân tay, Logs) sang 1 file JSON duy nhất để dễ dàng sao lưu, di chuyển server hoặc chuyển đổi giữa các loại database.
   - Tích hợp REST API `/api/database/export` và `/api/database/import` trên Web CMS.
---

## 🚀 Cài đặt & Sử dụng

### 1. Cài đặt qua [mise](https://mise.jdx.dev/) (Khuyên dùng)

Bạn có thể cài đặt và cập nhật binary `vrtfido` trực tiếp từ GitHub Releases trên bất kỳ máy tính Linux nào bằng `mise`:

```bash
# Cài đặt toàn cục (Global)
mise use -g github:manhavn/vrtfido

# Hoặc cài đặt riêng cho thư mục/dự án hiện tại
mise use github:manhavn/vrtfido

# Hoặc chạy trực tiếp không cần cài đặt
mise x github:manhavn/vrtfido -- vrtfido --daemon
```

Hoặc thêm vào file `mise.toml`:

```toml
[tools]
"github:manhavn/vrtfido" = "latest"
```

### 2. Cấp quyền truy cập `/dev/uhid`
Ứng dụng **đã được tích hợp sẵn tính năng tự động kiểm tra và yêu cầu cấp quyền qua `sudo`/`pkexec`** mỗi khi khởi động nếu chưa có quyền truy cập `/dev/uhid`.

Nếu muốn cấu hình udev rule vĩnh viễn (không bao giờ bị hỏi mật khẩu sudo):

```bash
echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 3. Biên dịch & Chạy từ mã nguồn

```bash
# Biên dịch phiên bản Release
cargo build --release

# Chạy ứng dụng thông thường (giới hạn 10 vân tay)
./target/release/vrtfido

# Chạy ngầm trong nền (DAEMON MODE):
./target/release/vrtfido --daemon

# Chạy ngầm kết hợp PostgreSQL và chế độ vân tay không giới hạn:
./target/release/vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --unlimited-fps --daemon

# Dừng tiến trình vrtfido đang chạy (cả daemon lẫn foreground):
./target/release/vrtfido --quit

# Xem log khi chạy ngầm:
tail -f /tmp/vrtfido.log

# Chạy với chế độ KHÔNG GIỚI HẠN VÂN TAY (--unlimited-fps hoặc -u)
./target/release/vrtfido --unlimited-fps

# Kết hợp chế độ không giới hạn vân tay và debug chi tiết
./target/release/vrtfido --unlimited-fps --debug
```

### 4. Tự build đa nền tảng cho GitHub Releases (Local Cross-build)

Dự án tích hợp sẵn script `build-cross.sh` (sử dụng `cargo-zigbuild`) tương tự dự án `manhavn/beauty` để bạn có thể biên dịch đa kiến trúc (x86_64 GNU/musl, aarch64 GNU/musl) ngay tại máy local mà không cần đến GitHub Actions CI:

```bash
# Cài đặt công cụ cross-build nếu chưa có:
cargo install cargo-zigbuild --locked
mise use -g zig

# Chạy build toàn bộ các target:
./build-cross.sh

# Hoặc chỉ định target mong muốn:
TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu ./build-cross.sh
```

Toàn bộ file nén upload-ready (`.tar.gz`) và mã băm kiểm tra (`.sha256`) sẽ được tạo tự động trong thư mục `dist/packages/`:
- `vrtfido-x86_64-unknown-linux-gnu.tar.gz`
- `vrtfido-x86_64-unknown-linux-musl.tar.gz`
- `vrtfido-aarch64-unknown-linux-gnu.tar.gz`
- `vrtfido-aarch64-unknown-linux-musl.tar.gz`

Bạn chỉ cần tạo Release trên GitHub và kéo thả các file trong `dist/packages/` lên. Người dùng ở bất kỳ máy tính nào đều có thể cài đặt ngay qua lệnh:
```bash
mise use -g github:manhavn/vrtfido
```

### 5. Trải nghiệm

1. Mở trình duyệt truy cập Web CMS: **http://localhost:10209**
2. Mở tab mới truy cập trang kiểm thử: **https://webauthn.io/**
3. Nhập tên tài khoản bất kỳ $\rightarrow$ Bấm **Register** hoặc **Authenticate**.
4. Cửa sổ popup trên Web CMS sẽ xuất hiện để bạn nhập PIN 6 số hoặc bấm xác thực vân tay.
---

## 📂 Cơ sở dữ liệu & Chuyển đổi dữ liệu (Data Migration)

Ứng dụng hỗ trợ đa dạng các hệ cơ sở dữ liệu: **SQLite**, **PostgreSQL**, **LibSQL (Turso)**, **MySQL** và **MariaDB**.

### 1. Cấu hình cơ sở dữ liệu qua CLI hoặc Biến môi trường

Mặc định, ứng dụng sử dụng file SQLite nội bộ `authenticator.db`. Bạn có thể thay đổi sang PostgreSQL, LibSQL, MySQL hoặc MariaDB bằng tham số `--database` / `--db` / `-D` hoặc biến môi trường `DATABASE_URL`:

```bash
# Sử dụng SQLite với file chỉ định:
./vrtfido --database my_data.db

# Sử dụng PostgreSQL:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres"

# Sử dụng LibSQL / Turso Cloud (với token xác thực):
./vrtfido --database "libsql://my-db.turso.io" --auth-token "my-turso-token"

# Sử dụng MySQL / MariaDB:
./vrtfido --database "mysql://root:secret@127.0.0.1:3306/vrtfido"
./vrtfido --database "mariadb://root:secret@127.0.0.1:3306/vrtfido"

# Hoặc thiết lập qua biến môi trường:
export DATABASE_URL="postgresql://postgres:vrtfido@127.0.0.1:5435/postgres"
./vrtfido
```

### 2. Xuất (Export) & Nhập (Import) 100% dữ liệu để chuyển server / chuyển DB

Hệ thống hỗ trợ xuất trọn vẹn 100% dữ liệu (bao gồm Credentials, Mã PIN, Dấu vân tay, Nhật ký xác thực Audit Logs, Debug Logs) ra 1 file JSON chuẩn để dễ dàng chuyển sang server khác hoặc chuyển đổi giữa các loại database (ví dụ: chuyển từ SQLite sang PostgreSQL hoặc ngược lại):

```bash
# 1. Xuất 100% dữ liệu từ SQLite ra file JSON rồi thoát:
./vrtfido --database authenticator.db --export backup.json

# 2. Nhập file JSON vào PostgreSQL:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json --exit-after-import

# 3. Hoặc vừa import vừa chạy tiếp ứng dụng:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json
```

Ngoài ra, Web CMS API cũng cung cấp 2 endpoint:
- `GET /api/database/export`: Tải về toàn bộ dữ liệu định dạng JSON.
- `POST /api/database/import`: Nhận payload JSON để nhập dữ liệu trực tiếp vào database đang hoạt động.

### 3. Cấu trúc bảng cơ sở dữ liệu

* `credentials`: Lưu private key (P-256 SEC1), public key (COSE), sign counter và thông tin Relying Party.
* `auth_logs`: Lưu vết toàn bộ thao tác xác thực và đăng ký.
* `security_settings`: Lưu trạng thái PIN (hash + salt) và chính sách xác thực.
* `fingerprints`: Quản lý các slot vân tay và tên gợi nhớ.
* `debug_logs`: Lưu vết lỗi và gói tin CTAPHID/CTAP2 khi bật debug.

## 📜 License
MIT
