# VrtFido Browser Extension (Platform Passkey Provider)

Tiện ích mở rộng đa trình duyệt (**Google Chrome**, **Chromium**, **Brave**, **Microsoft Edge**, **Mozilla Firefox**, **Apple Safari**) kết nối trực tiếp với máy chủ **VrtFido HTTP API** để hoạt động như một **Platform Passkey Authenticator** nội bộ (`authenticatorAttachment: "platform"`, `transports: ["internal", "hybrid"]`).

---

## 1. Cơ chế hoạt động & Tính năng nổi bật

- **Không phụ thuộc USB hay Native Messaging Host**: Tiện ích gọi trực tiếp qua HTTP REST API tới backend `vrtfido` (`/api/passkey/create`, `/api/passkey/get`).
- **Linh hoạt vị trí máy chủ**: Bạn có thể chạy VrtFido trên máy cục bộ (`http://127.0.0.1:10209`) hoặc deploy lên VPS/Cloud từ xa và cấu hình Host/Port linh hoạt.
- **Bypass giới hạn Platform Passkey**: Giả lập hoàn hảo định danh Google Password Manager (GPM AAGUID: `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`) và thuật toán `ES256` ECDSA P-256, cho phép đăng ký trên cả các website khắt khe như Nvidia, Google hay webauthn.io.
- **Hộp thoại xác thực bắt buộc (Approve / Cancel Prompt)**:
  - Khi có yêu cầu tạo hoặc đăng nhập Passkey từ trang web, tiện ích luôn hiển thị một **Modal Popup** nổi (sử dụng Shadow DOM cách ly CSS hoàn toàn khỏi website).
  - Tuyệt đối không tự động duyệt ngầm: người dùng bắt buộc phải bấm **Xác nhận (Approve)** hoặc **Hủy (Cancel)** (hỗ trợ phím tắt `Escape` để hủy, `Enter` để xác nhận).
- **Hỗ trợ đầy đủ luồng Đăng nhập không truyền Username (Discoverable Credentials / 1-Click Login)**:
  - Khi trang web gọi đăng nhập mà không chỉ định trước tài khoản (`allowCredentials` rỗng):
    - **0 tài khoản:** Hiển thị cảnh báo không có Passkey nào cho tên miền này, cho phép đóng và trả về lỗi hủy an toàn.
    - **1 tài khoản:** Tự động nhận diện tài khoản đã lưu, hiển thị tên tài khoản và chờ người dùng bấm Xác nhận.
    - **Nhiều tài khoản (2+):** Hiển thị danh sách thẻ tài khoản trực quan (tên đăng nhập, tên hiển thị) để người dùng chủ động chọn tài khoản mong muốn rồi bấm Xác nhận (tương tự Web CMS và Android Credential Manager).
- **Khu vực CMS quản lý đầy đủ (như ứng dụng Android)**:
  - Cấu hình linh hoạt **Host & Port** kèm thanh xem trước URL trực quan.
  - Thẻ hiển thị trạng thái kết nối máy chủ thời gian thực (Online / Offline, số Passkey lưu, phiên bản, cảm biến USB/UHID).
  - Thao tác nhanh: Mở Web Dashboard, Xuất tệp sao lưu JSON, Nhập tệp sao lưu JSON.
  - Quản lý danh sách Passkeys: Xem chi tiết, lọc tìm kiếm theo domain / username và xóa Passkey trực tiếp.
- **Hỗ trợ đa ngôn ngữ (i18n)**:
  - Chuyển đổi nhanh giữa **Tiếng Việt (VI)** và **Tiếng Anh (EN)** chỉ với 1 click, tự động đồng bộ sang hộp thoại xác thực in-page.
  - Chuẩn thư mục `_locales` (WebExtensions standard).
  - Nút **↗** mở giao diện CMS trên một tab trình duyệt riêng biệt toàn màn hình.

---

## 2. Lệnh Build tiện ích tự động

Tại thư mục gốc dự án, chạy script build:

```bash
# Build cùng lúc cho cả Chrome, Firefox và Safari:
./build-extension.sh

# Hoặc build riêng lẻ từng trình duyệt nếu muốn:
./build-chrome.sh
./build-firefox.sh
./build-safari.sh
```

Kết quả build sẽ nằm tại thư mục `dist/`:
- **Chrome / Chromium / Brave / Edge / Opera**: Thư mục `dist/chrome/` và tệp `dist/vrtfido-chrome.zip`.
- **Firefox**: Thư mục `dist/firefox/` và tệp `dist/vrtfido-firefox.zip`.
- **Apple Safari**: Thư mục `dist/safari/` và tệp `dist/vrtfido-safari.zip`.

---

## 3. Hướng dẫn cài đặt vào trình duyệt

### A. Cho Google Chrome / Chromium / Brave / Microsoft Edge / Opera:
1. Mở trang quản lý tiện ích: `chrome://extensions/` (hoặc `edge://extensions/`, `brave://extensions/`).
2. Bật công tắc **Chế độ dành cho nhà phát triển** (**Developer mode**) ở góc trên bên phải.
3. Nhấp vào nút **Tải tiện ích đã giải nén** (**Load unpacked**).
4. Chọn thư mục:
   ```text
   vrtfido/dist/chrome
   ```

### B. Cho Mozilla Firefox (kể cả bản Ubuntu Snap):
1. Mở trình duyệt Firefox và truy cập: `about:debugging#/runtime/this-firefox`.
2. Nhấp vào nút **Tải tiện ích bổ sung tạm thời...** (**Load Temporary Add-on...**).
3. Chọn tệp:
   ```text
   vrtfido/dist/vrtfido-firefox.zip
   ```

### C. Cho Apple Safari (macOS & iOS/iPadOS):
Safari đóng gói Web Extension dưới dạng một ứng dụng macOS native thông qua công cụ `safari-web-extension-converter` của Apple Xcode:

1. **Trên máy Mac**, đứng tại thư mục dự án và chạy lệnh:
   ```bash
   xcrun safari-web-extension-converter dist/safari --app-name "VrtFido"
   ```
   *(Nếu bạn chạy script `./build-safari.sh` trực tiếp trên macOS, script sẽ tự động tạo project Xcode giúp bạn)*.
2. **Khởi chạy trong Xcode:**
   - Mở file project `VrtFido.xcodeproj` vừa tạo.
   - Bấm nút **Run** (`Cmd + R`) để build và mở ứng dụng wrapper.
3. **Kích hoạt tiện ích trong Safari:**
   - Mở Safari > vào **Cài đặt (Settings)** (`Cmd + ,`) > chọn tab **Tiện ích (Extensions)**.
   - Tích chọn bật **VrtFido Passkey Provider**.
   - *(Nếu đang test tiện ích tự build chưa ký chứng chỉ App Store: Vào menu **Develop** trên thanh menu Safari > tích chọn **Allow Unsigned Extensions**)*.

---

## 4. Hướng dẫn Cấu hình & Sử dụng CMS Extension

1. Nhấp vào biểu tượng icon chìa khóa **VrtFido** trên thanh công cụ của trình duyệt.
2. Trong thẻ **Cấu hình kết nối & Xác thực**:
   - **Giao thức**: Chọn `http://` hoặc `https://`.
   - **Host**: Nhập địa chỉ IP máy chủ (ví dụ `127.0.0.1` nếu chạy cục bộ, hoặc IP VPS từ xa).
   - **Port**: Nhập cổng dịch vụ (mặc định: `10209`).
   - Kiểm tra đường dẫn trong ô xem trước URL (`http://127.0.0.1:10209`).
3. Bấm **Lưu cấu hình**.
   - Nút bấm sẽ chuyển sang trạng thái *Đang lưu...* và thông báo *✓ Đã lưu!*.
   - Đèn trạng thái sẽ chuyển sang **🟢 VrtFido đang chạy tại http://...** ngay khi kết nối thành công.
4. **Các tính năng quản lý nhanh:**
   - Bấm **Mở Web CMS Dashboard** để vào trang quản lý nâng cao trên trình duyệt.
   - Bấm **Xuất JSON** để tải tệp backup passkeys về máy tính.
   - Bấm **Nhập JSON** để nạp tệp backup vào cơ sở dữ liệu.
   - Ô tìm kiếm danh sách Passkeys cho phép gõ tên miền hoặc tài khoản để lọc nhanh, có nút xóa kèm hộp thoại xác nhận.
