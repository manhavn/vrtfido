# VrtFido Browser Extension (Platform Passkey Provider)

Tiện ích mở rộng đa trình duyệt (**Google Chrome**, **Chromium**, **Brave**, **Microsoft Edge**, **Mozilla Firefox**, **Apple Safari**) kết nối trực tiếp với máy chủ **VrtFido HTTP API** để hoạt động như một **Platform Passkey Authenticator** nội bộ (`authenticatorAttachment: "platform"`, `transports: ["internal", "hybrid"]`).

---

## 1. Cơ chế hoạt động & Tính năng nổi bật

- **Không phụ thuộc USB hay Native Messaging Host**: Tiện ích gọi trực tiếp qua HTTP REST API tới backend `vrtfido` (`/api/passkey/create`, `/api/passkey/get`).
- **Linh hoạt vị trí máy chủ**: Bạn có thể chạy VrtFido trên máy cục bộ (`http://127.0.0.1:10209`) hoặc deploy lên VPS/Cloud từ xa và cấu hình Host/Port linh hoạt.
- **Bypass giới hạn Platform Passkey**: Giả lập định danh Google Password Manager (GPM AAGUID: `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`) khi backend được chạy kèm `--google-aaguid` (nếu không, backend ký bằng AAGUID riêng `e672fbec-badd-58f1-a951-dcfa1a7f2b43`) và dùng thuật toán `ES256` ECDSA P-256, cho phép đăng ký trên cả các website khắt khe như Nvidia, Google hay webauthn.io khi bật định danh GPM.
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

---

## 5. Phát hành bản build Firefox (addons.mozilla.org)

`dist/vrtfido-firefox.zip` **chưa cài vĩnh viễn được trên Firefox release cho tới khi Mozilla ký** — nên "lên public" nghĩa là bản đã ký trên [addons.mozilla.org](https://addons.mozilla.org) (AMO), hoặc tệp `.xpi` đã ký do bạn tự host.

**Một lệnh duy nhất (tương tác).** Chạy từ thư mục gốc repo:

```bash
./publish-firefox.sh             # hỏi lần lượt: kênh, version, license, API key -> ký -> public
./publish-firefox.sh --dry-run   # build + lint, KHÔNG gọi AMO
./publish-firefox.sh --channel unlisted --version 0.3.4 --yes   # không tương tác
```

Script kiểm tra môi trường, hỏi kênh (`listed` = public trên AMO, `unlisted` = `.xpi` đã ký tự host), cho tăng version, chạy `build-firefox.sh` (đã ép addons-linter), hỏi giấy phép (chỉ kênh listed) và API key/secret của AMO (có thể lưu tại `~/.config/vrtfido/amo.env`, `chmod 600`), ký, rồi public (submit AMO với `listed`; tạo GitHub Release bằng `gh` nếu có với `unlisted`). Các bước thủ công bên dưới chính là những gì script tự động hoá.

**Metadata AMO (bắt buộc với `listed`).** AMO từ chối bản listed nếu thiếu license, nên script ghi/cập nhật `amo-metadata.json` (ở gốc repo) rồi truyền qua `--amo-metadata`. Mặc định license `MIT` (đổi bằng `--license SLUG`, hoặc dùng file riêng qua `--amo-metadata FILE`). File do bạn cung cấp chỉ được kiểm tra, không bị ghi đè. Với bản listed **đầu tiên**, AMO còn cần `name`, `summary` và `categories` cho mọi ứng dụng tương thích — các field này nằm trong `amo-metadata.json`:

```json
{
  "name": { "en-US": "VrtFido Passkey Provider", "vi": "VrtFido Passkey Provider" },
  "summary": { "en-US": "…", "vi": "…" },
  "categories": { "firefox": ["privacy-security"], "android": ["privacy-security"] },
  "version": { "license": "MIT" }
}
```

Slug category hợp lệ: <https://addons.mozilla.org/api/v5/addons/categories/>.

**Kiểm tra (`mozilla/addons-linter`).** `./build-firefox.sh` tự chạy linter chính thức trên file zip và dừng nếu có lỗi (`SKIP_LINT=1` để bỏ qua, hữu ích khi offline). Chạy lẻ:

```bash
npx --yes addons-linter@latest dist/vrtfido-firefox.zip
```

**Điều kiện.** Tài khoản AMO và API key tại <https://addons.mozilla.org/developers/addon/api/key/>, xuất thành biến `WEB_EXT_API_KEY` và `WEB_EXT_API_SECRET`.

**Listed (hiện công khai trên store).** Tạo listing một lần qua web tại <https://addons.mozilla.org/developers/addon/submit/>, các bản sau ký với channel `listed` (hoặc kéo-thả zip lên trang version của add-on):

```bash
npx --yes web-ext sign \
  --source-dir dist/firefox \
  --api-key "$WEB_EXT_API_KEY" \
  --api-secret "$WEB_EXT_API_SECRET" \
  --amo-metadata amo-metadata.json \
  --channel listed
```

**Unlisted (tự phân phối).** Trả về `.xpi` đã ký để bạn tự host (ví dụ gắn vào GitHub Releases):

```bash
npx --yes web-ext sign \
  --source-dir dist/firefox \
  --api-key "$WEB_EXT_API_KEY" \
  --api-secret "$WEB_EXT_API_SECRET" \
  --channel unlisted
```

Tệp đã ký nằm trong `web-ext-artifacts/`. ID extension (`vrtfido@local`) cùng trường `key` giữ ID ổn định giữa các phiên bản. Nếu tự host, thêm `browser_specific_settings.gecko.update_url` trỏ tới update manifest để bản đã cài nhận được cập nhật.

**Khai báo thu thập dữ liệu.** Manifest đặt `browser_specific_settings.gecko.data_collection_permissions.required: ["authenticationInfo", "personallyIdentifyingInfo"]` vì tiện ích truyền dữ liệu WebAuthn/passkey — bao gồm user name / display name do trang web cung cấp — tới backend VrtFido đã cấu hình (có thể ở xa). AMO bắt buộc key này với submission mới — xóa đi sẽ bị chặn ký. Nếu backend chỉ chạy nội bộ máy, có thể rút gọn thành `["none"]`. Key được hỗ trợ từ Firefox desktop 140+ / Android 142+, nên manifest đặt `strict_min_version` = `140.0` và `gecko_android.strict_min_version` = `142.0` — bản cũ hơn không được hỗ trợ, nhờ đó không còn warning về key không tương thích.

**Tuân thủ store.** Privacy policy công khai nằm ở `PRIVACY.md` (dùng làm URL privacy policy cho cả hai store); `store/REVIEW-CHECKLIST.md` chứa câu trả lời sẵn để dán vào mọi field duyệt của Chrome Web Store và AMO — single purpose, justification từng permission, checkbox data usage, chứng nhận Limited Use và hướng dẫn test cho reviewer.

---

## 6. Phát hành lên Chrome Web Store

Chrome không có công cụ tương đương `web-ext`: [Chrome Web Store API v2](https://developer.chrome.com/docs/webstore/using-api) cần OAuth, và item **đầu tiên** phải tạo thủ công trên [Developer Dashboard](https://chrome.google.com/webstore/devconsole/) (upload `dist/vrtfido-chrome.zip`, điền tab **Store listing** và **Privacy**). Sau đó có thể tự động hoá các bản cập nhật:

```bash
./publish-chrome.sh                      # hỏi lần lượt: version, OAuth, Publisher/Extension ID -> upload -> publish
./publish-chrome.sh --dry-run            # build + in lệnh API, không gọi mạng
./publish-chrome.sh --no-publish --yes   # chỉ upload, giữ ở bản nháp
```

Chuẩn bị:

1. Đăng ký tài khoản developer Chrome Web Store (phí một lần US$5) và bật **2-Step Verification** cho tài khoản Google.
2. Trong [Google Cloud Console](https://console.developers.google.com): bật **Chrome Web Store API**, cấu hình OAuth consent screen, rồi tạo **OAuth client ID** loại *Web application* với redirect URI `https://developers.google.com/oauthplayground`.
3. Lấy refresh token ở [OAuth 2.0 Playground](https://developers.google.com/oauthplayground) bằng client ID/secret của bạn với scope `https://www.googleapis.com/auth/chromewebstore`.
4. Ghi lại **Publisher ID** (Dashboard → Publisher → Settings) và **Item ID** của extension.

Script đọc `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN`, `CWS_PUBLISHER_ID`, `CWS_EXTENSION_ID` từ biến môi trường hoặc `~/.config/vrtfido/cws.env` (có thể lưu tại đó với `chmod 600`). Nó làm mới access token, kiểm tra `fetchStatus`, upload zip rồi gọi `publish`.

Lưu ý:
- Mỗi lần upload phải dùng `version` **cao hơn** bản đang publish — script có sẵn lựa chọn tăng patch/minor/major.
- Item luôn được publish theo visibility đang đặt.
- Vì tiện ích truyền dữ liệu xác thực tới backend VrtFido đã cấu hình, tab **Privacy practices** trên Dashboard cần khai báo data usage và URL privacy policy.
