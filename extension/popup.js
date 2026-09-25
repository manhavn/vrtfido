"use strict";

const isBrowser = typeof browser !== "undefined";
const runtime = isBrowser ? browser : chrome;

// Elements
const btnLangVi = document.getElementById("btnLangVi");
const btnLangEn = document.getElementById("btnLangEn");
const btnExpandTab = document.getElementById("btnExpandTab");
const btnRefreshStatus = document.getElementById("btnRefreshStatus");
const statusBadge = document.getElementById("statusBadge");
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const valServerUrl = document.getElementById("valServerUrl");
const valCredsCount = document.getElementById("valCredsCount");
const valVersion = document.getElementById("valVersion");
const valSensorStatus = document.getElementById("valSensorStatus");

const protoSelect = document.getElementById("protoSelect");
const hostInput = document.getElementById("hostInput");
const portInput = document.getElementById("portInput");
const urlPreview = document.getElementById("urlPreview");
const saveBtn = document.getElementById("saveBtn");

const btnOpenWeb = document.getElementById("btnOpenWeb");
const btnExportJson = document.getElementById("btnExportJson");
const btnImportJson = document.getElementById("btnImportJson");
const importFileInput = document.getElementById("importFileInput");

const passkeysList = document.getElementById("passkeysList");
const searchPasskeys = document.getElementById("searchPasskeys");
const passkeyBadgeCount = document.getElementById("passkeyBadgeCount");
const toastMsg = document.getElementById("toastMsg");

// Text elements for translation
const txtTagline = document.getElementById("txtTagline");
const txtStatusTitle = document.getElementById("txtStatusTitle");
const txtRefresh = document.getElementById("txtRefresh");
const txtLblServer = document.getElementById("txtLblServer");
const txtLblCount = document.getElementById("txtLblCount");
const txtLblVersion = document.getElementById("txtLblVersion");
const txtLblSensor = document.getElementById("txtLblSensor");
const txtSettingsTitle = document.getElementById("txtSettingsTitle");
const txtLblProto = document.getElementById("txtLblProto");
const txtLblHost = document.getElementById("txtLblHost");
const txtLblPort = document.getElementById("txtLblPort");
const txtSecurityNoticeTitle = document.getElementById("txtSecurityNoticeTitle");
const txtSecurityNoticeDesc = document.getElementById("txtSecurityNoticeDesc");
const txtSecurityNoticeBadge = document.getElementById("txtSecurityNoticeBadge");
const txtSaveBtn = document.getElementById("txtSaveBtn");
const txtOpenWeb = document.getElementById("txtOpenWeb");
const txtExportJson = document.getElementById("txtExportJson");
const txtImportJson = document.getElementById("txtImportJson");
const txtPasskeysTitle = document.getElementById("txtPasskeysTitle");
const txtLoadingPasskeys = document.getElementById("txtLoadingPasskeys");

// I18N dictionary
const TRANSLATIONS = {
  vi: {
    tagline: "Trình xác thực Passkey ảo",
    statusTitle: "Trạng thái dịch vụ",
    refresh: "Làm mới",
    lblServer: "Địa chỉ máy chủ",
    lblCount: "Số Passkeys lưu",
    lblVersion: "Phiên bản",
    lblSensor: "Cảm biến / UHID",
    settingsTitle: "Cấu hình kết nối & Xác thực",
    lblProto: "Giao thức",
    lblHost: "Host (IPv4 / Tên miền)",
    lblPort: "Port",
    securityNoticeTitle: "🛡️ Bảo mật bắt buộc",
    securityNoticeDesc: "Luôn hiển thị hộp thoại Approve / Cancel khi có yêu cầu Passkey",
    securityNoticeBadge: "BẬT",
    expandTabTitle: "Mở trang đầy đủ",
    createdPrefix: "Tạo: ",
    deleteBtnTitle: "Xóa Passkey",
    deleteFail: "Lỗi khi xóa: ",
    exportFail: "Lỗi khi xuất: ",
    saveBtn: "Lưu cấu hình",
    saving: "Đang lưu...",
    savedBtn: "✓ Đã lưu!",
    checking: "Đang kiểm tra kết nối...",
    searchEmpty: "Không tìm thấy kết quả phù hợp.",
    refreshTitle: "Làm mới trạng thái",
    openWebTitle: "Mở Web CMS Dashboard",
    exportJsonTitle: "Tải xuống tệp sao lưu JSON",
    importJsonTitle: "Nạp tệp sao lưu JSON",
    actionsTitle: "Thao tác nhanh",
    openWeb: "Mở Web CMS Dashboard",
    exportJson: "Xuất JSON",
    importJson: "Nhập JSON",
    passkeysTitle: "Passkeys đã lưu trên máy chủ",
    searchPlaceholder: "🔍 Tìm kiếm theo domain hoặc tài khoản...",
    loading: "Đang tải danh sách Passkeys...",
    empty: "Không có Passkey nào.",
    online: (url) => `VrtFido đang chạy tại ${url}`,
    offline: "Không thể kết nối tới máy chủ VrtFido",
    saved: "✓ Đã lưu cấu hình thành công!",
    invalidHost: "Host không được để trống",
    invalidPort: "Port phải là số từ 1 đến 65535",
    exportSuccess: "✓ Đã xuất sao lưu JSON thành công!",
    importSuccess: (c, f, l) => `✓ Đã nhập ${c} credential, ${f} fingerprint, ${l} log`,
    importFail: (e) => `Nhập thất bại: ${e}`,
    deleteConfirm: (domain, user) => `Bạn có chắc muốn xóa Passkey cho ${domain} (${user}) không?`,
    deleted: "✓ Đã xóa Passkey thành công",
    sensorOk: "Sẵn sàng",
    sensorNone: "Không có"
  },
  en: {
    tagline: "Virtual Passkey Provider",
    statusTitle: "Service Status",
    refresh: "Refresh",
    lblServer: "Server Address",
    lblCount: "Stored Passkeys",
    lblVersion: "Version",
    lblSensor: "Sensor / UHID",
    settingsTitle: "Connection & Authentication Settings",
    lblProto: "Protocol",
    lblHost: "Host (IPv4 / Domain)",
    lblPort: "Port",
    securityNoticeTitle: "🛡️ Required Security",
    securityNoticeDesc: "Always shows Approve / Cancel prompt on passkey requests",
    securityNoticeBadge: "ON",
    expandTabTitle: "Open full page",
    createdPrefix: "Created: ",
    deleteBtnTitle: "Delete Passkey",
    deleteFail: "Failed to delete: ",
    exportFail: "Export failed: ",
    saveBtn: "Save Settings",
    saving: "Saving...",
    savedBtn: "✓ Saved!",
    checking: "Checking connection...",
    searchEmpty: "No matching results found.",
    refreshTitle: "Refresh status",
    openWebTitle: "Open Web CMS Dashboard",
    exportJsonTitle: "Download JSON backup",
    importJsonTitle: "Import JSON backup",
    actionsTitle: "Quick Actions",
    empty: "No passkeys found.",
    online: (url) => `VrtFido is active at ${url}`,
    offline: "Cannot connect to VrtFido server",
    saved: "✓ Settings saved successfully!",
    invalidHost: "Host cannot be empty",
    invalidPort: "Port must be a number between 1 and 65535",
    exportSuccess: "✓ JSON backup exported successfully!",
    importSuccess: (c, f, l) => `✓ Imported ${c} credentials, ${f} fingerprints, ${l} logs`,
    importFail: (e) => `Import failed: ${e}`,
    deleteConfirm: (domain, user) => `Are you sure you want to delete passkey for ${domain} (${user})?`,
    deleted: "✓ Passkey deleted successfully",
    sensorOk: "Ready",
    sensorNone: "None"
  }
};

let currentLang = "vi";
let allCredentials = [];

function t(key, ...args) {
  const dict = TRANSLATIONS[currentLang] || TRANSLATIONS.vi;
  const val = dict[key];
  if (typeof val === "function") {
    return val(...args);
  }
  return val || key;
}

function showToast(msg) {
  toastMsg.textContent = msg;
  toastMsg.classList.add("show");
  setTimeout(() => {
    toastMsg.classList.remove("show");
  }, 2500);
}

function applyLanguage(lang) {
  currentLang = lang;
  btnLangVi.classList.toggle("active", lang === "vi");
  btnLangEn.classList.toggle("active", lang === "en");

  txtTagline.textContent = t("tagline");
  txtStatusTitle.textContent = t("statusTitle");
  txtRefresh.textContent = t("refresh");
  txtLblServer.textContent = t("lblServer");
  txtLblCount.textContent = t("lblCount");
  txtLblVersion.textContent = t("lblVersion");
  txtLblSensor.textContent = t("lblSensor");
  txtSettingsTitle.textContent = t("settingsTitle");
  txtLblProto.textContent = t("lblProto");
  txtLblHost.textContent = t("lblHost");
  txtLblPort.textContent = t("lblPort");
  if (txtSecurityNoticeTitle) txtSecurityNoticeTitle.textContent = t("securityNoticeTitle");
  if (txtSecurityNoticeDesc) txtSecurityNoticeDesc.textContent = t("securityNoticeDesc");
  if (txtSecurityNoticeBadge) txtSecurityNoticeBadge.textContent = t("securityNoticeBadge");
  if (btnExpandTab) btnExpandTab.title = t("expandTabTitle");
  txtSaveBtn.textContent = t("saveBtn");
  saveBtn.title = t("saveBtn");
  btnRefreshStatus.title = t("refreshTitle");
  btnOpenWeb.title = t("openWebTitle");
  btnExportJson.title = t("exportJsonTitle");
  btnImportJson.title = t("importJsonTitle");
  txtOpenWeb.textContent = t("openWeb");
  txtExportJson.textContent = t("exportJson");
  txtImportJson.textContent = t("importJson");
  txtPasskeysTitle.textContent = t("passkeysTitle");
  searchPasskeys.placeholder = t("searchPlaceholder");
  if (txtLoadingPasskeys) txtLoadingPasskeys.textContent = t("loading");
  document.title = "VrtFido Passkey CMS - " + t("tagline");
}
function computeBaseUrl() {
  const proto = protoSelect.value || "http";
  const rawHost = hostInput.value.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "") || "127.0.0.1";
  const port = parseInt(portInput.value.trim(), 10) || 10209;
  return `${proto}://${rawHost}:${port}`;
}

function updateUrlPreview() {
  const url = computeBaseUrl();
  urlPreview.textContent = url;
  valServerUrl.textContent = url;
}

// Call API via background script
function callExtApi(type, options) {
  return new Promise((resolve, reject) => {
    runtime.runtime.sendMessage({ type, options }, (response) => {
      if (runtime.runtime.lastError) {
        reject(new Error(runtime.runtime.lastError.message));
      } else if (response && response.error) {
        reject(new Error(response.error));
      } else {
        resolve(response ? response.result : null);
      }
    });
  });
}

// Load status from VrtFido daemon
async function refreshStatus() {
  statusDot.classList.add("pulsing");
  statusText.textContent = t("checking");

  try {
    const status = await callExtApi("STATUS");
    statusBadge.className = "status-badge status-online";
    statusDot.classList.remove("pulsing");
    statusText.textContent = t("online", computeBaseUrl());

    valCredsCount.textContent = status ? `${status.credentials_count || 0}` : "--";
    valVersion.textContent = status ? (status.version || "v0.2.9") : "--";

    const hasSensor = status && (status.usb_sensor_connected || status.uhid_connected);
    valSensorStatus.textContent = hasSensor ? t("sensorOk") : t("sensorNone");
  } catch (err) {
    statusBadge.className = "status-badge status-offline";
    statusDot.classList.remove("pulsing");
    statusText.textContent = t("offline");
    valCredsCount.textContent = "--";
    valVersion.textContent = "--";
    valSensorStatus.textContent = "--";
  }
}

// Render credentials list
function renderPasskeys(items) {
  passkeyBadgeCount.textContent = items.length;
  if (!items || items.length === 0) {
    passkeysList.innerHTML = `<div class="empty-state">${t("empty")}</div>`;
    return;
  }

  passkeysList.innerHTML = "";
  items.forEach((item) => {
    const el = document.createElement("div");
    el.className = "passkey-item";

    const info = document.createElement("div");
    info.className = "passkey-info";

    const domain = document.createElement("div");
    domain.className = "passkey-domain";
    domain.textContent = item.rp_id;

    const user = document.createElement("div");
    user.className = "passkey-user";
    user.textContent = item.user_display_name
      ? `${item.user_name} (${item.user_display_name})`
      : item.user_name;

    const meta = document.createElement("div");
    meta.className = "passkey-meta";
    meta.textContent = item.created_at ? `${t("createdPrefix")}${item.created_at}` : "";

    info.appendChild(domain);
    info.appendChild(user);
    if (item.created_at) info.appendChild(meta);

    const delBtn = document.createElement("button");
    delBtn.className = "passkey-delete-btn";
    delBtn.title = t("deleteBtnTitle");
    delBtn.textContent = "🗑️";
    delBtn.addEventListener("click", async () => {
      const confirmed = confirm(t("deleteConfirm", item.rp_id, item.user_name));
      if (!confirmed) return;

      try {
        await callExtApi("CREDENTIALS_DELETE", { id: item.id });
        showToast(t("deleted"));
        loadPasskeys();
        refreshStatus();
      } catch (e) {
        alert(t("deleteFail") + e.message);
      }
    });

    el.appendChild(info);
    el.appendChild(delBtn);
    passkeysList.appendChild(el);
  });
}

// Load passkeys list from API
async function loadPasskeys() {
  try {
    const list = await callExtApi("CREDENTIALS_LIST");
    allCredentials = Array.isArray(list) ? list : [];
    filterPasskeys();
  } catch (err) {
    allCredentials = [];
    passkeysList.innerHTML = `<div class="empty-state">${t("empty")}</div>`;
    passkeyBadgeCount.textContent = "0";
  }
}

function filterPasskeys() {
  const q = searchPasskeys.value.trim().toLowerCase();
  if (!q) {
    renderPasskeys(allCredentials);
    return;
  }
  const filtered = allCredentials.filter((c) => {
    return (
      (c.rp_id && c.rp_id.toLowerCase().includes(q)) ||
      (c.user_name && c.user_name.toLowerCase().includes(q)) ||
      (c.user_display_name && c.user_display_name.toLowerCase().includes(q))
    );
  });
  if (filtered.length === 0) {
    passkeysList.innerHTML = `<div class="empty-state">${t("searchEmpty")}</div>`;
    passkeyBadgeCount.textContent = "0";
  } else {
    renderPasskeys(filtered);
  }
}

// Initialize settings from storage
runtime.storage.sync.get(["protocol", "host", "port", "apiBaseUrl", "requireApproval", "language"], (data) => {
  const saved = data || {};

  // Language
  const lang = saved.language || (navigator.language && navigator.language.startsWith("vi") ? "vi" : "en");
  applyLanguage(lang);

  // Host & Port
  if (saved.host) {
    hostInput.value = saved.host;
    portInput.value = saved.port || 10209;
    protoSelect.value = saved.protocol || "http";
  } else if (saved.apiBaseUrl) {
    try {
      const u = new URL(saved.apiBaseUrl);
      protoSelect.value = u.protocol.replace(":", "") || "http";
      hostInput.value = u.hostname || "127.0.0.1";
      portInput.value = u.port || 10209;
    } catch (_) {
      hostInput.value = "127.0.0.1";
      portInput.value = 10209;
    }
  } else {
    protoSelect.value = "http";
    hostInput.value = "127.0.0.1";
    portInput.value = 10209;
  }


  updateUrlPreview();
  refreshStatus();
  loadPasskeys();
});

// Event listeners
protoSelect.addEventListener("change", updateUrlPreview);
hostInput.addEventListener("input", updateUrlPreview);
portInput.addEventListener("input", updateUrlPreview);

btnLangVi.addEventListener("click", () => {
  applyLanguage("vi");
  runtime.storage.sync.set({ language: "vi" });
});

btnLangEn.addEventListener("click", () => {
  applyLanguage("en");
  runtime.storage.sync.set({ language: "en" });
});

btnExpandTab.addEventListener("click", () => {
  const url = runtime.runtime.getURL("popup.html");
  if (runtime.tabs && runtime.tabs.create) {
    runtime.tabs.create({ url });
  } else {
    window.open(url, "_blank");
  }
});

btnRefreshStatus.addEventListener("click", () => {
  refreshStatus();
  loadPasskeys();
});

searchPasskeys.addEventListener("input", filterPasskeys);

// Save settings button
saveBtn.addEventListener("click", () => {
  const proto = protoSelect.value;
  const host = hostInput.value.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const port = parseInt(portInput.value.trim(), 10);

  if (!host) {
    alert(t("invalidHost"));
    hostInput.focus();
    return;
  }
  if (!port || port < 1 || port > 65535) {
    alert(t("invalidPort"));
    portInput.focus();
    return;
  }

  const apiBaseUrl = `${proto}://${host}:${port}`;

  saveBtn.disabled = true;
  txtSaveBtn.textContent = t("saving");

  runtime.storage.sync.set(
    {
      protocol: proto,
      host,
      port,
      apiBaseUrl,
      language: currentLang
    },
    () => {
      txtSaveBtn.textContent = t("savedBtn");
      showToast(t("saved"));
      updateUrlPreview();
      refreshStatus();
      loadPasskeys();
      setTimeout(() => {
        txtSaveBtn.textContent = t("saveBtn");
        saveBtn.disabled = false;
      }, 1200);
    }
  );
});

// Quick Action: Open Web CMS
btnOpenWeb.addEventListener("click", () => {
  const url = computeBaseUrl();
  if (runtime.tabs && runtime.tabs.create) {
    runtime.tabs.create({ url });
  } else {
    window.open(url, "_blank");
  }
});

// Quick Action: Export JSON Backup
btnExportJson.addEventListener("click", async () => {
  try {
    const data = await callExtApi("EXPORT_DB");
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const now = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const filename = `VrtFido-backup-${now}.json`;

    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);

    showToast(t("exportSuccess"));
  } catch (err) {
    alert(t("exportFail") + err.message);
  }
});

// Quick Action: Import JSON Backup
btnImportJson.addEventListener("click", () => {
  importFileInput.value = "";
  importFileInput.click();
});

importFileInput.addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function (evt) {
    try {
      const parsed = JSON.parse(evt.target.result);
      const res = await callExtApi("IMPORT_DB", parsed);
      const credCount = (res && res.credentials_imported) || 0;
      const fpCount = (res && res.fingerprints_imported) || 0;
      const logCount = (res && res.logs_imported) || 0;

      showToast(t("importSuccess", credCount, fpCount, logCount));
      refreshStatus();
      loadPasskeys();
    } catch (err) {
      alert(t("importFail", err.message));
    }
  };
  reader.readAsText(file);
});
