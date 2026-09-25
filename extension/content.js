(function () {
  "use strict";

  const isBrowser = typeof browser !== "undefined";
  const runtime = isBrowser ? browser : chrome;

  // Firefox MV3 does not yet support "world": "MAIN" in content_scripts manifest,
  // so we also ensure inject.js is injected via DOM if not already present.
  try {
    const script = document.createElement("script");
    script.src = runtime.runtime.getURL("inject.js");
    script.onload = function () {
      this.remove();
    };
    (document.head || document.documentElement).appendChild(script);
  } catch (_) {}

  // Localization dictionaries
  const I18N = {
    vi: {
      appName: "VrtFido Passkey",
      createTitle: "Tạo Passkey mới",
      getTitle: "Đăng nhập bằng Passkey",
      createDesc: "Trang web yêu cầu tạo và lưu trữ Passkey mới vào VrtFido.",
      getDesc: "Trang web yêu cầu xác thực Passkey để đăng nhập.",
      website: "Trang web",
      account: "Tài khoản",
      defaultAccount: "Tài khoản mặc định",
      chooseAccount: "Chọn tài khoản đăng nhập:",
      noCredentialsFound: "Không tìm thấy Passkey nào cho trang web này trên máy chủ VrtFido.",
      serverUnreachable: "Không thể kết nối tới máy chủ VrtFido.",
      cancel: "Hủy",
      close: "Đóng",
      approve: "Xác nhận",
      retry: "Thử lại",
      processing: "Đang xử lý...",
      approved: "✓ Đã xác nhận!",
      cancelError: "Người dùng đã hủy yêu cầu Passkey.",
      noCredsError: "Không có thông tin xác thực nào cho tên miền này."
    },
    en: {
      appName: "VrtFido Passkey",
      createTitle: "Create New Passkey",
      getTitle: "Sign In with Passkey",
      createDesc: "This website requests to create and store a Passkey in VrtFido.",
      getDesc: "This website requests Passkey authentication to sign in.",
      website: "Website",
      account: "Account",
      defaultAccount: "Default Account",
      chooseAccount: "Choose an account to sign in:",
      noCredentialsFound: "No Passkeys found for this website on VrtFido server.",
      serverUnreachable: "Cannot connect to VrtFido server.",
      cancel: "Cancel",
      close: "Close",
      approve: "Approve",
      retry: "Retry",
      processing: "Processing...",
      approved: "✓ Approved!",
      cancelError: "User cancelled the passkey request.",
      noCredsError: "No credentials found for this domain."
    }
  };

  // Helper to read extension configuration
  function getStoredSettings() {
    return new Promise((resolve) => {
      runtime.storage.sync.get(["requireApproval", "language", "apiBaseUrl", "host", "port", "protocol"], (data) => {
        resolve(data || {});
      });
    });
  }

  // Active prompt reference to ensure only one dialog is open at a time
  let activePrompt = null;

  function showApprovalDialog(type, options, candidates, candidatesError, langCode) {
    return new Promise((resolve, reject) => {
      if (activePrompt) {
        activePrompt.cancel("Superseded by new request");
      }

      const t = I18N[langCode] || I18N.vi;
      const logoUrl = runtime.runtime.getURL("icons/icon-32.png");

      const host = document.createElement("div");
      host.id = "vrtfido-prompt-root";
      const shadow = host.attachShadow({ mode: "open" });

      const isCreate = type === "CREATE";
      const rpId = isCreate
        ? (options.rp ? options.rp.id : window.location.hostname)
        : (options.rp_id || window.location.hostname);
      const rpName = isCreate && options.rp && options.rp.name ? options.rp.name : rpId;

      let accountName = "";
      if (isCreate) {
        accountName = options.user ? (options.user.displayName || options.user.name || t.defaultAccount) : t.defaultAccount;
      }

      // Check if there are no matching credentials for GET
      const hasCandidates = Array.isArray(candidates) && candidates.length > 0;
      const isGetWithNoCreds = !isCreate && !hasCandidates;
      const isGetWithMultiple = !isCreate && hasCandidates && candidates.length > 1;
      const isGetWithSingle = !isCreate && hasCandidates && candidates.length === 1;

      let initialSelectedId = options.credential_id;
      if (isGetWithSingle) {
        initialSelectedId = candidates[0].id_b64url || candidates[0].id;
        accountName = candidates[0].user_display_name && candidates[0].user_display_name !== candidates[0].user_name
          ? `${candidates[0].user_name} (${candidates[0].user_display_name})`
          : candidates[0].user_name;
      } else if (isGetWithMultiple) {
        initialSelectedId = candidates[0].id_b64url || candidates[0].id;
      }

      shadow.innerHTML = `
        <style>
          :host {
            all: initial;
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            font-size: 13px;
            color: #f1f5f9;
            box-sizing: border-box;
          }
          *, *::before, *::after {
            box-sizing: border-box;
          }
          .vrtfido-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(11, 15, 25, 0.78);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
            animation: vrtfidoFadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
          }
          @keyframes vrtfidoFadeIn {
            from { opacity: 0; transform: scale(0.96); }
            to { opacity: 1; transform: scale(1); }
          }
          .vrtfido-card {
            width: 100%;
            max-width: 420px;
            background: #0f172a;
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 16px;
            padding: 20px 22px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 35px rgba(56, 189, 248, 0.15);
            display: flex;
            flex-direction: column;
            gap: 14px;
          }
          .vrtfido-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
          }
          .vrtfido-brand {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 700;
            color: #38bdf8;
            letter-spacing: 0.3px;
          }
          .vrtfido-brand-icon {
            font-size: 18px;
            line-height: 1;
          }
          .vrtfido-close-btn {
            background: none;
            border: none;
            color: #64748b;
            font-size: 18px;
            cursor: pointer;
            padding: 4px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            line-height: 1;
            transition: color 0.15s, background 0.15s;
          }
          .vrtfido-close-btn:hover {
            color: #f1f5f9;
            background: #1e293b;
          }
          .vrtfido-badge-row {
            display: flex;
            align-items: center;
            gap: 8px;
          }
          .vrtfido-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: ${isCreate ? "rgba(14, 165, 233, 0.15)" : "rgba(16, 185, 129, 0.15)"};
            color: ${isCreate ? "#38bdf8" : "#34d399"};
            border: 1px solid ${isCreate ? "rgba(56, 189, 248, 0.3)" : "rgba(52, 211, 153, 0.3)"};
          }
          .vrtfido-title {
            font-size: 15px;
            font-weight: 600;
            color: #f8fafc;
            margin: 0;
          }
          .vrtfido-desc {
            font-size: 12px;
            color: #94a3b8;
            margin: 0;
            line-height: 1.45;
          }
          .vrtfido-info-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 12px 14px;
            display: flex;
            flex-direction: column;
            gap: 10px;
          }
          .vrtfido-info-item {
            display: flex;
            flex-direction: column;
            gap: 3px;
          }
          .vrtfido-info-label {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
            color: #64748b;
          }
          .vrtfido-info-value {
            font-size: 13px;
            font-weight: 500;
            color: #f1f5f9;
            word-break: break-all;
            display: flex;
            align-items: center;
            gap: 6px;
          }
          /* Account Selector Cards */
          .vrtfido-accounts-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-top: 4px;
            max-height: 150px;
            overflow-y: auto;
          }
          .vrtfido-account-card {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 8px 10px;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: all 0.15s ease;
          }
          .vrtfido-account-card:hover {
            border-color: #38bdf8;
            background: #142036;
          }
          .vrtfido-account-card.selected {
            border-color: #38bdf8;
            background: rgba(14, 165, 233, 0.12);
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.2);
          }
          .vrtfido-account-radio {
            accent-color: #38bdf8;
            cursor: pointer;
          }
          .vrtfido-account-meta {
            display: flex;
            flex-direction: column;
            gap: 1px;
            overflow: hidden;
          }
          .vrtfido-account-username {
            font-size: 12.5px;
            font-weight: 600;
            color: #f1f5f9;
          }
          .vrtfido-account-displayname {
            font-size: 11px;
            color: #94a3b8;
          }
          .vrtfido-alert {
            background: rgba(245, 158, 11, 0.12);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 8px;
            padding: 10px 12px;
            color: #fbbf24;
            font-size: 12px;
            line-height: 1.45;
            display: flex;
            align-items: flex-start;
            gap: 8px;
          }
          .vrtfido-error {
            display: none;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 8px 12px;
            color: #f87171;
            font-size: 11.5px;
            line-height: 1.4;
          }
          .vrtfido-actions {
            display: flex;
            gap: 10px;
            margin-top: 6px;
          }
          .vrtfido-btn {
            flex: 1;
            padding: 9px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: all 0.15s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
          }
          .vrtfido-btn-cancel {
            background: #1e293b;
            color: #94a3b8;
            border: 1px solid #334155;
          }
          .vrtfido-btn-cancel:hover:not(:disabled) {
            background: #334155;
            color: #f8fafc;
          }
          .vrtfido-btn-approve {
            background: linear-gradient(135deg, #0284c7, #0ea5e9);
            color: #ffffff;
            box-shadow: 0 2px 10px rgba(14, 165, 233, 0.35);
          }
          .vrtfido-btn-approve:hover:not(:disabled) {
            background: linear-gradient(135deg, #0369a1, #0284c7);
            box-shadow: 0 4px 14px rgba(14, 165, 233, 0.5);
          }
          .vrtfido-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .vrtfido-spinner {
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: vrtfidoSpin 0.7s linear infinite;
          }
          @keyframes vrtfidoSpin {
            to { transform: rotate(360deg); }
          }
        </style>

        <div class="vrtfido-backdrop" id="backdrop">
          <div class="vrtfido-card" id="card">
            <div class="vrtfido-header">
              <div class="vrtfido-brand">
                <img class="vrtfido-brand-icon" src="${logoUrl}" width="22" height="22" alt="VrtFido" style="border-radius: 4px; display: block;">
                <span>${t.appName}</span>
              </div>
              <button class="vrtfido-close-btn" id="closeBtn" title="${isGetWithNoCreds ? t.close : t.cancel}">✕</button>
            </div>

            <div class="vrtfido-badge-row">
              <span class="vrtfido-badge">
                <span>${isCreate ? "✨" : "🛡️"}</span>
                <span>${isCreate ? t.createTitle : t.getTitle}</span>
              </span>
            </div>

            <div>
              <h3 class="vrtfido-title">${isCreate ? t.createTitle : t.getTitle}</h3>
              <p class="vrtfido-desc">${isCreate ? t.createDesc : t.getDesc}</p>
            </div>

            ${
              isGetWithNoCreds
                ? `
              <div class="vrtfido-alert">
                <span>⚠️</span>
                <span>${candidatesError ? t.serverUnreachable : t.noCredentialsFound}</span>
              </div>
              <div class="vrtfido-info-box">
                <div class="vrtfido-info-item">
                  <span class="vrtfido-info-label">${t.website}</span>
                  <span class="vrtfido-info-value">🌐 ${escapeHtml(rpName || rpId)}</span>
                </div>
              </div>
            `
                : `
              <div class="vrtfido-info-box">
                <div class="vrtfido-info-item">
                  <span class="vrtfido-info-label">${t.website}</span>
                  <span class="vrtfido-info-value">🌐 ${escapeHtml(rpName || rpId)}</span>
                </div>

                ${
                  isGetWithMultiple
                    ? `
                  <div class="vrtfido-info-item">
                    <span class="vrtfido-info-label">${t.chooseAccount}</span>
                    <div class="vrtfido-accounts-group" id="accountsGroup">
                      ${candidates
                        .map((c, idx) => {
                          const cid = escapeHtml(c.id_b64url || c.id);
                          const isSelected = idx === 0;
                          return `
                          <div class="vrtfido-account-card ${isSelected ? "selected" : ""}" data-cid="${cid}">
                            <input type="radio" name="vrtfido_account_choice" value="${cid}" class="vrtfido-account-radio" ${isSelected ? "checked" : ""}>
                            <div class="vrtfido-account-meta">
                              <span class="vrtfido-account-username">👤 ${escapeHtml(c.user_name)}</span>
                              ${
                                c.user_display_name && c.user_display_name !== c.user_name
                                  ? `<span class="vrtfido-account-displayname">${escapeHtml(c.user_display_name)}</span>`
                                  : ""
                              }
                            </div>
                          </div>
                        `;
                        })
                        .join("")}
                    </div>
                  </div>
                `
                    : `
                  <div class="vrtfido-info-item">
                    <span class="vrtfido-info-label">${t.account}</span>
                    <span class="vrtfido-info-value">👤 ${escapeHtml(accountName || t.defaultAccount)}</span>
                  </div>
                `
                }
              </div>
            `
            }

            <div class="vrtfido-error" id="errorBox"></div>

            <div class="vrtfido-actions">
              <button class="vrtfido-btn vrtfido-btn-cancel" id="cancelBtn">
                ${isGetWithNoCreds ? t.close : t.cancel}
              </button>
              ${
                !isGetWithNoCreds
                  ? `
                <button class="vrtfido-btn vrtfido-btn-approve" id="approveBtn">
                  <span>${t.approve}</span>
                </button>
              `
                  : ""
              }
            </div>
          </div>
        </div>
      `;

      function escapeHtml(str) {
        return String(str || "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }

      const backdrop = shadow.getElementById("backdrop");
      const cancelBtn = shadow.getElementById("cancelBtn");
      const approveBtn = shadow.getElementById("approveBtn");
      const closeBtn = shadow.getElementById("closeBtn");
      const errorBox = shadow.getElementById("errorBox");

      let selectedCredentialId = initialSelectedId;

      // Account selector interaction when multiple accounts exist
      if (isGetWithMultiple) {
        const cards = shadow.querySelectorAll(".vrtfido-account-card");
        cards.forEach((card) => {
          card.addEventListener("click", () => {
            cards.forEach((c) => c.classList.remove("selected"));
            card.classList.add("selected");
            const radio = card.querySelector(".vrtfido-account-radio");
            if (radio) radio.checked = true;
            selectedCredentialId = card.getAttribute("data-cid");
          });
        });
      }

      function cleanUp() {
        window.removeEventListener("keydown", onKeyDown);
        if (host.parentNode) {
          host.parentNode.removeChild(host);
        }
        if (activePrompt && activePrompt.host === host) {
          activePrompt = null;
        }
      }

      function handleCancel(reason) {
        cleanUp();
        reject(new Error(reason || t.cancelError));
      }

      function onKeyDown(e) {
        if (e.key === "Escape") {
          e.preventDefault();
          handleCancel(isGetWithNoCreds ? t.noCredsError : t.cancelError);
        }
      }

      window.addEventListener("keydown", onKeyDown);

      cancelBtn.addEventListener("click", () => {
        handleCancel(isGetWithNoCreds ? t.noCredsError : t.cancelError);
      });
      closeBtn.addEventListener("click", () => {
        handleCancel(isGetWithNoCreds ? t.noCredsError : t.cancelError);
      });
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) {
          handleCancel(isGetWithNoCreds ? t.noCredsError : t.cancelError);
        }
      });

      if (approveBtn) {
        approveBtn.addEventListener("click", () => {
          approveBtn.disabled = true;
          cancelBtn.disabled = true;
          closeBtn.disabled = true;
          errorBox.style.display = "none";
          approveBtn.innerHTML = `<span class="vrtfido-spinner"></span><span>${t.processing}</span>`;

          const finalOptions = Object.assign({}, options);
          if (!isCreate && selectedCredentialId) {
            finalOptions.credential_id = selectedCredentialId;
          }

          runtime.runtime.sendMessage({ type, options: finalOptions }, (res) => {
            if (runtime.runtime.lastError || (res && res.error)) {
              const errMsg = (res && res.error) || (runtime.runtime.lastError && runtime.runtime.lastError.message) || "Unknown error";
              errorBox.textContent = `⚠️ ${errMsg}`;
              errorBox.style.display = "block";
              approveBtn.disabled = false;
              cancelBtn.disabled = false;
              closeBtn.disabled = false;
              approveBtn.innerHTML = `<span>${t.retry}</span>`;
              return;
            }

            approveBtn.innerHTML = `<span>${t.approved}</span>`;
            setTimeout(() => {
              cleanUp();
              resolve(res);
            }, 180);
          });
        });
      }

      activePrompt = {
        host,
        cancel: handleCancel
      };

      (document.body || document.documentElement).appendChild(host);
    });
  }

  // Helper to query candidates for GET operation
  function queryCandidates(rpId, allowCredentials) {
    return new Promise((resolve) => {
      runtime.runtime.sendMessage(
        {
          type: "CANDIDATES",
          options: {
            rp_id: rpId,
            allow_credentials: allowCredentials || []
          }
        },
        (res) => {
          if (runtime.runtime.lastError || (res && res.error)) {
            resolve({ candidates: [], error: (res && res.error) || (runtime.runtime.lastError && runtime.runtime.lastError.message) });
          } else if (res && res.result && Array.isArray(res.result)) {
            resolve({ candidates: res.result, error: null });
          } else {
            resolve({ candidates: [], error: null });
          }
        }
      );
    });
  }

  // Relay messages from page (inject.js) to background service worker
  window.addEventListener("message", async function (event) {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== "VRTFIDO_PAGE") return;

    const { requestId, type, options } = event.data;

    if (type !== "CREATE" && type !== "GET") {
      runtime.runtime.sendMessage({ type, options }, function (response) {
        if (runtime.runtime.lastError) {
          window.postMessage({
            source: "VRTFIDO_EXT",
            requestId,
            error: runtime.runtime.lastError.message
          }, "*");
        } else {
          window.postMessage({
            source: "VRTFIDO_EXT",
            requestId,
            result: response
          }, "*");
        }
      });
      return;
    }

    // Check stored settings
    const cfg = await getStoredSettings();
    const requireApproval = cfg.requireApproval !== false;
    const langCode = cfg.language || (navigator.language && navigator.language.startsWith("vi") ? "vi" : "en");

    // For GET: always query candidates to know accounts available on this domain
    let candidates = [];
    let candidatesError = null;
    if (type === "GET") {
      const queryRes = await queryCandidates(options.rp_id, options.allow_credentials);
      candidates = queryRes.candidates;
      candidatesError = queryRes.error;
    }

    // ALWAYS display interactive approval prompt modal (never auto-approve)
    try {
      const response = await showApprovalDialog(type, options, candidates, candidatesError, langCode);
      window.postMessage({
        source: "VRTFIDO_EXT",
        requestId,
        result: response
      }, "*");
    } catch (err) {
      window.postMessage({
        source: "VRTFIDO_EXT",
        requestId,
        error: err.message || "User cancelled the request",
        isCancelled: true
      }, "*");
    }
  });
})();
