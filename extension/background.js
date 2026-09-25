"use strict";

const isBrowser = typeof browser !== "undefined";
const runtime = isBrowser ? browser : chrome;
const DEFAULT_API_BASE = "http://127.0.0.1:10209";

async function callHttpApi(type, options) {
  // Read config from storage
  const cfg = await new Promise((resolve) => {
    runtime.storage.sync.get(["apiBaseUrl", "host", "port", "protocol"], (data) => resolve(data || {}));
  });
  let baseUrl = cfg.apiBaseUrl || DEFAULT_API_BASE;
  if (cfg.host && cfg.port) {
    const proto = cfg.protocol || "http";
    const cleanHost = String(cfg.host).replace(/^https?:\/\//, "").replace(/\/+$/, "");
    baseUrl = `${proto}://${cleanHost}:${cfg.port}`;
  }
  baseUrl = baseUrl.replace(/\/+$/, "");
  let endpoint = "";
  let method = "POST";
  let body = options;

  if (type === "CREATE") {
    endpoint = `${baseUrl}/api/passkey/create`;
  } else if (type === "GET") {
    endpoint = `${baseUrl}/api/passkey/get`;
  } else if (type === "CANDIDATES") {
    endpoint = `${baseUrl}/api/passkey/candidates`;
  } else if (type === "PING" || type === "STATUS") {
    endpoint = `${baseUrl}/api/status`;
    method = "GET";
    body = undefined;
  } else if (type === "CREDENTIALS_LIST") {
    endpoint = `${baseUrl}/api/credentials`;
    method = "GET";
    body = undefined;
  } else if (type === "CREDENTIALS_DELETE") {
    const id = options && options.id ? encodeURIComponent(options.id) : "";
    endpoint = `${baseUrl}/api/credentials/${id}`;
    method = "DELETE";
    body = undefined;
  } else if (type === "EXPORT_DB") {
    endpoint = `${baseUrl}/api/database/export`;
    method = "GET";
    body = undefined;
  } else if (type === "IMPORT_DB") {
    endpoint = `${baseUrl}/api/database/import`;
    method = "POST";
    body = options;
  } else {
    throw new Error(`Unsupported API action type: ${type}`);
  }

  const fetchOptions = {
    method,
    headers: {
      "Content-Type": "application/json"
    }
  };
  if (body !== undefined) {
    fetchOptions.body = JSON.stringify(body);
  }

  const response = await fetch(endpoint, fetchOptions);

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`HTTP ${response.status}: ${errorText || response.statusText}`);
  }

  const json = await response.json();
  if (json.success === false) {
    throw new Error(json.error || "API returned failure");
  }

  // Normalize response shape: { result: ... }
  return { result: json.data !== undefined ? json.data : json };
}


// Listen to messages from content script
runtime.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    sendResponse({ error: "Invalid message payload" });
    return false;
  }
  callHttpApi(message.type, message.options)
    .then((res) => {
      console.log("[VrtFido Background] API response:", res);
      sendResponse(res);
    })
    .catch((err) => {
      console.error("[VrtFido Background] API call error:", err);
      sendResponse({ error: err.message });
    });
  return true; // Keep asynchronous sendResponse channel open
});
