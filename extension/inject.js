(function () {
  "use strict";

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);


  console.log("[VrtFido] Initializing passkey hook...");
  // Mock PublicKeyCredential static capability checks so websites consider this browser 100% passkey-ready
  if (typeof window.PublicKeyCredential !== "undefined") {
    // 1. isUserVerifyingPlatformAuthenticatorAvailable(): Must resolve to true for platform passkeys
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function () {
      return true;
    };

    // 2. isConditionalMediationAvailable(): Required for auto-fill / conditional UI passkey prompts
    if (typeof window.PublicKeyCredential.isConditionalMediationAvailable === "function") {
      window.PublicKeyCredential.isConditionalMediationAvailable = async function () {
        return true;
      };
    }

    // 3. getClientCapabilities(): WebAuthn Level 3 capability query
    if (typeof window.PublicKeyCredential.getClientCapabilities === "function") {
      const origCapabilities = window.PublicKeyCredential.getClientCapabilities.bind(window.PublicKeyCredential);
      window.PublicKeyCredential.getClientCapabilities = async function () {
        try {
          const caps = await origCapabilities();
          return Object.assign({}, caps, {
            conditionalCreate: true,
            conditionalGet: true,
            hybridTransport: true,
            passkeyPlatformAuthenticator: true,
            userVerifyingPlatformAuthenticator: true
          });
        } catch (_) {
          return {
            conditionalCreate: true,
            conditionalGet: true,
            hybridTransport: true,
            passkeyPlatformAuthenticator: true,
            userVerifyingPlatformAuthenticator: true
          };
        }
      };
    }
  }
  function base64UrlEncode(buffer) {
    let bytes;
    if (buffer instanceof Uint8Array) {
      bytes = buffer;
    } else if (buffer instanceof ArrayBuffer) {
      bytes = new Uint8Array(buffer);
    } else if (ArrayBuffer.isView(buffer)) {
      bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else {
      bytes = new Uint8Array(buffer);
    }
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function base64UrlDecode(str) {
    if (!str) return new ArrayBuffer(0);
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
      base64 += "=";
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function serializeValue(val) {
    if (val === null || val === undefined) return val;
    if (val instanceof ArrayBuffer) {
      return base64UrlEncode(val);
    }
    if (ArrayBuffer.isView(val)) {
      return base64UrlEncode(val.buffer);
    }
    if (Array.isArray(val)) {
      return val.map(serializeValue);
    }
    if (typeof val === "object") {
      const out = {};
      for (const k of Object.keys(val)) {
        out[k] = serializeValue(val[k]);
      }
      return out;
    }
    return val;
  }

  function sendToExt(type, options) {
    return new Promise((resolve, reject) => {
      const requestId = Math.random().toString(36).substring(2) + Date.now().toString(36);

      function handleResponse(event) {
        if (event.source !== window) return;
        if (!event.data || event.data.source !== "VRTFIDO_EXT" || event.data.requestId !== requestId) return;

        window.removeEventListener("message", handleResponse);

        if (event.data.error) {
          const isCancelled = !!event.data.isCancelled ||
            (typeof event.data.error === "string" && (
              event.data.error.toLowerCase().includes("cancel") ||
              event.data.error.toLowerCase().includes("hủy") ||
              event.data.error.toLowerCase().includes("abort")
            ));
          const err = new DOMException(event.data.error, "NotAllowedError");
          err.isUserCancelled = isCancelled;
          reject(err);
        } else {
          resolve(event.data.result);
        }
      }
      window.addEventListener("message", handleResponse);

      window.postMessage({
        source: "VRTFIDO_PAGE",
        requestId,
        type,
        options: serializeValue(options)
      }, "*");
    });
  }

  // Hook navigator.credentials.create
  navigator.credentials.create = async function (options) {
    if (options && options.publicKey) {
      console.log("[VrtFido] Intercepted navigator.credentials.create() call:", options);
      try {
        const pk = options.publicKey;
        const challengeStr = pk.challenge ? (typeof pk.challenge === "string" ? pk.challenge : base64UrlEncode(pk.challenge)) : "";
        const originStr = window.location.origin;
        const clientDataObj = {
          type: "webauthn.create",
          challenge: challengeStr,
          origin: originStr,
          crossOrigin: false
        };
        const clientDataJSONStr = JSON.stringify(clientDataObj);
        const encoder = new TextEncoder();
        const clientDataJSONBytes = encoder.encode(clientDataJSONStr);
        const hashBuffer = await crypto.subtle.digest("SHA-256", clientDataJSONBytes);
        const clientDataHashB64 = base64UrlEncode(hashBuffer);

        const res = await sendToExt("CREATE", {
          rp: {
            id: pk.rp ? pk.rp.id : window.location.hostname,
            name: pk.rp ? pk.rp.name : undefined
          },
          user: {
            id: pk.user ? (typeof pk.user.id === "string" ? pk.user.id : base64UrlEncode(pk.user.id)) : "default",
            name: pk.user ? pk.user.name : "user",
            display_name: pk.user ? pk.user.displayName : undefined
          },
          challenge: challengeStr,
          client_data_json: base64UrlEncode(clientDataJSONBytes),
          client_data_hash: clientDataHashB64,
          user_verification: pk.userVerification || "USER_VERIFIED"
        });
        console.log("[VrtFido] Native host response received:", res);
        if (res && res.result) {
          const cred = res.result;
          const rawIdBuf = base64UrlDecode(cred.rawId || cred.id);
          const clientDataBuf = base64UrlDecode(cred.response.clientDataJSON);
          const attestationBuf = base64UrlDecode(cred.response.attestationObject);

          const credentialObj = {
            id: cred.id,
            rawId: rawIdBuf,
            type: "public-key",
            authenticatorAttachment: "platform",
            response: {
              clientDataJSON: clientDataBuf,
              attestationObject: attestationBuf,
              getTransports: () => ["internal", "hybrid"],
              getAuthenticatorData: () => base64UrlDecode(cred.response.authenticatorData),
              getPublicKeyAlgorithm: () => -7
            },
            getClientExtensionResults: () => cred.clientExtensionResults || {}
          };
          console.log("[VrtFido] Returning platform credential to site:", credentialObj);
          return credentialObj;
        } else if (res && res.error) {
          console.error("[VrtFido] Native host error:", res.error);
          throw new Error(res.error);
        }
      } catch (err) {
        console.error("[VrtFido] Native passkey error details:", err);
        if (err.isUserCancelled || (err.message && (
          err.message.toLowerCase().includes("cancel") ||
          err.message.toLowerCase().includes("hủy") ||
          err.message.toLowerCase().includes("abort")
        ))) {
          throw err;
        }
      }
    }
    console.warn("[VrtFido] Falling back to original browser navigator.credentials.create()");
    return originalCreate(options);
  };
  // Hook navigator.credentials.get
  navigator.credentials.get = async function (options) {
    if (options && options.publicKey) {
      console.log("[VrtFido] Intercepted navigator.credentials.get() call:", options);
      try {
        const pk = options.publicKey;
        const allowList = (pk.allowCredentials || []).map(c => {
          return typeof c.id === "string" ? c.id : base64UrlEncode(c.id);
        });

        const challengeStr = pk.challenge ? (typeof pk.challenge === "string" ? pk.challenge : base64UrlEncode(pk.challenge)) : "";
        const originStr = window.location.origin;
        const clientDataObj = {
          type: "webauthn.get",
          challenge: challengeStr,
          origin: originStr,
          crossOrigin: false
        };
        const clientDataJSONStr = JSON.stringify(clientDataObj);
        const encoder = new TextEncoder();
        const clientDataJSONBytes = encoder.encode(clientDataJSONStr);
        const hashBuffer = await crypto.subtle.digest("SHA-256", clientDataJSONBytes);
        const clientDataHashB64 = base64UrlEncode(hashBuffer);

        const res = await sendToExt("GET", {
          rp_id: pk.rpId || window.location.hostname,
          credential_id: allowList.length > 0 ? allowList[0] : undefined,
          allow_credentials: allowList,
          challenge: challengeStr,
          client_data_json: base64UrlEncode(clientDataJSONBytes),
          client_data_hash: clientDataHashB64,
          user_verification: pk.userVerification || "USER_VERIFIED"
        });
        if (res && res.result) {
          const ass = res.result;
          const rawIdBuf = base64UrlDecode(ass.rawId || ass.id);
          const clientDataBuf = base64UrlDecode(ass.response.clientDataJSON);
          const authDataBuf = base64UrlDecode(ass.response.authenticatorData);
          const sigBuf = base64UrlDecode(ass.response.signature);
          const userHandleBuf = ass.response.userHandle ? base64UrlDecode(ass.response.userHandle) : null;

          return {
            id: ass.id,
            rawId: rawIdBuf,
            type: "public-key",
            authenticatorAttachment: "platform",
            response: {
              clientDataJSON: clientDataBuf,
              authenticatorData: authDataBuf,
              signature: sigBuf,
              userHandle: userHandleBuf
            },
            getClientExtensionResults: () => ass.clientExtensionResults || {}
          };
        }
      } catch (err) {
        console.warn("[VrtFido] Native assertion error:", err);
        if (err.isUserCancelled || (err.message && (
          err.message.toLowerCase().includes("cancel") ||
          err.message.toLowerCase().includes("hủy") ||
          err.message.toLowerCase().includes("abort")
        ))) {
          throw err;
        }
      }
    }
    return originalGet(options);
  };
  console.log("[VrtFido] Platform Passkey Authenticator injected successfully.");
})();
