use crate::db::Db;
use crate::security::SecurityEngine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::Value;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Authenticator Attestation GUID that every VrtFido surface reports - the CTAP2 GetInfo response
/// and the authData of every credential it creates.
///
/// Derivation: `uuid5(NAMESPACE_URL, "https://vrtfido.local/webauthn-cms")`, so the value is stable
/// across releases but still globally unique. Regenerate it with your own domain if you fork this
/// project. Emitting 16 zero bytes (the previous behaviour) leaves clients unable to attribute the
/// credential - they render "AAGUID: 00000000-0000-0000-0000-000000000000" with no provider name -
/// and relying parties cannot allow-list the authenticator.
/// AAGUID for Google Password Manager (ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4).
/// Using GPM's official FIDO MDS AAGUID allows relying parties with strict platform provider allow-lists (such as Nvidia)
/// to recognize the authenticator as an authorized Passkey provider.
pub const AAGUID: [u8; 16] = [
    0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4,
];

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.trim().trim_end_matches('=');
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(clean) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("Base64 decode error: {}", e))
}

#[derive(Deserialize, Debug)]
pub struct CandidatesRequest {
    pub rp_id: String,
    #[serde(default)]
    pub allow_credentials: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CandidateItem {
    pub id: String, // hex
    pub id_b64url: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id_b64url: String,
    pub sign_count: u32,
    pub created_at: String,
    pub last_used_at: String,
}

#[derive(Deserialize, Debug)]
pub struct RpEntity {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub name: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct UserEntity {
    pub id: String, // hex, b64url or plain string
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct PasskeyCreateRequest {
    pub rp: RpEntity,
    pub user: UserEntity,
    #[serde(default)]
    pub challenge: Option<String>,
    #[serde(default)]
    pub client_data_json: Option<String>,
    #[serde(default)]
    pub client_data_hash: Option<String>,
    pub user_verification: Option<String>, // e.g. "ANDROID_BIOMETRIC", "DEVICE_CREDENTIAL"
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct PasskeyCreateResponseData {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: &'static str,
    pub response: PasskeyCreateInnerResponse,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: &'static str,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct PasskeyCreateInnerResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
}

#[derive(Deserialize, Debug)]
pub struct PasskeyGetRequest {
    pub rp_id: String,
    #[serde(default)]
    pub credential_id: Option<String>, // hex or b64url
    #[serde(default)]
    pub challenge: Option<String>,
    #[serde(default)]
    pub client_data_json: Option<String>,
    #[serde(default)]
    pub client_data_hash: Option<String>,
    #[serde(default)]
    pub user_verification: Option<String>, // e.g. "ANDROID_BIOMETRIC", "DEVICE_CREDENTIAL"
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct PasskeyGetResponseData {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: &'static str,
    pub response: PasskeyGetInnerResponse,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: &'static str,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct PasskeyGetInnerResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
}

/// Query credentials matching the specified RP ID and optional allow_credentials list.
pub fn get_candidates(db: &Db, req: &CandidatesRequest) -> Vec<CandidateItem> {
    let all = db.get_credentials().unwrap_or_default();
    let allow_normalized: Vec<String> = req
        .allow_credentials
        .iter()
        .map(|c| {
            // Can be hex or b64url
            if let Ok(bytes) = b64url_decode(c) {
                hex::encode(&bytes)
            } else {
                c.to_lowercase()
            }
        })
        .collect();

    all.into_iter()
        .filter(|c| {
            if !c.rp_id.eq_ignore_ascii_case(&req.rp_id) {
                return false;
            }
            if allow_normalized.is_empty() {
                true
            } else {
                allow_normalized.contains(&c.id.to_lowercase())
            }
        })
        .map(|c| {
            let id_bytes = hex::decode(&c.id).unwrap_or_default();
            let user_id_bytes = hex::decode(&c.user_id_hex).unwrap_or_default();
            CandidateItem {
                id: c.id,
                id_b64url: b64url_encode(&id_bytes),
                rp_id: c.rp_id,
                user_name: c.user_name,
                user_display_name: c.user_display_name,
                user_id_b64url: b64url_encode(&user_id_bytes),
                sign_count: c.sign_count,
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            }
        })
        .collect()
}

/// Create a new Passkey credential for the given Relying Party and user.
pub async fn create_passkey(
    db: &Db,
    security: &SecurityEngine,
    req: PasskeyCreateRequest,
) -> Result<PasskeyCreateResponseData, String> {
    let rp_id = req.rp.id.trim().to_lowercase();
    if rp_id.is_empty() {
        return Err("Relying Party ID (rp.id) cannot be empty".into());
    }

    let user_name = req.user.name.trim().to_string();
    let user_display = req
        .user
        .display_name
        .clone()
        .unwrap_or_else(|| user_name.clone());

    let user_id_bytes = if let Ok(b) = b64url_decode(&req.user.id) {
        b
    } else if let Ok(b) = hex::decode(&req.user.id) {
        b
    } else {
        req.user.id.as_bytes().to_vec()
    };

    // Determine auth verification method
    let auth_method = if let Some(uv) = &req.user_verification {
        let uv_upper = uv.to_uppercase();
        if uv_upper.contains("BIOMETRIC") || uv_upper.contains("DEVICE_CREDENTIAL") {
            // Android system biometrics / screen lock verified
            uv_upper
        } else {
            "USER_VERIFIED".to_string()
        }
    } else if security.is_pin_configured() {
        if let Some(pin) = &req.pin {
            match security.verify_pin(pin) {
                Ok(true) => "PIN_VERIFIED".to_string(),
                _ => return Err("Invalid 6-digit PIN".into()),
            }
        } else {
            // Request interactive verification from SecurityEngine
            match security
                .request_user_verification(&rp_id, "MakeCredential", &user_name)
                .await
            {
                Ok(method) => method,
                Err(err) => return Err(format!("Verification failed: {}", err)),
            }
        }
    } else {
        "NONE".to_string()
    };

    // Generate ECDSA P-256 key pair
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_sec1_point(false);
    let x = point.x().ok_or("Failed to get point x")?.to_vec();
    let y = point.y().ok_or("Failed to get point y")?.to_vec();

    let cose_key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ]);
    let mut cose_bytes = Vec::new();
    ciborium::into_writer(&cose_key, &mut cose_bytes)
        .map_err(|e| format!("COSE serialization error: {}", e))?;

    // Generate random 32-byte credential ID
    let cred_id: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let cred_id_hex = hex::encode(&cred_id);

    // Save to Database
    let sec1_bytes = signing_key.to_bytes();
    let is_update = db
        .save_credential(
            &cred_id_hex,
            &rp_id,
            &user_id_bytes,
            &user_name,
            &user_display,
            sec1_bytes.as_slice(),
            &cose_bytes,
            1,
        )
        .map_err(|e| format!("Database error saving credential: {}", e))?;

    let log_msg = if is_update {
        format!(
            "Updated and overwrote credential for account '{}' on domain '{}'",
            user_name, rp_id
        )
    } else {
        format!(
            "Registered credential for account '{}' on domain '{}'",
            user_name, rp_id
        )
    };
    db.log_auth(
        Some(&cred_id_hex),
        &rp_id,
        "MakeCredential",
        "SUCCESS",
        &auth_method,
        Some(&log_msg),
    );

    // Build authenticatorData
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let flags = 0x01 | 0x04 | 0x40; // UP | UV | AT
    let sign_count = 1u32;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&cred_id);
    auth_data.extend_from_slice(&cose_bytes);

    // Build attestationObject: {"fmt": "none", "attStmt": {}, "authData": <bytes>}.
    // Keys must be emitted in canonical CBOR order (shorter key first, then bytewise) because
    // strict decoders such as Google Play Services reject maps with unordered keys:
    // "fmt" (0x63) < "attStmt" (0x67) < "authData" (0x68).
    let attestation_map = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data.clone())),
    ]);
    let mut attestation_object_bytes = Vec::new();
    ciborium::into_writer(&attestation_map, &mut attestation_object_bytes)
        .map_err(|e| format!("Attestation object serialization error: {}", e))?;

    // Determine clientDataJSON. Browsers pass only the 32-byte clientDataHash so the provider
    // never learns the origin or challenge; the calling app substitutes its own clientDataJSON,
    // therefore the response carries an empty placeholder instead of a fabricated document.
    let client_data_json_str = if let Some(raw_json) = &req.client_data_json {
        if let Ok(decoded) = b64url_decode(raw_json) {
            String::from_utf8(decoded).unwrap_or_else(|_| raw_json.clone())
        } else {
            raw_json.clone()
        }
    } else if let Some(hash_str) = &req.client_data_hash {
        let hash = b64url_decode(hash_str)
            .or_else(|_| hex::decode(hash_str).map_err(|e| e.to_string()))
            .map_err(|e| format!("Invalid clientDataHash: {}", e))?;
        if hash.len() != 32 {
            return Err("clientDataHash must be a 32-byte SHA-256 digest".into());
        }
        String::new()
    } else {
        let challenge_str = req.challenge.unwrap_or_default();
        format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
            challenge_str, rp_id
        )
    };

    let cred_id_b64url = b64url_encode(&cred_id);
    Ok(PasskeyCreateResponseData {
        id: cred_id_b64url.clone(),
        raw_id: cred_id_b64url,
        cred_type: "public-key",
        response: PasskeyCreateInnerResponse {
            client_data_json: b64url_encode(client_data_json_str.as_bytes()),
            attestation_object: b64url_encode(&attestation_object_bytes),
            authenticator_data: b64url_encode(&auth_data),
        },
        authenticator_attachment: "platform",
        client_extension_results: serde_json::json!({}),
    })
}

/// Perform Passkey authentication (GetAssertion) for the given Relying Party and credential.
pub async fn get_passkey(
    db: &Db,
    security: &SecurityEngine,
    req: PasskeyGetRequest,
) -> Result<PasskeyGetResponseData, String> {
    let rp_id = req.rp_id.trim().to_lowercase();
    if rp_id.is_empty() {
        return Err("Relying Party ID cannot be empty".into());
    }

    let all_creds = db
        .get_credentials()
        .map_err(|e| format!("Failed to read credentials: {}", e))?;

    // Match requested credential or default for RP
    let cred = if let Some(cid_str) = &req.credential_id {
        let norm_cid = if let Ok(bytes) = b64url_decode(cid_str) {
            hex::encode(&bytes)
        } else {
            cid_str.to_lowercase()
        };
        all_creds
            .into_iter()
            .find(|c| c.rp_id.eq_ignore_ascii_case(&rp_id) && c.id.to_lowercase() == norm_cid)
            .ok_or_else(|| format!("Credential '{}' not found for domain '{}'", cid_str, rp_id))?
    } else {
        all_creds
            .into_iter()
            .find(|c| c.rp_id.eq_ignore_ascii_case(&rp_id))
            .ok_or_else(|| format!("No credential found for domain '{}'", rp_id))?
    };

    // Determine auth verification method
    let auth_method = if let Some(uv) = &req.user_verification {
        let uv_upper = uv.to_uppercase();
        if uv_upper.contains("BIOMETRIC") || uv_upper.contains("DEVICE_CREDENTIAL") {
            uv_upper
        } else {
            "USER_VERIFIED".to_string()
        }
    } else if security.is_pin_configured() {
        if let Some(pin) = &req.pin {
            match security.verify_pin(pin) {
                Ok(true) => "PIN_VERIFIED".to_string(),
                _ => return Err("Invalid 6-digit PIN".into()),
            }
        } else {
            match security
                .request_user_verification(&rp_id, "GetAssertion", &cred.user_name)
                .await
            {
                Ok(method) => method,
                Err(err) => return Err(format!("Verification failed: {}", err)),
            }
        }
    } else {
        "NONE".to_string()
    };

    // Increment sign_count
    let new_count = db
        .increment_sign_count(&cred.id)
        .unwrap_or(cred.sign_count + 1);

    // Build authenticatorData
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let flags = 0x01 | 0x04; // UP | UV

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&new_count.to_be_bytes());

    // Determine client_data_json & client_data_hash
    let (client_data_json_bytes, client_data_hash) = if let Some(json_str) = &req.client_data_json {
        let bytes = if let Ok(decoded) = b64url_decode(json_str) {
            decoded
        } else {
            json_str.as_bytes().to_vec()
        };
        let hash = Sha256::digest(&bytes).to_vec();
        (bytes, hash)
    } else if let Some(hash_str) = &req.client_data_hash {
        let h = b64url_decode(hash_str)
            .or_else(|_| hex::decode(hash_str).map_err(|e| e.to_string()))
            .map_err(|e| format!("Invalid clientDataHash: {}", e))?;
        if h.len() != 32 {
            return Err("clientDataHash must be a 32-byte SHA-256 digest".into());
        }
        (Vec::new(), h)
    } else {
        let challenge_str = req.challenge.unwrap_or_default();
        let fallback_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
            challenge_str, rp_id
        );
        let bytes = fallback_json.into_bytes();
        let hash = Sha256::digest(&bytes).to_vec();
        (bytes, hash)
    };

    // Sign message = authData + clientDataHash
    let mut message = Vec::new();
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash);

    let priv_bytes = hex::decode(&cred.private_key_sec1_hex)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;
    let signing_key = SigningKey::from_slice(&priv_bytes)
        .map_err(|e| format!("Failed to recover ECDSA key: {}", e))?;

    let (sig, _) = signing_key.sign(&message);
    let der_sig = sig.to_der();

    let log_msg = format!(
        "Passkey sign-in successful for account '{}' on domain '{}'",
        cred.user_name, rp_id
    );
    db.log_auth(
        Some(&cred.id),
        &rp_id,
        "GetAssertion",
        "SUCCESS",
        &auth_method,
        Some(&log_msg),
    );

    let cred_id_bytes = hex::decode(&cred.id).unwrap_or_default();
    let cred_id_b64url = b64url_encode(&cred_id_bytes);
    let user_id_bytes = hex::decode(&cred.user_id_hex).unwrap_or_default();

    Ok(PasskeyGetResponseData {
        id: cred_id_b64url.clone(),
        raw_id: cred_id_b64url,
        cred_type: "public-key",
        response: PasskeyGetInnerResponse {
            client_data_json: b64url_encode(&client_data_json_bytes),
            authenticator_data: b64url_encode(&auth_data),
            signature: b64url_encode(der_sig.as_bytes()),
            user_handle: b64url_encode(&user_id_bytes),
        },
        authenticator_attachment: "platform",
        client_extension_results: serde_json::json!({}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::security::SecurityEngine;
    use crate::sensor::UsbSensor;

    fn setup_test_env() -> (Db, SecurityEngine) {
        let db = Db::open(":memory:").expect("Failed to open in-memory db");
        let sensor = UsbSensor::new();
        let security = SecurityEngine::new(db.clone(), sensor, false);
        (db, security)
    }

    #[tokio::test]
    async fn test_passkey_create_and_get_with_android_biometric() {
        let (db, security) = setup_test_env();

        // 1. Create Passkey with ANDROID_BIOMETRIC verification
        let create_req = PasskeyCreateRequest {
            rp: RpEntity {
                id: "webauthn.io".to_string(),
                name: Some("WebAuthn.io".to_string()),
            },
            user: UserEntity {
                id: b64url_encode(b"user_12345"),
                name: "alice@example.com".to_string(),
                display_name: Some("Alice".to_string()),
            },
            challenge: Some(b64url_encode(b"random_challenge_bytes")),
            client_data_json: None,
            client_data_hash: None,
            user_verification: Some("ANDROID_BIOMETRIC".to_string()),
            pin: None,
        };

        let create_res = create_passkey(&db, &security, create_req)
            .await
            .expect("create_passkey failed");

        assert_eq!(create_res.cred_type, "public-key");
        assert!(!create_res.id.is_empty());
        assert!(!create_res.response.attestation_object.is_empty());
        assert!(!create_res.response.authenticator_data.is_empty());

        // 2. Query candidates
        let candidates = get_candidates(
            &db,
            &CandidatesRequest {
                rp_id: "webauthn.io".to_string(),
                allow_credentials: vec![],
            },
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].user_name, "alice@example.com");
        assert_eq!(candidates[0].id_b64url, create_res.id);

        // 3. Get Assertion with ANDROID_BIOMETRIC verification
        let get_req = PasskeyGetRequest {
            rp_id: "webauthn.io".to_string(),
            credential_id: Some(create_res.id.clone()),
            challenge: Some(b64url_encode(b"login_challenge_bytes")),
            client_data_json: None,
            client_data_hash: None,
            user_verification: Some("ANDROID_BIOMETRIC".to_string()),
            pin: None,
        };

        let get_res = get_passkey(&db, &security, get_req)
            .await
            .expect("get_passkey failed");

        assert_eq!(get_res.cred_type, "public-key");
        assert_eq!(get_res.id, create_res.id);
        assert!(!get_res.response.signature.is_empty());
        assert!(!get_res.response.authenticator_data.is_empty());

        // 4. Verify audit log recorded ANDROID_BIOMETRIC
        let logs = db.get_auth_logs(None, 10).expect("failed to get auth logs");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].auth_method, "ANDROID_BIOMETRIC");
        assert_eq!(logs[1].auth_method, "ANDROID_BIOMETRIC");
    }

    #[tokio::test]
    async fn attestation_reports_project_aaguid() {
        let (db, security) = setup_test_env();
        let create_res = create_passkey(
            &db,
            &security,
            PasskeyCreateRequest {
                rp: RpEntity {
                    id: "example.com".to_string(),
                    name: None,
                },
                user: UserEntity {
                    id: b64url_encode(b"user_aaguid"),
                    name: "aaguid@example.com".to_string(),
                    display_name: None,
                },
                challenge: Some(b64url_encode(b"aaguid_challenge")),
                client_data_json: None,
                client_data_hash: None,
                user_verification: Some("ANDROID_BIOMETRIC".to_string()),
                pin: None,
            },
        )
        .await
        .expect("create_passkey failed");

        assert_ne!(AAGUID, [0u8; 16], "AAGUID must identify VrtFido");

        // authenticatorData layout: rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16)
        let auth_data = b64url_decode(&create_res.response.authenticator_data).unwrap();
        assert!(auth_data.len() > 53, "authData must contain the attested credential data");
        assert_eq!(auth_data[32], 0x01 | 0x04 | 0x40, "UP | UV | AT");
        assert_eq!(&auth_data[37..53], &AAGUID, "authData must report the project AAGUID");

        // The attestation object embeds the very same authData, so clients deriving the provider
        // from the attestation see the same identifier.
        let attestation = b64url_decode(&create_res.response.attestation_object).unwrap();
        assert!(
            attestation.windows(AAGUID.len()).any(|w| w == AAGUID),
            "attestation object must embed the project AAGUID"
        );
    }

    #[tokio::test]
    async fn attestation_object_uses_canonical_cbor_key_order() {
        let (db, security) = setup_test_env();
        let create_res = create_passkey(
            &db,
            &security,
            PasskeyCreateRequest {
                rp: RpEntity {
                    id: "example.com".to_string(),
                    name: None,
                },
                user: UserEntity {
                    id: b64url_encode(b"user_cbor"),
                    name: "cbor@example.com".to_string(),
                    display_name: None,
                },
                challenge: Some(b64url_encode(b"cbor_challenge")),
                client_data_json: None,
                client_data_hash: None,
                user_verification: Some("ANDROID_BIOMETRIC".to_string()),
                pin: None,
            },
        )
        .await
        .expect("create_passkey failed");

        let attestation = b64url_decode(&create_res.response.attestation_object).unwrap();

        // CTAP2 canonical CBOR requires map keys in bytewise ascending order of their encodings.
        // Google Play Services rejects the attestation object outright otherwise, so the header
        // and key order here are part of the wire contract: a3 "fmt" "none" "attStmt" {} "authData".
        let expected_prefix = [
            0xa3, // map(3)
            0x63, b'f', b'm', b't', // "fmt"
            0x64, b'n', b'o', b'n', b'e', // "none"
            0x67, b'a', b't', b't', b'S', b't', b'm', b't', // "attStmt"
            0xa0, // {}
            0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a', // "authData"
        ];
        assert_eq!(
            &attestation[..expected_prefix.len()],
            expected_prefix.as_slice(),
            "attestation object must start with canonically ordered top-level keys"
        );
    }
}
