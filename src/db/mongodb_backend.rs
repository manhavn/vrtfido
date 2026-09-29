//! MongoDB backend.
//!
//! Mirrors the SQL backends at the [`DbBackend`] trait boundary: collections named after the SQL
//! tables hold JSON-shaped documents with the same field names. The primary keys in the
//! relational backends (`credentials.id` as hex string, `auth_logs.id` / `debug_logs.id` /
//! `fingerprints.id` as autoincrement ints) are preserved as MongoDB `_id`: same values, same names,
//! so JSON exports move between SQL and MongoDB backends without translation.
//!
//! All driver calls are async; the backend owns a dedicated single-thread tokio runtime on a
//! worker thread (same pattern as the LibSQL backend) so the rest of `Db` stays on the existing
//! synchronous trait surface.

use super::{
    AuthLogRow, CredentialRow, DbBackend, DbError, DebugLogRow, FingerprintRow,
    SecuritySettingsData,
};
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::bson as bson;
use mongodb::options::{ClientOptions, CollationStrength};
use mongodb::{Client, Collection};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

const COLL_CREDENTIALS: &str = "credentials";
const COLL_AUTH_LOGS: &str = "auth_logs";
const COLL_SECURITY: &str = "security_settings";
const COLL_FINGERPRINTS: &str = "fingerprints";
const COLL_APP_SETTINGS: &str = "app_settings";
const COLL_DEBUG_LOGS: &str = "debug_logs";

const SECURITY_SINGLETON_ID: &str = "vrtfido_singleton";

struct AsyncWorker {
    sender: mpsc::Sender<Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>>,
}

impl AsyncWorker {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>>();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[MongoDB] Failed to create dedicated tokio runtime: {e}");
                    return;
                }
            };
            while let Ok(job) = rx.recv() {
                job(&rt);
            }
        });
        Self { sender: tx }
    }

    fn run<R: Send + 'static, F: FnOnce(&tokio::runtime::Runtime) -> R + Send + 'static>(&self, f: F) -> R {
        let (res_tx, res_rx) = mpsc::channel();
        let _ = self.sender.send(Box::new(move |rt| {
            let r = f(rt);
            let _ = res_tx.send(r);
        }));
        res_rx
            .recv()
            .expect("MongoDB worker thread panicked or dropped channel")
    }
}

fn mongo_err<E: std::fmt::Display>(e: E) -> DbError {
    DbError::MongoDb(e.to_string())
}

fn bson_to_hex(v: Option<&Bson>) -> String {
    match v {
        Some(Bson::Binary(b)) => hex::encode(&b.bytes),
        Some(Bson::String(s)) => s.clone(),
        // Legacy / non-binary MongoDB documents produced outside this crate could store bytes as
        // an array; serialize it back to hex so the rest of the app keeps a uniform shape.
        Some(Bson::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Bson::Int32(n) => out.push(*n as u8),
                    Bson::Int64(n) => out.push(*n as u8),
                    Bson::Double(n) => out.push(*n as u8),
                    _ => {}
                }
            }
            hex::encode(out)
        }
        _ => String::new(),
    }
}

fn bson_to_optional_string(v: Option<&Bson>) -> Option<String> {
    match v {
        Some(Bson::String(s)) => Some(s.clone()),
        Some(Bson::Null) | None => None,
        _ => None,
    }
}

fn bson_to_i64(v: Option<&Bson>) -> i64 {
    match v {
        Some(Bson::Int64(n)) => *n,
        Some(Bson::Int32(n)) => *n as i64,
        Some(Bson::Double(n)) => *n as i64,
        _ => 0,
    }
}

pub struct MongoBackend {
    worker: Arc<AsyncWorker>,
    client: Arc<Client>,
    db_name: String,
}

impl MongoBackend {
    pub fn open(url: &str) -> Result<Self, DbError> {
        let worker = Arc::new(AsyncWorker::new());
        let url_owned = url.to_string();

        let (client, db_name) = worker.run(move |rt| {
            rt.block_on(async move {
                let mut opts = ClientOptions::parse(&url_owned).await.map_err(mongo_err)?;
                opts.app_name = Some("VrtFido".to_string());
                opts.connect_timeout = Some(Duration::from_secs(10));
                opts.server_selection_timeout = Some(Duration::from_secs(10));

                let client = Client::with_options(opts).map_err(mongo_err)?;
                // Ping so a wrong URL fails at open() instead of on the first write.
                client
                    .database("admin")
                    .run_command(doc! { "ping": 1 })
                    .await
                    .map_err(mongo_err)?;

                let db_name = client
                    .default_database()
                    .map(|d| d.name().to_string())
                    .ok_or_else(|| {
                        DbError::Config(
                            "MongoDB URL must include a database name (e.g. mongodb://host:27017/vrtfido)"
                                .into(),
                        )
                    })?;

                let database = client.database(&db_name);

                // Mirror the SQL backends: credentials is queried by rp_id+user_name; the rest
                // look up by _id only (already unique by definition).
                let _ = database
                    .collection::<Document>(COLL_CREDENTIALS)
                    .create_index(
                        mongodb::IndexModel::builder()
                            .keys(doc! { "rp_id": 1, "user_name": 1 })
                            .build(),
                    )
                    .await;

                // Seed singleton security settings if absent.
                let sec_col: Collection<Document> = database.collection(COLL_SECURITY);
                let existing = sec_col
                    .find_one(doc! { "_id": SECURITY_SINGLETON_ID })
                    .await
                    .map_err(mongo_err)?;
                if existing.is_none() {
                    let seed = doc! {
                        "_id": SECURITY_SINGLETON_ID,
                        "pin_hash": Bson::Null,
                        "pin_salt": Bson::Null,
                        "pin_enabled": false,
                        "fp_enabled": true,
                        "require_uv": true,
                        "updated_at": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    };
                    sec_col.insert_one(seed).await.map_err(mongo_err)?;
                }

                Ok::<(Arc<Client>, String), DbError>((Arc::new(client), db_name))
            })
        })?;

        Ok(Self {
            worker,
            client,
            db_name,
        })
    }
}

fn credential_to_doc(c: &CredentialRow) -> Document {
    doc! {
        "_id": &c.id,
        "rp_id": &c.rp_id,
        "user_id": Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: hex::decode(&c.user_id_hex).unwrap_or_default(),
        }),
        "user_name": &c.user_name,
        "user_display_name": &c.user_display_name,
        "private_key_sec1": Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: hex::decode(&c.private_key_sec1_hex).unwrap_or_default(),
        }),
        "public_key_cose": Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: hex::decode(&c.public_key_cose_hex).unwrap_or_default(),
        }),
        "sign_count": c.sign_count as i64,
        "created_at": &c.created_at,
        "last_used_at": &c.last_used_at,
    }
}

fn doc_to_credential(d: &Document) -> Result<CredentialRow, DbError> {
    let id = d.get_str("_id").map_err(mongo_err)?.to_string();
    let rp_id = d.get_str("rp_id").map_err(mongo_err)?.to_string();
    let user_name = d.get_str("user_name").map_err(mongo_err)?.to_string();
    let user_display_name = d.get_str("user_display_name").map_err(mongo_err)?.to_string();
    let created_at = d.get_str("created_at").map_err(mongo_err)?.to_string();
    let last_used_at = d.get_str("last_used_at").map_err(mongo_err)?.to_string();

    Ok(CredentialRow {
        id,
        rp_id,
        user_id_hex: bson_to_hex(d.get("user_id")),
        user_name,
        user_display_name,
        private_key_sec1_hex: bson_to_hex(d.get("private_key_sec1")),
        public_key_cose_hex: bson_to_hex(d.get("public_key_cose")),
        sign_count: bson_to_i64(d.get("sign_count")) as u32,
        created_at,
        last_used_at,
    })
}

fn auth_log_to_doc(log: &AuthLogRow) -> Document {
    doc! {
        "_id": log.id,
        "id": log.id,
        "credential_id": log.credential_id.clone().map(Bson::String).unwrap_or(Bson::Null),
        "rp_id": &log.rp_id,
        "operation": &log.operation,
        "status": &log.status,
        "auth_method": &log.auth_method,
        "details": log.details.clone().map(Bson::String).unwrap_or(Bson::Null),
        "created_at": &log.created_at,
    }
}

fn doc_to_auth_log(d: &Document) -> Result<AuthLogRow, DbError> {
    Ok(AuthLogRow {
        id: bson_to_i64(d.get("_id")),
        credential_id: bson_to_optional_string(d.get("credential_id")),
        rp_id: d.get_str("rp_id").map_err(mongo_err)?.to_string(),
        operation: d.get_str("operation").map_err(mongo_err)?.to_string(),
        status: d.get_str("status").map_err(mongo_err)?.to_string(),
        auth_method: d.get_str("auth_method").map_err(mongo_err)?.to_string(),
        details: bson_to_optional_string(d.get("details")),
        created_at: d.get_str("created_at").map_err(mongo_err)?.to_string(),
    })
}

fn debug_log_to_doc(log: &DebugLogRow) -> Document {
    doc! {
        "_id": log.id,
        "id": log.id,
        "level": &log.level,
        "component": &log.component,
        "message": &log.message,
        "created_at": &log.created_at,
    }
}

fn doc_to_debug_log(d: &Document) -> Result<DebugLogRow, DbError> {
    Ok(DebugLogRow {
        id: bson_to_i64(d.get("_id")),
        level: d.get_str("level").map_err(mongo_err)?.to_string(),
        component: d.get_str("component").map_err(mongo_err)?.to_string(),
        message: d.get_str("message").map_err(mongo_err)?.to_string(),
        created_at: d.get_str("created_at").map_err(mongo_err)?.to_string(),
    })
}

fn fingerprint_to_doc(fp: &FingerprintRow) -> Document {
    doc! {
        "_id": fp.id,
        "id": fp.id,
        "slot_index": fp.slot_index as i64,
        "name": &fp.name,
        "enrolled_at": &fp.enrolled_at,
    }
}

fn doc_to_fingerprint(d: &Document) -> Result<FingerprintRow, DbError> {
    Ok(FingerprintRow {
        id: bson_to_i64(d.get("_id")),
        slot_index: bson_to_i64(d.get("slot_index")) as u32,
        name: d.get_str("name").map_err(mongo_err)?.to_string(),
        enrolled_at: d.get_str("enrolled_at").map_err(mongo_err)?.to_string(),
    })
}

impl DbBackend for MongoBackend {
    fn backend_name(&self) -> &'static str {
        "MongoDB"
    }

    fn log_debug(&self, level: &str, component: &str, message: &str, now: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let level = level.to_string();
        let component = component.to_string();
        let message = message.to_string();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_DEBUG_LOGS);
                let _ = col
                    .insert_one(debug_log_to_doc(&DebugLogRow {
                        id: 0, // autogen ObjectId – overwritten below
                        level: level.clone(),
                        component: component.clone(),
                        message: message.clone(),
                        created_at: now.clone(),
                    }))
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn log_auth(
        &self,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
        now: &str,
    ) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let cid = credential_id.map(|s| s.to_string());
        let rp_id = rp_id.to_string();
        let operation = operation.to_string();
        let status = status.to_string();
        let auth_method = auth_method.to_string();
        let details = details.map(|s| s.to_string());
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_AUTH_LOGS);
                // Log writes don't need a stable id; let MongoDB assign an ObjectId per insert
                // and copy it back onto the document so we can recover it from the steady state.
                let mut doc = doc! {
                    "credential_id": cid.clone().map(Bson::String).unwrap_or(Bson::Null),
                    "rp_id": &rp_id,
                    "operation": &operation,
                    "status": &status,
                    "auth_method": &auth_method,
                    "details": details.clone().map(Bson::String).unwrap_or(Bson::Null),
                    "created_at": &now,
                };
                let res = col.insert_one(&doc).await.map_err(mongo_err)?;
                let inserted_id = res.inserted_id;
                doc.insert("_id", inserted_id.clone());
                doc.insert("id", inserted_id);
                Ok(())
            })
        })
    }

    fn get_app_settings(&self) -> Result<Vec<(String, String)>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_APP_SETTINGS);
                let mut cursor = col.find(doc! {}).await.map_err(mongo_err)?;
                let mut out = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    let key = d.get_str("_id").map_err(mongo_err)?.to_string();
                    let value = match d.get("value") {
                        Some(Bson::String(s)) => s.clone(),
                        Some(Bson::Null) | None => String::new(),
                        Some(other) => other.to_string(),
                    };
                    out.push((key, value));
                }
                out.sort();
                Ok(out)
            })
        })
    }

    fn set_app_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let key = key.to_string();
        let value = value.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_APP_SETTINGS);
                col.replace_one(doc! { "_id": &key }, doc! { "_id": &key, "value": &value })
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn get_credentials(&self) -> Result<Vec<CredentialRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                // Match the SQL backends' ordering: most recently used first.
                let mut cursor = col
                    .find(doc! {})
                    .sort(doc! { "last_used_at": -1 })
                    .await
                    .map_err(mongo_err)?;
                let mut list = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    list.push(doc_to_credential(&d)?);
                }
                Ok(list)
            })
        })
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let id = id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                let res = col.find_one(doc! { "_id": &id }).await.map_err(mongo_err)?;
                Ok(res.map(|d| doc_to_credential(&d)).transpose()?)
            })
        })
    }

    fn get_credentials_for_rp(
        &self,
        rp_id: &str,
    ) -> Result<Vec<(String, Vec<u8>, String, String)>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let rp_id = rp_id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                // MongoDB collation strength 2 = ignore case on the rp_id term.
                let mut cursor = col
                    .find(doc! { "rp_id": &rp_id })
                    .collation(
                        mongodb::options::Collation::builder()
                            .locale("en")
                            .strength(CollationStrength::Secondary)
                            .build(),
                    )
                    .await
                    .map_err(mongo_err)?;
                let mut list = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    let id = d.get_str("_id").map_err(mongo_err)?.to_string();
                    let user_id = bson_to_hex(d.get("user_id"));
                    let user_id_bytes = hex::decode(&user_id).unwrap_or_default();
                    let user_name = d
                        .get_str("user_name")
                        .map_err(mongo_err)?
                        .to_string();
                    let created_at = d
                        .get_str("created_at")
                        .map_err(mongo_err)?
                        .to_string();
                    list.push((id, user_id_bytes, user_name, created_at));
                }
                Ok(list)
            })
        })
    }

    fn delete_credential(&self, id: &str) -> Result<bool, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let id = id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                let res = col
                    .delete_one(doc! { "_id": &id })
                    .await
                    .map_err(mongo_err)?;
                Ok(res.deleted_count > 0)
            })
        })
    }

    fn update_credential_name(&self, id: &str, name: &str, display_name: &str) -> Result<bool, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let id = id.to_string();
        let name = name.to_string();
        let display_name = display_name.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                let res = col
                    .update_one(
                        doc! { "_id": &id },
                        doc! { "$set": { "user_name": &name, "user_display_name": &display_name } },
                    )
                    .await
                    .map_err(mongo_err)?;
                Ok(res.modified_count > 0)
            })
        })
    }

    fn update_auth_log_credential_id(&self, old_id: &str, new_id: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let old_id = old_id.to_string();
        let new_id = new_id.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_AUTH_LOGS);
                let _ = col
                    .update_many(
                        doc! { "credential_id": &old_id },
                        doc! { "$set": { "credential_id": &new_id } },
                    )
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn insert_credential(
        &self,
        id_hex: &str,
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        private_key_sec1: &[u8],
        public_key_cose: &[u8],
        sign_count: u32,
        created_at: &str,
        last_used_at: &str,
    ) -> Result<(), DbError> {
        let row = CredentialRow {
            id: id_hex.to_string(),
            rp_id: rp_id.to_string(),
            user_id_hex: hex::encode(user_id),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            private_key_sec1_hex: hex::encode(private_key_sec1),
            public_key_cose_hex: hex::encode(public_key_cose),
            sign_count,
            created_at: created_at.to_string(),
            last_used_at: last_used_at.to_string(),
        };
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                col.replace_one(doc! { "_id": &row.id }, credential_to_doc(&row))
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn increment_sign_count(&self, id: &str, now: &str) -> Result<u32, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let id = id.to_string();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_CREDENTIALS);
                let res = col
                    .find_one_and_update(
                        doc! { "_id": &id },
                        doc! { "$inc": { "sign_count": 1_i64 }, "$set": { "last_used_at": &now } },
                    )
                    .return_document(mongodb::options::ReturnDocument::After)
                    .await
                    .map_err(mongo_err)?;
                match res {
                    Some(d) => Ok(bson_to_i64(d.get("sign_count")) as u32),
                    None => Err(DbError::MongoDb("Credential not found".into())),
                }
            })
        })
    }

    fn get_auth_logs(&self, credential_id: Option<&str>, limit: usize) -> Result<Vec<AuthLogRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let cid = credential_id.map(|s| s.to_string());
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_AUTH_LOGS);
                let filter = match cid.as_deref() {
                    Some(c) => doc! { "credential_id": c },
                    None => doc! {},
                };
                let mut cursor = col
                    .find(filter)
                    .sort(doc! { "_id": -1 })
                    .limit(limit as i64)
                    .await
                    .map_err(mongo_err)?;
                let mut list = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    list.push(doc_to_auth_log(&d)?);
                }
                Ok(list)
            })
        })
    }

    fn get_debug_logs(&self, limit: usize) -> Result<Vec<DebugLogRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_DEBUG_LOGS);
                let mut cursor = col
                    .find(doc! {})
                    .sort(doc! { "_id": -1 })
                    .limit(limit as i64)
                    .await
                    .map_err(mongo_err)?;
                let mut list = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    list.push(doc_to_debug_log(&d)?);
                }
                Ok(list)
            })
        })
    }

    fn clear_auth_logs(&self) -> Result<usize, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_AUTH_LOGS);
                let res = col.delete_many(doc! {}).await.map_err(mongo_err)?;
                Ok(res.deleted_count as usize)
            })
        })
    }

    fn clear_debug_logs(&self) -> Result<usize, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_DEBUG_LOGS);
                let res = col.delete_many(doc! {}).await.map_err(mongo_err)?;
                Ok(res.deleted_count as usize)
            })
        })
    }

    fn get_security_settings_raw(&self) -> Result<SecuritySettingsData, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_SECURITY);
                let res = col
                    .find_one(doc! { "_id": SECURITY_SINGLETON_ID })
                    .await
                    .map_err(mongo_err)?;
                match res {
                    Some(d) => {
                        let pin_hash = bson_to_optional_string(d.get("pin_hash"));
                        let pin_salt = bson_to_optional_string(d.get("pin_salt"));
                        let pin_enabled = matches!(d.get("pin_enabled"), Some(Bson::Boolean(true)));
                        let fp_enabled =
                            matches!(d.get("fp_enabled"), Some(Bson::Boolean(true)));
                        let require_uv = matches!(
                            d.get("require_uv"),
                            Some(Bson::Boolean(true)) | None
                        );
                        let updated_at = d
                            .get_str("updated_at")
                            .map_err(mongo_err)?
                            .to_string();
                        Ok(SecuritySettingsData {
                            pin_hash,
                            pin_salt,
                            pin_enabled,
                            fp_enabled,
                            require_uv,
                            updated_at,
                        })
                    }
                    None => {
                        // Should not happen (open() seeds it), but stay defensive.
                        Ok(SecuritySettingsData {
                            pin_hash: None,
                            pin_salt: None,
                            pin_enabled: false,
                            fp_enabled: true,
                            require_uv: true,
                            updated_at: chrono::Utc::now()
                                .format("%Y-%m-%d %H:%M:%S")
                                .to_string(),
                        })
                    }
                }
            })
        })
    }

    fn get_fingerprint_count(&self) -> Result<usize, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                let res = col.count_documents(doc! {}).await.map_err(mongo_err)?;
                Ok(res as usize)
            })
        })
    }

    fn set_pin(&self, pin_hash: &str, pin_salt: &str, now: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let pin_hash = pin_hash.to_string();
        let pin_salt = pin_salt.to_string();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_SECURITY);
                col.update_one(
                    doc! { "_id": SECURITY_SINGLETON_ID },
                    doc! { "$set": {
                        "pin_hash": &pin_hash,
                        "pin_salt": &pin_salt,
                        "pin_enabled": true,
                        "updated_at": &now,
                    } },
                )
                .upsert(true)
                .await
                .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn remove_pin(&self, now: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_SECURITY);
                col.update_one(
                    doc! { "_id": SECURITY_SINGLETON_ID },
                    doc! {
                        "$set": {
                            "pin_enabled": false,
                            "updated_at": &now,
                        },
                        "$unset": {
                            "pin_hash": "",
                            "pin_salt": "",
                        },
                    },
                )
                .upsert(true)
                .await
                .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn set_require_uv(&self, require: bool, now: &str) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let now = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_SECURITY);
                col.update_one(
                    doc! { "_id": SECURITY_SINGLETON_ID },
                    doc! { "$set": { "require_uv": require, "updated_at": &now } },
                )
                .upsert(true)
                .await
                .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn set_security_settings_all(&self, settings: &SecuritySettingsData) -> Result<(), DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let settings = settings.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_SECURITY);
                let update = doc! { "$set": {
                    "pin_hash": settings.pin_hash.clone().map(Bson::String).unwrap_or(Bson::Null),
                    "pin_salt": settings.pin_salt.clone().map(Bson::String).unwrap_or(Bson::Null),
                    "pin_enabled": settings.pin_enabled,
                    "fp_enabled": settings.fp_enabled,
                    "require_uv": settings.require_uv,
                    "updated_at": &settings.updated_at,
                } };
                col.update_one(doc! { "_id": SECURITY_SINGLETON_ID }, update)
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn get_fingerprints(&self) -> Result<Vec<FingerprintRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                let mut cursor = col
                    .find(doc! {})
                    .sort(doc! { "slot_index": 1 })
                    .await
                    .map_err(mongo_err)?;
                let mut list = Vec::new();
                while cursor.advance().await.map_err(mongo_err)? {
                    let d = cursor.deserialize_current().map_err(mongo_err)?;
                    list.push(doc_to_fingerprint(&d)?);
                }
                Ok(list)
            })
        })
    }

    fn get_fingerprint_by_id(&self, id: i64) -> Result<Option<FingerprintRow>, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                let res = col.find_one(doc! { "_id": id }).await.map_err(mongo_err)?;
                Ok(res.map(|d| doc_to_fingerprint(&d)).transpose()?)
            })
        })
    }

    fn add_fingerprint(&self, slot_index: u32, name: &str, now: &str) -> Result<FingerprintRow, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        let slot = slot_index as i64;
        let name_owned = name.to_string();
        let now_owned = now.to_string();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                // Match SQL backends: `slot_index` is unique, so re-enrolling on the same slot
                // updates the existing record (new ObjectId, preserved on lookup by slot_index).
                let existing = col
                    .find_one(doc! { "slot_index": slot })
                    .await
                    .map_err(mongo_err)?;
                let fp_doc = match &existing {
                    Some(d) => {
                        let mut next = d.clone();
                        next.insert("name", &name_owned);
                        next.insert("enrolled_at", &now_owned);
                        next
                    }
                    None => doc! {
                        "slot_index": slot,
                        "name": &name_owned,
                        "enrolled_at": &now_owned,
                    },
                };
                let filter = match &existing {
                    Some(d) => doc! { "_id": d.get_object_id("_id").map_err(mongo_err)? },
                    None => doc! { "slot_index": slot },
                };
                col.replace_one(filter, &fp_doc)
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                let res = col
                    .find_one(doc! { "slot_index": slot })
                    .await
                    .map_err(mongo_err)?;
                let stored = res.ok_or_else(|| {
                    DbError::MongoDb("Just-inserted fingerprint not visible".into())
                })?;
                let id = match stored.get("_id") {
                    Some(Bson::ObjectId(o)) => o.timestamp().timestamp_millis(),
                    Some(Bson::Int64(n)) => *n,
                    Some(Bson::Int32(n)) => *n as i64,
                    _ => 0,
                };
                Ok(FingerprintRow {
                    id,
                    slot_index,
                    name: name_owned,
                    enrolled_at: now_owned,
                })
            })
        })
    }

    fn delete_fingerprint(&self, id: i64) -> Result<bool, DbError> {
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                let res = col
                    .delete_one(doc! { "_id": id })
                    .await
                    .map_err(mongo_err)?;
                Ok(res.deleted_count > 0)
            })
        })
    }

    fn insert_fingerprint_full(
        &self,
        id: i64,
        slot_index: u32,
        name: &str,
        enrolled_at: &str,
    ) -> Result<(), DbError> {
        let row = FingerprintRow {
            id,
            slot_index,
            name: name.to_string(),
            enrolled_at: enrolled_at.to_string(),
        };
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_FINGERPRINTS);
                col.replace_one(doc! { "_id": row.id }, fingerprint_to_doc(&row))
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn insert_auth_log_full(
        &self,
        id: i64,
        credential_id: Option<&str>,
        rp_id: &str,
        operation: &str,
        status: &str,
        auth_method: &str,
        details: Option<&str>,
        created_at: &str,
    ) -> Result<(), DbError> {
        let row = AuthLogRow {
            id,
            credential_id: credential_id.map(|s| s.to_string()),
            rp_id: rp_id.to_string(),
            operation: operation.to_string(),
            status: status.to_string(),
            auth_method: auth_method.to_string(),
            details: details.map(|s| s.to_string()),
            created_at: created_at.to_string(),
        };
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_AUTH_LOGS);
                col.replace_one(doc! { "_id": row.id }, auth_log_to_doc(&row))
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }

    fn insert_debug_log_full(
        &self,
        id: i64,
        level: &str,
        component: &str,
        message: &str,
        created_at: &str,
    ) -> Result<(), DbError> {
        let row = DebugLogRow {
            id,
            level: level.to_string(),
            component: component.to_string(),
            message: message.to_string(),
            created_at: created_at.to_string(),
        };
        let client = self.client.clone();
        let db_name = self.db_name.clone();
        self.worker.run(move |rt| {
            rt.block_on(async move {
                let col: Collection<Document> = client.database(&db_name).collection(COLL_DEBUG_LOGS);
                col.replace_one(doc! { "_id": row.id }, debug_log_to_doc(&row))
                    .upsert(true)
                    .await
                    .map_err(mongo_err)?;
                Ok(())
            })
        })
    }
}

// Touch the unused import path so the compiler doesn't drop the `bson::oid` re-export; this also
// reserves the unused slot for a future typed ObjectId migration of the auth-log _id column.
#[allow(dead_code)]
fn _oid_for_symmetry() -> ObjectId {
    ObjectId::new()
}
