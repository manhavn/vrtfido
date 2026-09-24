package com.vrtfido

import android.content.Context
import android.net.Uri
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import okio.source
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

data class CandidateAccount(
    val idHex: String,
    val idB64Url: String,
    val rpId: String,
    val userName: String,
    val userDisplayName: String,
    val userIdB64Url: String
)

object VrtfidoClient {
    private fun baseUrl(context: Context) = ServerSettings.load(context).localUrl
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    fun isRunning(context: Context): Boolean {
        return try {
            val req = Request.Builder().url("${baseUrl(context)}/api/status").get().build()
            client.newCall(req).execute().use { resp ->
                resp.isSuccessful
            }
        } catch (_: Exception) {
            false
        }
    }

    fun getCandidates(context: Context, rpId: String, allowCredentials: List<String> = emptyList()): List<CandidateAccount> {
        val json = JSONObject().apply {
            put("rp_id", rpId)
            val arr = JSONArray()
            allowCredentials.forEach { arr.put(it) }
            put("allow_credentials", arr)
        }

        val req = Request.Builder()
            .url("${baseUrl(context)}/api/passkey/candidates")
            .post(json.toString().toRequestBody(JSON_MEDIA))
            .build()

        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return emptyList()
                val bodyStr = resp.body?.string() ?: return emptyList()
                val root = JSONObject(bodyStr)
                if (!root.optBoolean("success", false)) return emptyList()

                val dataArr = root.optJSONArray("data") ?: return emptyList()
                val list = mutableListOf<CandidateAccount>()
                for (i in 0 until dataArr.length()) {
                    val obj = dataArr.getJSONObject(i)
                    list.add(
                        CandidateAccount(
                            idHex = obj.getString("id"),
                            idB64Url = obj.getString("id_b64url"),
                            rpId = obj.getString("rp_id"),
                            userName = obj.getString("user_name"),
                            userDisplayName = obj.optString("user_display_name", obj.getString("user_name")),
                            userIdB64Url = obj.optString("user_id_b64url", "")
                        )
                    )
                }
                list
            }
        } catch (e: Exception) {
            e.printStackTrace()
            emptyList()
        }
    }

    fun createPasskey(
        context: Context,
        rpId: String,
        rpName: String?,
        userIdB64: String,
        userName: String,
        userDisplayName: String?,
        challengeB64: String?,
        clientDataJsonB64: String?,
        clientDataHashB64: String?,
        userVerification: String = "ANDROID_BIOMETRIC"
    ): JSONObject? {
        val root = JSONObject().apply {
            put("rp", JSONObject().apply {
                put("id", rpId)
                if (!rpName.isNullOrEmpty()) put("name", rpName)
            })
            put("user", JSONObject().apply {
                put("id", userIdB64)
                put("name", userName)
                if (!userDisplayName.isNullOrEmpty()) put("display_name", userDisplayName)
            })
            if (!challengeB64.isNullOrEmpty()) put("challenge", challengeB64)
            if (!clientDataJsonB64.isNullOrEmpty()) put("client_data_json", clientDataJsonB64)
            if (!clientDataHashB64.isNullOrEmpty()) put("client_data_hash", clientDataHashB64)
            put("user_verification", userVerification)
        }

        val req = Request.Builder()
            .url("${baseUrl(context)}/api/passkey/create")
            .post(root.toString().toRequestBody(JSON_MEDIA))
            .build()

        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val bodyStr = resp.body?.string() ?: return null
                val resObj = JSONObject(bodyStr)
                if (resObj.optBoolean("success", false)) {
                    resObj.optJSONObject("data")
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun getPasskey(
        context: Context,
        rpId: String,
        credentialId: String?,
        challengeB64: String?,
        clientDataJsonB64: String?,
        clientDataHashB64: String?,
        userVerification: String = "ANDROID_BIOMETRIC"
    ): JSONObject? {
        val root = JSONObject().apply {
            put("rp_id", rpId)
            if (!credentialId.isNullOrEmpty()) put("credential_id", credentialId)
            if (!challengeB64.isNullOrEmpty()) put("challenge", challengeB64)
            if (!clientDataJsonB64.isNullOrEmpty()) put("client_data_json", clientDataJsonB64)
            if (!clientDataHashB64.isNullOrEmpty()) put("client_data_hash", clientDataHashB64)
            put("user_verification", userVerification)
        }

        val req = Request.Builder()
            .url("${baseUrl(context)}/api/passkey/get")
            .post(root.toString().toRequestBody(JSON_MEDIA))
            .build()

        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val bodyStr = resp.body?.string() ?: return null
                val resObj = JSONObject(bodyStr)
                if (resObj.optBoolean("success", false)) {
                    resObj.optJSONObject("data")
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Writes a full database backup to [target] in the same shape the desktop CLI writes with
     * `--export`, so the file can be moved between Android and Ubuntu in both directions.
     */
    fun exportDatabase(context: Context, target: Uri) {
        val req = Request.Builder().url("${baseUrl(context)}/api/database/export").get().build()
        client.newCall(req).execute().use { resp ->
            val body = resp.body?.string()
            if (!resp.isSuccessful || body.isNullOrEmpty()) {
                throw IllegalStateException("HTTP ${resp.code}")
            }
            val root = JSONObject(body)
            if (!root.optBoolean("success", false)) {
                throw IllegalStateException(root.optString("error", "HTTP ${resp.code}"))
            }
            val data = root.optJSONObject("data")
                ?: throw IllegalStateException("missing export payload")

            val stream = context.contentResolver.openOutputStream(target)
                ?: throw IllegalStateException("cannot open destination file")
            stream.bufferedWriter().use { it.write(data.toString(2)) }
        }
    }

    /**
     * Imports a backup file produced either by this screen or by the desktop CLI `--export`.
     * The payload is streamed straight from [source] so large backups are never buffered twice.
     */
    fun importDatabase(context: Context, source: Uri): ImportResult {
        val request = Request.Builder()
            .url("${baseUrl(context)}/api/database/import")
            .post(UriRequestBody(context, source, JSON_MEDIA))
            .build()

        client.newCall(request).execute().use { resp ->
            val body = resp.body?.string()
            if (!resp.isSuccessful || body.isNullOrEmpty()) {
                throw IllegalStateException("HTTP ${resp.code}")
            }
            val root = JSONObject(body)
            if (!root.optBoolean("success", false)) {
                throw IllegalStateException(root.optString("error", "HTTP ${resp.code}"))
            }
            val data = root.optJSONObject("data") ?: JSONObject()
            return ImportResult(
                credentials = data.optInt("credentials_imported"),
                fingerprints = data.optInt("fingerprints_imported"),
                authLogs = data.optInt("auth_logs_imported")
            )
        }
    }

    /** Streams a content-provider file as an HTTP request body. */
    private class UriRequestBody(
        private val context: Context,
        private val uri: Uri,
        private val mediaType: MediaType?
    ) : RequestBody() {
        override fun contentType(): MediaType? = mediaType
        override fun contentLength(): Long = -1L
        override fun writeTo(sink: BufferedSink) {
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IOException("cannot read selected file")
            input.use { sink.writeAll(it.source()) }
        }
    }
}

data class ImportResult(
    val credentials: Int,
    val fingerprints: Int,
    val authLogs: Int
)
