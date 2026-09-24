package com.vrtfido

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
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
    private const val BASE_URL = "http://127.0.0.1:10209"
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    fun isRunning(): Boolean {
        return try {
            val req = Request.Builder().url("$BASE_URL/api/status").get().build()
            client.newCall(req).execute().use { resp ->
                resp.isSuccessful
            }
        } catch (_: Exception) {
            false
        }
    }

    fun getCandidates(rpId: String, allowCredentials: List<String> = emptyList()): List<CandidateAccount> {
        val json = JSONObject().apply {
            put("rp_id", rpId)
            val arr = JSONArray()
            allowCredentials.forEach { arr.put(it) }
            put("allow_credentials", arr)
        }

        val req = Request.Builder()
            .url("$BASE_URL/api/passkey/candidates")
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
            .url("$BASE_URL/api/passkey/create")
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
            .url("$BASE_URL/api/passkey/get")
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
}
