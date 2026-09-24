package com.vrtfido

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CreateEntry
import android.service.credentials.CredentialEntry
import android.service.credentials.CredentialProviderService
import androidx.annotation.RequiresApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class VrtfidoCredentialProviderService : CredentialProviderService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO)

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, android.credentials.GetCredentialException>
    ) {
        serviceScope.launch {
            try {
                val responseBuilder = BeginGetCredentialResponse.Builder()
                val icon = Icon.createWithResource(this@VrtfidoCredentialProviderService, android.R.drawable.ic_lock_lock)

                for (option in request.beginGetCredentialOptions) {
                    if (option.type == "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL") {
                        val requestJsonStr = option.candidateQueryData.getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON")
                            ?: continue

                        val requestJson = JSONObject(requestJsonStr)
                        val rpId = requestJson.optString("rpId", "")
                        val challenge = requestJson.optString("challenge", "")
                        val clientDataHash = option.candidateQueryData.getString("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")

                        val allowList = mutableListOf<String>()
                        val allowArr = requestJson.optJSONArray("allowCredentials")
                        if (allowArr != null) {
                            for (i in 0 until allowArr.length()) {
                                val item = allowArr.getJSONObject(i)
                                allowList.add(item.optString("id", ""))
                            }
                        }

                        val candidates = VrtfidoClient.getCandidates(this@VrtfidoCredentialProviderService, rpId, allowList)

                        for ((index, cand) in candidates.withIndex()) {
                            val intent = Intent(this@VrtfidoCredentialProviderService, PasskeyAuthActivity::class.java).apply {
                                putExtra(PasskeyAuthActivity.EXTRA_RP_ID, rpId)
                                putExtra(PasskeyAuthActivity.EXTRA_CREDENTIAL_ID, cand.idB64Url)
                                putExtra(PasskeyAuthActivity.EXTRA_CHALLENGE, challenge)
                                if (!clientDataHash.isNullOrEmpty()) {
                                    putExtra(PasskeyAuthActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                                }
                            }

                            val pendingIntent = PendingIntent.getActivity(
                                this@VrtfidoCredentialProviderService,
                                index,
                                intent,
                                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                            )

                            val slice = android.app.slice.Slice.Builder(
                                android.net.Uri.parse("content://com.vrtfido.provider/get/$index"),
                                android.app.slice.SliceSpec("CredentialProvider", 1)
                            )
                                .addText(cand.userName, null, listOf("title"))
                                .addText(cand.rpId, null, listOf("subtitle"))
                                .addIcon(icon, null, listOf("icon"))
                                .addAction(pendingIntent, android.app.slice.Slice.Builder(
                                    android.net.Uri.parse("content://com.vrtfido.provider/get/$index/action"),
                                    android.app.slice.SliceSpec("CredentialProvider", 1)
                                ).build(), null)
                                .build()

                            responseBuilder.addCredentialEntry(CredentialEntry(option, slice))
                        }
                    }
                }

                callback.onResult(responseBuilder.build())
            } catch (e: Exception) {
                e.printStackTrace()
                callback.onError(
                    android.credentials.GetCredentialException(android.credentials.GetCredentialException.TYPE_UNKNOWN, e.message)
                )
            }
        }
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, android.credentials.CreateCredentialException>
    ) {
        serviceScope.launch {
            try {
                val responseBuilder = BeginCreateCredentialResponse.Builder()
                val icon = Icon.createWithResource(this@VrtfidoCredentialProviderService, android.R.drawable.ic_input_add)

                if (request.type == "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL") {
                    val requestJsonStr = request.data.getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON")
                        ?: throw IllegalArgumentException("Missing passkey creation request JSON")

                    val requestJson = JSONObject(requestJsonStr)
                    val rpObj = requestJson.getJSONObject("rp")
                    val rpId = rpObj.getString("id")
                    val rpName = rpObj.optString("name", rpId)

                    val userObj = requestJson.getJSONObject("user")
                    val userId = userObj.optString("id", "")
                    val userName = userObj.getString("name")
                    val userDisplayName = userObj.optString("displayName", userName)

                    val challenge = requestJson.optString("challenge", "")
                    val clientDataHash = request.data.getString("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")

                    val intent = Intent(this@VrtfidoCredentialProviderService, PasskeyCreateActivity::class.java).apply {
                        putExtra(PasskeyCreateActivity.EXTRA_RP_ID, rpId)
                        putExtra(PasskeyCreateActivity.EXTRA_RP_NAME, rpName)
                        putExtra(PasskeyCreateActivity.EXTRA_USER_ID, userId)
                        putExtra(PasskeyCreateActivity.EXTRA_USER_NAME, userName)
                        putExtra(PasskeyCreateActivity.EXTRA_USER_DISPLAY_NAME, userDisplayName)
                        putExtra(PasskeyCreateActivity.EXTRA_CHALLENGE, challenge)
                        if (!clientDataHash.isNullOrEmpty()) {
                            putExtra(PasskeyCreateActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                        }
                    }

                    val pendingIntent = PendingIntent.getActivity(
                        this@VrtfidoCredentialProviderService,
                        100,
                        intent,
                        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )

                    val slice = android.app.slice.Slice.Builder(
                        android.net.Uri.parse("content://com.vrtfido.provider/create"),
                        android.app.slice.SliceSpec("CredentialProvider", 1)
                    )
                        .addText(userName, null, listOf("title"))
                        .addText("Lưu Passkey vào vrtfido", null, listOf("subtitle"))
                        .addIcon(icon, null, listOf("icon"))
                        .addAction(pendingIntent, android.app.slice.Slice.Builder(
                            android.net.Uri.parse("content://com.vrtfido.provider/create/action"),
                            android.app.slice.SliceSpec("CredentialProvider", 1)
                        ).build(), null)
                        .build()

                    responseBuilder.addCreateEntry(CreateEntry(slice))
                }

                callback.onResult(responseBuilder.build())
            } catch (e: Exception) {
                e.printStackTrace()
                callback.onError(
                    android.credentials.CreateCredentialException(android.credentials.CreateCredentialException.TYPE_UNKNOWN, e.message)
                )
            }
        }
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, android.credentials.ClearCredentialStateException>
    ) {
        callback.onResult(null)
    }
}
