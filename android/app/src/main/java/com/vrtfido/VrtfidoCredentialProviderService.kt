package com.vrtfido

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

/// Credential Manager provider that serves vrtfido passkeys to Android 14+ browsers and apps.
///
/// The platform only accepts entries built through the Jetpack provider library: it parses the
/// Slice produced by [CreateEntry.toSlice] / [PublicKeyCredentialEntry.toSlice] against fixed
/// hints. Hand-built Slices (as used previously) are dropped, so this class never constructs
/// Slices itself.
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class VrtfidoCredentialProviderService : CredentialProviderService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO)

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        serviceScope.launch {
            try {
                val responseBuilder = BeginGetCredentialResponse.Builder()
                val icon = Icon.createWithResource(
                    this@VrtfidoCredentialProviderService,
                    android.R.drawable.ic_lock_lock
                )

                for (option in request.beginGetCredentialOptions) {
                    if (option !is BeginGetPublicKeyCredentialOption) continue

                    val requestJson = JSONObject(option.requestJson)
                    val rpId = requestJson.optString("rpId", "")
                    if (rpId.isEmpty()) continue

                    val allowList = mutableListOf<String>()
                    requestJson.optJSONArray("allowCredentials")?.let { arr ->
                        for (i in 0 until arr.length()) {
                            allowList.add(arr.getJSONObject(i).optString("id", ""))
                        }
                    }

                    val candidates =
                        VrtfidoClient.getCandidates(this@VrtfidoCredentialProviderService, rpId, allowList)

                    candidates.forEachIndexed { index, candidate ->
                        val intent = Intent(
                            this@VrtfidoCredentialProviderService,
                            PasskeyAuthActivity::class.java
                        ).apply {
                            putExtra(PasskeyAuthActivity.EXTRA_CREDENTIAL_ID, candidate.idB64Url)
                        }

                        val pendingIntent = PendingIntent.getActivity(
                            this@VrtfidoCredentialProviderService,
                            GET_REQUEST_CODE_BASE + index,
                            intent,
                            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                        )

                        val entry = PublicKeyCredentialEntry.Builder(
                            applicationContext,
                            candidate.userName,
                            pendingIntent,
                            option
                        )
                            .setDisplayName(
                                candidate.userDisplayName.ifEmpty { candidate.userName }
                            )
                            .setIcon(icon)
                            .build()

                        responseBuilder.addCredentialEntry(entry)
                    }
                }

                callback.onResult(responseBuilder.build())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to list passkeys for the requesting app", e)
                callback.onError(GetCredentialUnknownException(e.message ?: "vrtfido provider error"))
            }
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        serviceScope.launch {
            try {
                if (request !is BeginCreatePublicKeyCredentialRequest) {
                    callback.onResult(BeginCreateCredentialResponse())
                    return@launch
                }

                val accountName = runCatching {
                    JSONObject(request.requestJson).getJSONObject("user").optString("name")
                }.getOrNull().orEmpty().ifEmpty { getString(R.string.app_name) }

                val intent = Intent(
                    this@VrtfidoCredentialProviderService,
                    PasskeyCreateActivity::class.java
                )

                val pendingIntent = PendingIntent.getActivity(
                    this@VrtfidoCredentialProviderService,
                    CREATE_REQUEST_CODE,
                    intent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )

                val entry = CreateEntry.Builder(accountName, pendingIntent)
                    .setDescription(getString(R.string.create_entry_description, accountName))
                    .setIcon(
                        Icon.createWithResource(
                            this@VrtfidoCredentialProviderService,
                            android.R.drawable.ic_input_add
                        )
                    )
                    .build()

                callback.onResult(
                    BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build()
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to offer passkey creation", e)
                callback.onError(CreateCredentialUnknownException(e.message ?: "vrtfido provider error"))
            }
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        callback.onResult(null)
    }

    private companion object {
        const val TAG = "VrtfidoProvider"
        const val CREATE_REQUEST_CODE = 100
        const val GET_REQUEST_CODE_BASE = 200
    }
}
