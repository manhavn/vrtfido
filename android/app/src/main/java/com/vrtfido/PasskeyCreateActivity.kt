package com.vrtfido

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/// Completes a Credential Manager passkey creation request after user verification.
class PasskeyCreateActivity : AppCompatActivity() {

    private val activityScope = CoroutineScope(Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val providerRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val credentialRequest = providerRequest?.callingRequest as? CreatePublicKeyCredentialRequest
        if (credentialRequest == null) {
            Log.w(TAG, "Not launched from Credential Manager")
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val requestJson = runCatching { JSONObject(credentialRequest.requestJson) }.getOrNull()
        val rpId = requestJson?.optJSONObject("rp")?.optString("id").orEmpty()
        val rpName = requestJson?.optJSONObject("rp")?.optString("name")
        val userId = requestJson?.optJSONObject("user")?.optString("id").orEmpty()
        val userName = requestJson?.optJSONObject("user")?.optString("name").orEmpty()
        val userDisplayName = requestJson?.optJSONObject("user")?.optString("displayName")
        val challenge = requestJson?.optString("challenge")

        // Browsers pass only the hash so the provider never learns the origin or challenge.
        val clientDataHash = credentialRequest.clientDataHash?.let { encodeB64Url(it) }

        if (rpId.isEmpty() || userName.isEmpty()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        promptBiometricOrDeviceCredential(
            rpId, rpName, userId, userName, userDisplayName, challenge, clientDataHash
        )
    }

    private fun promptBiometricOrDeviceCredential(
        rpId: String,
        rpName: String?,
        userId: String,
        userName: String,
        userDisplayName: String?,
        challenge: String?,
        clientDataHash: String?
    ) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                createPasskeyCredential(
                    rpId, rpName, userId, userName, userDisplayName, challenge, clientDataHash
                )
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                setResult(Activity.RESULT_CANCELED)
                finish()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }
        }

        val biometricPrompt = BiometricPrompt(this, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.create_title, userName))
            .setSubtitle(rpName?.ifEmpty { rpId } ?: rpId)
            .setDescription(getString(R.string.create_description))
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        try {
            biometricPrompt.authenticate(promptInfo)
        } catch (e: Exception) {
            Log.e(TAG, "Cannot show biometric prompt", e)
            setResult(Activity.RESULT_CANCELED)
            finish()
        }
    }

    private fun createPasskeyCredential(
        rpId: String,
        rpName: String?,
        userId: String,
        userName: String,
        userDisplayName: String?,
        challenge: String?,
        clientDataHash: String?
    ) {
        activityScope.launch {
            val passkeyResult = withContext(Dispatchers.IO) {
                VrtfidoClient.createPasskey(
                    context = this@PasskeyCreateActivity,
                    rpId = rpId,
                    rpName = rpName,
                    userIdB64 = userId,
                    userName = userName,
                    userDisplayName = userDisplayName,
                    challengeB64 = challenge,
                    clientDataJsonB64 = null,
                    clientDataHashB64 = clientDataHash,
                    userVerification = "ANDROID_BIOMETRIC"
                )
            }

            if (passkeyResult != null) {
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(
                    result,
                    CreatePublicKeyCredentialResponse(passkeyResult.toString())
                )
                setResult(Activity.RESULT_OK, result)
                finish()
            } else {
                Toast.makeText(this@PasskeyCreateActivity, getString(R.string.create_error), Toast.LENGTH_SHORT).show()
                setResult(Activity.RESULT_CANCELED)
                finish()
            }
        }
    }

    private fun encodeB64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private companion object {
        const val TAG = "PasskeyCreateActivity"
    }
}
