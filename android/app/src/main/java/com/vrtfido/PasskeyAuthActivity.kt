package com.vrtfido

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/// Completes a Credential Manager passkey assertion for the credential the user picked.
class PasskeyAuthActivity : AppCompatActivity() {

    private val activityScope = CoroutineScope(Dispatchers.Main)

    companion object {
        const val EXTRA_CREDENTIAL_ID = "extra_credential_id"
        private const val TAG = "PasskeyAuthActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)

        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = providerRequest?.credentialOptions
            ?.filterIsInstance<GetPublicKeyCredentialOption>()
            ?.firstOrNull()
        if (option == null) {
            Log.w(TAG, "Not launched from Credential Manager")
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val requestJson = runCatching { JSONObject(option.requestJson) }.getOrNull()
        val rpId = requestJson?.optString("rpId").orEmpty()
        val challenge = requestJson?.optString("challenge")
        val clientDataHash = option.clientDataHash?.let { encodeB64Url(it) }

        if (rpId.isEmpty()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        promptBiometricOrDeviceCredential(rpId, credentialId, challenge, clientDataHash)
    }

    private fun promptBiometricOrDeviceCredential(
        rpId: String,
        credentialId: String?,
        challenge: String?,
        clientDataHash: String?
    ) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                signPasskeyAssertion(rpId, credentialId, challenge, clientDataHash)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                setResult(Activity.RESULT_CANCELED)
                finish()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Keep dialog open for retry
            }
        }

        val biometricPrompt = BiometricPrompt(this, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Đăng nhập Passkey")
            .setSubtitle(rpId)
            .setDescription("Quét vân tay, khuôn mặt hoặc dùng mã PIN/khóa màn hình để xác thực")
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

    private fun signPasskeyAssertion(
        rpId: String,
        credentialId: String?,
        challenge: String?,
        clientDataHash: String?
    ) {
        activityScope.launch {
            val passkeyResult = withContext(Dispatchers.IO) {
                VrtfidoClient.getPasskey(
                    context = this@PasskeyAuthActivity,
                    rpId = rpId,
                    credentialId = credentialId,
                    challengeB64 = challenge,
                    clientDataJsonB64 = null,
                    clientDataHashB64 = clientDataHash,
                    userVerification = "ANDROID_BIOMETRIC"
                )
            }

            if (passkeyResult != null) {
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(
                    result,
                    GetCredentialResponse(PublicKeyCredential(passkeyResult.toString()))
                )
                setResult(Activity.RESULT_OK, result)
                finish()
            } else {
                Toast.makeText(this@PasskeyAuthActivity, "Lỗi tạo chữ ký Passkey", Toast.LENGTH_SHORT).show()
                setResult(Activity.RESULT_CANCELED)
                finish()
            }
        }
    }

    private fun encodeB64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
