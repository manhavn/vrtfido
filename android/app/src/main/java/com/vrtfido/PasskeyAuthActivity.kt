package com.vrtfido

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.credentials.CredentialProviderService
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PasskeyAuthActivity : AppCompatActivity() {

    private val activityScope = CoroutineScope(Dispatchers.Main)

    companion object {
        const val EXTRA_RP_ID = "extra_rp_id"
        const val EXTRA_CREDENTIAL_ID = "extra_credential_id"
        const val EXTRA_CHALLENGE = "extra_challenge"
        const val EXTRA_CLIENT_DATA_JSON = "extra_client_data_json"
        const val EXTRA_CLIENT_DATA_HASH = "extra_client_data_hash"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rpId = intent.getStringExtra(EXTRA_RP_ID) ?: ""
        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
        val challenge = intent.getStringExtra(EXTRA_CHALLENGE)
        val clientDataJson = intent.getStringExtra(EXTRA_CLIENT_DATA_JSON)
        val clientDataHash = intent.getStringExtra(EXTRA_CLIENT_DATA_HASH)

        if (rpId.isEmpty()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        promptBiometricOrDeviceCredential(rpId, credentialId, challenge, clientDataJson, clientDataHash)
    }

    private fun promptBiometricOrDeviceCredential(
        rpId: String,
        credentialId: String?,
        challenge: String?,
        clientDataJson: String?,
        clientDataHash: String?
    ) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                signPasskeyAssertion(rpId, credentialId, challenge, clientDataJson, clientDataHash)
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
            e.printStackTrace()
            setResult(Activity.RESULT_CANCELED)
            finish()
        }
    }

    private fun signPasskeyAssertion(
        rpId: String,
        credentialId: String?,
        challenge: String?,
        clientDataJson: String?,
        clientDataHash: String?
    ) {
        activityScope.launch {
            val passkeyResult = withContext(Dispatchers.IO) {
                VrtfidoClient.getPasskey(
                    context = this@PasskeyAuthActivity,
                    rpId = rpId,
                    credentialId = credentialId,
                    challengeB64 = challenge,
                    clientDataJsonB64 = clientDataJson,
                    clientDataHashB64 = clientDataHash,
                    userVerification = "ANDROID_BIOMETRIC"
                )
            }

            if (passkeyResult != null) {
                val responseJson = passkeyResult.toString()
                val resultIntent = Intent()

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    val response = android.credentials.GetCredentialResponse(
                        android.credentials.Credential(
                            "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL",
                            android.os.Bundle().apply {
                                putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson)
                            }
                        )
                    )
                    resultIntent.putExtra(
                        CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                        response
                    )
                }

                setResult(Activity.RESULT_OK, resultIntent)
                finish()
            } else {
                Toast.makeText(this@PasskeyAuthActivity, "Lỗi tạo chữ ký Passkey", Toast.LENGTH_SHORT).show()
                setResult(Activity.RESULT_CANCELED)
                finish()
            }
        }
    }
}
