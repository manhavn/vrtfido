package com.vrtfido

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var switchService: MaterialSwitch
    private lateinit var btnOpenWeb: MaterialButton
    private lateinit var btnSettings: MaterialButton

    private val activityScope = CoroutineScope(Dispatchers.Main)
    private var pollJob: Job? = null

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val isRunning = intent?.getBooleanExtra(VrtfidoService.EXTRA_IS_RUNNING, false) ?: false
            updateUI(isRunning)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tv_status)
        switchService = findViewById(R.id.switch_service)
        btnOpenWeb = findViewById(R.id.btn_open_web)
        btnSettings = findViewById(R.id.btn_settings)

        switchService.setOnCheckedChangeListener { _, isChecked ->
            val intent = Intent(this, VrtfidoService::class.java).apply {
                action = if (isChecked) VrtfidoService.ACTION_START else VrtfidoService.ACTION_STOP
            }
            if (isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
            } else {
                startService(intent)
            }
        }

        btnOpenWeb.setOnClickListener {
            val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://127.0.0.1:10209"))
            startActivity(browserIntent)
        }

        btnSettings.setOnClickListener {
            openCredentialProviderSettings()
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(VrtfidoService.BROADCAST_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }

        startPollingStatus()
    }

    override fun onPause() {
        super.onPause()
        try {
            unregisterReceiver(statusReceiver)
        } catch (_: Exception) {}
        pollJob?.cancel()
    }

    private fun startPollingStatus() {
        pollJob?.cancel()
        pollJob = activityScope.launch {
            while (isActive) {
                val running = withContext(Dispatchers.IO) {
                    VrtfidoClient.isRunning() || VrtfidoService.isRunning
                }
                updateUI(running)
                delay(2000)
            }
        }
    }

    private fun updateUI(running: Boolean) {
        if (switchService.isChecked != running) {
            switchService.setOnCheckedChangeListener(null)
            switchService.isChecked = running
            switchService.setOnCheckedChangeListener { _, isChecked ->
                val intent = Intent(this, VrtfidoService::class.java).apply {
                    action = if (isChecked) VrtfidoService.ACTION_START else VrtfidoService.ACTION_STOP
                }
                if (isChecked) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(intent)
                    } else {
                        startService(intent)
                    }
                } else {
                    startService(intent)
                }
            }
        }

        if (running) {
            tvStatus.text = getString(R.string.service_running)
            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_green))
            btnOpenWeb.isEnabled = true
            btnOpenWeb.alpha = 1.0f
        } else {
            tvStatus.text = getString(R.string.service_stopped)
            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_red))
            btnOpenWeb.isEnabled = false
            btnOpenWeb.alpha = 0.5f
        }
    }

    private fun openCredentialProviderSettings() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                val intent = Intent(Settings.ACTION_CREDENTIAL_PROVIDER)
                startActivity(intent)
                return
            } catch (_: Exception) {}
        }

        // Fallback for Android settings
        try {
            val intent = Intent(Settings.ACTION_SYNC_SETTINGS)
            startActivity(intent)
        } catch (_: Exception) {
            val intent = Intent(Settings.ACTION_SETTINGS)
            startActivity(intent)
        }
    }
}
