package com.vrtfido

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
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
    private lateinit var editHost: EditText
    private lateinit var editPort: EditText
    private lateinit var btnOpenWeb: MaterialButton
    private lateinit var btnSettings: MaterialButton

    private val activityScope = CoroutineScope(Dispatchers.Main)
    private var pollJob: Job? = null
    private var startRequested = false
    private var permissionError: String? = null
    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted && startRequested) {
                startServiceInForeground()
            } else {
                startRequested = false
                permissionError = getString(R.string.notification_permission_required)
                updateUI(false, false, permissionError)
            }
        }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateUI(VrtfidoService.isRunning, VrtfidoService.isStarting, VrtfidoService.lastError)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tv_status)
        switchService = findViewById(R.id.switch_service)
        btnOpenWeb = findViewById(R.id.btn_open_web)
        btnSettings = findViewById(R.id.btn_settings)
        editHost = findViewById(R.id.edit_host)
        editPort = findViewById(R.id.edit_port)
        ServerSettings.load(this).let { binding ->
            editHost.setText(binding.host)
            editPort.setText(binding.port.toString())
        }

        switchService.setOnCheckedChangeListener { _, checked -> toggleDaemon(checked) }

        btnOpenWeb.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(ServerSettings.load(this).localUrl)))
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

    private fun toggleDaemon(checked: Boolean) {
        val intent = Intent(this, VrtfidoService::class.java)
        if (checked) {
            val host = editHost.text.toString().trim()
            val port = editPort.text.toString().toIntOrNull() ?: 0
            if (!ServerSettings.validate(host, port)) {
                editHost.error = getString(R.string.invalid_bind)
                switchService.setOnCheckedChangeListener(null)
                switchService.isChecked = false
                switchService.setOnCheckedChangeListener { _, value -> toggleDaemon(value) }
                return
            }
            ServerSettings.save(this, ServerBinding(host, port))
            startRequested = true
            permissionError = null
            editHost.isEnabled = false
            editPort.isEnabled = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
            startServiceInForeground()
        } else {
            startRequested = false
            stopService(intent)
        }
    }

    private fun startServiceInForeground() {
        val intent = Intent(this, VrtfidoService::class.java).apply { action = VrtfidoService.ACTION_START }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun startPollingStatus() {
        pollJob?.cancel()
        pollJob = activityScope.launch {
            while (isActive) {
                val running = withContext(Dispatchers.IO) {
                    VrtfidoService.isRunning && VrtfidoClient.isRunning(this@MainActivity)
                }
                updateUI(running, VrtfidoService.isStarting, VrtfidoService.lastError ?: permissionError)
                delay(2000)
            }
        }
    }

    private fun updateUI(running: Boolean, starting: Boolean, error: String?) {
        if (running || error != null) startRequested = false
        val pending = starting || startRequested
        val checked = running || pending
        if (switchService.isChecked != checked) {
            switchService.setOnCheckedChangeListener(null)
            switchService.isChecked = checked
            switchService.setOnCheckedChangeListener { _, isChecked -> toggleDaemon(isChecked) }
        }
        editHost.isEnabled = !checked
        editPort.isEnabled = !checked
        val binding = ServerSettings.load(this)
        btnOpenWeb.text = getString(R.string.open_web_ui, binding.localUrl)
        when {
            running -> {
                tvStatus.text = getString(R.string.service_running, binding.localUrl)
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_green))
            }
            pending -> {
                tvStatus.text = getString(R.string.service_starting, "${binding.host}:${binding.port}")
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            }
            error != null -> {
                tvStatus.text = getString(R.string.service_failed, error)
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_red))
            }
            else -> {
                tvStatus.text = getString(R.string.service_stopped)
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_red))
            }
        }
        btnOpenWeb.isEnabled = running
        btnOpenWeb.alpha = if (running) 1.0f else 0.5f
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
