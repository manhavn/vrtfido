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
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var switchService: MaterialSwitch
    private lateinit var editHost: EditText
    private lateinit var editPort: EditText
    private lateinit var editDatabase: EditText
    private lateinit var editDbType: EditText
    private lateinit var editAuthToken: EditText
    private lateinit var checkDebug: MaterialCheckBox
    private lateinit var checkUnlimitedFps: MaterialCheckBox
    private lateinit var btnOpenWeb: MaterialButton
    private lateinit var btnSettings: MaterialButton
    private lateinit var btnExport: MaterialButton
    private lateinit var btnImport: MaterialButton

    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri -> uri?.let { exportDatabase(it) } }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { importDatabase(it) } }

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
        btnExport = findViewById(R.id.btn_export)
        btnImport = findViewById(R.id.btn_import)
        editHost = findViewById(R.id.edit_host)
        editPort = findViewById(R.id.edit_port)
        editDatabase = findViewById(R.id.edit_database)
        editDbType = findViewById(R.id.edit_db_type)
        editAuthToken = findViewById(R.id.edit_auth_token)
        checkDebug = findViewById(R.id.check_debug)
        checkUnlimitedFps = findViewById(R.id.check_unlimited_fps)
        ServerSettings.load(this).let { binding ->
            editHost.setText(binding.host)
            editPort.setText(binding.port.toString())
            editDatabase.setText(binding.database)
            editDbType.setText(binding.dbType)
            editAuthToken.setText(binding.authToken)
            checkDebug.isChecked = binding.debugMode
            checkUnlimitedFps.isChecked = binding.unlimitedFingerprints
        }

        switchService.setOnCheckedChangeListener { _, checked -> toggleDaemon(checked) }

        btnOpenWeb.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(ServerSettings.load(this).localUrl)))
        }

        btnSettings.setOnClickListener {
            openCredentialProviderSettings()
        }

        btnExport.setOnClickListener {
            if (!VrtfidoService.isRunning) {
                toast(getString(R.string.daemon_required))
            } else {
                val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                exportLauncher.launch(getString(R.string.backup_file_name, stamp))
            }
        }

        btnImport.setOnClickListener {
            if (!VrtfidoService.isRunning) {
                toast(getString(R.string.daemon_required))
            } else {
                importLauncher.launch(arrayOf("application/json", "text/plain", "application/octet-stream"))
            }
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
            val database = editDatabase.text.toString().trim()
            if (!ServerSettings.validate(host, port, database)) {
                editHost.error = getString(R.string.invalid_bind)
                editDatabase.error = getString(R.string.invalid_database)
                switchService.setOnCheckedChangeListener(null)
                switchService.isChecked = false
                switchService.setOnCheckedChangeListener { _, value -> toggleDaemon(value) }
                return
            }
            ServerSettings.save(
                this,
                ServerBinding(
                    host = host,
                    port = port,
                    database = database,
                    dbType = editDbType.text.toString().trim(),
                    authToken = editAuthToken.text.toString().trim(),
                    debugMode = checkDebug.isChecked,
                    unlimitedFingerprints = checkUnlimitedFps.isChecked
                )
            )
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
        editDatabase.isEnabled = !checked
        editDbType.isEnabled = !checked
        editAuthToken.isEnabled = !checked
        checkDebug.isEnabled = !checked
        checkUnlimitedFps.isEnabled = !checked
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
        btnExport.isEnabled = running
        btnImport.isEnabled = running
        btnExport.alpha = if (running) 1.0f else 0.5f
        btnImport.alpha = if (running) 1.0f else 0.5f
    }

    private fun exportDatabase(target: Uri) {
        activityScope.launch {
            try {
                withContext(Dispatchers.IO) { VrtfidoClient.exportDatabase(this@MainActivity, target) }
                toast(getString(R.string.export_done, target.lastPathSegment ?: "JSON"))
            } catch (e: Exception) {
                toast(getString(R.string.export_failed, e.message ?: e.javaClass.simpleName))
            }
        }
    }

    private fun importDatabase(source: Uri) {
        activityScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    VrtfidoClient.importDatabase(this@MainActivity, source)
                }
                toast(
                    getString(
                        R.string.import_done,
                        result.credentials,
                        result.fingerprints,
                        result.authLogs
                    )
                )
            } catch (e: Exception) {
                toast(getString(R.string.import_failed, e.message ?: e.javaClass.simpleName))
            }
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
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
