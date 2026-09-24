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
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import org.json.JSONObject
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
    private lateinit var btnLangEn: MaterialButton
    private lateinit var btnLangVi: MaterialButton
    private var currentLanguage: String = ServerSettings.DEFAULT_LANGUAGE
    private var autoStartAttempted = false
    private var settingsPushed = false
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
        btnLangEn = findViewById(R.id.btn_lang_en)
        btnLangVi = findViewById(R.id.btn_lang_vi)
        ServerSettings.load(this).let { binding ->
            editHost.setText(binding.host)
            editPort.setText(binding.port.toString())
            editDatabase.setText(binding.database)
            editDbType.setText(binding.dbType)
            editAuthToken.setText(binding.authToken)
            checkDebug.isChecked = binding.debugMode
            currentLanguage = binding.language
        }
        renderLanguageButtons()
        // Apply the saved language before the first frame (no-op when it already matches).
        val savedLocale = LocaleListCompat.forLanguageTags(currentLanguage)
        if (AppCompatDelegate.getApplicationLocales() != savedLocale) {
            AppCompatDelegate.setApplicationLocales(savedLocale)
        }

        btnLangEn.setOnClickListener { changeLanguage("en") }
        btnLangVi.setOnClickListener { changeLanguage("vi") }

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
        restoreDaemonState()
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
            val binding = ServerBinding(
                host = host,
                port = port,
                database = database,
                dbType = editDbType.text.toString().trim(),
                authToken = editAuthToken.text.toString().trim(),
                debugMode = checkDebug.isChecked,
                // Kept from the stored configuration: the phone has no USB sensor, so the
                // fingerprint mode is managed from the Web CMS.
                unlimitedFingerprints = ServerSettings.load(this).unlimitedFingerprints,
                language = currentLanguage,
                daemonRunning = true,
                configured = true
            )
            ServerSettings.save(this, binding)
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
            ServerSettings.saveDaemonRunning(this, false)
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
        if (!running && !starting && !startRequested) {
            // The daemon is down (stopped or failed): a later app launch must not auto-start it.
            ServerSettings.saveDaemonRunning(this, false)
        }
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
        if (running && !settingsPushed) {
            settingsPushed = true
            pushSettingsToServer()
        }
        if (!running) settingsPushed = false
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

    private fun renderLanguageButtons() {
        val viActive = currentLanguage == "vi"
        btnLangEn.alpha = if (viActive) 0.55f else 1.0f
        btnLangVi.alpha = if (viActive) 1.0f else 0.55f
        btnLangEn.strokeWidth = if (viActive) 1 else 3
        btnLangVi.strokeWidth = if (viActive) 3 else 1
    }

    private fun changeLanguage(language: String) {
        if (!ServerSettings.SUPPORTED_LANGUAGES.contains(language)) return
        val binding = ServerSettings.load(this)
        if (binding.language == language) {
            renderLanguageButtons()
            return
        }
        currentLanguage = language
        ServerSettings.saveLanguage(this, language)
        renderLanguageButtons()
        // Mirror the choice into the database so the Web CMS follows the same language.
        activityScope.launch {
            withContext(Dispatchers.IO) {
                VrtfidoClient.updateSettings(
                    this@MainActivity,
                    JSONObject().put("language", language)
                )
            }
        }
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(language))
    }

    /**
     * Restores the daemon exactly as the user left it: if it was ON when the app was closed, it is
     * started again here without asking for the parameters a second time.
     */
    private fun restoreDaemonState() {
        val binding = ServerSettings.load(this)
        currentLanguage = binding.language
        if (binding.daemonRunning && !VrtfidoService.isRunning && !VrtfidoService.isStarting && !autoStartAttempted) {
            autoStartAttempted = true
            startServiceInForeground()
            activityScope.launch {
                delay(4000)
                syncSettingsWithServer(ServerSettings.load(this@MainActivity))
            }
            return
        }
        syncSettingsWithServer(binding)
    }

    /** Pulls parameters/language from the database the first time this device opens the app. */
    private fun syncSettingsWithServer(binding: ServerBinding) {
        if (!VrtfidoService.isRunning) return
        activityScope.launch {
            val remote = withContext(Dispatchers.IO) {
                VrtfidoClient.getSettings(this@MainActivity)
            } ?: return@launch

            val remoteLanguage = remote.optString("language", ServerSettings.DEFAULT_LANGUAGE)
            if (remoteLanguage != binding.language && ServerSettings.SUPPORTED_LANGUAGES.contains(remoteLanguage)) {
                currentLanguage = remoteLanguage
                ServerSettings.saveLanguage(this@MainActivity, remoteLanguage)
                renderLanguageButtons()
                AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(remoteLanguage))
                return@launch
            }

            // Only a device that never confirmed its parameters adopts the stored ones.
            if (!binding.configured && remote.has("daemon.host")) {
                val adopted = binding.copy(
                    host = remote.optString("daemon.host", binding.host),
                    port = remote.optInt("daemon.port", binding.port),
                    database = remote.optString("daemon.database", binding.database),
                    dbType = remote.optString("daemon.db_type", binding.dbType),
                    authToken = remote.optString("daemon.auth_token", binding.authToken),
                    debugMode = remote.optString("daemon.debug", "false").toBoolean(),
                    unlimitedFingerprints = remote
                        .optString("daemon.unlimited_fingerprints", "false").toBoolean(),
                    configured = true
                )
                if (!ServerSettings.validate(adopted.host, adopted.port, adopted.database)) return@launch
                ServerSettings.save(this@MainActivity, adopted)
                editHost.setText(adopted.host)
                editPort.setText(adopted.port.toString())
                editDatabase.setText(adopted.database)
                editDbType.setText(adopted.dbType)
                editAuthToken.setText(adopted.authToken)
                checkDebug.isChecked = adopted.debugMode
                toast(getString(R.string.settings_restored))
            }
        }
    }

    /** Mirrors the confirmed parameters into the database so a reinstall can restore them. */
    private fun pushSettingsToServer() {
        val binding = ServerSettings.load(this)
        if (!binding.configured) return
        activityScope.launch {
            withContext(Dispatchers.IO) {
                val daemon = JSONObject()
                    .put("host", binding.host)
                    .put("port", binding.port)
                    .put("database", binding.database)
                    .put("db_type", binding.dbType)
                    .put("auth_token", binding.authToken)
                    .put("debug", binding.debugMode)
                    .put("running", true)
                VrtfidoClient.updateSettings(
                    this@MainActivity,
                    JSONObject().put("language", binding.language).put("daemon", daemon)
                )
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
