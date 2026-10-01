package com.vrtfido

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class VrtfidoService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        const val CHANNEL_ID = "vrtfido_daemon_channel"
        const val NOTIFICATION_ID = 10209
        const val ACTION_START = "com.vrtfido.action.START"
        const val ACTION_STOP = "com.vrtfido.action.STOP"
        const val BROADCAST_STATUS = "com.vrtfido.broadcast.STATUS"
        const val EXTRA_IS_RUNNING = "is_running"

        @Volatile var isRunning: Boolean = false
            private set
        @Volatile var isStarting: Boolean = false
            private set
        @Volatile var lastError: String? = null
            private set

        private val loadError: String? = try {
            System.loadLibrary("vrtfido")
            null
        } catch (e: UnsatisfiedLinkError) {
            e.message ?: "Could not load native library"
        }

        @JvmStatic
        private external fun startVrtfidoDaemon(optionsJson: String): String?
        @JvmStatic
        private external fun stopVrtfidoDaemon()
        @JvmStatic
        private external fun isDaemonRunning(): Boolean
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
            wakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "vrtfido:daemon")?.apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Exception) {}
        wakeLock = null
    }


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        val binding = ServerSettings.load(this)
        startForeground(NOTIFICATION_ID, buildNotification(binding, starting = !isRunning))
        startDaemon(binding)
        return START_STICKY
    }

    private fun startDaemon(binding: ServerBinding) {
        if (isRunning || isStarting) return
        isStarting = true
        lastError = null
        broadcastStatus(false)

        serviceScope.launch {
            try {
                check(loadError == null) { "Native library: $loadError" }
                val error = startVrtfidoDaemon(daemonOptionsJson(binding))
                check(error == null) { error ?: "Unknown native startup error" }
                var reachable = false
                for (attempt in 0 until 20) {
                    if (!isActive) return@launch
                    if (VrtfidoClient.isRunning(this@VrtfidoService)) {
                        reachable = true
                        break
                    }
                    delay(250)
                }
                check(reachable) { "Server started but ${binding.localUrl}/api/health is unreachable" }
                if (!isActive) return@launch
                acquireWakeLock()
                isRunning = true
                (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                    .notify(NOTIFICATION_ID, buildNotification(binding, starting = false))
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lastError = e.message ?: e.javaClass.simpleName
                Log.e("VrtfidoService", "Failed to start dashboard", e)
                stopSelf()
            } catch (e: LinkageError) {
                lastError = e.message ?: "Native library error"
                Log.e("VrtfidoService", "Failed to load dashboard", e)
                stopSelf()
            } finally {
                isStarting = false
                broadcastStatus(isRunning)
            }
            if (isRunning) {
                while (isActive) {
                    delay(3000)
                    if (loadError == null && !isDaemonRunning()) {
                        lastError = getString(R.string.server_stopped_unexpectedly)
                        isRunning = false
                        broadcastStatus(false)
                        stopSelf()
                        break
                    }
                }
            }
        }
    }

    /**
     * The local SQLite files live under the app's private files directory, even when a bare
     * sqlite:/libsql: spec is supplied. Sidecars stay private if a user chooses an external
     * absolute primary path; they are never placed in public storage by default.
     */
    private fun daemonOptionsJson(binding: ServerBinding): String {
        val spec = binding.database.trim()
        val localPrefix = when {
            spec.startsWith("sqlite:") -> "sqlite:"
            spec.startsWith("libsql:") && !spec.startsWith("libsql://") -> "libsql:"
            else -> ""
        }
        val localSpec = spec.removePrefix(localPrefix)
        val isLocal = !spec.contains("://") && !spec.startsWith("file:") &&
            binding.dbType.trim().lowercase() !in setOf("postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongo")
        val localPath = localSpec.ifEmpty { "authenticator.db" }
        val database = if (isLocal && !localPath.startsWith("/") && localPath != ":memory:") {
            "$localPrefix${File(filesDir, localPath).canonicalPath}"
        } else {
            spec
        }

        val privateDir = filesDir.canonicalFile
        val primaryFile = if (isLocal && localPath != ":memory:") {
            File(localPath).let { if (it.isAbsolute) it else File(privateDir, it.path) }.canonicalFile
        } else {
            null
        }
        val privatePrimary = primaryFile?.parentFile?.takeIf { parent ->
            parent == privateDir || parent.toPath().startsWith(privateDir.toPath())
        }
        // Different remote (or externally located) primaries must not share an offline queue.
        // Hashing the spec gives stable filenames without exposing URL credentials in a filename.
        val stem = if (privatePrimary != null) {
            primaryFile.name.removeSuffix(".db").ifEmpty { "authenticator" }
        } else {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("${binding.dbType.trim()}:$database".toByteArray(Charsets.UTF_8))
                .take(12)
                .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            "primary-$digest"
        }
        val sidecarDir = privatePrimary ?: privateDir
        val shadowDb = File(sidecarDir, "$stem.shadow.db").absolutePath
        val queueDb = File(sidecarDir, "$stem.queue.db").absolutePath

        return JSONObject().apply {
            put("database", database)
            put("host", binding.host)
            put("port", binding.port)
            put("shadow_db", shadowDb)
            put("queue_db", queueDb)
            if (binding.dbType.isNotBlank()) put("db_type", binding.dbType.trim())
            if (binding.authToken.isNotBlank()) put("auth_token", binding.authToken.trim())
            put("debug_mode", binding.debugMode)
            put("unlimited_fingerprints", binding.unlimitedFingerprints)
        }.toString()
    }

    private fun stopDaemon() {
        releaseWakeLock()
        isRunning = false
        isStarting = false
        serviceScope.cancel()
        if (loadError == null) {
            try {
                stopVrtfidoDaemon()
            } catch (e: LinkageError) {
                Log.e("VrtfidoService", "Failed to stop native server", e)
            }
        }
        broadcastStatus(false)
    }

    private fun broadcastStatus(running: Boolean) {
        val intent = Intent(BROADCAST_STATUS).apply {
            putExtra(EXTRA_IS_RUNNING, running)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_text)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(binding: ServerBinding, starting: Boolean): Notification {
        val openWebIntent = Intent(Intent.ACTION_VIEW, Uri.parse(binding.localUrl))
        val openWebPendingIntent = PendingIntent.getActivity(
            this, 0, openWebIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val mainIntent = Intent(this, MainActivity::class.java)
        val mainPendingIntent = PendingIntent.getActivity(
            this, 1, mainIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = Intent(this, VrtfidoService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 2, stopIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val address = "http://${binding.host}:${binding.port}"
        val message = getString(
            if (starting) R.string.notification_starting else R.string.notification_running,
            address
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$message • ${binding.localUrl}"))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(mainPendingIntent)
            .addAction(android.R.drawable.ic_menu_view,
                getString(R.string.open_web_ui, binding.localUrl), openWebPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.notification_action_stop), stopPendingIntent)
            .setOngoing(true)
            .setAutoCancel(false)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopDaemon()
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
