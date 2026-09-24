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
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

class VrtfidoService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        const val CHANNEL_ID = "vrtfido_daemon_channel"
        const val NOTIFICATION_ID = 10209
        const val ACTION_START = "com.vrtfido.action.START"
        const val ACTION_STOP = "com.vrtfido.action.STOP"
        const val BROADCAST_STATUS = "com.vrtfido.broadcast.STATUS"
        const val EXTRA_IS_RUNNING = "is_running"

        var isRunning: Boolean = false
            private set

        init {
            try {
                System.loadLibrary("vrtfido")
            } catch (e: UnsatisfiedLinkError) {
                // If running standalone or during unit tests
                e.printStackTrace()
            }
        }

        @JvmStatic
        private external fun startVrtfidoDaemon(dbPath: String, port: Int)
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopDaemon()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                startDaemon()
                return START_STICKY
            }
        }
    }

    private fun startDaemon() {
        if (isRunning) return
        isRunning = true
        broadcastStatus(true)

        serviceScope.launch {
            val dbFile = File(filesDir, "authenticator.db")
            try {
                // Call native JNI method
                startVrtfidoDaemon(dbFile.absolutePath, 10209)
            } catch (e: Throwable) {
                e.printStackTrace()
            }
        }
    }

    private fun stopDaemon() {
        isRunning = false
        broadcastStatus(false)
        serviceScope.cancel()
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

    private fun buildNotification(): Notification {
        val openWebIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://127.0.0.1:10209"))
        val openWebPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openWebIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val mainIntent = Intent(this, MainActivity::class.java)
        val mainPendingIntent = PendingIntent.getActivity(
            this,
            1,
            mainIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(mainPendingIntent)
            .addAction(android.R.drawable.ic_menu_view, getString(R.string.open_web_ui), openWebPendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopDaemon()
        super.onDestroy()
    }
}
