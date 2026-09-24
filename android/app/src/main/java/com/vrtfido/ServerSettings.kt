package com.vrtfido

import android.content.Context

/**
 * Runtime configuration for the embedded daemon, mirroring the desktop CLI flags:
 * `--database`/`--db-type`/`--auth-token`, `--debug` and `--unlimited-fps`.
 *
 * Values are cached locally so reopening the app never asks for them again, and the same set is
 * mirrored into the database (through `/api/settings`) so it can be restored on a fresh install or
 * shared with the Web CMS.
 */
data class ServerBinding(
    val host: String,
    val port: Int,
    val database: String,
    val dbType: String,
    val authToken: String,
    val debugMode: Boolean,
    val unlimitedFingerprints: Boolean,
    val language: String = ServerSettings.DEFAULT_LANGUAGE,
    /// Last known daemon state, so opening the app restores the previous on/off choice.
    val daemonRunning: Boolean = false,
    /// True once the user confirmed the parameters at least once on this device.
    val configured: Boolean = false
) {
    val localUrl: String
        get() = "http://${if (host == "0.0.0.0") "127.0.0.1" else host}:$port"
}

object ServerSettings {
    private const val PREFS = "vrtfido_server"
    const val DEFAULT_HOST = "0.0.0.0"
    const val DEFAULT_PORT = 10209
    const val DEFAULT_DATABASE = "authenticator.db"
    const val DEFAULT_LANGUAGE = "en"
    val SUPPORTED_LANGUAGES = listOf("en", "vi")

    fun load(context: Context): ServerBinding {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return ServerBinding(
            host = prefs.getString("host", DEFAULT_HOST) ?: DEFAULT_HOST,
            port = prefs.getInt("port", DEFAULT_PORT),
            database = prefs.getString("database", DEFAULT_DATABASE) ?: DEFAULT_DATABASE,
            dbType = prefs.getString("db_type", "").orEmpty(),
            authToken = prefs.getString("auth_token", "").orEmpty(),
            debugMode = prefs.getBoolean("debug_mode", false),
            unlimitedFingerprints = prefs.getBoolean("unlimited_fingerprints", false),
            language = prefs.getString("language", DEFAULT_LANGUAGE) ?: DEFAULT_LANGUAGE,
            daemonRunning = prefs.getBoolean("daemon_running", false),
            configured = prefs.getBoolean("configured", false)
        )
    }

    fun validate(host: String, port: Int, database: String): Boolean =
        host.split('.').let { parts ->
            parts.size == 4 && parts.all { part ->
                val value = part.toIntOrNull()
                part.isNotEmpty() && part.all(Char::isDigit) && value != null &&
                    value in 0..255 && value.toString() == part
            }
        } && port in 1..65535 && database.isNotBlank()

    fun save(context: Context, binding: ServerBinding) {
        require(validate(binding.host, binding.port, binding.database))
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("host", binding.host)
            .putInt("port", binding.port)
            .putString("database", binding.database)
            .putString("db_type", binding.dbType)
            .putString("auth_token", binding.authToken)
            .putBoolean("debug_mode", binding.debugMode)
            .putBoolean("unlimited_fingerprints", binding.unlimitedFingerprints)
            .putString("language", binding.language)
            .putBoolean("daemon_running", binding.daemonRunning)
            .putBoolean("configured", binding.configured)
            .apply()
    }

    /** Stores only the language, leaving the daemon parameters untouched. */
    fun saveLanguage(context: Context, language: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("language", language)
            .apply()
    }

    /** Stores only the last daemon state, so reopening the app can restore it. */
    fun saveDaemonRunning(context: Context, running: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean("daemon_running", running)
            .apply()
    }
}
