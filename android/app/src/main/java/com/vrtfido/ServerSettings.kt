package com.vrtfido

import android.content.Context

/**
 * Runtime configuration for the embedded daemon, mirroring the desktop CLI flags:
 * `--database`/`--db-type`/`--auth-token`, `--debug` and `--unlimited-fps`.
 */
data class ServerBinding(
    val host: String,
    val port: Int,
    val database: String,
    val dbType: String,
    val authToken: String,
    val debugMode: Boolean,
    val unlimitedFingerprints: Boolean
) {
    val localUrl: String
        get() = "http://${if (host == "0.0.0.0") "127.0.0.1" else host}:$port"
}

object ServerSettings {
    private const val PREFS = "vrtfido_server"
    const val DEFAULT_HOST = "0.0.0.0"
    const val DEFAULT_PORT = 10209
    const val DEFAULT_DATABASE = "authenticator.db"

    fun load(context: Context): ServerBinding {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return ServerBinding(
            host = prefs.getString("host", DEFAULT_HOST) ?: DEFAULT_HOST,
            port = prefs.getInt("port", DEFAULT_PORT),
            database = prefs.getString("database", DEFAULT_DATABASE) ?: DEFAULT_DATABASE,
            dbType = prefs.getString("db_type", "").orEmpty(),
            authToken = prefs.getString("auth_token", "").orEmpty(),
            debugMode = prefs.getBoolean("debug_mode", false),
            unlimitedFingerprints = prefs.getBoolean("unlimited_fingerprints", false)
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
            .apply()
    }
}
