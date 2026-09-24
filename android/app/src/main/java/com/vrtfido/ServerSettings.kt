package com.vrtfido

import android.content.Context

data class ServerBinding(val host: String, val port: Int) {
    val localUrl: String
        get() = "http://${if (host == "0.0.0.0") "127.0.0.1" else host}:$port"
}

object ServerSettings {
    private const val PREFS = "vrtfido_server"
    const val DEFAULT_HOST = "0.0.0.0"
    const val DEFAULT_PORT = 10209

    fun load(context: Context): ServerBinding {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return ServerBinding(
            prefs.getString("host", DEFAULT_HOST) ?: DEFAULT_HOST,
            prefs.getInt("port", DEFAULT_PORT)
        )
    }

    fun validate(host: String, port: Int): Boolean =
        host.split('.').let { parts ->
            parts.size == 4 && parts.all { part ->
                val value = part.toIntOrNull()
                part.isNotEmpty() && part.all(Char::isDigit) && value != null &&
                    value in 0..255 && value.toString() == part
            }
        } && port in 1..65535

    fun save(context: Context, binding: ServerBinding) {
        require(validate(binding.host, binding.port))
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("host", binding.host)
            .putInt("port", binding.port)
            .apply()
    }
}
