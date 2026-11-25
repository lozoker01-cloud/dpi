package com.dpiguard.android.vpn

import com.dpiguard.android.model.BypassStrategy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED
}

object VpnStateHolder {
    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private val _strategy = MutableStateFlow(BypassStrategy.RF_TSPU_DEFAULT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()

    private val _dnsServer = MutableStateFlow("1.1.1.1")
    val dnsServer: StateFlow<String> = _dnsServer.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private val _packetsHandled = MutableStateFlow(0L)
    val packetsHandled: StateFlow<Long> = _packetsHandled.asStateFlow()

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    fun setState(newState: ConnectionState) {
        _state.value = newState
    }

    fun setStrategy(strategy: BypassStrategy) {
        _strategy.value = strategy
        log("Стратегия: ${strategy.title}")
    }

    fun setDnsServer(dns: String) {
        _dnsServer.value = dns
        log("DNS: $dns")
    }

    fun incrementPackets() {
        _packetsHandled.value += 1
    }

    fun resetStats() {
        _packetsHandled.value = 0
    }

    fun log(message: String) {
        val timestamp = timeFormat.format(Date())
        val entry = "[$timestamp] $message"
        val updated = (_logs.value + entry).takeLast(80)
        _logs.value = updated
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }
}
