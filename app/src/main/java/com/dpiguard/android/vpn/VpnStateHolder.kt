package com.dpiguard.android.vpn

import com.dpiguard.android.model.BypassStrategy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED
}

object VpnStateHolder {
    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private val _strategy = MutableStateFlow(BypassStrategy.S01_FAKE_TTL8_TLSREC)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()

    private val _dnsServer = MutableStateFlow("1.1.1.1")
    val dnsServer: StateFlow<String> = _dnsServer.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private val _packetsHandled = MutableStateFlow(0L)
    val packetsHandled: StateFlow<Long> = _packetsHandled.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanStatus = MutableStateFlow("Нажми «Автоподбор», чтобы проверить провайдера")
    val scanStatus: StateFlow<String> = _scanStatus.asStateFlow()

    private val packetCounter = AtomicLong(0L)
    private val logLock = Any()
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

    fun setScanning(scanning: Boolean) {
        _isScanning.value = scanning
    }

    fun setScanStatus(status: String) {
        _scanStatus.value = status
    }

    fun incrementPackets() {
        _packetsHandled.value = packetCounter.incrementAndGet()
    }

    fun resetStats() {
        packetCounter.set(0L)
        _packetsHandled.value = 0L
    }

    fun log(message: String) {
        val timestamp = timeFormat.format(Date())
        val entry = "[$timestamp] $message"
        synchronized(logLock) {
            _logs.value = (_logs.value + entry).takeLast(120)
        }
    }

    fun clearLogs() {
        synchronized(logLock) {
            _logs.value = emptyList()
        }
    }
}
