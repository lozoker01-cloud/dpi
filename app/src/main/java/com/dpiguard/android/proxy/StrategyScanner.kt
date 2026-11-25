package com.dpiguard.android.proxy

import android.content.Context
import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class StrategyScanResult(
    val strategy: BypassStrategy,
    val passed: Int,
    val total: Int,
    val avgLatencyMs: Long
)

object StrategyScanner {

    private val testHosts = listOf(
        "www.youtube.com",
        "i.ytimg.com",
        "redirector.googlevideo.com"
    )

    suspend fun scanAndSelectBest(context: Context): StrategyScanResult? = withContext(Dispatchers.IO) {
        VpnStateHolder.setScanning(true)
        VpnStateHolder.log("=== Запуск автоподбора стратегии ===")
        val results = mutableListOf<StrategyScanResult>()
        val runner = ByeDpiRunner(context)
        val hasNative = runner.isBinaryAvailable()
        VpnStateHolder.log(if (hasNative) "Режим теста: нативный ByeDPI" else "Режим теста: Kotlin fallback (нет libbyedpi.so)")

        try {
            val resolvedIps = mutableMapOf<String, String>()
            for (host in testHosts) {
                val ip = resolveHostClean(host)
                if (ip != null) {
                    resolvedIps[host] = ip
                } else {
                    VpnStateHolder.log("DNS ошибка для $host")
                }
            }

            if (resolvedIps.isEmpty()) {
                VpnStateHolder.setScanStatus("Нет доступа к DNS — проверь интернет")
                return@withContext null
            }

            val strategies = BypassStrategy.entries
            for ((index, strategy) in strategies.withIndex()) {
                VpnStateHolder.setScanStatus("Проверка ${index + 1}/${strategies.size}: ${strategy.title}...")
                var passed = 0
                var totalTime = 0L

                val testPort = 10809
                var fallbackProxy: DpiBypassProxy? = null
                val nativeStarted = if (hasNative) runner.start(testPort, strategy) else false
                if (!nativeStarted) {
                    fallbackProxy = DpiBypassProxy(port = testPort).apply { start() }
                    kotlinx.coroutines.delay(150)
                }

                try {
                    val rtts = coroutineScope {
                        resolvedIps.map { (host, ip) ->
                            async {
                                testHostViaSocks(host, ip, testPort)
                            }
                        }.awaitAll()
                    }
                    for (rtt in rtts) {
                        if (rtt != null) {
                            passed++
                            totalTime += rtt
                        }
                    }
                } finally {
                    if (nativeStarted) runner.stop()
                    fallbackProxy?.stop()
                }

                val avgMs = if (passed > 0) totalTime / passed else 9999L
                val result = StrategyScanResult(strategy, passed, resolvedIps.size, avgMs)
                results.add(result)
                VpnStateHolder.log("[${index + 1}/${strategies.size}] ${strategy.title}: $passed/${resolvedIps.size} (${avgMs} мс)")
            }

            val best = results.sortedWith(
                compareByDescending<StrategyScanResult> { it.passed }
                    .thenBy { it.avgLatencyMs }
            ).firstOrNull()

            if (best != null && best.passed > 0) {
                VpnStateHolder.setStrategy(best.strategy)
                val summary = "Лучшая: ${best.strategy.title} (${best.passed}/${best.total}, ${best.avgLatencyMs} мс)"
                VpnStateHolder.setScanStatus(summary)
                VpnStateHolder.log("Итог -> $summary")
            } else {
                VpnStateHolder.setScanStatus("0/${resolvedIps.size} — см. причину в журнале ниже")
                VpnStateHolder.log("Автоподбор: ни одна стратегия не прошла проверку")
            }

            best
        } finally {
            VpnStateHolder.setScanning(false)
        }
    }

    private fun resolveHostClean(host: String): String? {
        try {
            val url = URL("https://dns.google/resolve?name=$host&type=A")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 2500
                readTimeout = 2500
            }
            if (conn.responseCode == 200) {
                val json = JSONObject(conn.inputStream.bufferedReader().readText())
                val answers = json.optJSONArray("Answer")
                if (answers != null) {
                    for (i in 0 until answers.length()) {
                        val obj = answers.getJSONObject(i)
                        if (obj.optInt("type") == 1) {
                            return obj.optString("data")
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }

        return try {
            InetAddress.getByName(host).hostAddress
        } catch (_: Exception) {
            null
        }
    }

    private fun testHostViaSocks(host: String, ip: String, socksPort: Int): Long? {
        var socksSocket: Socket? = null
        var sslSocket: SSLSocket? = null
        return try {
            val start = System.currentTimeMillis()
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
            socksSocket = Socket(proxy)
            socksSocket.soTimeout = 2500
            socksSocket.connect(InetSocketAddress(ip, 443), 2500)

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = factory.createSocket(socksSocket, host, 443, true) as SSLSocket
            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(host))
            sslSocket.sslParameters = params
            sslSocket.soTimeout = 3000
            sslSocket.startHandshake()

            // Отправляем лёгкий HTTP GET, чтобы проверить, не режет ли ТСПУ передачу данных после TLS
            val out = sslSocket.outputStream
            out.write("GET /generate_204 HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
            out.flush()
            val firstRespByte = sslSocket.inputStream.read()
            if (firstRespByte == -1) return null

            System.currentTimeMillis() - start
        } catch (e: Exception) {
            val msg = e.message ?: e.javaClass.simpleName
            VpnStateHolder.log("  [$host] отказ: $msg")
            null
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { socksSocket?.close() } catch (_: Exception) {}
        }
    }
}
