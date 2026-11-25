package com.dpiguard.android.proxy

import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

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
        "discord.com"
    )

    suspend fun scanAndSelectBest(): StrategyScanResult? = withContext(Dispatchers.IO) {
        VpnStateHolder.setScanning(true)
        VpnStateHolder.log("=== Запуск автоподбора стратегии ===")
        val results = mutableListOf<StrategyScanResult>()

        try {
            val strategies = BypassStrategy.entries
            for ((index, strategy) in strategies.withIndex()) {
                VpnStateHolder.setScanStatus("Проверка ${index + 1}/${strategies.size}: ${strategy.title}...")
                var passed = 0
                var totalTime = 0L

                for (host in testHosts) {
                    val rtt = testHostWithStrategy(host, strategy)
                    if (rtt != null) {
                        passed++
                        totalTime += rtt
                    }
                }

                val avgMs = if (passed > 0) totalTime / passed else 9999L
                val result = StrategyScanResult(strategy, passed, testHosts.size, avgMs)
                results.add(result)
                VpnStateHolder.log("Тест [${strategy.title}]: $passed/${testHosts.size} (${avgMs} мс)")
            }

            val best = results.sortedWith(
                compareByDescending<StrategyScanResult> { it.passed }
                    .thenBy { it.avgLatencyMs }
            ).firstOrNull()

            if (best != null && best.passed > 0) {
                VpnStateHolder.setStrategy(best.strategy)
                val summary = "Выбрана: ${best.strategy.title} (${best.passed}/${best.total}, ${best.avgLatencyMs} мс)"
                VpnStateHolder.setScanStatus(summary)
                VpnStateHolder.log("Итог автоподбора -> $summary")
            } else {
                VpnStateHolder.setScanStatus("Не удалось пройти рукопожатие — проверь интернет")
                VpnStateHolder.log("Автоподбор не нашёл рабочего ответа от серверов")
            }

            best
        } finally {
            VpnStateHolder.setScanning(false)
        }
    }

    private suspend fun testHostWithStrategy(host: String, strategy: BypassStrategy): Long? {
        val socket = Socket()
        return try {
            val start = System.currentTimeMillis()
            socket.tcpNoDelay = true
            socket.soTimeout = 2500
            socket.connect(InetSocketAddress(host, 443), 2500)

            val clientHello = buildTlsClientHello(host)
            val out = socket.getOutputStream()
            DpiSplitter.sendWithStrategy(out, clientHello, clientHello.size, strategy)

            val inp = socket.getInputStream()
            val firstByte = inp.read()
            val secondByte = inp.read()
            if (firstByte == 0x16 && secondByte == 0x03) {
                System.currentTimeMillis() - start
            } else {
                null
            }
        } catch (_: Exception) {
            null
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun buildTlsClientHello(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val sniEntryLen = 3 + hostBytes.size
        val sniListLen = sniEntryLen
        val sniExtPayloadLen = 2 + sniListLen
        val sniExtTotalLen = 4 + sniExtPayloadLen

        val body = ByteArrayOutputStream()
        // Legacy version TLS 1.2 (0x0303)
        body.write(byteArrayOf(0x03, 0x03))
        // Random 32 bytes
        val random = ByteArray(32)
        SecureRandom().nextBytes(random)
        body.write(random)
        // Session ID length = 0
        body.write(0x00)
        // Cipher Suites (2 bytes length + 2 suites)
        body.write(byteArrayOf(0x00, 0x04, 0x13, 0x01, 0xC0.toByte(), 0x2F))
        // Compression methods (1 byte length = 1, null = 0)
        body.write(byteArrayOf(0x01, 0x00))
        // Extensions total length
        body.write((sniExtTotalLen shr 8) and 0xFF)
        body.write(sniExtTotalLen and 0xFF)
        // SNI extension (0x0000)
        body.write(byteArrayOf(0x00, 0x00))
        body.write((sniExtPayloadLen shr 8) and 0xFF)
        body.write(sniExtPayloadLen and 0xFF)
        body.write((sniListLen shr 8) and 0xFF)
        body.write(sniListLen and 0xFF)
        body.write(0x00) // host_name
        body.write((hostBytes.size shr 8) and 0xFF)
        body.write(hostBytes.size and 0xFF)
        body.write(hostBytes)

        val hsBody = body.toByteArray()
        val hsLen = hsBody.size
        val recLen = 4 + hsLen

        val packet = ByteArrayOutputStream()
        // TLS Record Header
        packet.write(byteArrayOf(0x16, 0x03, 0x01))
        packet.write((recLen shr 8) and 0xFF)
        packet.write(recLen and 0xFF)
        // Handshake ClientHello (0x01) + 3-byte length
        packet.write(0x01)
        packet.write((hsLen shr 16) and 0xFF)
        packet.write((hsLen shr 8) and 0xFF)
        packet.write(hsLen and 0xFF)
        packet.write(hsBody)
        return packet.toByteArray()
    }
}
