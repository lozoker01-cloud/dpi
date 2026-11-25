package com.dpiguard.android.proxy

import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.model.SplitMode
import kotlinx.coroutines.delay
import java.io.OutputStream

object DpiSplitter {

    suspend fun sendWithStrategy(
        out: OutputStream,
        data: ByteArray,
        length: Int,
        strategy: BypassStrategy
    ): String? {
        if (strategy.mode == SplitMode.DIRECT_QUIC_BLOCK || length <= 6) {
            out.write(data, 0, length)
            out.flush()
            return null
        }

        val isTls = data[0] == 0x16.toByte() && data[1] == 0x03.toByte()
        if (!isTls) {
            val splitAt = 3.coerceIn(1, length - 1)
            out.write(data, 0, splitAt)
            out.flush()
            if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
            out.write(data, splitAt, length - splitAt)
            out.flush()
            return null
        }

        val recordLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        val sniRange = findSniOffset(data, length)
        val canRecordSplit = recordLen > 4 && (5 + recordLen == length)

        when (strategy.mode) {
            SplitMode.TLS_TRIPLE_RECORD -> {
                if (canRecordSplit) {
                    val midPayload = if (sniRange != null) {
                        ((sniRange.first + sniRange.second) / 2 - 5).coerceIn(2, recordLen - 1)
                    } else {
                        (recordLen / 2).coerceIn(2, recordLen - 1)
                    }
                    writeTlsRecord(out, data[1], data[2], data, 5, 1)
                    if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
                    writeTlsRecord(out, data[1], data[2], data, 6, midPayload - 1)
                    if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
                    writeTlsRecord(out, data[1], data[2], data, 5 + midPayload, recordLen - midPayload)
                    return "TLS 3-Record"
                } else {
                    sendTcpMicroChunks(out, data, length, sniRange, strategy.splitDelayMs)
                    return "TCP-чанки"
                }
            }

            SplitMode.TLS_RECORD_SNI -> {
                if (canRecordSplit) {
                    val splitPayload = if (sniRange != null) {
                        ((sniRange.first + sniRange.second) / 2 - 5).coerceIn(1, recordLen - 1)
                    } else {
                        2.coerceIn(1, recordLen - 1)
                    }
                    writeTlsRecord(out, data[1], data[2], data, 5, splitPayload)
                    if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
                    writeTlsRecord(out, data[1], data[2], data, 5 + splitPayload, recordLen - splitPayload)
                    return "TLS 2-Record"
                } else {
                    val splitAt = (sniRange?.let { (it.first + it.second) / 2 } ?: 7).coerceIn(1, length - 1)
                    sendTwoTcpSegments(out, data, length, splitAt, strategy.splitDelayMs)
                    return "TCP SNI Split"
                }
            }

            SplitMode.TCP_MICRO_CHUNKS -> {
                sendTcpMicroChunks(out, data, length, sniRange, strategy.splitDelayMs)
                return "Микро-чанки 2B"
            }

            SplitMode.TCP_FIRST_BYTE -> {
                sendTwoTcpSegments(out, data, length, 1, strategy.splitDelayMs)
                return "TCP 1-Byte Split"
            }

            SplitMode.TCP_SNI_MID -> {
                val splitAt = (sniRange?.let { (it.first + it.second) / 2 } ?: 7).coerceIn(1, length - 1)
                sendTwoTcpSegments(out, data, length, splitAt, strategy.splitDelayMs)
                return "TCP SNI Mid"
            }

            SplitMode.DIRECT_QUIC_BLOCK -> {
                out.write(data, 0, length)
                out.flush()
                return null
            }
        }
    }

    private fun writeTlsRecord(
        out: OutputStream,
        verMajor: Byte,
        verMinor: Byte,
        src: ByteArray,
        offset: Int,
        len: Int
    ) {
        val pkt = ByteArray(5 + len)
        pkt[0] = 0x16
        pkt[1] = verMajor
        pkt[2] = verMinor
        pkt[3] = ((len shr 8) and 0xFF).toByte()
        pkt[4] = (len and 0xFF).toByte()
        System.arraycopy(src, offset, pkt, 5, len)
        out.write(pkt)
        out.flush()
    }

    private suspend fun sendTwoTcpSegments(
        out: OutputStream,
        data: ByteArray,
        length: Int,
        splitAt: Int,
        delayMs: Long
    ) {
        val pos = splitAt.coerceIn(1, length - 1)
        out.write(data, 0, pos)
        out.flush()
        if (delayMs > 0) delay(delayMs)
        out.write(data, pos, length - pos)
        out.flush()
    }

    private suspend fun sendTcpMicroChunks(
        out: OutputStream,
        data: ByteArray,
        length: Int,
        sniRange: Pair<Int, Int>?,
        delayMs: Long
    ) {
        val endChunkZone = (sniRange?.second ?: 64).coerceAtMost(length)
        var pos = 0
        while (pos < endChunkZone) {
            val step = 2.coerceAtMost(endChunkZone - pos)
            out.write(data, pos, step)
            out.flush()
            pos += step
            if (delayMs > 0) delay(delayMs)
        }
        if (pos < length) {
            out.write(data, pos, length - pos)
            out.flush()
        }
    }

    fun findSniOffset(data: ByteArray, length: Int): Pair<Int, Int>? {
        try {
            if (length < 44 || data[5] != 0x01.toByte()) return null
            var pos = 43
            if (pos >= length) return null
            val sessionIdLen = data[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            if (pos + 2 > length) return null

            val cipherSuitesLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos + 1 > length) return null

            val compMethodsLen = data[pos].toInt() and 0xFF
            pos += 1 + compMethodsLen
            if (pos + 2 > length) return null

            val extTotalLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = (pos + extTotalLen).coerceAtMost(length)

            while (pos + 4 <= extEnd) {
                val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
                pos += 4
                if (extType == 0x0000 && pos + extLen <= extEnd && extLen > 5) {
                    val nameStart = pos + 5
                    val nameLen = ((data[pos + 3].toInt() and 0xFF) shl 8) or (data[pos + 4].toInt() and 0xFF)
                    val nameEnd = (nameStart + nameLen).coerceAtMost(extEnd)
                    if (nameEnd > nameStart) return Pair(nameStart, nameEnd)
                }
                pos += extLen
            }
        } catch (_: Exception) {
        }
        return null
    }
}
