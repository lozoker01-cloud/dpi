package com.dpiguard.android.proxy

import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress

/**
 * Локальный SOCKS5 (TCP CONNECT + UDP ASSOCIATE) прокси с обходом DPI (ТСПУ).
 * Слушает на 127.0.0.1:10808.
 */
class DpiBypassProxy(
    private val port: Int = 10808,
    private val scope: CoroutineScope
) {
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    fun start() {
        if (acceptJob?.isActive == true) return
        acceptJob = scope.launch(Dispatchers.IO) {
            try {
                serverSocket = ServerSocket(port, 128, InetAddress.getByName("127.0.0.1"))
                VpnStateHolder.log("Прокси запущен: 127.0.0.1:$port")

                while (isActive) {
                    val client = serverSocket?.accept() ?: break
                    launch(Dispatchers.IO) {
                        handleClient(client)
                    }
                }
            } catch (e: Exception) {
                if (isActive) {
                    VpnStateHolder.log("Ошибка прокси: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        acceptJob?.cancel()
        acceptJob = null
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
        VpnStateHolder.log("Прокси остановлен")
    }

    private suspend fun handleClient(client: Socket) {
        client.use { clientSocket ->
            clientSocket.tcpNoDelay = true
            val input = clientSocket.getInputStream()
            val output = clientSocket.getOutputStream()

            val ver = input.read()
            if (ver != 0x05) return

            val nMethods = input.read()
            if (nMethods <= 0) return
            val methods = ByteArray(nMethods)
            if (!readFully(input, methods)) return

            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            val header = ByteArray(4)
            if (!readFully(input, header)) return
            val cmd = header[1].toInt() and 0xFF
            val atyp = header[3].toInt() and 0xFF

            val targetHost: String = when (atyp) {
                0x01 -> {
                    val addr = ByteArray(4)
                    if (!readFully(input, addr)) return
                    InetAddress.getByAddress(addr).hostAddress ?: return
                }
                0x03 -> {
                    val len = input.read()
                    if (len <= 0) return
                    val domain = ByteArray(len)
                    if (!readFully(input, domain)) return
                    String(domain, Charsets.UTF_8)
                }
                0x04 -> {
                    val addr = ByteArray(16)
                    if (!readFully(input, addr)) return
                    InetAddress.getByAddress(addr).hostAddress ?: return
                }
                else -> return
            }

            val portBytes = ByteArray(2)
            if (!readFully(input, portBytes)) return
            val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            when (cmd) {
                0x01 -> handleTcpConnect(input, output, targetHost, targetPort)
                0x03 -> handleUdpAssociate(input, output)
                else -> {
                    output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.flush()
                }
            }
        }
    }

    private suspend fun handleTcpConnect(
        input: InputStream,
        output: OutputStream,
        targetHost: String,
        targetPort: Int
    ) {
        val remote = Socket()
        try {
            remote.tcpNoDelay = true
            remote.connect(InetSocketAddress(targetHost, targetPort), 10000)

            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            VpnStateHolder.incrementPackets()
            relayWithDpiBypass(input, output, remote, targetHost, targetPort)
        } catch (_: Exception) {
            try {
                output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
            } catch (_: Exception) {
            }
        } finally {
            try {
                remote.close()
            } catch (_: Exception) {
            }
        }
    }

    private suspend fun handleUdpAssociate(
        tcpInput: InputStream,
        tcpOutput: OutputStream
    ) {
        val localUdp = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val outboundUdp = DatagramSocket()
        try {
            val boundPort = localUdp.localPort
            val pHi = ((boundPort shr 8) and 0xFF).toByte()
            val pLo = (boundPort and 0xFF).toByte()

            // Отвечаем локальным адресом 127.0.0.1:boundPort
            tcpOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pHi, pLo))
            tcpOutput.flush()

            var clientUdpAddr: SocketAddress? = null
            val strategy = VpnStateHolder.strategy.value

            val clientToRemote = scope.launch(Dispatchers.IO) {
                val buf = ByteArray(65535)
                while (isActive) {
                    val pkt = DatagramPacket(buf, buf.size)
                    localUdp.receive(pkt)
                    clientUdpAddr = pkt.socketAddress

                    val len = pkt.length
                    if (len < 10) continue

                    val atyp = buf[3].toInt() and 0xFF
                    var offset = 4
                    val dstAddr: InetAddress = when (atyp) {
                        0x01 -> {
                            if (len < offset + 4 + 2) continue
                            val raw = buf.copyOfRange(offset, offset + 4)
                            offset += 4
                            InetAddress.getByAddress(raw)
                        }
                        0x03 -> {
                            val dLen = buf[offset].toInt() and 0xFF
                            offset += 1
                            if (len < offset + dLen + 2) continue
                            val domain = String(buf, offset, dLen, Charsets.UTF_8)
                            offset += dLen
                            InetAddress.getByName(domain)
                        }
                        0x04 -> {
                            if (len < offset + 16 + 2) continue
                            val raw = buf.copyOfRange(offset, offset + 16)
                            offset += 16
                            InetAddress.getByAddress(raw)
                        }
                        else -> continue
                    }

                    val dstPort = ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
                    offset += 2

                    // Блокируем QUIC (UDP 443), чтобы приложения переключились на TCP TLS
                    if (strategy.blockQuic && dstPort == 443) {
                        continue
                    }

                    val payloadLen = len - offset
                    if (payloadLen <= 0) continue

                    val outPkt = DatagramPacket(buf, offset, payloadLen, dstAddr, dstPort)
                    outboundUdp.send(outPkt)
                }
            }

            val remoteToClient = scope.launch(Dispatchers.IO) {
                val buf = ByteArray(65535)
                while (isActive) {
                    val pkt = DatagramPacket(buf, buf.size)
                    outboundUdp.receive(pkt)
                    val target = clientUdpAddr ?: continue

                    val addrBytes = pkt.address.address
                    val atypByte: Byte = if (addrBytes.size == 4) 0x01 else 0x04
                    val headerLen = 4 + addrBytes.size + 2
                    val resp = ByteArray(headerLen + pkt.length)
                    resp[0] = 0x00
                    resp[1] = 0x00
                    resp[2] = 0x00
                    resp[3] = atypByte
                    System.arraycopy(addrBytes, 0, resp, 4, addrBytes.size)
                    resp[4 + addrBytes.size] = ((pkt.port shr 8) and 0xFF).toByte()
                    resp[5 + addrBytes.size] = (pkt.port and 0xFF).toByte()
                    System.arraycopy(pkt.data, pkt.offset, resp, headerLen, pkt.length)

                    localUdp.send(DatagramPacket(resp, resp.size, target))
                }
            }

            // Ждём закрытия управляющего TCP-соединения
            val tmp = ByteArray(64)
            while (tcpInput.read(tmp) != -1) {
                // ignore
            }
            clientToRemote.cancel()
            remoteToClient.cancel()
        } catch (_: Exception) {
        } finally {
            try { localUdp.close() } catch (_: Exception) {}
            try { outboundUdp.close() } catch (_: Exception) {}
        }
    }

    private suspend fun relayWithDpiBypass(
        clientIn: InputStream,
        clientOut: OutputStream,
        remote: Socket,
        targetHost: String,
        targetPort: Int
    ) {
        val remoteOut = remote.getOutputStream()
        val remoteIn = remote.getInputStream()
        val strategy = VpnStateHolder.strategy.value

        val upJob = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(16384)
            var isFirstPacket = true
            try {
                while (true) {
                    val bytesRead = clientIn.read(buffer)
                    if (bytesRead == -1) break

                    if (isFirstPacket && bytesRead > 6) {
                        isFirstPacket = false
                        sendSplitPacket(remoteOut, buffer, bytesRead, strategy, targetHost, targetPort)
                    } else {
                        remoteOut.write(buffer, 0, bytesRead)
                        remoteOut.flush()
                    }
                }
            } catch (_: Exception) {
            }
        }

        val downJob = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(16384)
            try {
                while (true) {
                    val bytesRead = remoteIn.read(buffer)
                    if (bytesRead == -1) break
                    clientOut.write(buffer, 0, bytesRead)
                    clientOut.flush()
                }
            } catch (_: Exception) {
            }
        }

        upJob.join()
        downJob.cancel()
    }

    private suspend fun sendSplitPacket(
        remoteOut: OutputStream,
        data: ByteArray,
        length: Int,
        strategy: BypassStrategy,
        targetHost: String,
        targetPort: Int
    ) {
        val isTls = length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()
        if (isTls) {
            val recordLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
            val sniRange = findSniOffset(data, length)

            // Выбираем точку разреза внутри полезной нагрузки TLS (относительно data[5])
            val payloadSplitPos = if (strategy.splitAtSni && sniRange != null) {
                val midSni = (sniRange.first + sniRange.second) / 2
                (midSni - 5).coerceIn(1, recordLen - 1)
            } else {
                strategy.splitOffset.coerceIn(1, recordLen - 1)
            }

            if (strategy.tlsRecordSplit && 5 + recordLen == length && recordLen > 2) {
                // Режем один TLS ClientHello на 2 валидных TLS-рекорда + разделяем по TCP
                val part1Len = payloadSplitPos
                val part2Len = recordLen - part1Len

                val rec1 = ByteArray(5 + part1Len)
                rec1[0] = 0x16
                rec1[1] = data[1]
                rec1[2] = data[2]
                rec1[3] = ((part1Len shr 8) and 0xFF).toByte()
                rec1[4] = (part1Len and 0xFF).toByte()
                System.arraycopy(data, 5, rec1, 5, part1Len)

                val rec2 = ByteArray(5 + part2Len)
                rec2[0] = 0x16
                rec2[1] = data[1]
                rec2[2] = data[2]
                rec2[3] = ((part2Len shr 8) and 0xFF).toByte()
                rec2[4] = (part2Len and 0xFF).toByte()
                System.arraycopy(data, 5 + part1Len, rec2, 5, part2Len)

                remoteOut.write(rec1)
                remoteOut.flush()
                if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
                remoteOut.write(rec2)
                remoteOut.flush()

                VpnStateHolder.log("TLS Record Split ($part1Len+$part2Len) -> $targetHost:$targetPort")
                return
            } else {
                val splitAt = (5 + payloadSplitPos).coerceIn(1, length - 1)
                remoteOut.write(data, 0, splitAt)
                remoteOut.flush()
                if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
                remoteOut.write(data, splitAt, length - splitAt)
                remoteOut.flush()

                VpnStateHolder.log("TCP Split ($splitAt B) -> $targetHost:$targetPort")
                return
            }
        }

        // Для обычного HTTP режем перед заголовком Host или на 3-м байте
        val splitAt = strategy.splitOffset.coerceIn(1, length - 1)
        remoteOut.write(data, 0, splitAt)
        remoteOut.flush()
        if (strategy.splitDelayMs > 0) delay(strategy.splitDelayMs)
        remoteOut.write(data, splitAt, length - splitAt)
        remoteOut.flush()
    }

    /**
     * Ищет байтовый диапазон SNI-домена в TLS ClientHello.
     */
    private fun findSniOffset(data: ByteArray, length: Int): Pair<Int, Int>? {
        try {
            if (length < 44 || data[5] != 0x01.toByte()) return null
            var pos = 43 // После Random (32 байта)
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

    private fun readFully(input: InputStream, buf: ByteArray): Boolean {
        var offset = 0
        while (offset < buf.size) {
            val read = input.read(buf, offset, buf.size - offset)
            if (read == -1) return false
            offset += read
        }
        return true
    }
}
