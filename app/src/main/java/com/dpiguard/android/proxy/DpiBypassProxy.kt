package com.dpiguard.android.proxy

import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/**
 * Локальный SOCKS5-прокси на 127.0.0.1:10808.
 * Использует CachedThreadPool (без лимита в 64 потока Dispatchers.IO, из-за которого падала скорость).
 * - UDP: пропускает DNS (53) и блокирует QUIC (443) для перехода YouTube на TCP.
 * - TCP: передаёт в нативный ByeDPI (10810) или применяет Kotlin-сплит.
 */
class DpiBypassProxy(
    private val port: Int = 10808,
    private val upstreamSocksPort: Int? = null
) {
    private val executor = Executors.newCachedThreadPool()
    private val dispatcher = executor.asCoroutineDispatcher()
    private val exceptionHandler = CoroutineExceptionHandler { _, _ -> }
    private val proxyScope = CoroutineScope(SupervisorJob() + dispatcher + exceptionHandler)
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    fun start() {
        if (acceptJob?.isActive == true) return
        acceptJob = proxyScope.launch {
            try {
                serverSocket = ServerSocket(port, 512, InetAddress.getByName("127.0.0.1"))
                VpnStateHolder.log("Прокси-шлюз запущен: 127.0.0.1:$port (QUIC блок: ВКЛ)")

                while (isActive) {
                    val client = serverSocket?.accept() ?: break
                    proxyScope.launch {
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
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        proxyScope.cancel()
        try { executor.shutdownNow() } catch (_: Exception) {}
    }

    private suspend fun handleClient(client: Socket) {
        client.use { clientSocket ->
            clientSocket.tcpNoDelay = true
            clientSocket.receiveBufferSize = 65536
            clientSocket.sendBufferSize = 65536
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

            val rawAddrBytes: ByteArray
            val targetHost: String
            when (atyp) {
                0x01 -> {
                    rawAddrBytes = ByteArray(4)
                    if (!readFully(input, rawAddrBytes)) return
                    targetHost = InetAddress.getByAddress(rawAddrBytes).hostAddress ?: return
                }
                0x03 -> {
                    val len = input.read()
                    if (len <= 0) return
                    val domain = ByteArray(len)
                    if (!readFully(input, domain)) return
                    rawAddrBytes = byteArrayOf(len.toByte()) + domain
                    targetHost = String(domain, Charsets.UTF_8)
                }
                0x04 -> {
                    rawAddrBytes = ByteArray(16)
                    if (!readFully(input, rawAddrBytes)) return
                    targetHost = InetAddress.getByAddress(rawAddrBytes).hostAddress ?: return
                }
                else -> return
            }

            val portBytes = ByteArray(2)
            if (!readFully(input, portBytes)) return
            val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            when (cmd) {
                0x01 -> handleTcpConnect(clientSocket, input, output, atyp, rawAddrBytes, portBytes, targetHost, targetPort)
                0x03 -> handleUdpAssociate(input, output)
                else -> {
                    output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.flush()
                }
            }
        }
    }

    private suspend fun handleTcpConnect(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream,
        atyp: Int,
        rawAddrBytes: ByteArray,
        portBytes: ByteArray,
        targetHost: String,
        targetPort: Int
    ) {
        val upPort = upstreamSocksPort
        if (upPort != null) {
            handleTcpViaUpstreamByeDpi(clientSocket, input, output, atyp, rawAddrBytes, portBytes, upPort)
            return
        }

        val remote = Socket()
        try {
            remote.tcpNoDelay = true
            remote.receiveBufferSize = 65536
            remote.sendBufferSize = 65536
            remote.soTimeout = 120000
            remote.connect(InetSocketAddress(targetHost, targetPort), 10000)

            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            VpnStateHolder.incrementPackets()
            relayStreams(clientSocket, input, output, remote, applyKotlinSplit = true)
        } catch (_: Exception) {
            try {
                output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
            } catch (_: Exception) {}
        } finally {
            try { remote.close() } catch (_: Exception) {}
        }
    }

    private suspend fun handleTcpViaUpstreamByeDpi(
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        atyp: Int,
        rawAddrBytes: ByteArray,
        portBytes: ByteArray,
        upPort: Int
    ) {
        val upstream = Socket()
        try {
            upstream.tcpNoDelay = true
            upstream.receiveBufferSize = 65536
            upstream.sendBufferSize = 65536
            upstream.soTimeout = 120000
            upstream.connect(InetSocketAddress("127.0.0.1", upPort), 5000)

            val upIn = upstream.getInputStream()
            val upOut = upstream.getOutputStream()

            upOut.write(byteArrayOf(0x05, 0x01, 0x00))
            upOut.flush()
            val authResp = ByteArray(2)
            if (!readFully(upIn, authResp) || authResp[1] != 0x00.toByte()) {
                clientOut.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOut.flush()
                return
            }

            val req = ByteArrayOutputStream()
            req.write(byteArrayOf(0x05, 0x01, 0x00, atyp.toByte()))
            req.write(rawAddrBytes)
            req.write(portBytes)
            upOut.write(req.toByteArray())
            upOut.flush()

            val repHead = ByteArray(4)
            if (!readFully(upIn, repHead)) return
            val repAtyp = repHead[3].toInt() and 0xFF
            val repAddr = when (repAtyp) {
                0x01 -> ByteArray(4).also { if (!readFully(upIn, it)) return }
                0x03 -> {
                    val l = upIn.read()
                    if (l <= 0) return
                    byteArrayOf(l.toByte()) + ByteArray(l).also { if (!readFully(upIn, it)) return }
                }
                0x04 -> ByteArray(16).also { if (!readFully(upIn, it)) return }
                else -> return
            }
            val repPort = ByteArray(2)
            if (!readFully(upIn, repPort)) return

            val fullRep = ByteArrayOutputStream()
            fullRep.write(repHead)
            fullRep.write(repAddr)
            fullRep.write(repPort)
            clientOut.write(fullRep.toByteArray())
            clientOut.flush()

            if (repHead[1] != 0x00.toByte()) return

            VpnStateHolder.incrementPackets()
            relayStreams(clientSocket, clientIn, clientOut, upstream, applyKotlinSplit = false)
        } catch (_: Exception) {
            try {
                clientOut.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOut.flush()
            } catch (_: Exception) {}
        } finally {
            try { upstream.close() } catch (_: Exception) {}
        }
    }

    private suspend fun handleUdpAssociate(
        tcpInput: InputStream,
        tcpOutput: OutputStream
    ) {
        val localUdp = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val outboundUdp = DatagramSocket()
        try {
            localUdp.soTimeout = 45000
            outboundUdp.soTimeout = 45000

            val boundPort = localUdp.localPort
            val pHi = ((boundPort shr 8) and 0xFF).toByte()
            val pLo = (boundPort and 0xFF).toByte()

            tcpOutput.write(
                byteArrayOf(
                    0x05.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(),
                    127.toByte(), 0.toByte(), 0.toByte(), 1.toByte(), pHi, pLo
                )
            )
            tcpOutput.flush()

            val clientUdpAddr = AtomicReference<SocketAddress?>(null)
            val strategy = VpnStateHolder.strategy.value

            val clientToRemote = proxyScope.launch {
                val buf = ByteArray(4096)
                while (isActive) {
                    val pkt = DatagramPacket(buf, buf.size)
                    localUdp.receive(pkt)
                    clientUdpAddr.set(pkt.socketAddress)

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

                    if (strategy.blockQuic && dstPort == 443) continue

                    val payloadLen = len - offset
                    if (payloadLen <= 0) continue

                    outboundUdp.send(DatagramPacket(buf, offset, payloadLen, dstAddr, dstPort))
                }
            }

            val remoteToClient = proxyScope.launch {
                val buf = ByteArray(4096)
                while (isActive) {
                    val pkt = DatagramPacket(buf, buf.size)
                    outboundUdp.receive(pkt)
                    val target = clientUdpAddr.get() ?: continue

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

            val tmp = ByteArray(64)
            while (tcpInput.read(tmp) != -1) {
            }
            clientToRemote.cancel()
            remoteToClient.cancel()
        } catch (_: Exception) {
        } finally {
            try { localUdp.close() } catch (_: Exception) {}
            try { outboundUdp.close() } catch (_: Exception) {}
        }
    }

    private suspend fun relayStreams(
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        remote: Socket,
        applyKotlinSplit: Boolean
    ) {
        val remoteOut = remote.getOutputStream()
        val remoteIn = remote.getInputStream()
        val strategy = VpnStateHolder.strategy.value

        val upJob = proxyScope.launch {
            val buffer = ByteArray(65536)
            var isFirstPacket = applyKotlinSplit
            try {
                while (true) {
                    val bytesRead = clientIn.read(buffer)
                    if (bytesRead == -1) {
                        try { remote.shutdownOutput() } catch (_: Exception) {}
                        break
                    }
                    if (isFirstPacket) {
                        isFirstPacket = false
                        DpiSplitter.sendWithStrategy(remoteOut, buffer, bytesRead, strategy)
                    } else {
                        remoteOut.write(buffer, 0, bytesRead)
                        remoteOut.flush()
                    }
                }
            } catch (_: Exception) {}
        }

        val downJob = proxyScope.launch {
            val buffer = ByteArray(65536)
            try {
                while (true) {
                    val bytesRead = remoteIn.read(buffer)
                    if (bytesRead == -1) {
                        try { clientSocket.shutdownOutput() } catch (_: Exception) {}
                        break
                    }
                    clientOut.write(buffer, 0, bytesRead)
                    clientOut.flush()
                }
            } catch (_: Exception) {}
        }

        // Ждём завершения ответа сервера, затем сразу освобождаем клиентский сокет
        downJob.join()
        try { clientSocket.close() } catch (_: Exception) {}
        upJob.cancel()
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
