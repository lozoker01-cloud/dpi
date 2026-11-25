package com.dpiguard.android.proxy

import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
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
import java.util.concurrent.atomic.AtomicReference

/**
 * Резервный локальный SOCKS5-прокси на Kotlin (используется, если нативный libbyedpi.so недоступен).
 */
class DpiBypassProxy(
    private val port: Int = 10808
) {
    private val exceptionHandler = CoroutineExceptionHandler { _, _ -> }
    private val proxyScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + exceptionHandler)
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    fun start() {
        if (acceptJob?.isActive == true) return
        acceptJob = proxyScope.launch {
            try {
                serverSocket = ServerSocket(port, 256, InetAddress.getByName("127.0.0.1"))
                VpnStateHolder.log("Kotlin-прокси запущен: 127.0.0.1:$port")

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
            remote.receiveBufferSize = 65536
            remote.sendBufferSize = 65536
            remote.soTimeout = 120000
            remote.connect(InetSocketAddress(targetHost, targetPort), 10000)

            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            VpnStateHolder.incrementPackets()
            relayWithDpiBypass(input, output, remote)
        } catch (_: Exception) {
            try {
                output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
            } catch (_: Exception) {}
        } finally {
            try { remote.close() } catch (_: Exception) {}
        }
    }

    private suspend fun handleUdpAssociate(
        tcpInput: InputStream,
        tcpOutput: OutputStream
    ) {
        val localUdp = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val outboundUdp = DatagramSocket()
        try {
            localUdp.soTimeout = 60000
            outboundUdp.soTimeout = 60000

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

    private suspend fun relayWithDpiBypass(
        clientIn: InputStream,
        clientOut: OutputStream,
        remote: Socket
    ) {
        val remoteOut = remote.getOutputStream()
        val remoteIn = remote.getInputStream()
        val strategy = VpnStateHolder.strategy.value

        val upJob = proxyScope.launch {
            val buffer = ByteArray(32768)
            var isFirstPacket = true
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
            val buffer = ByteArray(32768)
            try {
                while (true) {
                    val bytesRead = remoteIn.read(buffer)
                    if (bytesRead == -1) break
                    clientOut.write(buffer, 0, bytesRead)
                    clientOut.flush()
                }
            } catch (_: Exception) {}
        }

        upJob.join()
        downJob.join()
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
