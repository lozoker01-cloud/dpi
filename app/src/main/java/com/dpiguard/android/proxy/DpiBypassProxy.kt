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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Локальный SOCKS5 / HTTP CONNECT прокси с фрагментацией первого TCP-пакета (TLS ClientHello / HTTP).
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
                serverSocket = ServerSocket(port, 64, InetAddress.getByName("127.0.0.1"))
                VpnStateHolder.log("Локальный прокси запущен на 127.0.0.1:$port")

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
        VpnStateHolder.log("Локальный прокси остановлен")
    }

    private suspend fun handleClient(client: Socket) {
        client.use { clientSocket ->
            clientSocket.tcpNoDelay = true
            val input = clientSocket.getInputStream()
            val output = clientSocket.getOutputStream()

            val firstByte = input.read()
            if (firstByte == -1) return

            if (firstByte == 0x05) {
                handleSocks5(clientSocket, input, output)
            } else {
                // Поддержка HTTP CONNECT или обычного HTTP
                handleHttpProxy(firstByte, input, output)
            }
        }
    }

    private suspend fun handleSocks5(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream
    ) {
        val nMethods = input.read()
        if (nMethods <= 0) return
        val methods = ByteArray(nMethods)
        if (input.read(methods) != nMethods) return

        // Отвечаем: без аутентификации (0x00)
        output.write(byteArrayOf(0x05, 0x00))
        output.flush()

        val header = ByteArray(4)
        if (input.read(header) != 4) return
        val cmd = header[1].toInt() and 0xFF
        val atyp = header[3].toInt() and 0xFF
        if (cmd != 0x01) {
            output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            return
        }

        val targetHost: String = when (atyp) {
            0x01 -> {
                val addr = ByteArray(4)
                input.read(addr)
                InetAddress.getByAddress(addr).hostAddress ?: return
            }
            0x03 -> {
                val len = input.read()
                val domain = ByteArray(len)
                input.read(domain)
                String(domain, Charsets.UTF_8)
            }
            0x04 -> {
                val addr = ByteArray(16)
                input.read(addr)
                InetAddress.getByAddress(addr).hostAddress ?: return
            }
            else -> return
        }

        val portBytes = ByteArray(2)
        if (input.read(portBytes) != 2) return
        val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        val remote = Socket()
        try {
            remote.tcpNoDelay = true
            remote.connect(InetSocketAddress(targetHost, targetPort), 8000)

            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            VpnStateHolder.incrementPackets()
            relayWithDpiBypass(input, output, remote, targetHost)
        } catch (e: Exception) {
            output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()
        } finally {
            try {
                remote.close()
            } catch (_: Exception) {
            }
        }
    }

    private suspend fun handleHttpProxy(
        firstByte: Int,
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val rest = mutableListOf(firstByte.toByte())
        val buf = ByteArray(4096)
        val read = clientIn.read(buf)
        if (read > 0) {
            for (i in 0 until read) rest.add(buf[i])
        }
        val requestStr = String(rest.toByteArray(), Charsets.UTF_8)
        val firstLine = requestStr.lineSequence().firstOrNull() ?: return
        val parts = firstLine.split(" ")
        if (parts.size < 2 || !parts[0].equals("CONNECT", ignoreCase = true)) return

        val hostPort = parts[1].split(":")
        val host = hostPort[0]
        val port = hostPort.getOrNull(1)?.toIntOrNull() ?: 443

        val remote = Socket()
        try {
            remote.tcpNoDelay = true
            remote.connect(InetSocketAddress(host, port), 8000)
            clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            clientOut.flush()

            VpnStateHolder.incrementPackets()
            relayWithDpiBypass(clientIn, clientOut, remote, host)
        } finally {
            try {
                remote.close()
            } catch (_: Exception) {
            }
        }
    }

    private suspend fun relayWithDpiBypass(
        clientIn: InputStream,
        clientOut: OutputStream,
        remote: Socket,
        targetHost: String
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

                    if (isFirstPacket && bytesRead > strategy.splitOffset + 1) {
                        isFirstPacket = false
                        sendSplitPacket(remoteOut, buffer, bytesRead, strategy, targetHost)
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
        targetHost: String
    ) {
        val isTlsClientHello = length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()
        val splitAt = if (isTlsClientHello) {
            strategy.splitOffset.coerceIn(1, length - 1)
        } else {
            (length / 3).coerceIn(1, length - 1)
        }

        remoteOut.write(data, 0, splitAt)
        remoteOut.flush()

        if (strategy.splitDelayMs > 0) {
            delay(strategy.splitDelayMs)
        }

        if (strategy.disorderChunks && length - splitAt > 4) {
            val mid = splitAt + (length - splitAt) / 2
            remoteOut.write(data, splitAt, mid - splitAt)
            remoteOut.flush()
            delay(3L)
            remoteOut.write(data, mid, length - mid)
            remoteOut.flush()
        } else {
            remoteOut.write(data, splitAt, length - splitAt)
            remoteOut.flush()
        }

        if (isTlsClientHello) {
            VpnStateHolder.log("TLS split ($splitAt B) -> $targetHost")
        }
    }
}
