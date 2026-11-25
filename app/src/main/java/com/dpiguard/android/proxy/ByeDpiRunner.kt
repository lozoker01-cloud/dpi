package com.dpiguard.android.proxy

import android.content.Context
import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.vpn.VpnStateHolder
import java.io.File

/**
 * Запускает нативный движок ByeDPI (libbyedpi.so) из nativeLibraryDir.
 */
class ByeDpiRunner(private val context: Context) {

    private var process: Process? = null

    fun isBinaryAvailable(): Boolean {
        val bin = File(context.applicationInfo.nativeLibraryDir, "libbyedpi.so")
        return bin.exists() && bin.canExecute()
    }

    fun start(port: Int, strategy: BypassStrategy): Boolean {
        stop()
        val bin = File(context.applicationInfo.nativeLibraryDir, "libbyedpi.so")
        if (!bin.exists()) {
            VpnStateHolder.log("Внимание: libbyedpi.so не найден в APK, запуск Kotlin-прокси")
            return false
        }

        val cmd = mutableListOf(
            bin.absolutePath,
            "-i", "127.0.0.1",
            "-p", port.toString(),
            "-N" // --no-domain (чтобы не блокировать поток синхронным DNS)
        )
        cmd.addAll(strategy.byedpiArgs)

        return try {
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            process = pb.start()
            Thread.sleep(80)
            val alive = process?.isAlive == true
            if (alive) {
                VpnStateHolder.log("ByeDPI запущен на 127.0.0.1:$port")
            } else {
                val err = process?.inputStream?.bufferedReader()?.readText()?.take(200) ?: ""
                VpnStateHolder.log("ByeDPI завершился сразу: $err")
            }
            alive
        } catch (e: Exception) {
            VpnStateHolder.log("Ошибка запуска ByeDPI: ${e.message}")
            false
        }
    }

    fun stop() {
        try {
            process?.destroy()
            process = null
        } catch (_: Exception) {
        }
    }
}
