package com.dpiguard.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.dpiguard.android.MainActivity
import com.dpiguard.android.R
import com.dpiguard.android.proxy.DpiBypassProxy
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.File

class DpiVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.dpiguard.android.START"
        const val ACTION_STOP = "com.dpiguard.android.STOP"
        private const val CHANNEL_ID = "dpi_guard_vpn"
        private const val NOTIFICATION_ID = 1001
        private const val TUN_MTU = 8500
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null
    private var proxy: DpiBypassProxy? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> {
                startVpn()
                START_STICKY
            }
        }
    }

    private fun startVpn() {
        if (VpnStateHolder.state.value == ConnectionState.CONNECTED) return

        VpnStateHolder.setState(ConnectionState.CONNECTING)
        VpnStateHolder.resetStats()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        try {
            val dns = VpnStateHolder.dnsServer.value
            val builder = Builder()
                .setSession("DPI Guard")
                .setMtu(TUN_MTU)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(dns)
                .addDisallowedApplication(packageName)

            tunInterface = builder.establish()
            val pfd = tunInterface
            if (pfd == null) {
                VpnStateHolder.log("Не удалось создать TUN-интерфейс")
                stopVpn()
                return
            }

            proxy = DpiBypassProxy(port = 10808, scope = serviceScope).apply { start() }

            val configFile = File(cacheDir, "hev-socks5-tunnel.yml")
            val configText = buildString {
                appendLine("tunnel:")
                appendLine("  mtu: $TUN_MTU")
                appendLine("socks5:")
                appendLine("  port: 10808")
                appendLine("  address: 127.0.0.1")
                appendLine("  udp: 'udp'")
                appendLine("misc:")
                appendLine("  task-stack-size: 81920")
            }
            configFile.writeText(configText)

            val started = TProxyService.TProxyStartService(configFile.absolutePath, pfd.fd)
            if (!started) {
                VpnStateHolder.log("Ошибка запуска hev-socks5-tunnel")
                stopVpn()
                return
            }

            VpnStateHolder.setState(ConnectionState.CONNECTED)
            VpnStateHolder.log("Туннель активен (DNS: $dns)")
        } catch (e: Exception) {
            VpnStateHolder.log("Ошибка запуска VPN: ${e.message}")
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        } catch (_: Exception) {
        }

        proxy?.stop()
        proxy = null

        try {
            tunInterface?.close()
        } catch (_: Exception) {
        }
        tunInterface = null

        VpnStateHolder.setState(ConnectionState.DISCONNECTED)
        VpnStateHolder.log("VPN остановлен")

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DPI Guard VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Локальный обход DPI"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, DpiVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DPI Guard активен")
            .setContentText("Обход ТСПУ включён")
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(openIntent)
            .addAction(0, "Отключить", stopIntent)
            .setOngoing(true)
            .build()
    }
}
