package com.dpiguard.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.dpiguard.android.databinding.ActivityMainBinding
import com.dpiguard.android.model.BypassStrategy
import com.dpiguard.android.vpn.ConnectionState
import com.dpiguard.android.vpn.DpiVpnService
import com.dpiguard.android.vpn.VpnStateHolder
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            VpnStateHolder.log("Пользователь отклонил разрешение на VPN")
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        requestNotificationPermissionIfNeeded()
        setupStrategySpinner()
        setupDnsChips()
        setupButtons()
        observeState()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun setupStrategySpinner() {
        val strategies = BypassStrategy.entries
        val titles = strategies.map { it.title }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, titles)
        binding.spinnerStrategy.adapter = adapter
        binding.spinnerStrategy.setSelection(strategies.indexOf(VpnStateHolder.strategy.value))

        binding.spinnerStrategy.setOnItemSelectedListener(object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                val selected = strategies[position]
                VpnStateHolder.setStrategy(selected)
                binding.tvStrategyDesc.text = selected.description
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        })
    }

    private fun setupDnsChips() {
        binding.chipGroupDns.setOnCheckedStateChangeListener { _, checkedIds ->
            when (checkedIds.firstOrNull()) {
                R.id.chipDnsCloudflare -> VpnStateHolder.setDnsServer("1.1.1.1")
                R.id.chipDnsGoogle -> VpnStateHolder.setDnsServer("8.8.8.8")
                R.id.chipDnsQuad9 -> VpnStateHolder.setDnsServer("9.9.9.9")
            }
        }
    }

    private fun setupButtons() {
        binding.btnToggleVpn.setOnClickListener {
            when (VpnStateHolder.state.value) {
                ConnectionState.DISCONNECTED -> prepareAndStartVpn()
                ConnectionState.CONNECTED, ConnectionState.CONNECTING -> stopVpnService()
            }
        }

        binding.btnClearLogs.setOnClickListener {
            VpnStateHolder.clearLogs()
        }
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, DpiVpnService::class.java).apply {
            action = DpiVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, DpiVpnService::class.java).apply {
            action = DpiVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun observeState() {
        lifecycleScope.launch {
            VpnStateHolder.state.collect { state ->
                when (state) {
                    ConnectionState.DISCONNECTED -> {
                        binding.tvStatus.text = "Отключено"
                        binding.tvStatus.setTextColor(getColor(R.color.status_off))
                        binding.btnToggleVpn.text = "Включить защиту"
                    }
                    ConnectionState.CONNECTING -> {
                        binding.tvStatus.text = "Запуск..."
                        binding.tvStatus.setTextColor(getColor(R.color.status_wait))
                        binding.btnToggleVpn.text = "Остановить"
                    }
                    ConnectionState.CONNECTED -> {
                        binding.tvStatus.text = "Активно • 127.0.0.1:10808"
                        binding.tvStatus.setTextColor(getColor(R.color.status_on))
                        binding.btnToggleVpn.text = "Отключить"
                    }
                }
            }
        }

        lifecycleScope.launch {
            VpnStateHolder.packetsHandled.collect { count ->
                binding.tvStats.text = "Обработано соединений: $count"
            }
        }

        lifecycleScope.launch {
            VpnStateHolder.logs.collect { entries ->
                binding.tvLogs.text = if (entries.isEmpty()) {
                    "Логи появятся после запуска..."
                } else {
                    entries.joinToString("\n")
                }
            }
        }
    }
}
