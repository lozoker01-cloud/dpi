package com.dpiguard.android.model

enum class BypassStrategy(
    val title: String,
    val description: String,
    val splitAtSni: Boolean,
    val tlsRecordSplit: Boolean,
    val splitOffset: Int,
    val splitDelayMs: Long,
    val blockQuic: Boolean
) {
    RF_TSPU_DEFAULT(
        title = "РФ (ТСПУ): YouTube + Discord",
        description = "Режет TLS Record пополам внутри SNI + блокирует QUIC (UDP/443) для перехода на TCP",
        splitAtSni = true,
        tlsRecordSplit = true,
        splitOffset = 2,
        splitDelayMs = 8L,
        blockQuic = true
    ),
    RF_SOFT_SPLIT(
        title = "РФ: Мягкий TLS Split (1 байт)",
        description = "Делит первый TCP-пакет на 1-м байте + TLS Record Split без блокировки QUIC",
        splitAtSni = false,
        tlsRecordSplit = true,
        splitOffset = 1,
        splitDelayMs = 10L,
        blockQuic = false
    ),
    TLS_TCP_SEGMENTS(
        title = "TCP-сегментация (2 байта)",
        description = "Классическое деление первого TCP-сегмента на 2-м байте и середине SNI",
        splitAtSni = true,
        tlsRecordSplit = false,
        splitOffset = 2,
        splitDelayMs = 12L,
        blockQuic = true
    )
}
