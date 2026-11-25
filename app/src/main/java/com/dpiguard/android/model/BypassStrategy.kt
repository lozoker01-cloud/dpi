package com.dpiguard.android.model

enum class SplitMode {
    TLS_RECORD_SNI,       // 2 TLS-рекорда по середине SNI
    TLS_TRIPLE_RECORD,    // 3 TLS-рекорда: 1 байт + до середины SNI + остаток
    TCP_FIRST_BYTE,       // 1-й байт отдельно + остаток
    TCP_MICRO_CHUNKS,     // Нарезка заголовка и SNI по 2 байта
    TCP_SNI_MID,          // 2 TCP-сегмента по середине SNI
    DIRECT_QUIC_BLOCK     // Без резки TCP, только блок QUIC + чистый DNS
}

enum class BypassStrategy(
    val title: String,
    val description: String,
    val mode: SplitMode,
    val splitDelayMs: Long,
    val blockQuic: Boolean
) {
    RF_TRIPLE_RECORD(
        title = "РФ: Тройной TLS Split + блок QUIC",
        description = "Делит ClientHello на 3 TLS-рекорда (1B + SNI + остаток) — лучший режим для ТСПУ и видео",
        mode = SplitMode.TLS_TRIPLE_RECORD,
        splitDelayMs = 6L,
        blockQuic = true
    ),
    RF_RECORD_SNI(
        title = "РФ: TLS Record Split (SNI) + блок QUIC",
        description = "Режет TLS-запись на 2 части ровно внутри домена SNI и отключает QUIC",
        mode = SplitMode.TLS_RECORD_SNI,
        splitDelayMs = 8L,
        blockQuic = true
    ),
    RF_MICRO_CHUNKS(
        title = "РФ: Микро-чанки по 2 байта + блок QUIC",
        description = "Отправляет заголовок и SNI маленькими TCP-пакетами по 2 байта",
        mode = SplitMode.TCP_MICRO_CHUNKS,
        splitDelayMs = 2L,
        blockQuic = true
    ),
    RF_FIRST_BYTE(
        title = "РФ: Сплит на 1-м байте + блок QUIC",
        description = "Классический 1-байтовый TCP-сплит первого пакета",
        mode = SplitMode.TCP_FIRST_BYTE,
        splitDelayMs = 10L,
        blockQuic = true
    ),
    RF_SOFT_NO_QUIC(
        title = "Мягкий: TLS Split (без блока QUIC)",
        description = "Режет TCP по середине SNI, но оставляет UDP/443 (для звонков и игр)",
        mode = SplitMode.TCP_SNI_MID,
        splitDelayMs = 8L,
        blockQuic = false
    ),
    RF_QUIC_ONLY(
        title = "Только блок QUIC + DNS",
        description = "Не режет TCP, только переводит YouTube/Chrome с QUIC на TCP и меняет DNS",
        mode = SplitMode.DIRECT_QUIC_BLOCK,
        splitDelayMs = 0L,
        blockQuic = true
    )
}
