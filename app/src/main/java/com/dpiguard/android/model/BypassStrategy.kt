package com.dpiguard.android.model

enum class SplitMode {
    TLS_RECORD_SNI,
    TLS_TRIPLE_RECORD,
    TCP_FIRST_BYTE,
    TCP_MICRO_CHUNKS,
    TCP_SNI_MID,
    DIRECT_QUIC_BLOCK
}

enum class BypassStrategy(
    val title: String,
    val description: String,
    val byedpiArgs: List<String>,
    val mode: SplitMode,
    val splitDelayMs: Long,
    val blockQuic: Boolean
) {
    RF_DISORDER_OOB(
        title = "РФ: Disorder + OOB + TLSRec (Топ для ТСПУ)",
        description = "Комбинация --oob 1+s --disorder 3+s --tlsrec 1+s + --auto=torst",
        byedpiArgs = listOf("--oob", "1+s", "--disorder", "3+s", "--tlsrec", "1+s", "--udp-fake", "1", "--auto=torst", "--timeout", "3", "--split", "1"),
        mode = SplitMode.TLS_TRIPLE_RECORD,
        splitDelayMs = 6L,
        blockQuic = true
    ),
    RF_FAKE_TTL8(
        title = "РФ: Fake TLS (TTL 8) + TLSRec",
        description = "Отправляет фейковый ClientHello с TTL=8 и режет запись по SNI",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "8", "--fake-tls-mod", "rand", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI,
        splitDelayMs = 8L,
        blockQuic = true
    ),
    RF_FAKE_TTL5_DISORDER(
        title = "РФ: Fake TLS (TTL 5) + Disorder",
        description = "Агрессивный режим с TTL=5 и обратным порядком пакетов",
        byedpiArgs = listOf("--disorder", "1", "--fake", "-1", "--ttl", "5", "--fake-tls-mod", "rand", "--udp-fake", "2"),
        mode = SplitMode.TCP_MICRO_CHUNKS,
        splitDelayMs = 3L,
        blockQuic = true
    ),
    RF_DISOOB_SNI(
        title = "РФ: DisOOB + Split по SNI",
        description = "Обратная отправка с OOB-байтом внутри домена SNI",
        byedpiArgs = listOf("--disoob", "1+s", "--split", "1", "--tlsrec", "3+s", "--udp-fake", "1"),
        mode = SplitMode.TCP_FIRST_BYTE,
        splitDelayMs = 8L,
        blockQuic = true
    ),
    RF_AUTO_MULTI(
        title = "РФ: Авто-перебор групп (Torst)",
        description = "Начинает с TLSRec+Disorder, при сбросе переключается на OOB+Fake",
        byedpiArgs = listOf("--disorder", "1", "--tlsrec", "1+s", "--auto=torst", "--timeout", "2", "--oob", "1+s", "--fake", "-1", "--ttl", "7"),
        mode = SplitMode.TLS_TRIPLE_RECORD,
        splitDelayMs = 6L,
        blockQuic = true
    ),
    RF_SPLIT_SOFT(
        title = "РФ: Мягкий Split + HttpMod",
        description = "Без OOB и Fake, только TLSRec + модификация HTTP Host",
        byedpiArgs = listOf("--split", "1+s", "--tlsrec", "1+s", "--mod-http", "h,d"),
        mode = SplitMode.TCP_SNI_MID,
        splitDelayMs = 8L,
        blockQuic = false
    )
}
