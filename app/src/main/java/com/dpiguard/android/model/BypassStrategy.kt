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
    S01_FAKE_TTL8_TLSREC(
        title = "01. Fake TLS (TTL 8) + TLSRec",
        description = "Фейковый ClientHello (TTL=8) + резка TLS-записи по SNI",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "8", "--fake-tls-mod", "rand", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 8L, blockQuic = true
    ),
    S02_FAKE_GOOGLE_TTL6(
        title = "02. ALT1: Fake Google (TTL 6) + Disorder",
        description = "Фейк SNI www.google.com (TTL=6) + Disorder + TLSRec",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "6", "--fake-sni", "www.google.com", "--fake-tls-mod", "rand", "--disorder", "1", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S03_FAKE_YARU_TTL10(
        title = "03. ALT2 (5G/LTE): Fake ya.ru (TTL 10) + OOB",
        description = "Для мобильных сетей (TTL=10) с фейковым SNI ya.ru и OOB",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "10", "--fake-sni", "ya.ru", "--fake-tls-mod", "rand", "--oob", "1+s", "--tlsrec", "1+s", "--udp-fake", "2"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S04_FAKE_VK_TTL8(
        title = "04. ALT3: Fake vk.com (TTL 8) + Split SNI",
        description = "Фейк SNI vk.com (TTL=8) + резка по середине SNI",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "8", "--fake-sni", "vk.com", "--fake-tls-mod", "rand", "--split", "0+sm", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 8L, blockQuic = true
    ),
    S05_FAKE_OZON_TTL9(
        title = "05. ALT4: Fake ozon.ru (TTL 9) + Disorder",
        description = "Фейк SNI ozon.ru (TTL=9) + Disorder + модификация HTTP",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "9", "--fake-sni", "ozon.ru", "--fake-tls-mod", "rand", "--disorder", "1+s", "--mod-http", "h,d", "--udp-fake", "2"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S06_FAKE_RUTUBE_TTL7(
        title = "06. ALT5: Fake rutube.ru (TTL 7) + DisOOB",
        description = "Фейк SNI rutube.ru (TTL=7) + обратный OOB по SNI",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "7", "--fake-sni", "rutube.ru", "--fake-tls-mod", "rand", "--disoob", "1+s", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S07_DISOOB_SNI(
        title = "07. DisOOB + Split 1 + TLSRec 3+s",
        description = "Обратная отправка с OOB-байтом внутри SNI",
        byedpiArgs = listOf("--disoob", "1+s", "--split", "1", "--tlsrec", "3+s", "--udp-fake", "1"),
        mode = SplitMode.TCP_FIRST_BYTE, splitDelayMs = 8L, blockQuic = true
    ),
    S08_OOB_DISORDER(
        title = "08. OOB + Disorder + TLSRec (Torst)",
        description = "Классический OOB 1+s + Disorder 3+s + авто-сброс",
        byedpiArgs = listOf("--oob", "1+s", "--disorder", "3+s", "--tlsrec", "1+s", "--udp-fake", "1", "--auto=torst", "--split", "1"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S09_FAKE_TTL3(
        title = "09. Дом. инет: Fake TTL 3 + TLSRec",
        description = "Ультра-низкий TTL=3 для проводных провайдеров (РФ)",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "3", "--fake-tls-mod", "rand", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 8L, blockQuic = true
    ),
    S10_FAKE_TTL4_SPLIT(
        title = "10. Дом. инет: Fake TTL 4 + Split+Disorder",
        description = "TTL=4 + split 1+s и disorder 3+s",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "4", "--fake-tls-mod", "rand", "--split", "1+s", "--disorder", "3+s", "--udp-fake", "1"),
        mode = SplitMode.TCP_MICRO_CHUNKS, splitDelayMs = 4L, blockQuic = true
    ),
    S11_FAKE_TTL5_DISORDER(
        title = "11. Fake TTL 5 + Disorder 1",
        description = "TTL=5 с обратным порядком пакетов + 2 UDP-фейка",
        byedpiArgs = listOf("--disorder", "1", "--fake", "-1", "--ttl", "5", "--fake-tls-mod", "rand", "--udp-fake", "2"),
        mode = SplitMode.TCP_MICRO_CHUNKS, splitDelayMs = 4L, blockQuic = true
    ),
    S12_FAKE_TTL12_MOBILE(
        title = "12. Мобильный 4G/5G: Fake TTL 12 + OOB",
        description = "Высокий TTL=12 для сложных мобильных маршрутов",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "12", "--fake-sni", "www.google.com", "--fake-tls-mod", "rand", "--oob", "1+s", "--udp-fake", "2"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S13_FAKE_ORIG_TTL7(
        title = "13. Fake Orig ClientHello (TTL 7)",
        description = "Использует оригинальный ClientHello как фейк с TTL=7",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "7", "--fake-tls-mod", "orig", "--disorder", "1+s", "--tlsrec", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 6L, blockQuic = true
    ),
    S14_MULTI_SPLIT_SNI(
        title = "14. Мульти-сплит (без Fake/TTL)",
        description = "Дробит TLS в нескольких точках + Disorder — без TTL",
        byedpiArgs = listOf("--split", "1", "--split", "2+s", "--disorder", "1+s", "--tlsrec", "1+s", "--mod-http", "h,d", "--udp-fake", "1"),
        mode = SplitMode.TCP_MICRO_CHUNKS, splitDelayMs = 4L, blockQuic = true
    ),
    S15_SPLIT_MID_SNI(
        title = "15. Сплит ровно по центру SNI (0+sm)",
        description = "Разделяет пакет и TLS-запись ровно посередине домена",
        byedpiArgs = listOf("--split", "0+sm", "--tlsrec", "0+sm", "--disorder", "1", "--udp-fake", "1"),
        mode = SplitMode.TCP_SNI_MID, splitDelayMs = 8L, blockQuic = true
    ),
    S16_AUTO_TORST_FALLBACK(
        title = "16. Авто-перебор (Torst -> OOB+Fake)",
        description = "Сначала TLSRec+Disorder, при сбросе — OOB + Fake TTL=8",
        byedpiArgs = listOf("--disorder", "1", "--tlsrec", "1+s", "--auto=torst", "--oob", "1+s", "--fake", "-1", "--ttl", "8", "--udp-fake", "1"),
        mode = SplitMode.TLS_TRIPLE_RECORD, splitDelayMs = 6L, blockQuic = true
    ),
    S17_AUTO_SSLERR(
        title = "17. Авто-перебор (SSL Err -> Fake TTL 6)",
        description = "При ошибке TLS переключается на Fake TTL=6 + DisOOB",
        byedpiArgs = listOf("--split", "1+s", "--auto=ssl_err", "--fake", "-1", "--ttl", "6", "--fake-sni", "ya.ru", "--disoob", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 6L, blockQuic = true
    ),
    S18_DISOOB_ONLY(
        title = "18. Чистый DisOOB (1+s и 3+s)",
        description = "Только обратный OOB в двух точках без Fake/TTL",
        byedpiArgs = listOf("--disoob", "1+s", "--split", "3+s", "--mod-http", "h,d,r", "--udp-fake", "1"),
        mode = SplitMode.TCP_FIRST_BYTE, splitDelayMs = 6L, blockQuic = true
    ),
    S19_OOB_ONLY(
        title = "19. Чистый OOB + TLSRec + HttpMod",
        description = "OOB на 1-м байте и внутри SNI + подмена HTTP-заголовков",
        byedpiArgs = listOf("--oob", "1", "--oob", "2+s", "--tlsrec", "1+s", "--mod-http", "h,d", "--udp-fake", "1"),
        mode = SplitMode.TCP_FIRST_BYTE, splitDelayMs = 6L, blockQuic = true
    ),
    S20_TLSMINOR_SPLIT(
        title = "20. TLS Minor + Fake TTL 8 + Split",
        description = "Меняет минорную версию TLS-записи + Fake TTL=8",
        byedpiArgs = listOf("--fake", "-1", "--ttl", "8", "--fake-tls-mod", "rand", "--tlsminor", "3", "--split", "1+s", "--udp-fake", "1"),
        mode = SplitMode.TLS_RECORD_SNI, splitDelayMs = 6L, blockQuic = true
    ),
    S21_SOFT_NO_QUIC(
        title = "21. Мягкий Split + HttpMod (без OOB/Fake)",
        description = "Минимальное вмешательство, не блокирует QUIC/игры",
        byedpiArgs = listOf("--split", "1+s", "--tlsrec", "1+s", "--mod-http", "h,d"),
        mode = SplitMode.TCP_SNI_MID, splitDelayMs = 8L, blockQuic = false
    )
}
