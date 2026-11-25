package com.dpiguard.android.model

enum class BypassStrategy(
    val title: String,
    val description: String,
    val splitOffset: Int,
    val splitDelayMs: Long,
    val disorderChunks: Boolean
) {
    TLS_SPLIT_2(
        title = "TLS Split (2 байта)",
        description = "Делит TLS ClientHello на 2-м байте — базовый режим для большинства провайдеров",
        splitOffset = 2,
        splitDelayMs = 5L,
        disorderChunks = false
    ),
    TLS_SPLIT_SNI(
        title = "TLS Split + Пауза",
        description = "Делит первый пакет пополам с задержкой 15 мс",
        splitOffset = 1,
        splitDelayMs = 15L,
        disorderChunks = true
    ),
    HTTP_AND_TLS(
        title = "HTTP Host + TLS",
        description = "Фрагментация и TLS ClientHello, и HTTP-запросов",
        splitOffset = 3,
        splitDelayMs = 8L,
        disorderChunks = false
    )
}
