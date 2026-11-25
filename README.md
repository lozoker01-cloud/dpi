# DPI Guard — Android DPI Bypass App

Лёгкое Android-приложение на Kotlin для локального обхода DPI (без root-прав) через `VpnService` и встроенный локальный прокси с фрагментацией TLS ClientHello и HTTP-заголовков.

> **Важно:** В проекте реализован полноценный локальный SOCKS5/HTTP-прокси (`127.0.0.1:10808`) с разбиением TLS ClientHello и HTTP Host, а также каркас `VpnService` с UI на Material 3 и сборочным пайплайном для GitHub Actions. Для прозрачного перехвата всего TCP/UDP-трафика в `VpnService` без настроек прокси в системе/браузере рекомендуется подключить нативный `hev-socks5-tunnel` в `DpiVpnService.kt` (комментарии с точкой интеграции оставлены в коде).

## Как собрать APK

### Способ 1: Через GitHub Actions (без установки Android Studio)
1. Создай новый репозиторий на GitHub и загрузи в него все файлы из этой папки.
2. Перейди во вкладку **Actions** -> **Build Android APK** -> **Run workflow** (или просто сделай `git push` в ветку `main`).
3. После завершения сборки скачай готовый `app-debug.apk` из раздела **Artifacts**.

### Способ 2: Локально в Android Studio
1. Открой папку `dpi-guard-android` в **Android Studio** (Ladybug / Koala или новее).
2. Дождись синхронизации Gradle (потребуется JDK 17 и Android SDK 34).
3. Нажми **Build -> Build Bundle(s) / APK(s) -> Build APK(s)**.
4. Готовый файл появится в `app/build/outputs/apk/debug/app-debug.apk`.
