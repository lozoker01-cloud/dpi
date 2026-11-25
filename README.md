# DPI Guard — Android DPI Bypass App (РФ / ТСПУ)

Android-приложение на Kotlin для локального обхода DPI без root-прав через `VpnService`, нативный `hev-socks5-tunnel` (TUN -> SOCKS5 TCP+UDP) и встроенный прокси с обходом ТСПУ:
- Разбиение **TLS ClientHello** по границе **SNI** (TLS Record Split + TCP-сегментация).
- Опциональная блокировка **QUIC (UDP/443)**, чтобы YouTube, Chrome и Discord переключались на TCP/443.
- Полноценный проброс **DNS (UDP/53)** через SOCKS5 `UDP ASSOCIATE` на выбранный DNS (`1.1.1.1` / `8.8.8.8` / `9.9.9.9`).

## Как собрать APK

### Через GitHub Actions (проще всего)
1. Загрузи все файлы в репозиторий на GitHub (убедись, что `.github/workflows/build-apk.yml` в корне).
2. Во вкладке **Actions** выбери **Build Android APK** и нажми **Run workflow**.
3. После зелёной галочки скачай `dpi-guard-debug-apk` из блока **Artifacts**.
