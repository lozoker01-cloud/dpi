# DPI Guard — Android DPI Bypass App (РФ / ТСПУ)

Android-приложение на Kotlin с нативным движком **ByeDPI (`libbyedpi.so`)** и **hev-socks5-tunnel** для обхода ТСПУ без root-прав.

## Что внутри
- Нативный движок **ByeDPI (`hufrea/byedpi`)**, компилируемый в `.github/workflows/build-apk.yml` для `arm64-v8a` и `armeabi-v7a`: поддержка `--oob`, `--fake`, `--ttl`, `--disorder`, `--tlsrec`, `--auto=torst` и `--udp-fake`.
- **Автоподбор стратегии**: тестирует каждую стратегию через реальный `libbyedpi.so` + `SSLSocket` на `www.youtube.com`, `i.ytimg.com`, `discord.com` и выбирает рабочую с минимальным пингом.
- **Важно:** при загрузке на GitHub обязательно обнови `.github/workflows/build-apk.yml`, чтобы в APK собрался нативный `libbyedpi.so`.
