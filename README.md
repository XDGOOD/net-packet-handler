# AEGS v6 "Titan" — Ultra High-Speed Stealth Protocol 🛡️⚡

[![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Edition](https://img.shields.io/badge/Edition-v6.0%20Titan-blueviolet.svg)](#)
[![Status](https://img.shields.io/badge/Status-Release%20Ready-success.svg)](#)

> ⚡ **AEGS v6 Titan Core Edition** — высокоскоростной (300–900+ Мбит/с), криптографически стойкий транспортный протокол с полной защитой от блокировок DPI и ТСПУ. Предназначен для развертывания на персональных серверах, домашних роутерах (OpenWrt) и рабочих станциях.
> 
> 🌐 **Мобильное приложение (Android APK) и распределённый кластер (10+ Гбит/с):**  
> Официальное мобильное приложение и разработка enterprise multi-node архитектуры ведутся в репозитории: **[AEGS Global Edition (XDGOOD/AEGS-Global-)](https://github.com/XDGOOD/AEGS-Global-)**.

---

## 🧠 Что такое AEGS v6 Titan?

**AEGS** — это защищённый транспортный протокол нового поколения, спроектированный для преодоления систем глубокой фильтрации пакетов (DPI, ТСПУ, GFW, Cloudflare Magic Firewall) и статистических анализаторов трафика (Anti-ML / AI), которые легко блокируют стандартные протоколы WireGuard, OpenVPN и простые обфускации.

---

## 🛡 Архитектура и технологии скрытности

### 1. 🧠 State-Machine Pre-Bypass («AEGS Illusion»)
Перед отправкой `HANDSHAKE_INIT` клиент передает 1–3 decoy-пакета, точно имитирующих **RFC 5389 STUN Binding Requests** или **RFC 9000 QUIC Initial** (≥1200 байт). DPI классифицирует соединение как доверенный WebRTC/STUN или HTTP/3 трафик и отключает углубленный анализ потока.

### 2. 🎭 Семантический паддинг («Bimodal Shaping» — Anti-ML)
Вместо равномерного случайного шума протокол формирует бимодальный профиль реального видеостриминга:
* Малые пакеты (≤200 B: ACK, DNS, TCP SYN) дополняются до **~256 B** (профиль QUIC ACK).
* Большие пакеты (>200 B) дополняются до **~1350 B** (полный MTU QUIC).
* 5% случайного шума (512–768 B) для защиты от фингерпринтинга распределения.

### 3. 👻 Active Chaffing (Защита от тайминг-анализа)
При простое канала (>500 мс) клиент генерирует зашифрованные фиктивные chaff-пакеты (флаг `0x80`). Сервер проверяет криптографическую подпись Poly1305 и бесшумно отбрасывает их. Для провайдера туннель выглядит как непрерывный видеозвонок или голосовая сессия.

### 4. 🛡 Cryptographic Blackhole (Защита от активного сканирования)
При получении некорректных зондов от сетевых сканеров сервер отвечает аутентичными QUIC-пакетами (Version Negotiation, Retry, Connection Close) с нулевым коэффициентом усиления (0.0x amplification на мелкие зонды).

### 5. 🔀 Port Hopping
Периодическая смена UDP-портов по алгоритму HMAC-SHA256 на основе сессионного ключа для обхода точечной блокировки портов.

### 6. ⚡ Zero-RTT Session Resumption
Мгновенное возобновление сессии (<5 мс) по зашифрованному 96-байтному `ResumptionToken` без повторного тяжелого вычисления Curve25519 ECDH.

### 7. 🔒 Fail-Closed Kill-Switch & DNS Leak Shield
Аппаратная изоляция через выделенные цепочки сетевого фильтра (iptables / WinFilter) с блокировкой открытого 53 порта и принудительным туннельным DNS (`10.8.0.1`).

---

## 📡 Спецификация пакетов на проводе

* **HANDSHAKE_INIT** (72 байта): `type(1)` + `reserved(7)` + `key_id(8)` + `ephemeral_pk(32)` + `timestamp_ms(8)` + `mac(16, HMAC-SHA256(MasterKey))`
* **HANDSHAKE_RESP** (80 байт): `type(1)` + `reserved(7)` + `session_id(8)` + `server_epk(32)` + `encrypted_config(16)` + `aead_tag(16, Poly1305)`
* **DATA packet**: `hdr_iv(12)` + `masked_hdr(16, ChaCha20)` + `[junk/chaff]` + `aead_nonce(12)` + `ChaCha20-Poly1305(frame)`
* **Frame**: `plen(2)` + `ip_packet(plen)` + `bimodal_padding` (целевые ~256B / ~1350B)

---

## 📊 Сравнительная таблица

| Функция | WireGuard | AmneziaWG | XTLS-Reality | **AEGS v6 Titan** |
|---|---|---|---|---|
| Сигнатура заголовка на проводе | ❌ Статическая | ⚠️ Маскированная | N/A (TCP) | ✅ **Zero signatures (рандомный IV + маска)** |
| Обход DPI State-Machine | ❌ Нет | ⚠️ Случайный мусор | ⚠️ TLS ClientHello | ✅ **Illusion (RFC 5389 STUN + RFC 9000 QUIC)** |
| Мимикрия протокола | ❌ Нет | ❌ Нет | ⚠️ TLS | ✅ **RFC 9000/9369 QUIC Initial Evasion** |
| Защита от нейросетей (Pad) | ❌ Нет | ⚠️ Равномерный | ❌ Нет | ✅ **Бимодальный шейпинг (~256B / ~1350B)** |
| Защита от тайминг-анализа | ❌ Нет | ❌ Нет | ❌ Нет | ✅ **Active Chaffing (флаг 0x80)** |
| Защита от активных сканеров | ❌ Нет | ⚠️ DNS FORMERR | ✅ TLS Camouflage | ✅ **Cryptographic Blackhole (0.0x amp)** |
| Perfect Forward Secrecy (PFS) | ✅ Noise IK | ✅ Noise IK | ✅ TLS 1.3 | ✅ **X25519 ECDH на каждую сессию + 0-RTT** |
| Пакетный конвейер | ⚠️ Стандартный | ⚠️ Стандартный | ⚠️ Стандартный | ✅ **Zero-Copy `sendmmsg`/`recvmmsg` (до 900+ Мбит/с)** |
| Jumbo MTU | ❌ До 1420B | ❌ До 1420B | ❌ Стандартный | ✅ **До 9000B Jumbo MTU + AIMD Pacing** |

---

## 🚀 Быстрый запуск

### Сервер (Linux)
```bash
git clone https://github.com/XDGOOD/net-packet-handler
cd net-packet-handler
./manage.sh install        # Сборка, настройка сети и запуск службы systemd
./manage.sh add-user alice # Добавление пользователя и вывод токена
```

### Клиенты

* **Windows:** Запустите `tools/AEGS.bat` или графический интерфейс `tools/aegs_app.py`.
* **Домашний роутер (OpenWrt):** Выполните `scripts/aegs_openwrt.sh`.
* **Linux / macOS (CLI):**
  ```bash
  ./build/aegis_client <IP_СЕРВЕРА> 50001 <ВАШ_ТОКЕН>
  ```
* **Мобильный клиент Android:**  
  Доступен в официальном репозитории **[XDGOOD/AEGS-Global-](https://github.com/XDGOOD/AEGS-Global-)**.

---

## 🧪 Тестирование и верификация

Запуск полного тестового набора безопасности и устойчивости к атакам:
```bash
python tests/test_suite_v4.py
python tests/run_attack_tests.py
```
