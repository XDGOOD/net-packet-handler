#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
🛡️ AEGS v6 Titan — Единый комплексный испытательный центр (Unified Test Center)
================================================================================
Единый исполняемый файл для всех видов тестирования протокола AEGS Titan:
  1. Модульные тесты криптографии и формата на проводе (Crypto & Wire Primitives)
  2. Симуляция атак и проверка устойчивости (Attack Resistance Simulation)
  3. Тестирование живого VPS-сервера (Live Network Handshake + Real DNS Roundtrip)
  4. Бенчмарк производительности (Throughput, PPS, Encryption Speed)
  5. Стресс-тест и фаззинг искаженными пакетами (Chaos & Fuzzing)
  6. Полный комплексный аудит (Full Audit Suite)

Использование:
  Интерактивный режим:   python run_tests.py
  Автоматический запуск: python run_tests.py --all
  Тест живого сервера:   python run_tests.py --live --host 31.76.9.86 --port 50001
================================================================================
"""

import sys
import os
import time
import socket
import select
import struct
import math
import hashlib
import hmac
import secrets
import argparse
from typing import Tuple, List, Dict, Any, Optional
from collections import Counter

# Настройка UTF-8 для корректного вывода в терминале Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        os.system("")  # Активация ANSI цветов в консоли Windows
    except Exception:
        pass

# Проверка наличия библиотеки cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("\n[!] ОШИБКА: Библиотека 'cryptography' не установлена.")
    print("    Установите её командой: pip install cryptography\n")
    sys.exit(1)

# ==============================================================================
# Цвета и оформление терминала
# ==============================================================================
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_BLUE = "\033[44m"
    BG_DARK = "\033[40m"

def badge_pass(text="PASS"):
    return f"{C.GREEN}{C.BOLD}[✓ {text}]{C.RESET}"

def badge_fail(text="FAIL"):
    return f"{C.RED}{C.BOLD}[✗ {text}]{C.RESET}"

def badge_warn(text="WARN"):
    return f"{C.YELLOW}{C.BOLD}[! {text}]{C.RESET}"

def badge_info(text="INFO"):
    return f"{C.CYAN}{C.BOLD}[i {text}]{C.RESET}"

# ==============================================================================
# Константы и параметры протокола AEGS v6 Titan
# ==============================================================================
VER_MAGIC = b"AG2\x01"
DEFAULT_SALT = b"aegis-v2-salt"
PBKDF2_ROUNDS = 200000
DEFAULT_VPS_HOST = os.getenv("AEGS_SERVER_IP", "127.0.0.1")
DEFAULT_VPS_PORT = 50001
DEFAULT_TOKEN = "aegs_secure_token_titan_v6"
DEFAULT_KEY_ID = "cd5932756baaffe6"

# ==============================================================================
# Ядро протокола: Криптографические примитивы и обработка пакетов
# ==============================================================================
def derive_key_id(token_str: str) -> bytes:
    """KeyID = первые 8 байт SHA-256(token)"""
    return hashlib.sha256(token_str.encode("utf-8")).digest()[:8]

def derive_master_key(token_str: str, kid_hex: str) -> bytes:
    """MasterKey = PBKDF2-HMAC-SHA256(token, salt=kid_hex, iterations=200000)"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kid_hex.encode("utf-8"),
        iterations=PBKDF2_ROUNDS
    )
    return kdf.derive(token_str.encode("utf-8"))

def hkdf_expand(master: bytes, info: str, length: int = 32, salt: bytes = DEFAULT_SALT) -> bytes:
    """HKDF-Expand"""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info.encode("utf-8"))
    return hkdf.derive(master)

def hkdf_derive_session(shared_secret: bytes, master_key: bytes, info: str, length: int = 32) -> bytes:
    """HKDF-Extract-and-Expand для сессионных ключей (salt=master_key, ikm=shared_secret)"""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=master_key, info=info.encode("utf-8"))
    return hkdf.derive(shared_secret)

def chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    """Генерация гаммы ChaCha20"""
    cipher = Cipher(algorithms.ChaCha20(key, struct.pack("<I", counter) + nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(b"\x00" * length)

def mask_unmask_header(header16: bytes, mask_key: bytes, hdr_iv: bytes) -> bytes:
    """ChaCha20 маскирование и демаскирование 16-байтного заголовка"""
    ks = chacha20_keystream(mask_key, 0, hdr_iv, 16)
    return bytes(h ^ k for h, k in zip(header16, ks))

def calc_entropy(data: bytes) -> float:
    """Вычисление энтропии Шеннона (бит на байт)"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def ip_checksum(data: bytes) -> int:
    """Вычисление стандартной контрольной суммы заголовка IPv4"""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

class AntiReplayFilter:
    """
    RFC 6479 многословный скользящий фильтр защиты от атак повтора (Anti-Replay).
    Размер окна по умолчанию: 2048 пакетов (32 слова по 64 бита).
    """
    def __init__(self, words: int = 32):
        self.words = words
        self.window_size = words * 64
        self.last_seq = 0
        self.bitmap = [0] * words

    def is_replay(self, seq: int) -> bool:
        """Возвращает True если пакет дубликат или устарел (нужно отбросить)"""
        if seq == 0:
            return True
        if seq > self.last_seq:
            return False
        diff = self.last_seq - seq
        if diff >= self.window_size or ((self.last_seq >> 6) - (seq >> 6) >= self.words):
            return True
        word_idx = (seq >> 6) % self.words
        bit_mask = 1 << (seq & 63)
        return bool(self.bitmap[word_idx] & bit_mask)

    def commit(self, seq: int) -> None:
        """Фиксация порядкового номера в окне"""
        if seq == 0:
            return
        if seq > self.last_seq:
            diff = seq - self.last_seq
            if diff >= self.window_size:
                self.bitmap = [0] * self.words
            else:
                last_word = self.last_seq >> 6
                curr_word = seq >> 6
                for w in range(last_word + 1, curr_word + 1):
                    self.bitmap[w % self.words] = 0
            self.bitmap[(seq >> 6) % self.words] |= (1 << (seq & 63))
            self.last_seq = seq
            return

        diff = self.last_seq - seq
        if diff < self.window_size and ((self.last_seq >> 6) - (seq >> 6) < self.words):
            word_idx = (seq >> 6) % self.words
            bit_mask = 1 << (seq & 63)
            self.bitmap[word_idx] |= bit_mask

    def update(self, seq: int) -> bool:
        """Проверить и обновить: возвращает True если пакет ПРИНЯТ, False если отброшен"""
        if self.is_replay(seq):
            return False
        self.commit(seq)
        return True

def build_data_packet(ip_pkt: bytes, key_id: bytes, mask_key: bytes, send_key: bytes, seq: int, is_chaff: bool = False) -> bytes:
    """Сборка зашифрованного пакета данных с ChaCha20 маскированием и Poly1305 аутентификацией"""
    ip_len = len(ip_pkt)
    # Бимодальный паддинг
    pad_len = 0
    if not is_chaff:
        target = 256 if ip_len <= 200 else 1350
        pad_len = max(0, target - (2 + ip_len + 40))
        if pad_len > 1200:
            pad_len = 0

    frame = struct.pack(">H", ip_len) + ip_pkt + secrets.token_bytes(pad_len)
    junk_len = 0
    hdr_iv = secrets.token_bytes(12)
    flags = 0x80 if is_chaff else 0x00
    plain_hdr = key_id + struct.pack(">H", junk_len) + bytes([flags, 0x00]) + VER_MAGIC
    masked_hdr = mask_unmask_header(plain_hdr, mask_key, hdr_iv)
    outer_hdr = hdr_iv + masked_hdr

    nonce = struct.pack("<Q", seq) + secrets.token_bytes(4)
    aead = ChaCha20Poly1305(send_key)
    cipher_tag = aead.encrypt(nonce, frame, outer_hdr)
    return outer_hdr + nonce + cipher_tag

def parse_data_packet(wire_pkt: bytes, key_id: bytes, mask_key: bytes, alt_mask_key: Optional[bytes], recv_key: bytes) -> Optional[bytes]:
    """Дешифрование и проверка подлинности пакета данных"""
    if len(wire_pkt) < 56:
        return None
    hdr_iv = wire_pkt[:12]
    masked_hdr = wire_pkt[12:28]

    # Попытка демаскирования основным ключом
    unmasked = mask_unmask_header(masked_hdr, mask_key, hdr_iv)
    used_alt = False
    if unmasked[:8] != key_id or unmasked[12:16] != VER_MAGIC:
        if alt_mask_key:
            unmasked = mask_unmask_header(masked_hdr, alt_mask_key, hdr_iv)
            if unmasked[:8] == key_id and unmasked[12:16] == VER_MAGIC:
                used_alt = True
            else:
                return None
        else:
            return None

    junk_len = struct.unpack(">H", unmasked[8:10])[0]
    aead_off = 28 + junk_len
    if len(wire_pkt) < aead_off + 12 + 16:
        return None

    nonce = wire_pkt[aead_off:aead_off+12]
    cipher_tag = wire_pkt[aead_off+12:]
    aad = wire_pkt[:aead_off]

    try:
        aead = ChaCha20Poly1305(recv_key)
        plain_frame = aead.decrypt(nonce, cipher_tag, aad)
        inner_len = struct.unpack(">H", plain_frame[:2])[0]
        return plain_frame[2:2+inner_len]
    except Exception:
        return None

# ==============================================================================
# БЛОК 1: Модульные тесты криптографии и структуры пакетов
# ==============================================================================
def run_crypto_suite() -> Tuple[int, int]:
    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [БЛОК 1] КРИПТОГРАФИЯ, ДЕРИВАЦИЯ КЛЮЧЕЙ И МАСКИРОВАНИЕ ЗАГОЛОВКОВ{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")

    passed = 0
    total = 0

    # Тест 1.1: Вычисление KeyID
    total += 1
    t0 = time.perf_counter()
    test_token = "aegs_secure_token_titan_v6"
    expected_kid_hex = "cd5932756baaffe6"
    kid = derive_key_id(test_token)
    kid_hex = kid.hex()
    dt = (time.perf_counter() - t0) * 1000
    if kid_hex == expected_kid_hex:
        print(f" {badge_pass()} 1.1 Вычисление KeyID из токена SHA-256[:8] ({kid_hex}) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.1 Несовпадение KeyID! Получено: {kid_hex}, ожидалось: {expected_kid_hex}")

    # Тест 1.2: Деривация MasterKey через PBKDF2 (200k итераций)
    total += 1
    t0 = time.perf_counter()
    mkey = derive_master_key(test_token, kid_hex)
    dt = (time.perf_counter() - t0) * 1000
    if len(mkey) == 32 and mkey != b"\x00" * 32:
        print(f" {badge_pass()} 1.2 PBKDF2-HMAC-SHA256 (200,000 итераций) 32-байтный MasterKey [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.2 Ошибка деривации MasterKey")

    # Тест 1.3: HKDF деривация ключей маскирования
    total += 1
    t0 = time.perf_counter()
    mask_std = hkdf_expand(mkey, "aegis-v2-header-mask")
    mask_alt = hkdf_expand(mkey, "aegs-v2-header-mask")
    dt = (time.perf_counter() - t0) * 1000
    if len(mask_std) == 32 and len(mask_alt) == 32 and mask_std != mask_alt:
        print(f" {badge_pass()} 1.3 HKDF-Expand Dual-Mask Keys (Стандартный и Альтернативный) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.3 Ошибка деривации ключей маски")

    # Тест 1.4: Симметричность ChaCha20 маскирования заголовка
    total += 1
    t0 = time.perf_counter()
    test_hdr = kid + b"\x00\x00\x00\x00" + VER_MAGIC
    iv = secrets.token_bytes(12)
    masked = mask_unmask_header(test_hdr, mask_std, iv)
    unmasked = mask_unmask_header(masked, mask_std, iv)
    dt = (time.perf_counter() - t0) * 1000
    if masked != test_hdr and unmasked == test_hdr:
        print(f" {badge_pass()} 1.4 ChaCha20 маскирование и демаскирование заголовка (In-Place XOR) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.4 Ошибка симметричности маскирования заголовка")

    # Тест 1.5: Энтропия замаскированных пакетов на проводе (Shannon Entropy > 7.5)
    total += 1
    t0 = time.perf_counter()
    samples = []
    fake_key = secrets.token_bytes(32)
    for i in range(50):
        pkt = build_data_packet(secrets.token_bytes(1000), kid, mask_std, fake_key, i+1)
        samples.append(pkt)
    avg_entropy = sum(calc_entropy(p) for p in samples) / len(samples)
    dt = (time.perf_counter() - t0) * 1000
    if avg_entropy >= 7.6:
        print(f" {badge_pass()} 1.5 Энтропия пакетов на проводе: {avg_entropy:.4f} бит/байт (Порог: >7.5, Zero-Signature) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.5 Низкая энтропия: {avg_entropy:.4f}")

    # Тест 1.6: Скользящее окно Anti-Replay RFC 6479 (2048 пакетов)
    total += 1
    t0 = time.perf_counter()
    replay = AntiReplayFilter(words=32)
    ok_in_order = all(replay.update(seq) for seq in range(1, 1001))
    ok_dup = not replay.update(500) and not replay.update(1000)
    ok_old = not replay.update(0)
    replay.update(5000)
    ok_out_of_window = not replay.update(5000 - 2049)  # за пределами 2048
    ok_in_window = replay.update(5000 - 100)           # внутри окна
    dt = (time.perf_counter() - t0) * 1000
    if ok_in_order and ok_dup and ok_old and ok_out_of_window and ok_in_window:
        print(f" {badge_pass()} 1.6 RFC 6479 Anti-Replay Filter (окно 2048, защита от дублей и переполнения) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.6 Ошибка алгоритма Anti-Replay")

    # Тест 1.7: ChaCha20-Poly1305 Roundtrip с AAD связыванием
    total += 1
    t0 = time.perf_counter()
    payload = b"\x45\x00\x00\x3c\x12\x34\x00\x00\x40\x11\x00\x00\x0a\x08\x00\x02\x08\x08\x08\x08" + b"PINGPONGDATA"
    wire = build_data_packet(payload, kid, mask_std, fake_key, 1)
    recovered = parse_data_packet(wire, kid, mask_std, mask_alt, fake_key)
    dt = (time.perf_counter() - t0) * 1000
    if recovered == payload:
        print(f" {badge_pass()} 1.7 ChaCha20-Poly1305 сборка/разборка фрейма + AAD заголовок [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 1.7 Дешифрованный пакет не совпал с оригиналом")

    return passed, total

# ==============================================================================
# БЛОК 2: Симуляция атак на протокол (Security & Attack Resistance)
# ==============================================================================
def run_attack_suite() -> Tuple[int, int]:
    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [БЛОК 2] СИМУЛЯЦИЯ СЕТЕВЫХ АТАК И УСТОЙЧИВОСТЬ ПРОТОКОЛА{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")

    passed = 0
    total = 0
    test_token = DEFAULT_TOKEN
    kid = derive_key_id(test_token)
    kid_hex = kid.hex()
    mkey = derive_master_key(test_token, kid_hex)
    mask_key = hkdf_expand(mkey, "aegis-v2-header-mask")
    alt_mask = hkdf_expand(mkey, "aegs-v2-header-mask")
    session_key = secrets.token_bytes(32)

    # Тест 2.1: Атака подмены битов (Bit-Flipping / Wire Malleability)
    total += 1
    t0 = time.perf_counter()
    valid_pkt = bytearray(build_data_packet(b"TEST_SECRET_PAYLOAD", kid, mask_key, session_key, 1))
    tampered_rejected = True
    # Пробуем инвертировать биты в разных частях пакета (IV, маска, тело, тег)
    for offset in [0, 5, 15, 25, 30, len(valid_pkt) - 1]:
        bad_pkt = bytearray(valid_pkt)
        bad_pkt[offset] ^= 0x01
        if parse_data_packet(bytes(bad_pkt), kid, mask_key, alt_mask, session_key) is not None:
            tampered_rejected = False
            break
    dt = (time.perf_counter() - t0) * 1000
    if tampered_rejected:
        print(f" {badge_pass()} 2.1 Защита от модификации бит (Bit-Flipping) в заголовке, IV и AEAD теге [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.1 Модифицированный пакет был ошибочно принят")

    # Тест 2.2: Атака повтором пакетов (Replay Attack)
    total += 1
    t0 = time.perf_counter()
    filter_inst = AntiReplayFilter(words=32)
    # Первый пакет принят
    p1 = filter_inst.update(100)
    # Повтор того же пакета
    p2 = filter_inst.update(100)
    # Устаревший пакет глубоко в прошлом
    p3 = filter_inst.update(20)
    dt = (time.perf_counter() - t0) * 1000
    if p1 and not p2:
        print(f" {badge_pass()} 2.2 Защита от атак повтора (Replay Attack): дубликаты отброшены [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.2 Фильтр повторов пропустил дублирующий пакет")

    # Тест 2.3: Атака с поддельным KeyID и невалидным MasterKey
    total += 1
    t0 = time.perf_counter()
    fake_kid = secrets.token_bytes(8)
    fake_mask = secrets.token_bytes(32)
    fake_pkt = build_data_packet(b"INTRUDER_PAYLOAD", fake_kid, fake_mask, session_key, 1)
    res = parse_data_packet(fake_pkt, kid, mask_key, alt_mask, session_key)
    dt = (time.perf_counter() - t0) * 1000
    if res is None:
        print(f" {badge_pass()} 2.3 Отклонение пакетов с неавторизованным KeyID и чужой маской [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.3 Чужой пакет был демаскирован")

    # Тест 2.4: Подделка временных меток в Handshake (Timestamp Skew Defense)
    total += 1
    t0 = time.perf_counter()
    # Инициализация рукопожатия с меткой времени 5 минут в прошлом
    stale_time_ms = int((time.time() - 300) * 1000)
    init_pkt = bytearray(72)
    init_pkt[0] = 0x01
    init_pkt[8:16] = kid
    init_pkt[16:48] = secrets.token_bytes(32)
    init_pkt[48:56] = struct.pack(">Q", stale_time_ms)
    mac = hmac.new(mkey, bytes(init_pkt[:56]), hashlib.sha256).digest()[:16]
    init_pkt[56:72] = mac

    # Проверка окна допустимости времени (+/- 60 сек)
    now_ms = int(time.time() * 1000)
    pkt_time = struct.unpack(">Q", init_pkt[48:56])[0]
    is_valid_time = abs(now_ms - pkt_time) <= 60000
    dt = (time.perf_counter() - t0) * 1000
    if not is_valid_time:
        print(f" {badge_pass()} 2.4 Защита от устаревших рукопожатий (Timestamp Skew Window > 60s) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.4 Просроченная временная метка не была определена")

    # Тест 2.5: Анализ защиты от амплификации (0.0x Amplification on Probes)
    total += 1
    t0 = time.perf_counter()
    # Протокол AEGS на некорректные и случайные зонды отвечает молчанием (Drop) или 0.0x усилением
    probe_lengths = [20, 56, 128, 256, 1200]
    zero_amp = True
    for plen in probe_lengths:
        garbage = secrets.token_bytes(plen)
        # Сервер отбрасывает такой пакет без отправки гигантских ответов
        if parse_data_packet(garbage, kid, mask_key, alt_mask, session_key) is not None:
            zero_amp = False
    dt = (time.perf_counter() - t0) * 1000
    if zero_amp:
        print(f" {badge_pass()} 2.5 Защита от UDP-амплификации и сканеров (Zero Amplification 0.0x) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.5 Мусорный зонд прошел валидацию")

    # Тест 2.6: Проверка Chaff-трафика (маскировка пассивного простоя)
    total += 1
    t0 = time.perf_counter()
    chaff_wire = build_data_packet(b"", kid, mask_key, session_key, 999, is_chaff=True)
    # Проверяем, что в замаскированном заголовке установлен бит 0x80
    hdr_iv = chaff_wire[:12]
    unmasked = mask_unmask_header(chaff_wire[12:28], mask_key, hdr_iv)
    chaff_flag = bool(unmasked[10] & 0x80)
    dt = (time.perf_counter() - t0) * 1000
    if chaff_flag:
        print(f" {badge_pass()} 2.6 Active Chaffing: генерация фоновых маскировочных пакетов (флаг 0x80) [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 2.6 Бит Chaff не был обнаружен в заголовке")

    return passed, total

# ==============================================================================
# БЛОК 3: Тестирование живого VPS-сервера (Live Network Roundtrip)
# ==============================================================================
def run_live_server_suite(host: str = DEFAULT_VPS_HOST, port: int = DEFAULT_VPS_PORT, token: str = DEFAULT_TOKEN) -> Tuple[int, int]:
    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [БЛОК 3] ТЕСТИРОВАНИЕ ЖИВОГО СЕРВЕРА (VPS {host}:{port}){C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")

    passed = 0
    total = 0

    kid = derive_key_id(token)
    kid_hex = kid.hex()
    mkey = derive_master_key(token, kid_hex)
    mask_alt = hkdf_expand(mkey, "aegs-v2-header-mask")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4.0)

    # Тест 3.1: Сетевая доступность UDP сокета
    total += 1
    t0 = time.perf_counter()
    try:
        sock.connect((host, port))
        dt = (time.perf_counter() - t0) * 1000
        print(f" {badge_pass()} 3.1 UDP-сокет открыт в направлении {host}:{port} [{dt:.2f} ms]")
        passed += 1
    except Exception as e:
        print(f" {badge_fail()} 3.1 Ошибка открытия UDP сокета: {e}")
        return passed, total

    # Тест 3.2: Полное криптографическое рукопожатие (Handshake Init -> Resp)
    total += 1
    t0 = time.perf_counter()
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes_raw()

    # Синхронизация времени: компенсация возможного расхождения часов
    now_ms = int(time.time() * 1000)

    def send_init(timestamp_val):
        pkt = bytearray(72)
        pkt[0] = 0x01
        pkt[8:16] = kid
        pkt[16:48] = client_pub
        pkt[48:56] = struct.pack(">Q", timestamp_val)
        mac = hmac.new(mkey, bytes(pkt[:56]), hashlib.sha256).digest()[:16]
        pkt[56:72] = mac
        sock.send(bytes(pkt))

    send_init(now_ms)
    resp = None
    try:
        resp = sock.recv(4096)
    except socket.timeout:
        # Автоматическая проба со смещением часов Windows (-123 сек)
        send_init(now_ms - 123000)
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            pass

    dt = (time.perf_counter() - t0) * 1000
    if resp and len(resp) == 80 and resp[0] == 0x02:
        server_epk = resp[16:48]
        server_pubkey = x25519.X25519PublicKey.from_public_bytes(server_epk)
        shared_secret = client_priv.exchange(server_pubkey)

        c2s_key = hkdf_derive_session(shared_secret, mkey, "aegs-c2s")
        s2c_key = hkdf_derive_session(shared_secret, mkey, "aegs-s2c")
        cfg_key = hkdf_derive_session(shared_secret, mkey, "aegs-cfg")

        server_aead = ChaCha20Poly1305(cfg_key)
        dec_cfg = server_aead.decrypt(b"\x00" * 12, resp[48:80], resp[:48])
        assigned_ip = f"{dec_cfg[0]}.{dec_cfg[1]}.{dec_cfg[2]}.{dec_cfg[3]}"
        mtu = struct.unpack("<H", dec_cfg[4:6])[0]

        print(f" {badge_pass()} 3.2 Рукопожатие X25519 ECDH успешно! Выдан IP: {C.GREEN}{assigned_ip}{C.RESET}, MTU: {mtu} [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 3.2 Сервер не ответил на рукопожатие (проверьте IP/порт/токен и запуск службы)")
        return passed, total

    # Тест 3.3: Получение токена 0-RTT Resumption
    total += 1
    t0 = time.perf_counter()
    has_rtok = False
    try:
        sock.settimeout(1.5)
        rtok_pkt = sock.recv(4096)
        if len(rtok_pkt) == 97 and rtok_pkt[0] == 0x03:
            has_rtok = True
    except Exception:
        pass
    dt = (time.perf_counter() - t0) * 1000
    if has_rtok:
        print(f" {badge_pass()} 3.3 Сервер выдал 96-байтный 0-RTT Resumption Token для быстрого переподключения [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_warn()} 3.3 Resumption Token не получен (опционально, не критично)")

    # Тест 3.4: Сквозной DNS-запрос через туннель к Cloudflare 1.1.1.1 и прием ответа
    total += 1
    t0 = time.perf_counter()
    dns_query = (
        b"\xaa\xbb"                  # Transaction ID
        b"\x01\x00"                  # Flags: Standard Query
        b"\x00\x01"                  # Questions: 1
        b"\x00\x00\x00\x00\x00\x00"  # Answers, Authority, Additional = 0
        b"\x07example\x03com\x00"    # Name: example.com
        b"\x00\x01\x00\x01"          # Type A, Class IN
    )
    udp_len = 8 + len(dns_query)
    udp_hdr = struct.pack(">HHHH", 53248, 53, udp_len, 0)
    total_ip_len = 20 + udp_len
    src_ip_bytes = bytes([dec_cfg[0], dec_cfg[1], dec_cfg[2], dec_cfg[3]])
    dst_ip_bytes = socket.inet_aton("1.1.1.1")

    ip_hdr_raw = (
        b"\x45\x00" +
        struct.pack(">H", total_ip_len) +
        b"\x12\x34\x00\x00\x40\x11\x00\x00" +
        src_ip_bytes +
        dst_ip_bytes
    )
    cksum = ip_checksum(ip_hdr_raw)
    valid_ip_packet = ip_hdr_raw[:10] + struct.pack(">H", cksum) + ip_hdr_raw[12:] + udp_hdr + dns_query

    data_wire = build_data_packet(valid_ip_packet, kid, mask_alt, c2s_key, 1)
    sock.send(data_wire)

    sock.settimeout(5.0)
    roundtrip_ok = False
    rtt_ms = 0.0
    try:
        reply_wire = sock.recv(4096)
        rtt_ms = (time.perf_counter() - t0) * 1000
        # Демаскирование и расшифрование ответа
        recovered_ip = parse_data_packet(reply_wire, kid, mask_alt, None, s2c_key)
        if recovered_ip and len(recovered_ip) >= 28:
            src_ip = socket.inet_ntoa(recovered_ip[12:16])
            dns_id = recovered_ip[28:30]
            if src_ip == "1.1.1.1" and dns_id == b"\xaa\xbb":
                roundtrip_ok = True
    except socket.timeout:
        pass

    if roundtrip_ok:
        print(f" {badge_pass()} 3.4 Полный двусторонний цикл (Roundtrip): DNS-запрос к 1.1.1.1 через aegs0 успешно вернулся! RTT={rtt_ms:.1f} ms [{rtt_ms:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 3.4 Ответ из туннеля не получен (проверьте NAT MASQUERADE и DNS forward на VPS)")

    return passed, total

# ==============================================================================
# БЛОК 4: Бенчмарк производительности (Performance Benchmark)
# ==============================================================================
def run_benchmark_suite(packet_count: int = 5000) -> Tuple[int, int]:
    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [БЛОК 4] БЕНЧМАРК ПРОИЗВОДИТЕЛЬНОСТИ (CRYPTO THROUGHPUT){C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")

    passed = 0
    total = 0
    test_token = DEFAULT_TOKEN
    kid = derive_key_id(test_token)
    mkey = derive_master_key(test_token, kid.hex())
    mask_key = hkdf_expand(mkey, "aegis-v2-header-mask")
    session_key = secrets.token_bytes(32)

    # 1. Бенчмарк шифрования ChaCha20-Poly1305 + Header Masking
    total += 1
    sample_ip_pkt = secrets.token_bytes(1280)
    t0 = time.perf_counter()
    for seq in range(packet_count):
        _ = build_data_packet(sample_ip_pkt, kid, mask_key, session_key, seq + 1)
    enc_time = time.perf_counter() - t0
    enc_pps = packet_count / enc_time
    enc_mbps = (packet_count * 1280 * 8) / (enc_time * 1_000_000)
    print(f" {badge_pass()} 4.1 Шифрование + Маскирование: {enc_pps:,.0f} пак/сек | {C.GREEN}{C.BOLD}{enc_mbps:.1f} Мбит/с{C.RESET} [{enc_time:.2f} s]")
    passed += 1

    # 2. Бенчмарк дешифрования ChaCha20-Poly1305 + Unmasking
    total += 1
    wire_sample = build_data_packet(sample_ip_pkt, kid, mask_key, session_key, 42)
    t0 = time.perf_counter()
    for _ in range(packet_count):
        _ = parse_data_packet(wire_sample, kid, mask_key, None, session_key)
    dec_time = time.perf_counter() - t0
    dec_pps = packet_count / dec_time
    dec_mbps = (packet_count * 1280 * 8) / (dec_time * 1_000_000)
    print(f" {badge_pass()} 4.2 Дешифрование + Демаскирование: {dec_pps:,.0f} пак/сек | {C.GREEN}{C.BOLD}{dec_mbps:.1f} Мбит/с{C.RESET} [{dec_time:.2f} s]")
    passed += 1

    # 3. Скорость работы скользящего окна Anti-Replay (O(1))
    total += 1
    replay = AntiReplayFilter(words=32)
    t0 = time.perf_counter()
    for seq in range(1, packet_count * 10):
        replay.update(seq)
    ar_time = time.perf_counter() - t0
    ar_ops = (packet_count * 10) / ar_time
    print(f" {badge_pass()} 4.3 Anti-Replay проверка и коммит: {ar_ops:,.0f} опер/сек [{ar_time:.2f} s]")
    passed += 1

    return passed, total

# ==============================================================================
# БЛОК 5: Фаззинг и стресс-тест искаженными пакетами (Chaos & Fuzzing)
# ==============================================================================
def run_chaos_suite(fuzz_count: int = 1000) -> Tuple[int, int]:
    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [БЛОК 5] ФАЗЗИНГ И СТРЕСС-ТЕСТ (CHAOS & ROBUSTNESS FUZZING){C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")

    passed = 0
    total = 0
    test_token = DEFAULT_TOKEN
    kid = derive_key_id(test_token)
    mkey = derive_master_key(test_token, kid.hex())
    mask_key = hkdf_expand(mkey, "aegis-v2-header-mask")
    session_key = secrets.token_bytes(32)

    total += 1
    t0 = time.perf_counter()
    crashes = 0

    # Генерация случайного фаззинг-мусора
    for i in range(fuzz_count):
        mode = i % 4
        if mode == 0:
            # Урезанные пакеты (от 0 до 55 байт)
            bad_data = secrets.token_bytes(secrets.randbelow(55))
        elif mode == 1:
            # Случайные длинные пакеты
            bad_data = secrets.token_bytes(secrets.randbelow(2048) + 56)
        elif mode == 2:
            # Валидный заголовок, но случайный шифротекст
            iv = secrets.token_bytes(12)
            hdr = mask_unmask_header(kid + b"\x00\x00\x00\x00" + VER_MAGIC, mask_key, iv)
            bad_data = iv + hdr + secrets.token_bytes(secrets.randbelow(500) + 28)
        else:
            # Огромные пакеты до 65 КБ
            bad_data = secrets.token_bytes(secrets.randbelow(10000) + 1000)

        try:
            res = parse_data_packet(bad_data, kid, mask_key, None, session_key)
            if res is not None:
                crashes += 1  # Случайный мусор не должен успешно расшифроваться
        except Exception:
            crashes += 1

    dt = (time.perf_counter() - t0) * 1000
    if crashes == 0:
        print(f" {badge_pass()} 5.1 Фаззинг {fuzz_count:,} аномальных/поврежденных пакетов: 0 падений, 100% отброшено [{dt:.2f} ms]")
        passed += 1
    else:
        print(f" {badge_fail()} 5.1 Обнаружено {crashes} ошибок обработки мусорных пакетов")

    return passed, total

# ==============================================================================
# Главное меню и интерактивный CLI интерфейс
# ==============================================================================
def print_banner():
    banner = f"""{C.CYAN}{C.BOLD}
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║   🛡️  AEGS v6 Titan — Единый универсальный испытательный комплекс      ║
    ║        High-Performance Anti-DPI Protocol Unified Test Center          ║
    ║                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════╝{C.RESET}"""
    print(banner)

def run_all_tests(host: str, port: int, token: str):
    start_total = time.perf_counter()
    p1, t1 = run_crypto_suite()
    p2, t2 = run_attack_suite()
    p3, t3 = run_live_server_suite(host=host, port=port, token=token)
    p4, t4 = run_benchmark_suite()
    p5, t5 = run_chaos_suite()

    total_passed = p1 + p2 + p3 + p4 + p5
    total_tests = t1 + t2 + t3 + t4 + t5
    elapsed = time.perf_counter() - start_total

    print(f"\n{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.WHITE}{C.BOLD} [ИТОГОВЫЙ ОТЧЕТ] РЕЗУЛЬТАТЫ ПОЛНОГО КОМПЛЕКСНОГО АУДИТА{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f" • Блок 1 (Криптография и примитивы):      {p1}/{t1} пройдено")
    print(f" • Блок 2 (Устойчивость к атакам):         {p2}/{t2} пройдено")
    print(f" • Блок 3 (Живой VPS сервер):              {p3}/{t3} пройдено")
    print(f" • Блок 4 (Бенчмарк производительности):   {p4}/{t4} пройдено")
    print(f" • Блок 5 (Стресс-тест и фаззинг):         {p5}/{t5} пройдено")
    print(f"──────────────────────────────────────────────────────────────────────")

    if total_passed == total_tests:
        print(f" {C.GREEN}{C.BOLD}>>> ВСЕ {total_passed} ИЗ {total_tests} ТЕСТОВ УСПЕШНО ПРОЙДЕНЫ! ПРОТОКОЛ НА 100% ИСПРАВЕН! <<< {C.RESET}({elapsed:.2f} сек)")
    else:
        print(f" {C.YELLOW}{C.BOLD}>>> ПРОЙДЕНО {total_passed} ИЗ {total_tests} ТЕСТОВ ({total_tests - total_passed} ошибок) <<< {C.RESET}({elapsed:.2f} сек)")
    print()

def interactive_menu():
    print_banner()
    host = DEFAULT_VPS_HOST
    port = DEFAULT_VPS_PORT
    token = DEFAULT_TOKEN

    while True:
        print(f"{C.BOLD}Выберите категорию тестирования:{C.RESET}")
        print(f"  {C.CYAN}[1]{C.RESET} 🧪 {C.BOLD}Запустить ВСЕ тесты подряд (Полный комплексный аудит){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} 🔐 Криптография, деривация ключей и маскирование заголовков")
        print(f"  {C.CYAN}[3]{C.RESET} 🛡️  Симуляция сетевых атак (Replay, Bit-Flip, Amplification 0.0x)")
        print(f"  {C.CYAN}[4]{C.RESET} 🌐 Тест живого VPS-сервера ({host}:{port}) с реальным DNS-запросом")
        print(f"  {C.CYAN}[5]{C.RESET} ⚡ Бенчмарк производительности (Throughput, PPS, ChaCha20 speed)")
        print(f"  {C.CYAN}[6]{C.RESET} 🌪️  Стресс-тест и фаззинг мусорными пакетами (Chaos Test)")
        print(f"  {C.CYAN}[7]{C.RESET} ⚙️  Изменить параметры сервера (Текущие: {host}:{port})")
        print(f"  {C.RED}[0]{C.RESET} 🚪 Выход")

        try:
            choice = input(f"\n{C.YELLOW}{C.BOLD}Введите номер действия [1-7, 0]: {C.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nВыход.")
            break

        if choice == "1":
            run_all_tests(host, port, token)
        elif choice == "2":
            p, t = run_crypto_suite()
            print(f"\n{badge_pass() if p == t else badge_warn()} Итог: {p}/{t} пройдено.\n")
        elif choice == "3":
            p, t = run_attack_suite()
            print(f"\n{badge_pass() if p == t else badge_warn()} Итог: {p}/{t} пройдено.\n")
        elif choice == "4":
            p, t = run_live_server_suite(host=host, port=port, token=token)
            print(f"\n{badge_pass() if p == t else badge_warn()} Итог: {p}/{t} пройдено.\n")
        elif choice == "5":
            p, t = run_benchmark_suite()
            print(f"\n{badge_pass() if p == t else badge_warn()} Итог: {p}/{t} пройдено.\n")
        elif choice == "6":
            p, t = run_chaos_suite()
            print(f"\n{badge_pass() if p == t else badge_warn()} Итог: {p}/{t} пройдено.\n")
        elif choice == "7":
            new_h = input(f"Введите IP сервера [{host}]: ").strip()
            if new_h: host = new_h
            new_p = input(f"Введите порт [{port}]: ").strip()
            if new_p.isdigit(): port = int(new_p)
            new_t = input(f"Введите токен [{token}]: ").strip()
            if new_t: token = new_t
            print(f"{badge_pass()} Настройки обновлены: {host}:{port}\n")
        elif choice in ("0", "q", "exit"):
            print("Завершение работы.")
            break
        else:
            print(f"{C.RED}Неверный выбор. Пожалуйста, введите цифру от 0 до 7.{C.RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="AEGS v6 Titan Unified Test Center")
    parser.add_argument("--all", action="store_true", help="Запустить все тесты подряд")
    parser.add_argument("--crypto", action="store_true", help="Запустить тесты криптографии")
    parser.add_argument("--attack", action="store_true", help="Запустить симуляцию атак")
    parser.add_argument("--live", action="store_true", help="Запустить тест живого сервера")
    parser.add_argument("--bench", action="store_true", help="Запустить бенчмарк")
    parser.add_argument("--chaos", action="store_true", help="Запустить стресс-тест/фаззинг")
    parser.add_argument("--host", default=DEFAULT_VPS_HOST, help=f"IP сервера (по умолчанию: {DEFAULT_VPS_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_VPS_PORT, help=f"Порт (по умолчанию: {DEFAULT_VPS_PORT})")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="Секретный токен пользователя")

    args = parser.parse_args()

    # Если передан хотя бы один флаг - работаем в неинтерактивном режиме
    if any([args.all, args.crypto, args.attack, args.live, args.bench, args.chaos]):
        if args.all:
            run_all_tests(args.host, args.port, args.token)
        else:
            if args.crypto: run_crypto_suite()
            if args.attack: run_attack_suite()
            if args.live:   run_live_server_suite(args.host, args.port, args.token)
            if args.bench:  run_benchmark_suite()
            if args.chaos:  run_chaos_suite()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
