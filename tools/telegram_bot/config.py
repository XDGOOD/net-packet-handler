"""
AEGS Titan Telegram Bot - Configuration Module
"""

import os

# --- Telegram Bot Settings ---
BOT_TOKEN = os.getenv("BOT_TOKEN", "8988683377:AAGlu7emVUqm_khSQFpZWruFWSBqd0QBc-U")

ADMIN_IDS_RAW = os.getenv("ADMIN_IDS", "")
ADMIN_IDS = [int(x.strip()) for x in ADMIN_IDS_RAW.split(",") if x.strip().isdigit()]

# --- AEGS VPN Server Settings ---
SERVER_IP = os.getenv("AEGS_SERVER_IP", "185.196.8.10")
SERVER_PORT = int(os.getenv("AEGS_SERVER_PORT", "50001"))
SERVER_NAME = os.getenv("AEGS_SERVER_NAME", "AEGS Titan-01")

# Paths
AEGIS_DB_PATH = os.getenv("AEGIS_DB_PATH", "/app/data/aegis.db")
if not os.path.exists(os.path.dirname(AEGIS_DB_PATH)) and os.path.exists("./data"):
    AEGIS_DB_PATH = "./data/aegis.db"
elif not os.path.exists(os.path.dirname(AEGIS_DB_PATH)):
    AEGIS_DB_PATH = "tools/telegram_bot/data/aegis.db"

BOT_DB_PATH = os.getenv("BOT_DB_PATH", "tools/telegram_bot/data/bot_billing.db")

os.makedirs(os.path.dirname(BOT_DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(AEGIS_DB_PATH), exist_ok=True)

# --- Subscription Plans & Pricing (RUB & Crypto) ---
PLANS = {
    "trial": {
        "id": "trial",
        "name": "Тестовый период (3 дня)",
        "days": 3,
        "price_rub": 0,
        "description": "Тестовый доступ на 3 дня (пропускная способность 300-900 Мбит/с, Anti-DPI)"
    },
    "1_month": {
        "id": "1_month",
        "name": "1 месяц — Базовый",
        "days": 30,
        "price_rub": 199,
        "description": "Трафик 300-900 Мбит/с, Anti-DPI QUIC Mimicry, до 5 устройств"
    },
    "3_months": {
        "id": "3_months",
        "name": "3 месяца — Квартальный",
        "days": 90,
        "price_rub": 499,
        "description": "Срок 90 дней, скидка 15%"
    },
    "6_months": {
        "id": "6_months",
        "name": "6 месяцев — Полугодовой",
        "days": 180,
        "price_rub": 899,
        "description": "Срок 180 дней, скидка 25%"
    },
    "12_months": {
        "id": "12_months",
        "name": "12 месяцев — Годовой",
        "days": 365,
        "price_rub": 1499,
        "description": "Срок 365 дней, скидка 40%"
    }
}

ENABLE_FREE_TRIAL = True
TRIAL_DAYS = 3
REFERRAL_BONUS_DAYS = 7

SUPPORT_USERNAME = os.getenv("SUPPORT_USERNAME", "AEGS_Support")
NEWS_CHANNEL = os.getenv("NEWS_CHANNEL", "AEGS_Official")
APK_DOWNLOAD_URL = "https://github.com/XDGOOD/net-packet-handler/releases/download/v6.0-titan/AEGS-v6.0-titan.apk"
GITHUB_REPO_URL = "https://github.com/XDGOOD/net-packet-handler"

AEGS_GLOBAL_URL = "https://github.com/XDGOOD/AEGS-Global-"
