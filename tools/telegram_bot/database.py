"""
AEGS Titan Telegram Bot - Billing, Subscription & Support Database Engine
"""

import os
import sqlite3
import datetime
from typing import Optional, Tuple, Dict, Any, List
from . import config
from . import aegs_sync

def get_conn():
    os.makedirs(os.path.dirname(config.BOT_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(config.BOT_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the SQLite database schema."""
    conn = get_conn()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                aegs_token TEXT NOT NULL,
                aegs_key_id TEXT NOT NULL,
                sub_expires_at DATETIME,
                is_active INTEGER DEFAULT 0,
                trial_used INTEGER DEFAULT 0,
                warned_24h INTEGER DEFAULT 0,
                warned_72h INTEGER DEFAULT 0,
                referrer_id INTEGER,
                referral_count INTEGER DEFAULT 0,
                waiting_support_input INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bot_users_key_id ON users(aegs_key_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bot_users_expires ON users(sub_expires_at);")

            conn.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id TEXT NOT NULL,
                days_added INTEGER NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                provider TEXT NOT NULL,
                payment_id TEXT UNIQUE,
                status TEXT DEFAULT 'success',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS promocodes (
                code TEXT PRIMARY KEY,
                days INTEGER NOT NULL,
                max_uses INTEGER DEFAULT 100,
                used_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS promocode_uses (
                code TEXT,
                user_id INTEGER,
                used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (code, user_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT,
                question TEXT NOT NULL,
                reply TEXT,
                admin_id INTEGER,
                status TEXT DEFAULT 'open',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                answered_at DATETIME
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_user ON support_tickets(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(status);")
    finally:
        conn.close()

def get_or_create_user(user_id: int, username: Optional[str], first_name: str, referrer_id: Optional[int] = None) -> Dict[str, Any]:
    init_db()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            if row['username'] != username or row['first_name'] != first_name:
                with conn:
                    conn.execute("UPDATE users SET username = ?, first_name = ? WHERE user_id = ?;", (username, first_name, user_id))
            return dict(row)

        token = aegs_sync.generate_token()
        key_id = aegs_sync.compute_key_id(token)

        valid_referrer = None
        if referrer_id and referrer_id != user_id:
            cur.execute("SELECT user_id FROM users WHERE user_id = ?;", (referrer_id,))
            if cur.fetchone():
                valid_referrer = referrer_id

        with conn:
            conn.execute("""
            INSERT INTO users (user_id, username, first_name, aegs_token, aegs_key_id, referrer_id)
            VALUES (?, ?, ?, ?, ?, ?);
            """, (user_id, username, first_name, token, key_id, valid_referrer))

            if valid_referrer:
                conn.execute("UPDATE users SET referral_count = referral_count + 1 WHERE user_id = ?;", (valid_referrer,))

        cur.execute("SELECT * FROM users WHERE user_id = ?;", (user_id,))
        return dict(cur.fetchone())
    finally:
        conn.close()

def get_user(user_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def set_user_support_state(user_id: int, waiting: bool):
    conn = get_conn()
    try:
        with conn:
            conn.execute("UPDATE users SET waiting_support_input = ? WHERE user_id = ?;", (1 if waiting else 0, user_id))
    finally:
        conn.close()

def activate_trial(user_id: int) -> Tuple[bool, str]:
    user = get_user(user_id)
    if not user:
        return False, "Пользователь не найден."
    if user['trial_used']:
        return False, "Тестовый период уже был активирован ранее."

    days = config.TRIAL_DAYS
    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(days=days)
    expires_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

    conn = get_conn()
    try:
        with conn:
            conn.execute("""
            UPDATE users SET
                sub_expires_at = ?,
                is_active = 1,
                trial_used = 1,
                warned_24h = 0,
                warned_72h = 0
            WHERE user_id = ?;
            """, (expires_str, user_id))

        srv_username = f"tg_{user_id}_{user.get('username') or 'user'}"
        aegs_sync.sync_add_user_to_server(srv_username, user['aegs_key_id'], user['aegs_token'])
        return True, f"Тестовый доступ на {days} дня(ей) активирован. Срок действия: до {expires_str} UTC."
    except Exception as e:
        return False, f"Ошибка активации: {e}"
    finally:
        conn.close()

def extend_subscription(user_id: int, days: int, plan_id: str, payment_id: str, amount: float, currency: str = 'RUB', provider: str = 'telegram_stars') -> Tuple[bool, str]:
    user = get_user(user_id)
    if not user:
        return False, "Пользователь не найден."

    now = datetime.datetime.utcnow()
    current_expires = None
    if user['sub_expires_at']:
        try:
            current_expires = datetime.datetime.strptime(user['sub_expires_at'], '%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

    if current_expires and current_expires > now:
        new_expires = current_expires + datetime.timedelta(days=days)
    else:
        new_expires = now + datetime.timedelta(days=days)

    new_expires_str = new_expires.strftime('%Y-%m-%d %H:%M:%S')

    conn = get_conn()
    try:
        with conn:
            conn.execute("""
            INSERT INTO payments (user_id, plan_id, days_added, amount, currency, provider, payment_id)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (user_id, plan_id, days, amount, currency, provider, payment_id))

            conn.execute("""
            UPDATE users SET
                sub_expires_at = ?,
                is_active = 1,
                warned_24h = 0,
                warned_72h = 0
            WHERE user_id = ?;
            """, (new_expires_str, user_id))

            referrer_id = user.get('referrer_id')
            if referrer_id:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) as cnt FROM payments WHERE user_id = ?;", (user_id,))
                if cur.fetchone()['cnt'] == 1:
                    reward_days = config.REFERRAL_BONUS_DAYS
                    ref_user = get_user(referrer_id)
                    if ref_user:
                        ref_exp = None
                        if ref_user['sub_expires_at']:
                            try:
                                ref_exp = datetime.datetime.strptime(ref_user['sub_expires_at'], '%Y-%m-%d %H:%M:%S')
                            except Exception:
                                pass
                        ref_new_exp = (ref_exp if ref_exp and ref_exp > now else now) + datetime.timedelta(days=reward_days)
                        conn.execute("UPDATE users SET sub_expires_at = ?, is_active = 1 WHERE user_id = ?;", 
                                     (ref_new_exp.strftime('%Y-%m-%d %H:%M:%S'), referrer_id))
                        aegs_sync.sync_add_user_to_server(f"tg_{referrer_id}", ref_user['aegs_key_id'], ref_user['aegs_token'])

        srv_username = f"tg_{user_id}_{user.get('username') or 'user'}"
        aegs_sync.sync_add_user_to_server(srv_username, user['aegs_key_id'], user['aegs_token'])

        return True, f"Подписка продлена на {days} дней. Срок действия: до {new_expires_str} UTC."
    except Exception as e:
        return False, f"Ошибка продления: {e}"
    finally:
        conn.close()

def check_subscription_status(user_id: int) -> Dict[str, Any]:
    user = get_user(user_id)
    if not user:
        return {'exists': False, 'active': False, 'message': 'Пользователь не найден'}

    now = datetime.datetime.utcnow()
    expires_str = user['sub_expires_at']
    if not expires_str:
        return {
            'exists': True,
            'active': False,
            'status_label': 'Не активна',
            'expires_at': None,
            'days_left': 0,
            'hours_left': 0,
            'user': user
        }

    try:
        expires_dt = datetime.datetime.strptime(expires_str, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return {'exists': True, 'active': False, 'status_label': 'Некорректная дата', 'expires_at': None, 'days_left': 0, 'hours_left': 0, 'user': user}

    if expires_dt > now:
        diff = expires_dt - now
        days_left = diff.days
        hours_left = int(diff.total_seconds() // 3600)
        return {
            'exists': True,
            'active': True,
            'status_label': 'Активна',
            'expires_at': expires_str,
            'days_left': days_left,
            'hours_left': hours_left,
            'total_seconds_left': int(diff.total_seconds()),
            'user': user
        }
    else:
        return {
            'exists': True,
            'active': False,
            'status_label': 'Истекла',
            'expires_at': expires_str,
            'days_left': 0,
            'hours_left': 0,
            'total_seconds_left': 0,
            'user': user
        }

def get_expiring_users(hours_left_min: int, hours_left_max: int, flag_col: str) -> List[Dict[str, Any]]:
    now = datetime.datetime.utcnow()
    t_min = now + datetime.timedelta(hours=hours_left_min)
    t_max = now + datetime.timedelta(hours=hours_left_max)
    conn = get_conn()
    try:
        cur = conn.cursor()
        query = f"""
        SELECT * FROM users
        WHERE is_active = 1
          AND {flag_col} = 0
          AND sub_expires_at BETWEEN ? AND ?;
        """
        cur.execute(query, (t_min.strftime('%Y-%m-%d %H:%M:%S'), t_max.strftime('%Y-%m-%d %H:%M:%S')))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def mark_reminder_sent(user_id: int, flag_col: str):
    conn = get_conn()
    try:
        with conn:
            conn.execute(f"UPDATE users SET {flag_col} = 1 WHERE user_id = ?;", (user_id,))
    finally:
        conn.close()

def get_expired_active_users() -> List[Dict[str, Any]]:
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE is_active = 1 AND sub_expires_at < ?;", (now,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def deactivate_user(user_id: int):
    user = get_user(user_id)
    if not user:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE user_id = ?;", (user_id,))
        aegs_sync.sync_remove_user_from_server(user['aegs_key_id'])
    finally:
        conn.close()

def apply_promocode(user_id: int, code: str) -> Tuple[bool, str]:
    code = code.strip().upper()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM promocodes WHERE code = ?;", (code,))
        promo = cur.fetchone()
        if not promo:
            return False, "Промокод не найден."
        if promo['used_count'] >= promo['max_uses']:
            return False, "Лимит активаций промокода исчерпан."

        cur.execute("SELECT * FROM promocode_uses WHERE code = ? AND user_id = ?;", (code, user_id))
        if cur.fetchone():
            return False, "Промокод уже был активирован вами ранее."

        days = promo['days']
        user = get_user(user_id)
        now = datetime.datetime.utcnow()
        current_expires = None
        if user['sub_expires_at']:
            try:
                current_expires = datetime.datetime.strptime(user['sub_expires_at'], '%Y-%m-%d %H:%M:%S')
            except Exception:
                pass

        new_expires = (current_expires if current_expires and current_expires > now else now) + datetime.timedelta(days=days)
        new_expires_str = new_expires.strftime('%Y-%m-%d %H:%M:%S')

        with conn:
            conn.execute("INSERT INTO promocode_uses (code, user_id) VALUES (?, ?);", (code, user_id))
            conn.execute("UPDATE promocodes SET used_count = used_count + 1 WHERE code = ?;", (code,))
            conn.execute("UPDATE users SET sub_expires_at = ?, is_active = 1 WHERE user_id = ?;", (new_expires_str, user_id))

        aegs_sync.sync_add_user_to_server(f"tg_{user_id}", user['aegs_key_id'], user['aegs_token'])
        return True, f"Промокод активирован. Начислено: {days} дней (до {new_expires_str} UTC)."
    except Exception as e:
        return False, f"Ошибка промокода: {e}"
    finally:
        conn.close()

def create_promocode(code: str, days: int, max_uses: int = 100) -> Tuple[bool, str]:
    code = code.strip().upper()
    conn = get_conn()
    try:
        with conn:
            conn.execute("""
            INSERT INTO promocodes (code, days, max_uses)
            VALUES (?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET days = excluded.days, max_uses = excluded.max_uses;
            """, (code, days, max_uses))
        return True, f"Промокод {code} на {days} дней (макс. {max_uses} исп.) создан."
    except Exception as e:
        return False, f"Ошибка: {e}"
    finally:
        conn.close()

# --- Support Tickets ---
def create_support_ticket(user_id: int, username: Optional[str], question: str) -> int:
    init_db()
    conn = get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO support_tickets (user_id, username, question, status)
            VALUES (?, ?, ?, 'open');
            """, (user_id, username, question))
            return cur.lastrowid
    finally:
        conn.close()

def get_open_tickets() -> List[Dict[str, Any]]:
    init_db()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM support_tickets WHERE status = 'open' ORDER BY ticket_id DESC;")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def get_ticket(ticket_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM support_tickets WHERE ticket_id = ?;", (ticket_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def reply_support_ticket(ticket_id: int, admin_id: int, reply_text: str) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_conn()
    try:
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        with conn:
            conn.execute("""
            UPDATE support_tickets SET
                reply = ?,
                admin_id = ?,
                status = 'closed',
                answered_at = ?
            WHERE ticket_id = ?;
            """, (reply_text, admin_id, now, ticket_id))
        return get_ticket(ticket_id)
    finally:
        conn.close()

def get_admin_stats() -> Dict[str, Any]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as total FROM users;")
        total_users = cur.fetchone()['total']

        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("SELECT COUNT(*) as active FROM users WHERE is_active = 1 AND sub_expires_at > ?;", (now,))
        active_subs = cur.fetchone()['active']

        cur.execute("SELECT COUNT(*) as paid_cnt, COALESCE(SUM(amount), 0) as total_revenue FROM payments WHERE status = 'success';")
        row = cur.fetchone()
        paid_cnt = row['paid_cnt']
        total_revenue = row['total_revenue']

        cur.execute("SELECT COUNT(*) as open_tickets FROM support_tickets WHERE status = 'open';")
        open_tickets = cur.fetchone()['open_tickets']

        return {
            'total_users': total_users,
            'active_subs': active_subs,
            'paid_cnt': paid_cnt,
            'total_revenue': total_revenue,
            'open_tickets': open_tickets
        }
    finally:
        conn.close()
