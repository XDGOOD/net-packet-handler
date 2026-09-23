"""
AEGS Titan - Telegram Bot & Support Desk Engine
Professional, unemotional interface for subscriptions, keys, and technical support ticketing.
"""

import os
import sys
import time
import json
import logging
import requests
from typing import Dict, Any, Optional, List

from . import config
from . import database
from . import aegs_sync
from . import qr_generator
from .subscription_worker import SubscriptionWorker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(name)s) %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('aegs_bot')

class TelegramBot:
    def __init__(self, token: str):
        self.token = token.strip()
        if not self.token:
            raise ValueError("BOT_TOKEN is empty.")
        self.api_url = f"https://api.telegram.org/bot{self.token}"
        self.last_update_id = 0
        self.worker = SubscriptionWorker(self.send_worker_notification)

    def _api_call(self, method: str, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.api_url}/{method}"
        try:
            if files:
                resp = requests.post(url, data=data, files=files, timeout=30)
            else:
                resp = requests.post(url, json=data, timeout=30)
            res_json = resp.json()
            if not res_json.get('ok'):
                logger.warning(f"Telegram API error in {method}: {res_json}")
            return res_json
        except Exception as e:
            logger.error(f"HTTP request error calling {method}: {e}")
            return None

    def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        payload = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode,
            'disable_web_page_preview': True
        }
        if reply_markup:
            payload['reply_markup'] = reply_markup
        return self._api_call('sendMessage', payload)

    def edit_message_text(self, chat_id: int, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        payload = {
            'chat_id': chat_id,
            'message_id': message_id,
            'text': text,
            'parse_mode': parse_mode,
            'disable_web_page_preview': True
        }
        if reply_markup:
            payload['reply_markup'] = reply_markup
        return self._api_call('editMessageText', payload)

    def send_photo(self, chat_id: int, photo_bytes: bytes, caption: str = '', reply_markup: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        data = {
            'chat_id': str(chat_id),
            'caption': caption,
            'parse_mode': 'HTML'
        }
        if reply_markup:
            data['reply_markup'] = json.dumps(reply_markup)
        files = {
            'photo': ('qrcode.png', photo_bytes, 'image/png')
        }
        return self._api_call('sendPhoto', data=data, files=files)

    def answer_callback_query(self, callback_query_id: str, text: Optional[str] = None, show_alert: bool = False):
        payload = {'callback_query_id': callback_query_id}
        if text:
            payload['text'] = text
            payload['show_alert'] = show_alert
        self._api_call('answerCallbackQuery', payload)

    def send_worker_notification(self, user_id: int, text: str, extra: Any):
        markup = {
            'inline_keyboard': [
                [{'text': 'Продлить подписку', 'callback_data': 'buy_menu'}],
                [{'text': 'Профиль', 'callback_data': 'status'}]
            ]
        }
        self.send_message(user_id, text, reply_markup=markup)

    def notify_admins_new_ticket(self, ticket_id: int, user_id: int, username: Optional[str], question: str):
        for admin_id in config.ADMIN_IDS:
            admin_text = (
                f"Новое обращение в поддержку #{ticket_id}\n"
                f"Пользователь: @{username or 'нет'} (ID: <code>{user_id}</code>)\n"
                f"Текст:\n{question}\n\n"
                f"Команда для ответа:\n<code>/reply {ticket_id} Текст ответа</code>"
            )
            self.send_message(admin_id, admin_text)

    # --- UI Keyboards ---
    def get_main_keyboard(self, user_id: int) -> Dict[str, Any]:
        user = database.get_user(user_id)
        trial_btn = []
        if user and not user.get('trial_used') and config.ENABLE_FREE_TRIAL:
            trial_btn = [[{'text': 'Активировать тестовый период (3 дня)', 'callback_data': 'activate_trial'}]]

        admin_btn = []
        if user_id in config.ADMIN_IDS:
            admin_btn = [[{'text': 'Панель администратора', 'callback_data': 'admin_panel'}]]

        keyboard = trial_btn + [
            [
                {'text': 'Профиль и статус', 'callback_data': 'status'},
                {'text': 'Тарифы и оплата', 'callback_data': 'buy_menu'}
            ],
            [
                {'text': 'Конфигурация и ключ', 'callback_data': 'get_key'},
                {'text': 'Клиентские приложения', 'callback_data': 'downloads'}
            ],
            [
                {'text': 'Техническая поддержка', 'callback_data': 'support_menu'},
                {'text': 'Реферальная программа', 'callback_data': 'referrals'}
            ],
            [
                {'text': 'Активация промокода', 'callback_data': 'promo_prompt'},
                {'text': 'Спецификация протокола', 'callback_data': 'about_proto'}
            ]
        ] + admin_btn
        return {'inline_keyboard': keyboard}

    def get_buy_keyboard(self) -> Dict[str, Any]:
        buttons = []
        for pid, p in config.PLANS.items():
            if pid == 'trial':
                continue
            buttons.append([{
                'text': f"{p['name']} — {p['price_rub']} RUB",
                'callback_data': f"select_plan:{pid}"
            }])
        buttons.append([{'text': 'Главное меню', 'callback_data': 'main_menu'}])
        return {'inline_keyboard': buttons}

    # --- Handlers ---
    def handle_start(self, chat_id: int, username: Optional[str], first_name: str, args: str):
        referrer_id = None
        if args and args.startswith('ref_') and args[4:].isdigit():
            referrer_id = int(args[4:])

        user = database.get_or_create_user(chat_id, username, first_name, referrer_id)
        status = database.check_subscription_status(chat_id)

        welcome_text = (
            f"Панель управления AEGS Titan Protocol.\n\n"
            f"Идентификатор пользователя: <code>{chat_id}</code>\n"
            f"Статус подписки: <b>{status['status_label']}</b>\n"
        )

        if status['active']:
            welcome_text += f"Срок действия: до <b>{status['expires_at']} UTC</b> (осталось {status['days_left']} дн. {status['hours_left'] % 24} ч.).\n"
        else:
            if not user.get('trial_used'):
                welcome_text += "Доступен тестовый период на 3 дня.\n"

        welcome_text += "\nВыберите раздел:"
        self.send_message(chat_id, welcome_text, reply_markup=self.get_main_keyboard(chat_id))

    def handle_status(self, chat_id: int, message_id: Optional[int] = None):
        status = database.check_subscription_status(chat_id)
        user = status.get('user', {})

        text = (
            "Информация об учетной записи:\n"
            "----------------------------------------\n"
            f"ID: <code>{chat_id}</code>\n"
            f"Статус подписки: <b>{status['status_label']}</b>\n"
        )

        if status['active']:
            text += (
                f"Срок действия: <code>{status['expires_at']} UTC</code>\n"
                f"Осталось времени: {status['days_left']} дн. {status['hours_left'] % 24} ч.\n"
                f"Пропускная способность: 300-900+ Мбит/с\n"
                f"Протокол: AEGS v6 Titan (QUIC Mimicry RFC 9000/9369)\n"
                f"KeyID: <code>{user.get('aegs_key_id', 'N/A')}</code>\n"
            )
        else:
            text += (
                "Активная подписка отсутствует.\n"
                "Для активации выберите тариф в разделе оплаты.\n"
            )

        text += "----------------------------------------"

        markup = {
            'inline_keyboard': [
                [{'text': 'Продлить / Купить подписку', 'callback_data': 'buy_menu'}],
                [{'text': 'Получить ключ и QR-код', 'callback_data': 'get_key'}],
                [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
            ]
        }

        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_buy_menu(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "Тарифные планы AEGS Titan:\n\n"
            "1 месяц: 199 RUB\n"
            "3 месяца: 499 RUB (скидка 15%)\n"
            "6 месяцев: 899 RUB (скидка 25%)\n"
            "12 месяцев: 1499 RUB (скидка 40%)\n\n"
            "При продлении оставшийся срок суммируется с новым периодом."
        )
        markup = self.get_buy_keyboard()
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_select_plan(self, chat_id: int, message_id: int, plan_id: str):
        plan = config.PLANS.get(plan_id)
        if not plan:
            return

        text = (
            f"Выбранный тариф: {plan['name']}\n"
            f"Срок действия: {plan['days']} дней\n"
            f"Стоимость: {plan['price_rub']} RUB\n\n"
            "Выберите способ проведения транзакции:"
        )

        markup = {
            'inline_keyboard': [
                [{'text': f"Банковская карта / СБП ({plan['price_rub']} RUB)", 'callback_data': f"pay_card:{plan_id}"}],
                [{'text': 'Криптовалюта (USDT / TON)', 'callback_data': f"pay_crypto:{plan_id}"}],
                [{'text': 'Тестовая транзакция (Sandbox)', 'callback_data': f"pay_sandbox:{plan_id}"}],
                [{'text': 'Назад к списку тарифов', 'callback_data': 'buy_menu'}]
            ]
        }
        self.edit_message_text(chat_id, message_id, text, reply_markup=markup)

    def handle_get_key(self, chat_id: int):
        status = database.check_subscription_status(chat_id)
        user = status.get('user')
        if not user:
            self.send_message(chat_id, "Пользователь не найден.")
            return

        if not status['active']:
            text = "Доступ заблокирован. Активная подписка отсутствует."
            markup = {
                'inline_keyboard': [
                    [{'text': 'Активировать тестовый период', 'callback_data': 'activate_trial'}],
                    [{'text': 'Купить подписку', 'callback_data': 'buy_menu'}],
                    [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
                ]
            }
            self.send_message(chat_id, text, reply_markup=markup)
            return

        token = user['aegs_token']
        sub_uri = aegs_sync.make_subscription_uri(token, f"AEGS_Titan_{chat_id}")
        quick_cmd = aegs_sync.make_quick_command(token)

        caption = (
            "Параметры подключения AEGS Titan:\n"
            "----------------------------------------\n"
            f"Статус: Активна (до {status['expires_at']} UTC)\n\n"
            f"URI конфигурации:\n<code>{sub_uri}</code>\n\n"
            f"Токен авторизации:\n<code>{token}</code>\n\n"
            f"Команда запуска Linux/macOS:\n<code>{quick_cmd}</code>\n"
            "----------------------------------------"
        )

        markup = {
            'inline_keyboard': [
                [{'text': 'Скачать Android APK', 'url': config.APK_DOWNLOAD_URL}],
                [{'text': 'Проверить статус', 'callback_data': 'status'}],
                [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
            ]
        }

        try:
            qr_bytes = qr_generator.get_qr_image_bytes(sub_uri)
            self.send_photo(chat_id, qr_bytes, caption=caption, reply_markup=markup)
        except Exception as e:
            logger.error(f"QR generation error: {e}")
            self.send_message(chat_id, caption, reply_markup=markup)

    def handle_downloads(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "Клиентское программное обеспечение AEGS VPN:\n\n"
            f"1. Android Client (APK, 5.18 MB):\n{config.APK_DOWNLOAD_URL}\n\n"
            "2. Windows Launcher:\nЗапуск через tools/AEGS.bat или tools/aegs_app.py\n\n"
            f"3. Исходный код ядра:\n{config.GITHUB_REPO_URL}\n\n4. AEGS Global Enterprise (10+ Gbps):\nhttps://github.com/XDGOOD/AEGS-Global-"
        )
        markup = {
            'inline_keyboard': [
                [{'text': 'Скачать APK', 'url': config.APK_DOWNLOAD_URL}],
                [{'text': 'Получить ключ', 'callback_data': 'get_key'}],
                [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_support_menu(self, chat_id: int, message_id: Optional[int] = None):
        database.set_user_support_state(chat_id, True)
        text = (
            "Отдел технической поддержки AEGS Titan.\n\n"
            "Для регистрации обращения отправьте текст вашего вопроса в этот чат следующим сообщением.\n\n"
            "Или используйте команду:\n"
            "<code>/support Текст вашего вопроса</code>"
        )
        markup = {
            'inline_keyboard': [
                [{'text': 'Отмена', 'callback_data': 'cancel_support'}],
                [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_submit_support_ticket(self, chat_id: int, username: Optional[str], question: str):
        ticket_id = database.create_support_ticket(chat_id, username, question)
        database.set_user_support_state(chat_id, False)

        resp_text = (
            f"Обращение #{ticket_id} зарегистрировано.\n"
            f"Вопрос: {question}\n\n"
            "Ожидайте ответа специалиста технической поддержки."
        )
        self.send_message(chat_id, resp_text, reply_markup=self.get_main_keyboard(chat_id))
        self.notify_admins_new_ticket(ticket_id, chat_id, username, question)

    def handle_referrals(self, chat_id: int, message_id: Optional[int] = None):
        user = database.get_user(chat_id)
        ref_count = user.get('referral_count', 0) if user else 0
        bot_username = "AEGS_Titan_Bot"
        ref_link = f"https://t.me/{bot_username}?start=ref_{chat_id}"

        text = (
            "Реферальная программа:\n\n"
            "За каждую первую оплату приглашенного пользователя начисляется +7 дней к сроку действия подписки.\n\n"
            f"Количество привлеченных пользователей: {ref_count}\n"
            f"Реферальная ссылка:\n<code>{ref_link}</code>"
        )
        markup = {'inline_keyboard': [[{'text': 'Главное меню', 'callback_data': 'main_menu'}]]}
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_about_proto(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "Спецификация транспортного протокола AEGS v6 Titan:\n\n"
            "1. Отсутствие статических сигнатур (Header Masking ChaCha20, Shannon Entropy > 7.7/8.0)\n"
            "2. Мимикрия под протокол RFC 9000/9369 QUIC Initial и STUN RFC 5389\n"
            "3. Пропускная способность до 900+ Мбит/с (конвейер sendmmsg/recvmmsg, Zero-Copy)\n"
            "4. Perfect Forward Secrecy (Curve25519 ECDH) и шифрование ChaCha20-Poly1305 (RFC 8439)\n"
            "5. Двухфазный Anti-Replay RFC 6479 и Fail-Closed Kill-Switch"
        )
        markup = {'inline_keyboard': [[{'text': 'Главное меню', 'callback_data': 'main_menu'}]]}
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_admin_panel(self, chat_id: int, message_id: Optional[int] = None):
        if chat_id not in config.ADMIN_IDS:
            return

        stats = database.get_admin_stats()
        text = (
            "Панель администратора AEGS Titan:\n"
            "----------------------------------------\n"
            f"Всего пользователей: {stats['total_users']}\n"
            f"Активных подписок: {stats['active_subs']}\n"
            f"Открытых обращений в поддержку: {stats['open_tickets']}\n"
            f"Оплаченных транзакций: {stats['paid_cnt']}\n"
            f"Суммарный доход: {stats['total_revenue']} RUB\n"
            f"Адрес сервера: {config.SERVER_IP}:{config.SERVER_PORT}\n"
            "----------------------------------------\n"
            "Команда ответа на обращение:\n/reply <ID_обращения> <Текст_ответа>"
        )
        markup = {
            'inline_keyboard': [
                [{'text': 'Создать промокод', 'callback_data': 'admin_create_promo'}],
                [{'text': 'Обновить данные', 'callback_data': 'admin_panel'}],
                [{'text': 'Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def process_update(self, update: Dict[str, Any]):
        if 'message' in update:
            msg = update['message']
            chat_id = msg['chat']['id']
            username = msg.get('from', {}).get('username')
            first_name = msg.get('from', {}).get('first_name', 'User')
            text = msg.get('text', '').strip()
            user = database.get_user(chat_id)

            if text.startswith('/reply'):
                if chat_id in config.ADMIN_IDS:
                    parts = text.split(maxsplit=2)
                    if len(parts) >= 3 and parts[1].isdigit():
                        t_id = int(parts[1])
                        reply_body = parts[2].strip()
                        ticket = database.reply_support_ticket(t_id, chat_id, reply_body)
                        if ticket:
                            user_msg = (
                                f"Ответ службы поддержки по обращению #{t_id}:\n\n"
                                f"{reply_body}"
                            )
                            self.send_message(ticket['user_id'], user_msg)
                            self.send_message(chat_id, f"Ответ на обращение #{t_id} отправлен пользователю {ticket['user_id']}.")
                        else:
                            self.send_message(chat_id, f"Обращение #{t_id} не найдено.")
                    else:
                        self.send_message(chat_id, "Формат команды: /reply <ID_обращения> <Текст_ответа>")
                return

            if text.startswith('/support'):
                question = text[8:].strip()
                if question:
                    self.handle_submit_support_ticket(chat_id, username, question)
                else:
                    self.send_message(chat_id, "Укажите текст обращения: /support <текст>")
                return

            if user and user.get('waiting_support_input') and not text.startswith('/'):
                self.handle_submit_support_ticket(chat_id, username, text)
                return

            if text.startswith('/start'):
                args = text[7:].strip()
                self.handle_start(chat_id, username, first_name, args)
            elif text.startswith('/status') or text.lower() == 'профиль':
                self.handle_status(chat_id)
            elif text.startswith('/buy') or text.lower() == 'тарифы':
                self.handle_buy_menu(chat_id)
            elif text.startswith('/key') or text.lower() == 'ключ':
                self.handle_get_key(chat_id)
            elif text.startswith('/admin'):
                self.handle_admin_panel(chat_id)
            elif text.startswith('/promo'):
                parts = text.split(maxsplit=1)
                if len(parts) > 1:
                    ok, res = database.apply_promocode(chat_id, parts[1])
                    self.send_message(chat_id, res, reply_markup=self.get_main_keyboard(chat_id))
                else:
                    self.send_message(chat_id, "Формат команды: /promo <промокод>")
            else:
                self.send_message(chat_id, "Выберите раздел:", reply_markup=self.get_main_keyboard(chat_id))

        elif 'callback_query' in update:
            cb = update['callback_query']
            cb_id = cb['id']
            chat_id = cb['message']['chat']['id']
            message_id = cb['message']['message_id']
            data = cb.get('data', '')

            self.answer_callback_query(cb_id)

            if data == 'main_menu':
                self.handle_start(chat_id, cb.get('from', {}).get('username'), cb.get('from', {}).get('first_name', 'User'), '')
            elif data == 'status':
                self.handle_status(chat_id, message_id)
            elif data == 'buy_menu':
                self.handle_buy_menu(chat_id, message_id)
            elif data.startswith('select_plan:'):
                plan_id = data.split(':', 1)[1]
                self.handle_select_plan(chat_id, message_id, plan_id)
            elif data.startswith('pay_sandbox:'):
                plan_id = data.split(':', 1)[1]
                plan = config.PLANS.get(plan_id, config.PLANS['1_month'])
                ok, note = database.extend_subscription(
                    user_id=chat_id,
                    days=plan['days'],
                    plan_id=plan_id,
                    payment_id=f"sandbox_{chat_id}_{int(time.time())}",
                    amount=plan['price_rub'],
                    currency='RUB',
                    provider='sandbox'
                )
                res_text = f"Тестовая оплата подтверждена.\n{note}"
                markup = {
                    'inline_keyboard': [
                        [{'text': 'Конфигурация и ключ', 'callback_data': 'get_key'}],
                        [{'text': 'Профиль', 'callback_data': 'status'}]
                    ]
                }
                self.send_message(chat_id, res_text, reply_markup=markup)
            elif data.startswith('pay_card:') or data.startswith('pay_crypto:'):
                self.send_message(
                    chat_id, 
                    "Для оплаты картой или криптовалютой обратитесь в техническую поддержку через раздел «Техническая поддержка».",
                    reply_markup={'inline_keyboard': [[{'text': 'Техническая поддержка', 'callback_data': 'support_menu'}]]}
                )
            elif data == 'activate_trial':
                ok, note = database.activate_trial(chat_id)
                self.send_message(chat_id, note, reply_markup=self.get_main_keyboard(chat_id))
            elif data == 'get_key':
                self.handle_get_key(chat_id)
            elif data == 'downloads':
                self.handle_downloads(chat_id, message_id)
            elif data == 'support_menu':
                self.handle_support_menu(chat_id, message_id)
            elif data == 'cancel_support':
                database.set_user_support_state(chat_id, False)
                self.send_message(chat_id, "Обращение отменено.", reply_markup=self.get_main_keyboard(chat_id))
            elif data == 'referrals':
                self.handle_referrals(chat_id, message_id)
            elif data == 'about_proto':
                self.handle_about_proto(chat_id, message_id)
            elif data == 'promo_prompt':
                self.send_message(chat_id, "Отправьте промокод командой:\n<code>/promo ПРОМОКОД</code>")
            elif data == 'admin_panel':
                self.handle_admin_panel(chat_id, message_id)
            elif data == 'admin_create_promo':
                code = f"TITAN{int(time.time()) % 10000}"
                database.create_promocode(code, days=30, max_uses=50)
                self.send_message(chat_id, f"Промокод создан: <code>{code}</code> (+30 дней, 50 активаций)")

    def run(self):
        logger.info("Initializing database...")
        database.init_db()

        logger.info("Starting Subscription Lifecycle Worker...")
        self.worker.start()

        logger.info(f"AEGS Titan Telegram Bot started. Server: {config.SERVER_IP}:{config.SERVER_PORT}")

        while True:
            try:
                url = f"{self.api_url}/getUpdates"
                params = {'offset': self.last_update_id + 1, 'timeout': 25}
                resp = requests.get(url, params=params, timeout=35)
                data = resp.json()
                if data.get('ok'):
                    for update in data.get('result', []):
                        self.last_update_id = update['update_id']
                        try:
                            self.process_update(update)
                        except Exception as e:
                            logger.error(f"Error processing update {update.get('update_id')}: {e}", exc_info=True)
                else:
                    logger.warning(f"getUpdates returned not ok: {data}")
                    time.sleep(2)
            except requests.exceptions.RequestException as e:
                logger.warning(f"Network error: {e}. Retrying in 3s...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Error in poll loop: {e}", exc_info=True)
                time.sleep(2)

def main():
    token = config.BOT_TOKEN
    bot = TelegramBot(token)
    bot.run()

if __name__ == '__main__':
    main()
