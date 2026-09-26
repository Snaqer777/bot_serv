import asyncio
import base64
import difflib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import struct
import sys
import time
import uuid

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import ROUND_UP, Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from html import escape
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
from aiohttp import web
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    LabeledPrice,
    Message,
    PreCheckoutQuery,
)

# =========================
# НАСТРОЙКИ (Railway -> Variables)
# =========================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vpn-bot")


def _parse_id_list(raw: str) -> list[int]:
    """
    Разбирает ADMIN_ID как список Telegram ID.

    Поддерживаются «123», «123,456», «123 456», «+123». Нечисловые куски
    (например, @username) пропускаются с предупреждением в лог.
    """
    ids: list[int] = []
    for chunk in re.split(r"[,\s;]+", (raw or "").strip()):
        candidate = chunk.strip().lstrip("+")
        if not candidate:
            continue
        if candidate.isdigit():
            value = int(candidate)
            if value not in ids:
                ids.append(value)
        else:
            logger.warning(
                "ADMIN_ID: «%s» не похоже на Telegram ID — пропускаю. "
                "Свой ID можно узнать командой /myid у бота.",
                chunk,
            )
    return ids


def _int_env(name: str, default: int = 0) -> int:
    """Безопасно считывает целое число из переменной окружения."""
    val = (os.getenv(name) or "").strip()
    if not val:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        logger.warning("Переменная %s ('%s') не является числом, беру %s", name, val, default)
        return default


# =========================
# 2FA / TOTP (Google Authenticator)
# =========================
# Панель 3x-ui (все сборки на MHSanaei, v2.x и v3.x) при включённой двухфакторке
# требует в теле POST /login дополнительное поле twoFactorCode — одноразовый
# 6-значный код из Google Authenticator. Код считается из того же base32-секрета,
# который панель показывает в Settings -> Security -> Two-factor authentication.

TOTP_PERIOD = 30          # секунд в одном окне кода (стандарт Google Authenticator)
TOTP_DIGITS = 6           # длина кода
TOTP_SKEW_WINDOWS = 1     # 3x-ui принимает код текущего окна ±1 (допуск рассинхрона часов ~30 сек)
TOTP_MIN_SECRET_LEN = 16  # RFC 4226: не короче 128 бит (16 символов base32)
TOTP_MIN_WINDOW_LEFT = 3  # если до смены кода меньше 3 секунд — дождёмся нового окна


def normalize_totp_secret(raw: str) -> str:
    """
    Приводит секрет 2FA к каноничному виду: base32 в верхнем регистре без пробелов.

    Понимает любой формат вставки из панели:
      • сам секрет:        JBSWY3DPEHPK3PXP
      • с пробелами/дефисами: JBSW Y3DP-EHPK 3PXP
      • строку параметра:  secret=JBSWY3DPEHPK3PXP
      • целиком otpauth:   otpauth://totp/3x-ui?secret=JBSWY3DPEHPK3PXP&issuer=3x-ui
    """
    value = (raw or "").strip()
    if not value:
        return ""
    match = re.search(r"secret=([A-Za-z2-7=\s]+)", value, re.IGNORECASE)
    if match:
        value = match.group(1)
    value = re.sub(r"[\s\-_]", "", value).rstrip("=").upper()
    return value


def totp_secret_problem(secret: str) -> str | None:
    """Возвращает описание проблемы с секретом 2FA или None, если секрет корректен."""
    if not secret:
        return "секрет пустой"
    bad_chars = sorted(set(re.findall(r"[^A-Z2-7]", secret)))
    if bad_chars:
        return f"в секрете есть символы, недопустимые в base32: {' '.join(bad_chars)}"
    if len(secret) < TOTP_MIN_SECRET_LEN:
        return f"секрет слишком короткий ({len(secret)} символов, ожидается ≥ {TOTP_MIN_SECRET_LEN})"
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except Exception as exc:  # pragma: no cover — защита от экзотических опечаток
        return f"секрет не декодируется как base32 ({exc})"
    return None


def totp_code(secret: str, at: float | None = None, shift_windows: int = 0) -> str:
    """
    Считает код Google Authenticator (RFC 6238: HMAC-SHA1, 30 секунд, 6 цифр).

    :param secret: base32-секрет (как из панели 3x-ui)
    :param at: момент времени в секундах (по умолчанию — сейчас)
    :param shift_windows: сдвиг на N окон вперёд/назад (для повторной попытки входа)
    """
    if not secret:
        raise ValueError("Секрет 2FA не задан (XUI_2FA_SECRET)")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    moment = (time.time() if at is None else at) + shift_windows * TOTP_PERIOD
    counter = int(moment // TOTP_PERIOD)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_seconds_left(at: float | None = None) -> float:
    """Сколько секунд осталось до смены текущего кода 2FA."""
    moment = time.time() if at is None else at
    return TOTP_PERIOD - (moment % TOTP_PERIOD)


def _handle_cli_args() -> bool:
    """
    Разовые команды для диагностики (без запуска бота):

        python bot.py --totp [BASE32_SECRET]

    Печатает текущий код Google Authenticator, предыдущий и следующий.
    Секрет можно не указывать — тогда берётся переменная окружения XUI_2FA_SECRET.
    """
    args = sys.argv[1:]
    if not args or args[0] not in ("--totp", "-totp", "--2fa"):
        return False

    secret = normalize_totp_secret(args[1] if len(args) > 1 else (os.getenv("XUI_2FA_SECRET") or ""))
    problem = totp_secret_problem(secret)
    if problem:
        print(f"❌ Секрет 2FA не задан или некорректен: {problem}")
        print("Использование: python bot.py --totp BASE32_SECRET")
        print("Либо задай переменную окружения XUI_2FA_SECRET и запусти: python bot.py --totp")
        raise SystemExit(1)

    now = time.time()
    print(f"🔐 Код Google Authenticator: {totp_code(secret, at=now)}  (действует ещё {totp_seconds_left(now):.0f} сек)")
    print(f"   Предыдущий код: {totp_code(secret, at=now, shift_windows=-1)}")
    print(f"   Следующий код:  {totp_code(secret, at=now, shift_windows=1)}")
    return True


# Если передан флаг --totp, дальше (проверка BOT_TOKEN, запуск бота) не идём.
if _handle_cli_args():  # pragma: no cover
    raise SystemExit(0)


# --- Telegram ---
BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip()
if not BOT_TOKEN:
    raise SystemExit(
        "BOT_TOKEN не задан! Добавь его в Railway -> Variables и перезапусти сервис."
    )

# Администраторы бота. Можно указать несколько ID через запятую: «123,456».
# Ведущий «+», лишние пробелы и точки с запятой не мешают; нечисловые куски
# пропускаются с предупреждением в лог (частая ошибка — вставить @username).
ADMIN_ID_RAW = (os.getenv("ADMIN_ID") or "").strip()
ADMIN_IDS = _parse_id_list(ADMIN_ID_RAW)
ADMIN_ID = ADMIN_IDS[0] if ADMIN_IDS else 0   # основной админ — первый в списке

# --- Панель 3x-ui ---
# XUI_URL копируй из браузера ровно так, как открываешь:
#   http://1.2.3.4:2053
#   https://1.2.3.4:2053
#   https://domain.com:2053/secretpath (если есть webBasePath)
# Без слэша на конце!
XUI_URL = (os.getenv("XUI_URL") or "").strip().rstrip("/")
XUI_USERNAME = (os.getenv("XUI_USERNAME") or "").strip()
XUI_PASSWORD = os.getenv("XUI_PASSWORD") or ""

# Если в 3x-ui создан API Token (в настройках панели) — можно указать его вместо логина/пароля
XUI_TOKEN = (os.getenv("XUI_TOKEN") or "").strip()

# --- Двухфакторная аутентификация (Google Authenticator) ---
# Если в панели 3x-ui включена 2FA (Settings -> Security -> Two-factor authentication),
# укажи здесь её секрет — бот сам будет считать 6-значный код при каждом входе.
# Принимается и сам base32-секрет, и целиком ссылка otpauth:// из QR-кода.
XUI_2FA_SECRET = normalize_totp_secret(os.getenv("XUI_2FA_SECRET") or "")
if XUI_2FA_SECRET:
    _totp_problem = totp_secret_problem(XUI_2FA_SECRET)
    if _totp_problem:
        logger.warning(
            "Переменная XUI_2FA_SECRET заполнена некорректно (%s) — 2FA работать не будет. "
            "Скопируй секрет из панели 3x-ui: Settings -> Security -> Two-factor authentication.",
            _totp_problem,
        )
    else:
        logger.info("2FA для панели 3x-ui включена: код будет считаться из XUI_2FA_SECRET.")

# ID входящего подключения (VLESS). Если 0 — бот подберёт подходящее автоматически.
XUI_INBOUND_ID = _int_env("XUI_INBOUND_ID")

# --- Локации (серверы) ---
# Каждая локация — своё входящее подключение (inbound) в панели 3x-ui. Клиент выбирает
# локацию при покупке тарифа на один туннель; тарифы на два и больше туннелей выдают
# доступ сразу во всех локациях.
#
# ID подключений берутся из переменных XUI_INBOUND_<ЛОКАЦИЯ>. Если переменная не задана,
# бот ищет подключение по названию (remark) в панели: «Стокгольм»/«Stockholm» для первой
# локации, «Варшава»/«Warsaw» — для второй. Если и по названию не нашлось, локация
# работает на общем XUI_INBOUND_ID (как до появления выбора сервера) — что именно
# сопоставилось, видно в /panel_debug.
XUI_INBOUND_STOCKHOLM = _int_env("XUI_INBOUND_STOCKHOLM")
XUI_INBOUND_WARSAW = _int_env("XUI_INBOUND_WARSAW")

LOCATIONS = {
    "stockholm": {
        "title": "🇸🇪 Стокгольм",
        "short": "Стокгольм",
        "env": "XUI_INBOUND_STOCKHOLM",
        "inbound_id": XUI_INBOUND_STOCKHOLM,
        "aliases": ("стокгольм", "stockholm", "швец", "sweden", "-se-", " se ", "se-"),
    },
    "warsaw": {
        "title": "🇵🇱 Варшава",
        "short": "Варшава",
        "env": "XUI_INBOUND_WARSAW",
        "inbound_id": XUI_INBOUND_WARSAW,
        "aliases": ("варшав", "warsaw", "варшавa", "польш", "poland", "-pl-", "pl-"),
    },
}
# Порядок локаций в кнопках и текстах.
LOCATION_ORDER = ("stockholm", "warsaw")

# --- Группа клиентов в 3x-ui ---
# Если задано, все создаваемые ботом клиенты помечаются этой группой (раздел
# "Группы"/Groups в панели 3x-ui, версия 3.2+): в панели их можно отфильтровать,
# видеть общий расход трафика группы и т.д. Группа создаётся автоматически.
XUI_CLIENT_GROUP = (os.getenv("XUI_CLIENT_GROUP") or "").strip()
if XUI_CLIENT_GROUP:
    logger.info("Клиенты бота будут добавляться в группу 3x-ui «%s».", XUI_CLIENT_GROUP)

# --- Необязательные переопределения ---
# По умолчанию адрес сервера в ключе = хост из XUI_URL, порт = порт inbound.
VPN_HOST = (os.getenv("VPN_HOST") or "").strip()
VPN_PORT = _int_env("VPN_PORT")

# --- Ссылка-подписка (сервис подписок 3x-ui) ---
# Клиент получает не отдельный ключ, а ссылку-подписку: приложение по ней само
# забирает конфигурацию и обновляет её, когда что-то меняется на сервере.
# Адрес сервиса подписок бот спрашивает у панели (Settings -> Subscription:
# Sub URI / Sub Domain / Sub Port / Sub Path) и проверяет ссылку запросом.
# Переменные ниже — принудительное переопределение (например, панель за прокси):
#   SUB_URL_BASE=https://sub.example.com:2096 — адрес сервиса подписок (можно с путём);
#   SUB_PORT=2096     — порт сервиса подписок, если он не входит в SUB_URL_BASE;
#   SUB_PATH=/sub/    — путь сервиса подписок, если отличается от настроек панели.
SUB_URL_BASE = (os.getenv("SUB_URL_BASE") or "").strip().rstrip("/")
SUB_PORT = (os.getenv("SUB_PORT") or "").strip()
SUB_PATH = (os.getenv("SUB_PATH") or "").strip()

# =========================
# ОПЛАТА ПОДПИСОК
# =========================
# Режимы (PAYMENTS_MODE):
#   • platega   — Platega: бот создаёт транзакцию через API и присылает ссылку на
#                 оплату (карта, СБП, кошельки, крипта), результат приходит
#                 callback-уведомлением на /platega/webhook.
#   • stars     — Telegram Stars (XTR). Штатный способ оплаты цифровых товаров
#                 внутри Telegram: не нужны ни юрлицо, ни платёжный шлюз.
#   • provider  — Telegram Payments через платёжный токен BotFather (ЮKassa и др.),
#                 оплата картой в рублях прямо в чате.
#   • yookassa  — прямая интеграция с API ЮKassa: бот создаёт платёж и присылает
#                 ссылку на оплату (карта, СБП), результат приходит вебхуком.
#   • off       — приём оплаты выключен (кнопки тарифов показывают заглушку).
# Если PAYMENTS_MODE не задан: provider → при наличии PAYMENT_PROVIDER_TOKEN,
# иначе yookassa → при наличии ключей ЮKassa, иначе platega → при наличии
# Merchant ID и ключа Platega, иначе stars.

PAYMENTS_MODE = (os.getenv("PAYMENTS_MODE") or "").strip().lower()

# Токен платёжного провайдера из @BotFather (Bot Settings -> Payments).
# Для ЮKassa тестовый токен выглядит как 381764678:TEST:..., боевой — x:LIVE:...
PAYMENT_PROVIDER_TOKEN = (os.getenv("PAYMENT_PROVIDER_TOKEN") or "").strip()
PROVIDER_TEST_MODE = ":TEST:" in PAYMENT_PROVIDER_TOKEN.upper()

# Чек 54-ФЗ для оплаты картой внутри Telegram: 1 — бот передаёт данные чека в
# provider_data (формат ЮKassa) и просит у покупателя email для отправки чека,
# 0 (по умолчанию) — чек не передаём (безопасно, если фискализация не подключена).
TELEGRAM_SEND_RECEIPT = (os.getenv("TELEGRAM_SEND_RECEIPT") or "").strip().lower() in ("1", "true", "yes", "on")
TELEGRAM_RECEIPT_VAT_CODE = _int_env("TELEGRAM_RECEIPT_VAT_CODE", 1)

# --- Platega (карта, СБП, кошельки — оплата по ссылке) ---
# Merchant ID (UUID) и API-ключ из личного кабинета Platega: Настройки → Интеграция → API.
# Те же два значения Platega присылает заголовками X-MerchantId и X-Secret при вызове
# нашего вебхука — по ним бот проверяет, что уведомление настоящее.
PLATEGA_MERCHANT_ID = (os.getenv("PLATEGA_MERCHANT_ID") or "").strip()
PLATEGA_SECRET = (os.getenv("PLATEGA_SECRET") or "").strip()

# Адрес API. Меняется, только если менеджер Platega выдал другой хост.
PLATEGA_API_URL = (os.getenv("PLATEGA_API_URL") or "https://app.platega.io").strip().rstrip("/")

# Валюта счёта: RUB (по умолчанию).
PLATEGA_CURRENCY = (os.getenv("PLATEGA_CURRENCY") or "RUB").strip().upper()

# Способ оплаты. Пусто (по умолчанию) — плательщик сам выбирает способ на странице
# Platega: так касса сама показывает то, что доступно магазину. Можно зафиксировать
# один метод: 2 — СБП (QR), 3 — ЕРИП, 11 — карточный эквайринг,
# 12 — международная оплата, 13 — криптовалюта, 14 — SberPay.
PLATEGA_METHOD_RAW = (os.getenv("PLATEGA_METHOD") or "").strip()
PLATEGA_METHOD = int(PLATEGA_METHOD_RAW) if PLATEGA_METHOD_RAW.isdigit() else None
PLATEGA_METHODS = {
    2: "СБП (QR-код)",
    3: "ЕРИП",
    11: "карточный эквайринг",
    12: "международная оплата",
    13: "криптовалюта",
    14: "SberPay",
}

# Куда Platega вернёт плательщика после успешной оплаты и после неудачи.
# Пусто — используется ссылка на бота (клиент возвращается прямо в Telegram).
PLATEGA_RETURN_URL = (os.getenv("PLATEGA_RETURN_URL") or "").strip()
PLATEGA_FAILED_URL = (os.getenv("PLATEGA_FAILED_URL") or "").strip()

# Путь вебхука: этот адрес вписывается в кабинет Platega (Настройки → Callback URLs)
# как https://<домен сервиса><PLATEGA_WEBHOOK_PATH>.
PLATEGA_WEBHOOK_PATH = (os.getenv("PLATEGA_WEBHOOK_PATH") or "/platega/webhook").strip() or "/platega/webhook"
if not PLATEGA_WEBHOOK_PATH.startswith("/"):
    PLATEGA_WEBHOOK_PATH = "/" + PLATEGA_WEBHOOK_PATH

# Проверка выдачи ключа БЕЗ реальной оплаты (только для админа): /test_pay.
# Бот прогоняет тот же путь, что и после настоящей оплаты — создаёт заказ, клиента
# в 3x-ui и отправляет сообщение с ключом, — но денег не списывает. Такой заказ
# помечается тестовым и не попадает в выручку. Включается переменной
# PAYMENTS_ALLOW_TEST_PAY=1 (после проверки её лучше убрать).
PAYMENTS_ALLOW_TEST_PAY = (os.getenv("PAYMENTS_ALLOW_TEST_PAY") or "").strip().lower() in ("1", "true", "yes", "on")

# Видны ли тестовые команды (/test_pay, /platega_check) и их кнопки.
# По умолчанию — только когда включена проверка без оплаты (PAYMENTS_ALLOW_TEST_PAY=1).
# В обычном режиме
# этих команд в боте нет совсем: ни в меню Telegram, ни в /payments.
# TEST_TOOLS=0 — спрятать даже в тестовой сети (бот выглядит полностью боевым);
# TEST_TOOLS=1 — включить принудительно.
TEST_TOOLS_RAW = (os.getenv("TEST_TOOLS") or "").strip().lower()

# Видны ли служебные команды администратора: /inbounds, /reset_vpn, /panel_debug,
# /totp, /groups, /payments, /revoke, /test_pay, /platega_check.
#   ADMIN_TOOLS=0 (по умолчанию) — в боте их нет совсем: ни в меню Telegram, ни по вводу.
#     Пользователи видят только рабочие команды, бот выглядит как обычный сервис.
#   ADMIN_TOOLS=1 — все админ-команды возвращаются (нужно для обслуживания).
# /myid остаётся доступной всегда: по ней админ понимает свой ID и видит подсказку,
# как включить служебные команды обратно.
ADMIN_TOOLS = (os.getenv("ADMIN_TOOLS") or "0").strip().lower() in ("1", "true", "yes", "on")

# Промо-тариф (бесплатно 15 дней, 10 ГБ): виден всем, но выдаётся один раз на аккаунт.
#   PROMO_ENABLED=0 — полностью убрать пункт из тарифов (промо закончилось);
#   PROMO_ONCE=0    — разрешить получать промо повторно (для своих тестов).
PROMO_KEY = "promo"
PROMO_DAYS = 15          # срок промо-доступа в днях (см. тариф PROMO_KEY ниже)
PROMO_ENABLED = (os.getenv("PROMO_ENABLED") or "1").strip().lower() in ("1", "true", "yes", "on")
PROMO_ONCE = (os.getenv("PROMO_ONCE") or "1").strip().lower() in ("1", "true", "yes", "on")

# Доступен ли бесплатный тест на 24 часа обычным пользователям (/test_vpn).
#   0 (по умолчанию) — тестовый доступ только у администратора (как было);
#   1 — тест доступен всем: кнопка есть в меню у каждого, ключ выдаётся на 24 часа.
TRIAL_PUBLIC = (os.getenv("TRIAL_PUBLIC") or "0").strip().lower() in ("1", "true", "yes", "on")

# Показывать ли кнопки и пункт бесплатного теста (главное меню, профиль, тарифы).
#   0 (по умолчанию) — кнопок теста нет ни у кого, даже у администратора: бот
#       выглядит полностью боевым. Сам ключ остаётся доступен админу командой /test_vpn.
#   1 — кнопки показываются тем, кому доступен тест (см. TRIAL_PUBLIC).
TRIAL_BUTTON = (os.getenv("TRIAL_BUTTON") or "0").strip().lower() in ("1", "true", "yes", "on")

# --- Реферальная программа («пригласи друга») ---
# Работает во всех режимах оплаты: бонусные дни начисляются после ПЕРВОЙ оплаты
# приглашённого. Пока приглашённый не купил подписку, ничего не начисляется —
# так программа не превращается в способ раздавать бесплатные ключи.
REFERRAL_ENABLED = (os.getenv("REFERRAL_ENABLED") or "1").strip().lower() not in ("0", "false", "no", "off")
# Сколько дней получает пригласивший за друга, который оплатил подписку.
REFERRAL_BONUS_DAYS = _int_env("REFERRAL_BONUS_DAYS", 7)
# Сколько дней получает сам приглашённый (добавляются к его первой оплате).
REFERRAL_INVITED_BONUS_DAYS = _int_env("REFERRAL_INVITED_BONUS_DAYS", 3)
# Журнал рефералов (кто кого пригласил, кому какие дни уже начислены).
REFERRAL_STORE_FILE = (os.getenv("REFERRAL_STORE_FILE") or "data/referrals.json").strip()
# Username бота для реферальной ссылки. Если не задан — бот спросит его у Telegram.
BOT_USERNAME = (os.getenv("BOT_USERNAME") or "").strip().lstrip("@")

# --- Сервис и документы ---
# Название сервиса — шапка соглашения (/terms) и политики (/privacy).
SERVICE_NAME = (os.getenv("SERVICE_NAME") or "Darktier VPN").strip()
# Username поддержки без @ — куда писать пользователю. Используется и в соглашении
# (п. 10.1), и в политике (п. 5.3), и в разделе «Поддержка», и в кнопке «💬 Поддержка».
# Переменная SUPPORT_USERNAME в Railway имеет приоритет: если она задана, в боте будет
# она, а не значение ниже.
SUPPORT_USERNAME = (os.getenv("SUPPORT_USERNAME") or "Darktier_support").strip().lstrip("@")
# Email поддержки — указывается в соглашении (п. 10.1) и в разделе «Поддержка».
SUPPORT_EMAIL = (os.getenv("SUPPORT_EMAIL") or "darktier.online@gmail.com").strip()
# Кто оказывает услугу (реквизиты для соглашения): ИП/ООО/самозанятый, город, ИНН.
# Если задано — в шапку соглашения добавляется строка «Исполнитель: …». Если пусто,
# строка не показывается, реквизиты выдаёт поддержка.
TERMS_OPERATOR = (os.getenv("TERMS_OPERATOR") or "").strip()
# Дата последней редакции соглашения и политики (меняется вручную при правках текста).
TERMS_UPDATED = (os.getenv("TERMS_UPDATED") or "22.09.2026").strip()

# Показывать ли соглашение при первом запуске бота (кнопка «✅ Согласен»).
#   1 (по умолчанию) — новичок сначала видит соглашение и подтверждает его;
#   0 — соглашение не спрашивается, бот сразу показывает меню (остаётся /terms).
TERMS_ACCEPT = (os.getenv("TERMS_ACCEPT") or "1").strip().lower() not in ("0", "false", "no", "off")
# Файл с отметками о принятии соглашения (кто и когда подтвердил).
TERMS_STORE_FILE = (os.getenv("TERMS_STORE_FILE") or "data/terms.json").strip()

# Лимит одного сообщения Telegram. Документы (соглашение, политика) упакованы в
# раскрывающуюся цитату и обычно умещаются целиком; если из-за длинных SERVICE_NAME
# и TERMS_OPERATOR текст не влезает, бот отправит документ несколькими сообщениями.
TELEGRAM_MESSAGE_LIMIT = 4096

# ЮKassa: Shop ID и секретный ключ (Интеграция -> Ключи API). test_* ключи = тестовый магазин.
YOOKASSA_SHOP_ID = (os.getenv("YOOKASSA_SHOP_ID") or "").strip()
YOOKASSA_SECRET_KEY = (os.getenv("YOOKASSA_SECRET_KEY") or "").strip()
YOOKASSA_API_URL = (os.getenv("YOOKASSA_API_URL") or "https://api.yookassa.ru/v3").strip().rstrip("/")

# OAuth-токен ЮKassa (необязательно). При Basic-авторизации вебхуки настраиваются
# ТОЛЬКО в личном кабинете (Интеграция → HTTP-уведомления), через API их можно
# задать лишь OAuth-токеном — если он указан, бот зарегистрирует вебхук сам.
YOOKASSA_OAUTH_TOKEN = (os.getenv("YOOKASSA_OAUTH_TOKEN") or "").strip()
YOOKASSA_TEST = (os.getenv("YOOKASSA_TEST") or "").strip().lower() in ("1", "true", "yes", "on") or \
    YOOKASSA_SECRET_KEY.startswith("test_")

# Публичный адрес сервиса (нужен для вебхука ЮKassa). Railway подставляет его сам.
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/")
if not PUBLIC_BASE_URL:
    _railway_domain = (os.getenv("RAILWAY_PUBLIC_DOMAIN") or "").strip()
    if _railway_domain:
        PUBLIC_BASE_URL = f"https://{_railway_domain}"

# Порт веб-сервера (вебхуки ЮKassa). Railway передаёт PORT автоматически.
WEB_PORT = _int_env("PORT", 8080)

# Часовой пояс для дат в сообщениях бота (срок в панели хранится в UTC-миллисекундах).
BOT_TIMEZONE = (os.getenv("BOT_TIMEZONE") or "Europe/Moscow").strip()
try:
    from zoneinfo import ZoneInfo

    LOCAL_TZ = ZoneInfo(BOT_TIMEZONE)
except Exception:   # нет базы часовых поясов — работаем в UTC
    LOCAL_TZ = timezone.utc

# Файл с журналом заказов (идемпотентность, статистика).
# На Railway без volume файл живёт до передеплоя: заказы также пишутся в 3x-ui.
PAYMENT_STORE_FILE = (os.getenv("PAYMENT_STORE_FILE") or "data/payments.json").strip()

# Сколько рублей в одной звезде при пересчёте цены тарифа в Stars (цену в звёздах для
# конкретного тарифа можно задать точно: STARS_TIME_1, STARS_TRAFFIC_4 и т.п.).
STARS_RUB_RATE = float((os.getenv("STARS_RUB_RATE") or "1.6").replace(",", "."))

# Чек 54-ФЗ для ЮKassa: 1..6 — ставка НДС (чек формирует и передаёт бот), 0 — не передавать.
# По умолчанию 0 (безопасно): если фискализация не подключена, передача чека ломает
# создание платежа. Включай 1..6, только если чеки фискализирует твоя онлайн-касса.
# Если чеки делает сам сервис («Чеки от ЮKassa»), оставь 0 — ЮKassa сформирует их сама.
YOOKASSA_VAT_CODE = _int_env("YOOKASSA_VAT_CODE", 0)

if not PAYMENTS_MODE:
    if PAYMENT_PROVIDER_TOKEN:
        PAYMENTS_MODE = "provider"
    elif YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY:
        PAYMENTS_MODE = "yookassa"
    elif PLATEGA_MERCHANT_ID and PLATEGA_SECRET:
        PAYMENTS_MODE = "platega"
    else:
        PAYMENTS_MODE = "stars"

if PAYMENTS_MODE not in ("stars", "provider", "yookassa", "platega", "off"):
    logger.warning("Неизвестный PAYMENTS_MODE=%r — платежи выключены.", PAYMENTS_MODE)
    PAYMENTS_MODE = "off"

if PAYMENTS_MODE == "provider" and not PAYMENT_PROVIDER_TOKEN:
    logger.warning(
        "PAYMENTS_MODE=provider, но PAYMENT_PROVIDER_TOKEN не задан — оплата картой работать не будет. "
        "Возьмите токен в @BotFather -> Bot Settings -> Payments."
    )
if PAYMENTS_MODE == "yookassa" and not (YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY):
    logger.warning(
        "PAYMENTS_MODE=yookassa, но не заданы YOOKASSA_SHOP_ID / YOOKASSA_SECRET_KEY — платежи не создадутся."
    )
if PAYMENTS_ALLOW_TEST_PAY:
    logger.info(
        "Проверка выдачи ключа без оплаты включена: команда /test_pay (только для администратора)."
    )

if PAYMENTS_MODE == "platega" and not (PLATEGA_MERCHANT_ID and PLATEGA_SECRET):
    logger.warning(
        "PAYMENTS_MODE=platega, но не заданы PLATEGA_MERCHANT_ID / PLATEGA_SECRET — "
        "платежи создаваться не будут. Оба значения есть в кабинете Platega: "
        "Настройки -> Интеграция -> API."
    )
if PAYMENTS_MODE == "platega" and not PUBLIC_BASE_URL:
    logger.warning(
        "Не задан PUBLIC_BASE_URL (публичный адрес сервиса) — Platega не сможет прислать "
        "callback об оплате, заказ будет подтверждаться только кнопкой «Проверить оплату»."
    )

if PAYMENTS_MODE == "yookassa" and not PUBLIC_BASE_URL:
    logger.warning(
        "Не задан PUBLIC_BASE_URL (публичный адрес сервиса) — вебхук ЮKassa не будет зарегистрирован, "
        "оплата будет подтверждаться только кнопкой «Проверить оплату»."
    )

# Прокси для запросов к панели (если хостер блокирует IP Railway).
# Формат: http://user:pass@host:port
XUI_PROXY = (os.getenv("XUI_PROXY") or "").strip() or None

# Reality-параметры (по умолчанию читаются автоматически из настроек inbound):
REALITY_PUBLIC_KEY = (os.getenv("REALITY_PUBLIC_KEY") or "").strip()
REALITY_SNI = (os.getenv("REALITY_SNI") or "").strip()
REALITY_SHORT_ID = (os.getenv("REALITY_SHORT_ID") or "").strip()
REALITY_FP = (os.getenv("REALITY_FP") or "").strip()

# Параметры тестового ключа
TEST_HOURS = 24
TEST_TRAFFIC_BYTES = 1024 ** 3  # 1 ГиБ
TEST_IP_LIMIT = 1

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
vpn_lock = asyncio.Lock()

# Кэш адреса сервиса подписок: чтобы не проверять его на каждой выдаче ключа.
SUB_CACHE_TTL = 600
_sub_base_cache: dict = {"base": None, "note": "", "at": 0.0, "checked": False}


# =========================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================

def _snip(text: str, limit: int = 160) -> str:
    """Выжимка из HTML-ответа для компактного отображения ошибки."""
    return " ".join((text or "").split())[:limit]


def _human_bytes(value) -> str:
    """Переводит байты в читаемый вид (1.5 ГиБ, 780 МиБ и т.д.)."""
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "—"

    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if size < 1024:
            return f"{size:.1f} {unit}".replace(".0 ", " ")
        size /= 1024
    return f"{size:.1f} ПиБ"


def classify_body(text: str) -> str:
    """Определяет, кто ответил вместо API панели (Cloudflare, Nginx, WAF и т.д.)."""
    low = (text or "").lower()
    if "error code: 1020" in low or "cf-ray" in low or "cloudflare" in low:
        return "Cloudflare/WAF блокирует запрос (error 1020 / challenge)"
    if "ddos-guard" in low:
        return "DDoS-Guard блокирует запрос"
    if "qrator" in low:
        return "Qrator (анти-DDoS) блокирует запрос"
    if "stormwall" in low:
        return "StormWall (анти-DDoS) блокирует запрос"
    if "ddos" in low or "access denied" in low or "forbidden" in low:
        return "WAF/файрвол вернул «Forbidden / Access Denied»"
    if "nginx" in low:
        return "на порту отвечает nginx-заглушка (не панель 3x-ui)"
    if ("window.location" in low and "login" in low) or "x-ui" in low or "3x-ui" in low:
        return "страница панели 3x-ui — панель жива"
    return "неопознанный ответ"


class XUIError(Exception):
    """Ошибка, текст которой можно безопасно и понятно показать пользователю."""


# Подсказки в сообщениях панели, по которым понятно, что отклонили именно код 2FA
# (в 3x-ui сообщения локализованы, поэтому проверяем и русские варианты).
_2FA_HINTS = (
    "2fa", "2-фа", "2фа", "twofactor", "two-factor", "two factor",
    "otp", "authenticator", "двухфактор", "двух-фактор", "двух фактор",
    "код аутентификации", "одноразов", "invalid code", "wrong code",
)


def _looks_like_2fa_error(text: str) -> bool:
    """Похоже ли, что панель отклонила код двухфакторной аутентификации."""
    low = (text or "").lower()
    return any(hint in low for hint in _2FA_HINTS)


def two_factor_hint() -> str:
    """Единая подсказка про 2FA для сообщений об ошибках авторизации."""
    if XUI_2FA_SECRET:
        problem = totp_secret_problem(XUI_2FA_SECRET)
        if problem:
            return (
                "🔐 <b>Панель использует 2FA</b>, но переменная <b>XUI_2FA_SECRET</b> заполнена некорректно:\n"
                f"<i>{escape(problem)}</i>\n\n"
                "Скопируй секрет заново: 3x-ui → Settings → Security → Two-factor authentication "
                "(кнопка показа секрета / QR-код) и вставь его в Railway → Variables → <b>XUI_2FA_SECRET</b>.\n"
                "<i>Проверить секрет можно командой /totp у бота или локально: "
                "<code>python bot.py --totp</code></i>"
            )
        return (
            "🔐 <b>2FA включена</b>: бот отправил панели код из <b>XUI_2FA_SECRET</b>.\n"
            "Если панель код не приняла, проверь, что секрет тот же, что привязан к Google Authenticator "
            "(3x-ui → Settings → Security → Two-factor authentication), и что часы сервера синхронизированы по NTP.\n"
            "<i>Посмотреть текущий код: /totp</i>"
        )
    return (
        "🔐 <b>Если в панели включена 2FA</b> (двухфакторная аутентификация) — добавь в Railway → Variables "
        "переменную <b>XUI_2FA_SECRET</b> с секретом из 3x-ui → Settings → Security → Two-factor authentication.\n"
        "<i>Либо сгенерируй API-токен в настройках 3x-ui и укажи его в <b>XUI_TOKEN</b>.</i>"
    )


def as_dict(value) -> dict:
    """3x-ui часто отдаёт settings и streamSettings JSON-строкой — безопасно распаковываем."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _ssl_context() -> ssl.SSLContext:
    """Создаёт SSL-контекст без проверки сертификата (для самоподписанных сертификатов)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def panel_host() -> str:
    """Извлекает хост (IP или домен) из XUI_URL для использования в ссылке по умолчанию."""
    try:
        return urlsplit(XUI_URL).hostname or ""
    except Exception:
        return ""


# =========================
# КЛИЕНТ 3X-UI С ПОДДЕРЖКОЙ ВСЕХ ВЕРСИЙ
# =========================

class XUIClient:
    """
    Универсальный клиент 3x-ui:
    - Поддерживает авторизацию по API Token (Bearer).
    - Поддерживает CSRF-токен (MHSanaei 3x-ui v2.4+ / v3.x).
    - Поддерживает сессии и cookies с unsafe=True (для IP).
    - Поддерживает как новые пути (/panel/api/clients/add), так и старые (/panel/api/inbounds/addClient).
    - Поддерживает безопасный повтор при таймаутах.
    """

    def __init__(self):
        self.session: aiohttp.ClientSession | None = None
        self.csrf_token: str | None = None
        # Рассинхрон часов с панелью (из HTTP-заголовка Date) — нужен для кода 2FA
        self.server_time_offset: float = 0.0
        # True/False, если панель умеет отвечать про 2FA; None — если версия старая
        self.two_factor_enabled: bool | None = None
        # Номер 30-секундного окна, код которого мы отправили последним
        self.last_totp_counter: int | None = None

    async def __aenter__(self):
        if not XUI_URL:
            raise XUIError(
                "❌ Не задан <b>XUI_URL</b> в переменных Railway!\n\n"
                "Добавь адрес панели в Railway -> Variables -> <b>XUI_URL</b> "
                "(например <code>http://1.2.3.4:2053</code> или с секретным путём)."
            )

        if not XUI_TOKEN and (not XUI_USERNAME or not XUI_PASSWORD):
            raise XUIError(
                "❌ Не заданы логин и пароль от 3x-ui!\n\n"
                "Добавь в Railway -> Variables:\n"
                "• <b>XUI_USERNAME</b> — логин от панели\n"
                "• <b>XUI_PASSWORD</b> — пароль от панели\n"
                "<i>(Либо укажи <b>XUI_TOKEN</b>, если сгенерировал API токен в 3x-ui)</i>"
            )

        if not XUI_URL.startswith(("http://", "https://")):
            raise XUIError(
                f"❌ XUI_URL должен начинаться с <code>http://</code> или <code>https://</code>.\n"
                f"Сейчас указано: <code>{escape(XUI_URL)}</code>"
            )

        ssl_ctx = _ssl_context() if XUI_URL.startswith("https://") else None

        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
        )

        # Если есть API Token (Bearer), авторизация через сессию не нужна
        if XUI_TOKEN:
            return self

        # 1. Проверяем доступность панели (прогрев)
        try:
            async with self.session.get(
                f"{XUI_URL}/",
                headers={"User-Agent": BROWSER_UA},
                allow_redirects=True,
                proxy=XUI_PROXY,
            ) as resp:
                # По заголовку Date определяем рассинхрон часов: код 2FA должен
                # быть валиден именно по часам панели.
                self._remember_server_time(resp.headers.get("Date"))
        except Exception as exc:
            raise XUIError(
                f"❌ Панель 3x-ui не отвечает по адресу:\n<code>{escape(XUI_URL)}</code>\n\n"
                f"Ошибка: <code>{escape(str(exc))}</code>\n\n"
                "<b>Что проверить:</b>\n"
                "1. Сервер с 3x-ui включён и панель открывается в браузере.\n"
                "2. Порт панели открыт в фаерволе сервера (UFW / Security Groups).\n"
                "3. В XUI_URL указан точный адрес, включая порт и секретный путь (webBasePath), если он есть."
            ) from exc

        # 2. Пытаемся получить CSRF-токен (нужен для MHSanaei 3x-ui v2.4+)
        for csrf_path in ("/csrf-token", "/panel/csrf-token"):
            try:
                async with self.session.get(
                    f"{XUI_URL}{csrf_path}",
                    headers={"User-Agent": BROWSER_UA, "Accept": "application/json"},
                    proxy=XUI_PROXY,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        token = data.get("obj")
                        if isinstance(token, str) and token:
                            self.csrf_token = token
                            logger.info("CSRF токен 3x-ui успешно получен (%s)", csrf_path)
                            break
            except Exception:
                pass

        # 3. Узнаём у панели, включена ли двухфакторная аутентификация
        self.two_factor_enabled = await self._detect_two_factor()
        if self.two_factor_enabled is True and not XUI_2FA_SECRET:
            raise XUIError(
                "🔐 <b>В панели 3x-ui включена двухфакторная аутентификация (2FA), "
                "а секрет не задан.</b>\n\n"
                "Бот не сможет войти по логину и паролю без одноразовых кодов.\n\n"
                "<b>Что сделать (любой вариант):</b>\n"
                "1. Добавь в Railway → Variables переменную <b>XUI_2FA_SECRET</b> — секрет "
                "из 3x-ui → Settings → Security → Two-factor authentication "
                "(кнопка показа секрета или QR-код). Бот сам будет считать код Google Authenticator.\n"
                "2. Либо сгенерируй в панели <b>API Token</b> (Settings → Security → API Token) "
                "и добавь его в Railway → Variables как <b>XUI_TOKEN</b> — с токеном 2FA не нужна.\n\n"
                "<i>Проверить секрет можно командой /totp или локально: <code>python bot.py --totp</code></i>"
            )

        # 4. Авторизуемся по логину и паролю (+ код 2FA, если он нужен панели)
        login_errors: list[str] = []
        login_paths = ("/login", "/login/", "/panel/api/login", "/panel/login")

        # При настроенном 2FA даём вторую попытку: код мог устареть, пока панель
        # отвечала, или часы серверов могут слегка расходиться.
        max_attempts = 2 if XUI_2FA_SECRET else 1
        for attempt in range(max_attempts):
            try:
                # Первая попытка — текущее окно кода, вторая — следующее
                # (панель допускает сдвиг на TOTP_SKEW_WINDOWS окна).
                await self._login(login_paths, login_errors, shift_windows=min(attempt, TOTP_SKEW_WINDOWS))
                break
            except XUIError as exc:
                retry_reason = _looks_like_2fa_error(str(exc))
                if attempt + 1 < max_attempts and (retry_reason or self._code_rolled_over()):
                    logger.warning(
                        "Вход с кодом 2FA не удался (%s) — повторяю со следующим кодом.",
                        _snip(str(exc), 120),
                    )
                    continue
                raise

        return self

    def _remember_server_time(self, date_header: str | None) -> None:
        """Определяет рассинхрон часов с панелью 3x-ui по HTTP-заголовку Date."""
        if not date_header:
            return
        try:
            server_dt = parsedate_to_datetime(date_header)
        except Exception:
            return
        if server_dt is None:
            return
        if server_dt.tzinfo is None:
            server_dt = server_dt.replace(tzinfo=timezone.utc)
        offset = server_dt.timestamp() - time.time()
        if abs(offset) >= 24 * 3600:  # явно мусорный заголовок — не учитываем
            return
        self.server_time_offset = offset
        if abs(offset) >= 5:
            logger.warning(
                "Часы панели 3x-ui расходятся с сервером бота на %.0f сек — учту при генерации кода 2FA.",
                offset,
            )

    def _server_now(self) -> float:
        """Текущее время по часам панели 3x-ui (если удалось его узнать)."""
        return time.time() + self.server_time_offset

    async def _fresh_totp_code(self, shift_windows: int = 0) -> str:
        """
        Возвращает актуальный код Google Authenticator для панели.

        Если до смены кода осталось меньше TOTP_MIN_WINDOW_LEFT секунд, ждём
        начала следующего окна — иначе код «сгорит» прямо во время запроса.
        """
        if not XUI_2FA_SECRET:
            raise XUIError(
                "🔐 Панель требует код двухфакторной аутентификации, но переменная "
                "<b>XUI_2FA_SECRET</b> не задана в Railway → Variables."
            )

        problem = totp_secret_problem(XUI_2FA_SECRET)
        if problem:
            raise XUIError(
                f"🔐 Переменная <b>XUI_2FA_SECRET</b> заполнена некорректно: <i>{escape(problem)}</i>\n\n"
                "Скопируй секрет заново из 3x-ui → Settings → Security → Two-factor authentication "
                "(подойдёт и целиком ссылка <code>otpauth://…</code> из QR-кода)."
            )

        left = totp_seconds_left(self._server_now())
        if shift_windows == 0 and left < TOTP_MIN_WINDOW_LEFT:
            logger.info("Код 2FA действует ещё %.1f сек — дожидаюсь нового окна.", left)
            await asyncio.sleep(left + 0.2)

        moment = self._server_now()
        code = totp_code(XUI_2FA_SECRET, at=moment, shift_windows=shift_windows)
        self.last_totp_counter = int((moment + shift_windows * TOTP_PERIOD) // TOTP_PERIOD)
        return code

    def _code_rolled_over(self) -> bool:
        """True, если окно кода 2FA успело смениться, пока панель отвечала на запрос."""
        if not XUI_2FA_SECRET or self.last_totp_counter is None:
            return False
        return int(self._server_now() // TOTP_PERIOD) != self.last_totp_counter

    async def _detect_two_factor(self) -> bool | None:
        """
        Спрашивает у панели, включена ли 2FA (POST /getTwoFactorEnable).

        Возвращает True/False либо None, если эндпоинт недоступен
        (старые сборки 3x-ui про 2FA не знают — тогда просто пробуем войти).
        """
        for path in ("/getTwoFactorEnable", "/panel/getTwoFactorEnable"):
            try:
                async with self.session.post(
                    f"{XUI_URL}{path}",
                    headers=self._login_headers(),
                    proxy=XUI_PROXY,
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
            except Exception:
                continue

            if isinstance(data, dict) and "obj" in data:
                enabled = bool(data.get("obj"))
                logger.info("Панель 3x-ui сообщила: 2FA %s.", "включена" if enabled else "выключена")
                return enabled

        return None

    def _login_headers(self) -> dict:
        """Заголовки для запроса авторизации (в стиле браузерной панели)."""
        origin = f"{urlsplit(XUI_URL).scheme}://{urlsplit(XUI_URL).netloc}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, text/plain, */*",
            "Origin": origin,
            "Referer": f"{XUI_URL}/",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        return headers

    async def _post_login(self, path: str, two_factor_code: str | None) -> tuple[int, str, dict | None]:
        """
        Отправляет логин/пароль (и код 2FA) на панель.

        Сначала JSON (3x-ui v2.4+ / v3.x), при не-JSON ответе — form-data
        (для старых сборок Gin). Возвращает (HTTP-статус, тело, JSON или None).
        """
        payload = {"username": XUI_USERNAME, "password": XUI_PASSWORD}
        if two_factor_code:
            payload["twoFactorCode"] = two_factor_code

        headers = self._login_headers()

        async with self.session.post(
            f"{XUI_URL}{path}",
            json=payload,
            headers=headers,
            proxy=XUI_PROXY,
        ) as resp:
            status = resp.status
            raw = await resp.text()

        try:
            return status, raw, json.loads(raw)
        except ValueError:
            data = None

        if status in (404, 405):
            return status, raw, data

        # Ответ не JSON — пробуем form-data
        async with self.session.post(
            f"{XUI_URL}{path}",
            data=payload,
            headers=headers,
            proxy=XUI_PROXY,
        ) as form_resp:
            form_raw = await form_resp.text()
            try:
                return form_resp.status, form_raw, json.loads(form_raw)
            except ValueError:
                return status, raw, None

    async def _login(self, paths: tuple[str, ...], login_errors: list[str], shift_windows: int = 0) -> None:
        """
        Пробует войти в панель по указанным путям.

        При успехе просто возвращает управление, иначе бросает XUIError
        с понятным описанием проблемы.
        """
        two_factor_code: str | None = None
        if XUI_2FA_SECRET:
            two_factor_code = await self._fresh_totp_code(shift_windows)
            logger.info(
                "Вход в 3x-ui с кодом двухфакторной аутентификации (окно %+d, рассинхрон часов %.0f сек).",
                shift_windows,
                self.server_time_offset,
            )

        for login_path in paths:
            try:
                status, raw, data = await self._post_login(login_path, two_factor_code)
            except Exception as exc:
                login_errors.append(f"{login_path} -> {exc}")
                continue

            if status in (404, 405):
                login_errors.append(f"{login_path} -> HTTP {status}")
                continue

            if data is None:
                login_errors.append(f"{login_path} -> не JSON (HTTP {status}): {_snip(raw)}")
                continue

            if data.get("success"):
                logger.info("Успешный вход в 3x-ui через %s", login_path)
                return

            # Панель ответила осмысленно, но отклонила вход
            msg = data.get("msg") or raw[:200]
            raise XUIError(self._login_rejected_message(msg))

        raise XUIError(self._login_failed_message(login_errors))

    def _login_rejected_message(self, msg: str) -> str:
        """Понятное объяснение отказа во входе с учётом 2FA."""
        text = (
            f"❌ Панель 3x-ui отклонила логин/пароль:\n<code>{escape(str(msg))}</code>\n\n"
            "Проверь <b>XUI_USERNAME</b> и <b>XUI_PASSWORD</b> в Railway Variables.\n\n"
        )
        return text + two_factor_hint()

    def _login_failed_message(self, login_errors: list[str]) -> str:
        """Сообщение, когда ни один из адресов авторизации не ответил внятно."""
        text = (
            "❌ Не удалось войти в панель 3x-ui:\n"
            + "\n".join(f"• {e}" for e in login_errors)
            + "\n\n<b>Возможные причины:</b>\n"
            "1. Неверный путь панели. Если панель открывается как <code>https://ip:port/mysecret</code>, "
            "обязательно укажи секретный путь в <b>XUI_URL</b>.\n"
            "2. Защита хостера (Cloudflare / DDoS-Guard) блокирует запросы Railway."
        )
        if self.two_factor_enabled is True and not XUI_2FA_SECRET:
            text += "\n3. В панели включена 2FA — нужен <b>XUI_2FA_SECRET</b> или <b>XUI_TOKEN</b>."
        return text

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session and not self.session.closed:
            await self.session.close()

    def _default_headers(self) -> dict:
        origin = f"{urlsplit(XUI_URL).scheme}://{urlsplit(XUI_URL).netloc}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, text/plain, */*",
            "Origin": origin,
            "Referer": f"{XUI_URL}/panel/",
            "X-Requested-With": "XMLHttpRequest",
        }
        if XUI_TOKEN:
            headers["Authorization"] = f"Bearer {XUI_TOKEN}"
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        return headers

    async def request(self, method: str, path: str, **kwargs):
        """Выполняет запрос к API 3x-ui."""
        headers = self._default_headers()
        headers.update(kwargs.pop("headers", {}))

        async with self.session.request(
            method,
            f"{XUI_URL}{path}",
            headers=headers,
            proxy=XUI_PROXY,
            **kwargs,
        ) as resp:
            status = resp.status
            raw = await resp.text()

        try:
            result = json.loads(raw)
        except ValueError as exc:
            raise XUIError(
                f"3x-ui вернула некорректный ответ (не JSON, HTTP {status}) на {path}.\n"
                f"Ответ: {_snip(raw, 200)}"
            ) from exc

        if status >= 400:
            raise XUIError(f"3x-ui вернула HTTP {status} на {path}: {_snip(raw, 200)}")

        if isinstance(result, dict) and result.get("success") is not True:
            msg = result.get("msg") or raw[:200]
            raise XUIError(f"3x-ui отклонила {method} {path}: {msg}")

        return result.get("obj") if isinstance(result, dict) else result

    async def get_inbounds(self) -> list:
        """Получает список всех входящих подключений (inbounds)."""
        data = await self.request("GET", "/panel/api/inbounds/list")
        if isinstance(data, list):
            return data
        return []

    # --- Группы клиентов (3x-ui v3.2+) ---
    # В панели группа хранится в поле group каждого клиента; список групп панель
    # ведёт отдельно (таблица client_groups) и создаёт запись автоматически,
    # когда клиенту проставляют новую группу.

    GROUPS_PATH = "/panel/api/clients/groups"
    GROUP_BULK_ADD_PATH = "/panel/api/clients/groups/bulkAdd"

    @staticmethod
    def _route_missing(exc: Exception) -> bool:
        """Похоже ли, что панель просто не знает такой ручки (старая версия)."""
        text = str(exc).lower()
        return "404" in text or "not found" in text

    async def list_groups(self) -> list | None:
        """Список групп панели. None — если версия 3x-ui ещё не умеет группы."""
        try:
            data = await self.request("GET", self.GROUPS_PATH)
        except XUIError as exc:
            if self._route_missing(exc):
                return None
            raise
        if isinstance(data, list):
            return [g for g in data if isinstance(g, dict)]
        return []

    async def client_group(self, email: str) -> str | None:
        """Название группы клиента (или None, если группы нет либо панель старая)."""
        try:
            data = await self.request("GET", f"/panel/api/clients/get/{quote(email, safe='')}")
        except XUIError:
            return None
        group = as_dict(data).get("group")
        return str(group) if group else None

    async def resolve_client_group(self) -> tuple[str | None, str]:
        """
        Находит в панели группу XUI_CLIENT_GROUP, чтобы клиенты попадали
        именно в уже созданную группу, а не в новую с похожим названием.

        Возвращает (название группы в панели, статус):
          • ('bot-test', 'exists')  — группа уже создана в панели (регистр поправлен, если отличался);
          • ('bot-test', 'new')     — такой группы в панели нет, она будет создана;
          • (None, 'unsupported')   — версия панели не умеет группы (нужна 3x-ui 3.2+);
          • (None, 'disabled')      — переменная XUI_CLIENT_GROUP не задана.
        """
        if not XUI_CLIENT_GROUP:
            return None, "disabled"

        groups = await self.list_groups()
        if groups is None:
            return None, "unsupported"

        existed = self.group_exists(groups)
        if existed:
            # В панели группа уже есть — берём её точное название (регистр и пробелы).
            if existed != XUI_CLIENT_GROUP:
                logger.info(
                    "Группа «%s» найдена в панели как «%s» — использую название из панели.",
                    XUI_CLIENT_GROUP,
                    existed,
                )
            return existed, "exists"

        close = self.similar_groups(groups)
        if close:
            logger.warning(
                "Группы «%s» в панели нет. Похожие названия: %s — проверь XUI_CLIENT_GROUP, "
                "иначе будет создана новая группа.",
                XUI_CLIENT_GROUP,
                ", ".join(f"«{name}»" for name in close),
            )
        return XUI_CLIENT_GROUP, "new"

    @staticmethod
    def group_names(groups: list[dict]) -> list[str]:
        """Названия групп из ответа панели."""
        return [str(g.get("name") or "").strip() for g in (groups or []) if str(g.get("name") or "").strip()]

    @classmethod
    def group_exists(cls, groups: list[dict], wanted: str | None = None) -> str | None:
        """
        Ищет группу в панели и возвращает её точное название, если она есть.

        Сначала точное совпадение, затем сравнение без учёта регистра —
        чтобы «bot-test» из переменной попал в существующую группу «Bot-Test»,
        а не создал вторую.
        """
        names = cls.group_names(groups)
        target = (wanted or XUI_CLIENT_GROUP).strip()

        if target in names:
            return target
        for name in names:
            if name.casefold() == target.casefold():
                return name
        return None

    @classmethod
    def similar_groups(cls, groups: list[dict]) -> list[str]:
        """Похожие названия групп — подсказка при опечатке в XUI_CLIENT_GROUP."""
        names = cls.group_names(groups)
        target = XUI_CLIENT_GROUP.casefold()
        close = difflib.get_close_matches(target, [n.casefold() for n in names], n=3, cutoff=0.7)
        return [name for name in names if name.casefold() in close]

    async def add_clients_to_group(self, emails: list[str], group_name: str, existed: bool | None = None) -> str:
        """
        Помечает клиентов указанной группой панели (обычно уже существующей).

        :param existed: была ли группа в панели до создания клиента. Если None —
            бот проверяет сам (для вызовов вне обычной выдачи ключа).

        Возвращает статус:
          • 'assigned'    — клиент в уже созданной группе (проверено);
          • 'assigned_new'— такой группы в панели не было, панель её создала;
          • 'not_assigned'— панель приняла запрос, но группа не подтвердилась;
          • 'skipped'     — группа не задана.
        Ошибки не пробрасываем: клиент уже создан, группа — дополнительный штрих.
        """
        emails = [e for e in emails if e]
        if not XUI_CLIENT_GROUP or not group_name or not emails:
            return "skipped"

        if existed is None:
            existed = self.group_exists(await self._safe_groups(), group_name) is not None
        payload = {"emails": emails, "group": group_name}

        for attempt in range(2):
            try:
                result = as_dict(await self.request("POST", self.GROUP_BULK_ADD_PATH, json=payload))
            except XUIError as exc:
                if self._route_missing(exc):
                    logger.info(
                        "Панель 3x-ui не поддерживает группы клиентов (нужна версия 3.2+): %s",
                        _snip(str(exc), 120),
                    )
                    return "unsupported"
                logger.warning("Не удалось добавить клиента в группу «%s»: %s", group_name, exc)
                return "not_assigned"

            if int(result.get("affected") or 0) > 0:
                logger.info("Клиент %s добавлен в группу 3x-ui «%s».", emails[0], group_name)
                return "assigned" if existed else "assigned_new"

            # Панель могла сохранить группу сразу из payload клиента (affected=0)
            # либо ещё не синхронизировать нового клиента в свою базу — проверяем.
            if (await self.client_group(emails[0]) or "").casefold() == group_name.casefold():
                logger.info("Клиент %s уже состоит в группе 3x-ui «%s».", emails[0], group_name)
                return "assigned" if existed else "assigned_new"

            if attempt == 0:
                await asyncio.sleep(1.0)

        logger.warning("Клиент %s создан, но остался без группы «%s».", emails[0], group_name)
        return "not_assigned"

    async def _safe_groups(self) -> list[dict]:
        """Список групп панели; на старых версиях — пустой список."""
        try:
            groups = await self.list_groups()
        except XUIError:
            return []
        return groups or []

    async def get_inbound(self, inbound_id: int) -> dict:
        """Получает данные конкретного подключения."""
        data = await self.request("GET", f"/panel/api/inbounds/get/{inbound_id}")
        if isinstance(data, dict):
            return data
        raise XUIError(f"Подключение #{inbound_id} не найдено в 3x-ui.")

    async def find_suitable_inbound(self, preferred_id: int = 0) -> tuple[dict, bool]:
        """
        Ищет подходящее подключение VLESS Reality.
        Если preferred_id > 0, проверяет его.
        Если preferred_id <= 0 или не найден, выбирает первое подходящее автоматически.
        Возвращает (inbound_dict, auto_picked: bool).
        """
        if preferred_id > 0:
            try:
                inbound = await self.get_inbound(preferred_id)
                if inbound and inbound.get("id"):
                    return inbound, False
            except Exception as e:
                logger.warning("Не удалось получить подключение #%s: %s", preferred_id, e)

        # Автопоиск среди всех inbounds
        inbounds = await self.get_inbounds()
        if not inbounds:
            raise XUIError(
                "❌ В панели 3x-ui нет ни одного входящего подключения (inbound).\n\n"
                "Зайди в панель 3x-ui -> Inbounds (Подключения) -> Добавить подключение:\n"
                "• Протокол: <b>VLESS</b>\n"
                "• Транспорт: <b>TCP</b>\n"
                "• Безопасность: <b>Reality</b>\n"
                "Затем отправь /test_vpn снова."
            )

        # 1-й приоритет: VLESS + TCP + Reality
        for item in inbounds:
            proto = item.get("protocol", "").lower()
            stream = as_dict(item.get("streamSettings"))
            net = stream.get("network", "").lower()
            sec = stream.get("security", "").lower()
            if proto == "vless" and net == "tcp" and sec == "reality":
                return item, True

        # 2-й приоритет: любой VLESS Reality (например gRPC / ws / xhttp)
        for item in inbounds:
            proto = item.get("protocol", "").lower()
            stream = as_dict(item.get("streamSettings"))
            sec = stream.get("security", "").lower()
            if proto == "vless" and sec == "reality":
                return item, True

        # 3-й приоритет: любой VLESS
        for item in inbounds:
            if item.get("protocol", "").lower() == "vless":
                return item, True

        # Fallback: первое подключение
        return inbounds[0], True

    async def find_inbound_by_name(self, names: list[str]) -> dict | None:
        """
        Ищет подключение по названию (remark) в панели.

        Нужно для выбора сервера: локации «Стокгольм» и «Варшава» — это разные inbound
        одной панели, и клиент должен попадать именно в выбранный (название сравнивается
        без учёта регистра, подходит и латиница).
        """
        wanted = [name.strip().lower() for name in names if name]
        if not wanted:
            return None
        try:
            inbounds = await self.get_inbounds()
        except Exception as exc:
            logger.warning("Не удалось получить список подключений для поиска по названию: %s", exc)
            return None
        for inbound in inbounds:
            remark = str(inbound.get("remark") or "").strip().lower()
            if remark and any(name in remark for name in wanted):
                return inbound
        return None

    async def add_client(self, inbound_id: int, client_payload: dict):
        """
        Универсальное добавление клиента.
        Пробует все форматы эндпоинтов 3x-ui (новые и старые).
        """
        errors = []

        # Способ 1: MHSanaei 3x-ui v2.4+ / v3.x (/panel/api/clients/add)
        try:
            body = {
                "client": client_payload,
                "inboundIds": [inbound_id],
            }
            res = await self.request("POST", "/panel/api/clients/add", json=body)
            logger.info("Клиент добавлен через /panel/api/clients/add")
            return res
        except Exception as e:
            errors.append(f"/panel/api/clients/add: {e}")

        # Способ 2: Классический 3x-ui / x-ui (/panel/api/inbounds/addClient) с JSON-строкой
        try:
            body = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [client_payload]}),
            }
            res = await self.request("POST", "/panel/api/inbounds/addClient", json=body)
            logger.info("Клиент добавлен через /panel/api/inbounds/addClient (JSON-строка)")
            return res
        except Exception as e:
            errors.append(f"/panel/api/inbounds/addClient (string): {e}")

        # Способ 3: /panel/api/inbounds/addClient с JSON-объектом
        try:
            body = {
                "id": inbound_id,
                "settings": {"clients": [client_payload]},
            }
            res = await self.request("POST", "/panel/api/inbounds/addClient", json=body)
            logger.info("Клиент добавлен через /panel/api/inbounds/addClient (JSON-объект)")
            return res
        except Exception as e:
            errors.append(f"/panel/api/inbounds/addClient (object): {e}")

        # Способ 4: /panel/api/inbounds/addClientInbounds
        try:
            body = {
                "settings": json.dumps({"clients": [client_payload]}),
                "inboundIds": [inbound_id],
            }
            res = await self.request("POST", "/panel/api/inbounds/addClientInbounds", json=body)
            logger.info("Клиент добавлен через /panel/api/inbounds/addClientInbounds")
            return res
        except Exception as e:
            errors.append(f"/panel/api/inbounds/addClientInbounds: {e}")

        raise XUIError(
            "❌ Не удалось добавить клиента в 3x-ui ни одним методом:\n"
            + "\n".join(f"• {err}" for err in errors)
        )

    async def update_client(self, inbound_id: int, client_payload: dict):
        """Обновляет параметры существующего клиента."""
        client_uuid = client_payload.get("id")
        email = client_payload.get("email")

        # Способ 1: /panel/api/clients/update/{email}
        if email:
            try:
                body = client_payload
                res = await self.request("POST", f"/panel/api/clients/update/{email}", json=body)
                logger.info("Клиент обновлён через /panel/api/clients/update/%s", email)
                return res
            except Exception as e:
                logger.debug("update by email failed: %s", e)

        # Способ 2: /panel/api/inbounds/updateClient/{uuid}
        if client_uuid:
            try:
                body = {
                    "id": inbound_id,
                    "settings": json.dumps({"clients": [client_payload]}),
                }
                res = await self.request("POST", f"/panel/api/inbounds/updateClient/{client_uuid}", json=body)
                logger.info("Клиент обновлён через /panel/api/inbounds/updateClient/%s", client_uuid)
                return res
            except Exception as e:
                logger.debug("updateClient by uuid failed: %s", e)

        # Способ 3: удалить и добавить заново
        logger.info("Обновление через удаление и повторное добавление клиента...")
        await self.delete_client(inbound_id, email, client_uuid)
        return await self.add_client(inbound_id, client_payload)

    async def delete_client(self, inbound_id: int, email: str | None, client_uuid: str | None):
        """Удаляет клиента из подключения."""
        if email:
            try:
                await self.request("POST", f"/panel/api/clients/del/{email}")
                logger.info("Клиент %s удалён через /panel/api/clients/del", email)
                return True
            except Exception:
                pass

        if client_uuid:
            try:
                await self.request("POST", f"/panel/api/inbounds/delClient/{inbound_id}/{client_uuid}")
                logger.info("Клиент %s удалён через /panel/api/inbounds/delClient", client_uuid)
                return True
            except Exception:
                pass

        return False


# =========================
# ГЕНЕРАЦИЯ VLESS REALITY КЛЮЧА
# =========================

def extract_vless_params(inbound: dict) -> dict:
    """Извлекает все параметры Reality / TLS из настроек inbound."""
    stream = as_dict(inbound.get("streamSettings"))
    network = stream.get("network") or "tcp"
    security = stream.get("security") or "reality"

    rs = as_dict(stream.get("realitySettings"))
    inner = as_dict(rs.get("settings"))

    # Публичный ключ Reality
    public_key = (
        REALITY_PUBLIC_KEY
        or str(rs.get("publicKey") or "")
        or str(inner.get("publicKey") or "")
        or str(rs.get("masterKey") or "")
    ).strip()

    # SNI / ServerNames
    server_names: list[str] = []
    for source in (rs.get("serverNames"), inner.get("serverNames")):
        if isinstance(source, list):
            server_names.extend([str(x).strip() for x in source if x])
        elif isinstance(source, str) and source.strip():
            server_names.extend([x.strip() for x in source.split(",") if x.strip()])

    sni = REALITY_SNI
    if not sni and server_names:
        sni = server_names[0]
    if not sni:
        # Пытаемся взять хост из поля dest (например 'www.microsoft.com:443')
        dest = str(rs.get("dest") or inner.get("dest") or "").strip()
        if dest:
            sni = dest.split(":")[0].strip()

    # Short ID
    short_ids: list[str] = []
    for source in (rs.get("shortIds"), inner.get("shortIds")):
        if isinstance(source, list):
            short_ids.extend([str(x).strip() for x in source if x])
        elif isinstance(source, str) and source.strip():
            short_ids.extend([x.strip() for x in source.split(",") if x.strip()])

    sid = REALITY_SHORT_ID
    if not sid and short_ids:
        sid = next((x for x in short_ids if x), "")

    # Fingerprint
    fp = (
        REALITY_FP
        or str(inner.get("fingerprint") or "")
        or str(rs.get("fingerprint") or "")
        or "chrome"
    ).strip()

    # SpiderX
    spx = (str(inner.get("spiderX") or "") or str(rs.get("spiderX") or "") or "/").strip()

    if security == "reality" and not public_key:
        raise XUIError(
            "❌ Не найден <b>публичный ключ Reality</b> (publicKey) в настройках подключения.\n\n"
            "Открой подключение в панели 3x-ui и нажми «Сохранить», либо задай в Railway Variables:\n"
            "<b>REALITY_PUBLIC_KEY</b>=твой_публичный_ключ"
        )

    if security == "reality" and not sni:
        raise XUIError(
            "❌ Не найден <b>SNI (домен маскировки)</b> в RealitySettings.\n\n"
            "Укажи в Reality в панели сервер маскировки (например www.microsoft.com или yahoo.com), "
            "либо добавь в Railway Variables:\n"
            "<b>REALITY_SNI</b>=www.microsoft.com"
        )

    return {
        "protocol": inbound.get("protocol", "vless"),
        "network": network,
        "security": security,
        "pbk": public_key,
        "sni": sni,
        "sid": sid,
        "fp": fp,
        "spx": spx,
    }


def _norm_sub_path(path: str) -> str:
    """Приводит путь сервиса подписок к виду «/sub/» (со слэшами с обеих сторон)."""
    path = (path or "").strip()
    if not path:
        return "/sub/"
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path += "/"
    return path


def panel_host_port() -> tuple[str, str]:
    """Хост и порт панели из XUI_URL (без секретного пути webBasePath)."""
    raw = XUI_URL if "://" in XUI_URL else f"http://{XUI_URL}"
    parsed = urlsplit(raw)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = str(parsed.port or (443 if scheme == "https" else 80))
    return host, port


def build_sub_link(base: str, sub_id: str) -> str:
    """Склеивает адрес сервиса подписок с Sub ID клиента."""
    return f"{(base or '').strip().rstrip('/')}/{sub_id}"


def subscription_candidates(settings: dict | None = None) -> list[tuple[str, str]]:
    """
    Возможные адреса сервиса подписок: [(база, откуда взяли)].

    Порядок — от самого надёжного к запасному: явные настройки (SUB_URL_BASE, Sub URI
    в панели), затем Sub Domain, затем хост панели с портом сервиса подписок и, наконец,
    адрес панели целиком (вариант с обратным прокси, когда /sub/ отдаёт сам веб-сервер).
    """
    settings = settings or {}
    path = _norm_sub_path(SUB_PATH or str(settings.get("subPath") or ""))
    panel_host, panel_port = panel_host_port()

    candidates: list[tuple[str, str]] = []

    def add(base: str, source: str) -> None:
        base = (base or "").strip().rstrip("/")
        if base and base not in [known for known, _ in candidates]:
            candidates.append((base, source))

    def with_path(raw: str) -> str:
        """Дописывает стандартный путь, если в адресе его нет."""
        raw = (raw or "").strip().rstrip("/")
        return raw if urlsplit(raw).path.strip("/") else f"{raw}{path}"

    if SUB_URL_BASE:
        add(with_path(SUB_URL_BASE), "SUB_URL_BASE")

    sub_uri = str(settings.get("subURI") or "").strip()
    if sub_uri.startswith(("http://", "https://")):
        add(with_path(sub_uri), "настройки панели (Sub URI)")

    sub_domain = str(settings.get("subDomain") or "").strip().strip("/")
    sub_port = (SUB_PORT or str(settings.get("subExternalPort") or "")
                or str(settings.get("subPort") or "")).strip()
    port_part = f":{sub_port}" if sub_port and sub_port not in ("80", "443") else ""

    if sub_domain and "/" not in sub_domain:
        add(f"https://{sub_domain}{port_part}{path}", "настройки панели (Sub Domain)")

    if panel_host:
        if sub_port:
            add(f"{'https' if XUI_URL.startswith('https://') else 'http'}://{panel_host}:{sub_port}{path}",
                "адрес панели и порт сервиса подписок")
        elif panel_port:
            add(f"{'https' if XUI_URL.startswith('https://') else 'http'}://{panel_host}:{panel_port}{path}",
                "адрес панели")
        # Запасной вариант: панель отдаёт подписку сама (обратный прокси), тогда
        # путь сервиса подписок живёт на том же адресе, что и панель.
        add(f"{XUI_URL.rstrip('/')}{path}", "адрес панели с путём подписок")

    return candidates


async def _check_sub_link(url: str, *, timeout: int = 6) -> tuple[bool, str]:
    """Проверяет, отдаёт ли сервис подписок конфигурацию по ссылке."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            async with session.get(url, headers={"User-Agent": BROWSER_UA},
                                   proxy=XUI_PROXY, allow_redirects=True) as resp:
                body = await resp.text()
                if resp.status != 200:
                    return False, f"HTTP {resp.status}"
                if not body.strip():
                    return False, "пустой ответ"
                return True, "200"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


async def get_subscription_base(
    client: "XUIClient | None" = None,
    *,
    sub_id: str = "",
    refresh: bool = False,
    probe: bool = True,
) -> tuple[str | None, str]:
    """
    Определяет адрес сервиса подписок: (база без Sub ID, пояснение).

    Базу бот берёт из настроек панели (или переменных SUB_*), а затем проверяет
    реальным запросом: сервис подписок обычно слушает отдельный порт (по умолчанию
    2096), и без проверки клиент рискует получить нерабочую ссылку. Результат
    кэшируется на 10 минут, чтобы не дёргать панель на каждую выдачу.

    probe=False — отдать адрес из кэша или первый по приоритету, без сетевых
    проверок. Так бот показывает ссылку в /profile, не заставляя клиента ждать.
    Пояснение — откуда адрес или почему его нет (идёт в лог и админу).
    """
    now = time.monotonic()
    cached = _sub_base_cache
    if (not refresh and cached["base"] and now - cached["at"] < SUB_CACHE_TTL
            and (not sub_id or cached["checked"])):
        return cached["base"], cached["note"]

    settings: dict = {}
    if client is not None:
        settings = await fetch_panel_settings(client)

    if settings and settings.get("subEnable") is False:
        note = "сервис подписок выключен в панели (Settings → Subscription → Enable)"
        logger.warning("Ссылка-подписка недоступна: %s", note)
        return None, note

    candidates = subscription_candidates(settings)
    if not candidates:
        return None, "не удалось определить адрес сервиса подписок (задай SUB_URL_BASE)"

    if sub_id and probe:
        # Проверяем не все варианты, а первые два: на выдаче доступа клиент ждёт,
        # а вебхук платёжной системы — ответа. Остальные адреса видны в /panel_debug.
        for base, source in candidates[:2]:
            ok, detail = await _check_sub_link(build_sub_link(base, sub_id))
            if ok:
                logger.info("Ссылка-подписка: адрес «%s» (%s), проверка пройдена.", base, source)
                _sub_base_cache.update(base=base, note=source, at=now, checked=True)
                return base, source
            logger.info("Ссылка-подписка: адрес «%s» (%s) не ответил (%s).", base, source, detail)
        base, source = candidates[0]
        note = f"{source}, но проверка не прошла"
        logger.warning("Ссылка-подписка: ни один адрес не ответил, показываю «%s».", base)
        _sub_base_cache.update(base=base, note=note, at=now, checked=False)
        return base, note

    base, source = candidates[0]
    _sub_base_cache.update(base=base, note=source, at=now, checked=False)
    return base, source


async def fetch_panel_settings(client: "XUIClient") -> dict:
    """Читает настройки панели 3x-ui (нужны для адреса сервиса подписок)."""
    for method, path in (("POST", "/panel/api/setting/all"), ("GET", "/panel/setting/all")):
        try:
            kwargs = {"json": {}} if method == "POST" else {}
            data = await client.request(method, path, **kwargs)
        except Exception as exc:
            logger.debug("Настройки панели не получены (%s %s): %s", method, path, exc)
            continue
        if isinstance(data, dict):
            return data
    return {}


def build_vless_link(client: dict, inbound: dict, params: dict) -> str:
    """Собирает рабочую ссылку vless:// из параметров подключения."""
    host = VPN_HOST or panel_host()

    if not host or any(char in host for char in "/?#@"):
        raise XUIError(
            "❌ Не удалось определить адрес сервера для ключа.\n\n"
            "Добавь в Railway -> Variables:\n"
            "<b>VPN_HOST</b> — IP-адрес или домен твоего VPN-сервера (без http/https и без порта)."
        )

    try:
        port = VPN_PORT or int(inbound.get("port"))
    except (TypeError, ValueError) as exc:
        raise XUIError("Не удалось определить порт подключения в 3x-ui.") from exc

    if not 1 <= port <= 65535:
        raise XUIError(f"Некорректный порт: {port}")

    query_params = {
        "type": params.get("network") or "tcp",
        "encryption": "none",
        "security": params.get("security") or "reality",
    }

    if params.get("pbk"):
        query_params["pbk"] = params["pbk"]
    if params.get("fp"):
        query_params["fp"] = params["fp"]
    if params.get("sni"):
        query_params["sni"] = params["sni"]
    if params.get("sid"):
        query_params["sid"] = params["sid"]
    if params.get("spx"):
        query_params["spx"] = params["spx"]

    if client.get("flow"):
        query_params["flow"] = client["flow"]

    # Дополнительные параметры для WebSocket / gRPC
    stream = as_dict(inbound.get("streamSettings"))
    if params.get("network") == "ws":
        ws = as_dict(stream.get("wsSettings"))
        if ws.get("path"):
            query_params["path"] = ws["path"]
        if ws.get("headers", {}).get("Host"):
            query_params["host"] = ws["headers"]["Host"]
    elif params.get("network") == "grpc":
        grpc = as_dict(stream.get("grpcSettings"))
        if grpc.get("serviceName"):
            query_params["serviceName"] = grpc["serviceName"]

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6

    query = urlencode(query_params, quote_via=quote)
    label = quote(client.get("email") or inbound.get("remark") or "VPN", safe="")

    return f"vless://{client['id']}@{host}:{port}?{query}#{label}"


def _test_client_payload(
    telegram_id: int,
    client_uuid: str,
    now_ms: int,
    inbound: dict,
    group_name: str = "",
) -> dict:
    """Генерирует payload клиента для 3x-ui с корректными типами полей."""
    stream = as_dict(inbound.get("streamSettings"))
    network = stream.get("network", "tcp")
    security = stream.get("security", "reality")

    # xtls-rprx-vision используется для VLESS + TCP + Reality / TLS
    flow = "xtls-rprx-vision" if (network == "tcp" and security in ("reality", "tls")) else ""

    payload = {
        "id": client_uuid,
        "email": f"tg-test-{telegram_id}",
        "flow": flow,
        "enable": True,
        "limitIp": TEST_IP_LIMIT,
        "totalGB": TEST_TRAFFIC_BYTES,
        "expiryTime": now_ms + TEST_HOURS * 60 * 60 * 1000,
        "tgId": int(telegram_id),  # число для Go struct int64!
        "subId": secrets.token_hex(8),
        "reset": 0,
    }

    # Группа клиента (3x-ui 3.2+; на старых сборках поле просто игнорируется).
    # Название берём из панели — чтобы клиент попал в уже созданную группу.
    if XUI_CLIENT_GROUP and group_name:
        payload["group"] = group_name

    return payload


def _group_note(status: str, group_name: str | None = None) -> str:
    """Пояснение к статусу добавления клиента в группу 3x-ui."""
    if not XUI_CLIENT_GROUP or status == "skipped":
        return ""

    name = group_name or XUI_CLIENT_GROUP
    group = f"<code>{escape(name)}</code>"

    if status == "assigned":
        return f"\n🏷 <b>Группа:</b> клиент добавлен в существующую группу {group}."
    if status == "assigned_new":
        return (
            f"\n🏷 <b>Группа:</b> клиент добавлен в группу {group}.\n"
            "⚠️ <i>Такой группы в панели раньше не было — если нужна другая (уже созданная), "
            "проверь название командой /groups.</i>"
        )
    if status == "unsupported":
        return (
            "\n⚠️ <b>Группы недоступны:</b> эта версия панели 3x-ui не поддерживает группы "
            "(нужна 3.2 или новее), поэтому клиент создан без группы.\n"
            "<i>Обнови панель или убери переменную XUI_CLIENT_GROUP.</i>"
        )
    return (
        f"\n⚠️ <b>Группа:</b> клиент создан, но панель не подтвердила добавление в группу {group}.\n"
        "<i>Проверь название группы и логи сервиса — команда /groups покажет группы панели.</i>"
    )


async def get_or_create_test_key(telegram_id: int) -> tuple[str, str, dict, bool, str | None, str]:
    """
    Создаёт клиента в 3x-ui (или продлевает/возвращает существующего).
    Возвращает: (vless_link, status, inbound_dict, auto_picked: bool, sub_link, group_note).
    Статусы: 'created', 'updated', 'exists'.
    """
    async with XUIClient() as client:
        # Тестовый ключ живёт в первой локации каталога (Стокгольм), а не в случайном
        # подключении панели — иначе после появления выбора сервера тест уезжал бы
        # в Варшаву или в чужой inbound.
        first_spot = configured_locations()[0] if configured_locations() else None
        if first_spot:
            inbound, auto_picked, source = await resolve_location_inbound(client, first_spot)
        else:
            inbound, auto_picked, source = await client.find_suitable_inbound(XUI_INBOUND_ID)
        inbound_id = inbound.get("id")
        params = extract_vless_params(inbound)

        settings = as_dict(inbound.get("settings"))
        clients = settings.get("clients") or []
        target_email = f"tg-test-{telegram_id}"

        async def sub_link_for(sub_id: str | None) -> str | None:
            """Ссылка-подписка клиента (или None, если сервис подписок недоступен)."""
            if not sub_id:
                return None
            base, note = await get_subscription_base(client, sub_id=sub_id)
            if not base:
                logger.warning("Тестовый клиент %s: подписка недоступна — %s", target_email, note)
                return None
            return build_sub_link(base, sub_id)

        # ВАЖНО: ищем только тестового клиента (tg-test-*). Платная подписка того же
        # человека (tg-paid-*) — отдельный клиент, тестовый ключ её не трогает.
        existing = next(
            (
                c for c in clients
                if isinstance(c, dict) and str(c.get("email")) == target_email
            ),
            None,
        )

        # Группа: ищем в панели именно ту, что указана в XUI_CLIENT_GROUP,
        # чтобы клиент попал в уже существующую, а не в новую с похожим названием.
        group_name, group_state = await client.resolve_client_group()
        if group_state == "exists":
            logger.info("Клиенты бота будут добавлены в существующую группу 3x-ui «%s».", group_name)

        async def assign_group() -> str:
            """Досылает клиента в настроенную группу (если она есть)."""
            if group_state == "unsupported":
                return "unsupported"
            if group_state == "disabled" or not group_name:
                return "skipped"
            # Важно: existed вычислен ДО создания клиента — панель могла создать
            # группу сама из payload, и тогда проверка после факта дала бы ложное «уже была».
            return await client.add_clients_to_group(
                [target_email], group_name, existed=(group_state == "exists")
            )

        now_ms = int(time.time() * 1000)

        if existing is not None:
            expiry = int(existing.get("expiryTime") or 0)
            enabled = bool(existing.get("enable", True))

            # Если ключ активен и срок не истёк — отдаём как есть
            if enabled and (expiry <= 0 or expiry > now_ms):
                link = build_vless_link(existing, inbound, params)
                sub_link = await sub_link_for(existing.get("subId"))
                # Клиент мог быть создан до настройки группы — досылаем его в группу
                group_note = _group_note(await assign_group(), group_name)
                return link, "exists", inbound, auto_picked, sub_link, group_note

            # Если ключ истёк или выключен — продлеваем на 24 часа
            payload = _test_client_payload(
                telegram_id,
                existing.get("id") or str(uuid.uuid4()),
                now_ms,
                inbound,
                group_name or "",
            )
            await client.update_client(inbound_id, payload)
            link = build_vless_link(payload, inbound, params)
            sub_link = await sub_link_for(payload.get("subId"))
            group_note = _group_note(await assign_group(), group_name)
            return link, "updated", inbound, auto_picked, sub_link, group_note

        # Клиента ещё нет — регистрируем нового
        new_uuid = str(uuid.uuid4())
        payload = _test_client_payload(telegram_id, new_uuid, now_ms, inbound, group_name or "")
        await client.add_client(inbound_id, payload)

        link = build_vless_link(payload, inbound, params)
        sub_link = await sub_link_for(payload.get("subId"))
        group_note = _group_note(await assign_group(), group_name)
        return link, "created", inbound, auto_picked, sub_link, group_note


async def delete_test_key(telegram_id: int) -> bool:
    """Удаляет тестового клиента из 3x-ui (ищем во всех подключениях панели)."""
    target_email = f"tg-test-{telegram_id}"
    async with XUIClient() as client:
        inbounds = await client.get_inbounds()
        for inbound in inbounds:
            settings = as_dict(inbound.get("settings"))
            for candidate in settings.get("clients") or []:
                if isinstance(candidate, dict) and str(candidate.get("email")) == target_email:
                    return await client.delete_client(inbound.get("id"), target_email,
                                                      candidate.get("id"))

        # На случай, если в inbound кэш устарел, пробуем удалить напрямую по email
        inbound, _ = await client.find_suitable_inbound(XUI_INBOUND_ID)
        return await client.delete_client(inbound.get("id"), target_email, None)


# =========================
# ОПЛАТА: ЖУРНАЛ ЗАКАЗОВ, ЮKASSA, ВЫДАЧА ПОДПИСКИ
# =========================

class PaymentError(Exception):
    """Ошибка оплаты, текст которой можно показать пользователю."""


class PaymentStore:
    """
    Журнал заказов: идемпотентность (повторный вебхук/платёж не выдаёт ключ дважды)
    и статистика для админа.

    Пишется в JSON-файл (PAYMENT_STORE_FILE) атомарно; если файл недоступен
    (например, эфемерная файловая система Railway) — работаем в памяти и
    дополнительно помечаем факт оплаты в комментарии клиента в панели.
    """

    def __init__(self, path: str):
        self.path = path
        self.orders: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._loaded = False

    # --- файл ---

    def load(self) -> None:
        """Читает журнал с диска (один раз при старте)."""
        if self._loaded:
            return
        self._loaded = True
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            orders = data.get("orders") if isinstance(data, dict) else None
            if isinstance(orders, dict):
                self.orders = {str(k): v for k, v in orders.items() if isinstance(v, dict)}
                logger.info("Журнал оплат загружен: %s заказов из %s", len(self.orders), self.path)
        except FileNotFoundError:
            logger.info("Журнал оплат пуст — создам %s при первой оплате.", self.path)
        except Exception as exc:
            logger.warning("Не удалось прочитать журнал оплат (%s): %s", self.path, exc)

    def _write(self) -> None:
        if not self.path:
            return
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "orders": self.orders}, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)   # атомарная замена: файл не побьётся при падении
        except Exception as exc:
            logger.warning("Не удалось сохранить журнал оплат (%s): %s", self.path, exc)

    # --- заказы ---

    async def create(self, order: dict) -> dict:
        async with self._lock:
            self.load()
            self.orders[order["id"]] = order
            self._write()
        return order

    async def get(self, order_id: str) -> dict | None:
        self.load()
        return self.orders.get(order_id)

    async def update(self, order_id: str, **fields) -> dict | None:
        async with self._lock:
            self.load()
            order = self.orders.get(order_id)
            if order is None:
                return None
            order.update(fields)
            self._write()
            return order

    async def find_by_charge(self, charge_id: str) -> dict | None:
        """Заказ, который уже был активирован этим платежом (защита от дублей)."""
        self.load()
        if not charge_id:
            return None
        for order in self.orders.values():
            if order.get("charge_id") == charge_id and order.get("status") == "paid":
                return order
        return None

    def stats(self) -> dict:
        """Сводка: сколько оплат, выручка в рублях и звёздах, разбивка по тарифам."""
        self.load()
        # Тестовые заказы (/test_pay) не считаем оплатами: денег по ним не приходило.
        paid = [o for o in self.orders.values() if o.get("status") == "paid" and not o.get("simulated")]
        by_tariff: dict[str, int] = {}
        for order in paid:
            by_tariff[order.get("tariff", "?")] = by_tariff.get(order.get("tariff", "?"), 0) + 1
        promo = [o for o in self.orders.values()
                 if o.get("status") == "paid" and o.get("promo")]
        return {
            "orders_total": len(self.orders),
            "paid_count": len(paid),
            "promo_count": len(promo),
            "rub": sum(int(o.get("amount_rub") or 0) for o in paid
                       if o.get("mode") in ("yookassa", "provider", "platega")),
            "stars": sum(int(o.get("amount_stars") or 0) for o in paid if o.get("currency") == "XTR"),
            "by_tariff": by_tariff,
        }

    def recent(self, limit: int = 10) -> list[dict]:
        self.load()
        orders = sorted(
            self.orders.values(),
            key=lambda o: o.get("paid_at") or o.get("created_at") or 0,
            reverse=True,
        )
        return orders[:limit]


payment_store = PaymentStore(PAYMENT_STORE_FILE)


# =========================
# РЕФЕРАЛЬНАЯ ПРОГРАММА
# =========================

class ReferralStore:
    """
    Журнал приглашений: кто кого позвал, кто уже оплатил и какие дни начислены.

    Файл отдельный от журнала заказов (REFERRAL_STORE_FILE), формат — JSON:

        users:   {"<id приглашённого>": {..., "referrer": <id>, "first_paid_at": 0}}
        users_started: ["<id>"]  — все, кто хоть раз запускал бота (кого можно приглашать)
        pending: {"<id пригласившего>": <сколько дней ждёт следующей подписки>}
        rewarded: [ ... история начислений для статистики ]
    """

    def __init__(self, path: str):
        self.path = path
        self.users: dict[str, dict] = {}
        self.started: list[int] = []
        self.pending: dict[str, int] = {}
        self.rewarded: list[dict] = []
        self._lock = asyncio.Lock()
        self._loaded = False

    # --- файл ---

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.users = {str(k): v for k, v in (data.get("users") or {}).items() if isinstance(v, dict)}
            self.started = [int(x) for x in (data.get("users_started") or []) if str(x).isdigit()]
            self.pending = {str(k): int(v) for k, v in (data.get("pending") or {}).items() if str(v).lstrip("-").isdigit()}
            self.rewarded = [r for r in (data.get("rewarded") or []) if isinstance(r, dict)][-500:]
            logger.info("Журнал рефералов загружен: %s приглашений, %s ожидающих бонусов.",
                        len(self.users), len(self.pending))
        except FileNotFoundError:
            logger.info("Журнал рефералов пуст — создам %s при первом приглашении.", self.path)
        except Exception as exc:
            logger.warning("Не удалось прочитать журнал рефералов (%s): %s", self.path, exc)

    def _write(self) -> None:
        if not self.path:
            return
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({
                    "version": 1,
                    "users": self.users,
                    "users_started": self.started[-5000:],
                    "pending": self.pending,
                    "rewarded": self.rewarded[-500:],
                }, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.warning("Не удалось сохранить журнал рефералов (%s): %s", self.path, exc)

    # --- пользователи ---

    def touch_user(self, tg_id: int) -> None:
        """Запоминает, что человек запускал бота (только таких можно приглашать)."""
        if tg_id and tg_id not in self.started:
            self.started.append(tg_id)
            self._write()

    def knows_user(self, tg_id: int) -> bool:
        return tg_id in self.started

    # --- приглашения ---

    async def register(self, invited_id: int, referrer_id: int) -> str:
        """
        Записывает, что пользователя позвал referrer_id.

        Возвращает статус: 'ok', 'self', 'already', 'unknown_referrer', 'disabled'.
        Первое приглашение побеждает: переписать его другой ссылкой нельзя.
        """
        if not REFERRAL_ENABLED:
            return "disabled"
        if not invited_id or not referrer_id:
            return "unknown_referrer"
        if invited_id == referrer_id:
            return "self"
        self.load()
        key = str(invited_id)
        if key in self.users:
            return "already"
        if not self.knows_user(referrer_id):
            return "unknown_referrer"
        async with self._lock:
            self.users[key] = {
                "referrer": int(referrer_id),
                "joined_at": int(time.time()),
                "first_paid_at": 0,
                "order_id": "",
            }
            self._write()
        logger.info("Реферал: %s пришёл по ссылке %s.", invited_id, referrer_id)
        return "ok"

    def invite_of(self, invited_id: int) -> dict | None:
        self.load()
        return self.users.get(str(invited_id))

    def invite_pending(self, invited_id: int, order: dict) -> dict | None:
        """
        Приглашение, по которому ещё не начислён бонус, — и только если текущий
        заказ оплачен ПОСЛЕ прихода по ссылке (иначе бонус задним числом не даём).
        """
        invite = self.invite_of(invited_id)
        if not invite or invite.get("first_paid_at"):
            return None
        if int(order.get("created_at") or 0) < int(invite.get("joined_at") or 0):
            return None
        return invite

    async def mark_first_payment(self, invited_id: int, order_id: str) -> None:
        """Помечает, что приглашённый оплатил подписку (бонус начисляется один раз)."""
        key = str(invited_id)
        invite = self.users.get(key)
        if not invite:
            return
        async with self._lock:
            invite["first_paid_at"] = int(time.time())
            invite["order_id"] = order_id
            self._write()

    async def log_reward(self, referrer_id: int, invited_id: int, days: int, applied: str, order_id: str) -> None:
        async with self._lock:
            self.rewarded.append({
                "referrer": int(referrer_id),
                "invited": int(invited_id),
                "days": int(days),
                "applied": applied,          # immediate | pending | invited
                "order": order_id,
                "at": int(time.time()),
            })
            self._write()

    # --- отложенные бонусы пригласившего ---

    def pending_days(self, referrer_id: int) -> int:
        self.load()
        return int(self.pending.get(str(referrer_id)) or 0)

    async def add_pending(self, referrer_id: int, days: int) -> None:
        if days <= 0:
            return
        async with self._lock:
            key = str(referrer_id)
            self.pending[key] = int(self.pending.get(key) or 0) + int(days)
            self._write()

    async def clear_pending(self, referrer_id: int) -> None:
        async with self._lock:
            self.pending.pop(str(referrer_id), None)
            self._write()

    # --- статистика ---

    def stats(self, referrer_id: int) -> dict:
        self.load()
        invited = [u for u in self.users.values() if int(u.get("referrer") or 0) == int(referrer_id)]
        earned = sum(
            int(r.get("days") or 0) for r in self.rewarded
            if int(r.get("referrer") or 0) == int(referrer_id) and r.get("applied") != "invited"
        )
        return {
            "came": len(invited),                                   # пришло по ссылке
            "paid": len([u for u in invited if u.get("first_paid_at")]),  # из них оплатили
            "earned_days": earned,                                  # начислено дней всего
            "pending_days": self.pending_days(referrer_id),         # ждут следующей подписки
        }

    def totals(self) -> dict:
        self.load()
        return {
            "invites": len(self.users),
            "paid": len([u for u in self.users.values() if u.get("first_paid_at")]),
            "days": sum(int(r.get("days") or 0) for r in self.rewarded),
            "rewards": len(self.rewarded),
        }


referral_store = ReferralStore(REFERRAL_STORE_FILE)


class TermsStore:
    """
    Отметки о принятии пользовательского соглашения: кто и когда нажал «✅ Согласен».

    Формат файла (TERMS_STORE_FILE) — JSON: {"accepted": {"<telegram_id>": <unixtime>}}.
    Если файл недоступен (например, эфемерная файловая система Railway) — работаем
    в памяти: после перезапуска бот ещё раз покажет соглашение, ничего не сломается.
    """

    def __init__(self, path: str):
        self.path = path
        self.accepted: dict[str, int] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.accepted = {
                str(k): int(v) for k, v in (data.get("accepted") or {}).items()
                if str(k).lstrip("-").isdigit() and str(v).lstrip("-").isdigit()
            }
            logger.info("Отметки о принятии соглашения загружены: %s пользователей.", len(self.accepted))
        except FileNotFoundError:
            logger.info("Отметок о принятии соглашения нет — создам %s при первом принятии.", self.path)
        except Exception as exc:
            logger.warning("Не удалось прочитать отметки о соглашении (%s): %s", self.path, exc)

    def _write(self) -> None:
        if not self.path:
            return
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "accepted": self.accepted}, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.warning("Не удалось сохранить отметки о соглашении (%s): %s", self.path, exc)

    def accepted_at(self, tg_id: int | None) -> int:
        """Когда пользователь принял соглашение (0 — ещё не принимал)."""
        if not tg_id:
            return 0
        self.load()
        return int(self.accepted.get(str(tg_id)) or 0)

    def is_accepted(self, tg_id: int | None) -> bool:
        return self.accepted_at(tg_id) > 0

    def accept(self, tg_id: int) -> bool:
        """Отмечает принятие. Возвращает True, если это первое принятие."""
        if not tg_id:
            return False
        self.load()
        key = str(tg_id)
        if key in self.accepted:
            return False
        self.accepted[key] = int(time.time())
        self._write()
        return True


terms_store = TermsStore(TERMS_STORE_FILE)

# Username бота нужен для реферальной ссылки: спрашиваем у Telegram один раз и кэшируем.
_bot_username_cache = ""


async def get_bot_username() -> str:
    """Username бота для ссылок вида t.me/<username>?start=ref_123."""
    global _bot_username_cache
    if BOT_USERNAME:
        return BOT_USERNAME
    if _bot_username_cache:
        return _bot_username_cache
    try:
        me = await bot.get_me()
        _bot_username_cache = (getattr(me, "username", "") or "").strip()
    except Exception as exc:
        logger.warning("Не удалось узнать username бота для реферальной ссылки: %s", exc)
    return _bot_username_cache


async def referral_link(tg_id: int) -> str:
    """Личная ссылка-приглашение. Пустая строка, если username бота неизвестен."""
    username = await get_bot_username()
    if not username:
        return ""
    return f"https://t.me/{username}?start=ref_{tg_id}"


# Приветствия приглашённых, которые ждут нажатия «✅ Согласен — продолжить».
# Хранится в памяти: после перезапуска бота друг просто не увидит приветствие,
# а сами бонусные дни (журнал приглашений) уже записаны и не потеряются.
pending_referral_greet: dict[int, str] = {}


def parse_referral_payload(payload: str) -> int | None:
    """Разбирает deep-link «ref_12345» (то, что приходит в /start ref_12345)."""
    text = (payload or "").strip()
    if not text:
        return None
    match = re.fullmatch(r"ref[_-]?(\d{1,15})", text, flags=re.IGNORECASE)
    if not match:
        return None
    value = int(match.group(1))
    return value if value > 0 else None


def referral_rules_text() -> str:
    """Правила программы — показываем в /invite, чтобы не было вопросов."""
    return (
        f"• За каждого друга, который <b>оплатил</b> подписку, тебе — "
        f"<b>+{REFERRAL_BONUS_DAYS} {days_word(REFERRAL_BONUS_DAYS)}</b>. Другу — "
        f"<b>+{REFERRAL_INVITED_BONUS_DAYS} {days_word(REFERRAL_INVITED_BONUS_DAYS)}</b> "
        "к первой оплате.\n"
        "• Бонус начисляется один раз за друга и только после его первой оплаты.\n"
        "• Дни прибавляются к текущей подписке; если подписки нет — копится и добавится "
        "к следующей покупке.\n"
        "• Пригласить можно только того, кто ещё не оплачивал VPN, и нельзя себя самого."
    )


def devices_word(count: int) -> str:
    """«1 устройство», «3 устройства», «6 устройств»."""
    value = abs(int(count))
    if value % 100 in (11, 12, 13, 14):
        return "устройств"
    if value % 10 == 1:
        return "устройство"
    if value % 10 in (2, 3, 4):
        return "устройства"
    return "устройств"


def days_word(days: int) -> str:
    """«1 день», «3 дня», «7 дней» — чтобы сообщения читались по-человечески."""
    value = abs(int(days))
    if value % 100 in (11, 12, 13, 14):
        return "дней"
    if value % 10 == 1:
        return "день"
    if value % 10 in (2, 3, 4):
        return "дня"
    return "дней"


def comment_with_new_expiry(comment: str | None, expiry_ms: int) -> str:
    """
    Обновляет дату в комментарии клиента, сохраняя номер платежа.

    Комментарий выглядит как «basic до 17.10.2026 | platega-123456»; по хвосту после «|»
    бот понимает, что подписка уже выдана (защита от повторной выдачи), поэтому
    при продлении меняем только дату.
    """
    text = str(comment or "").strip()
    if not text or "|" not in text:
        return text
    head, ref = text.rsplit("|", 1)
    tariff_key = head.split()[0] if head.split() else ""
    if not tariff_key:
        return text
    return f"{tariff_key} до {format_date(expiry_ms)} | {ref.strip()}"


async def extend_subscription_days(tg_id: int, days: int) -> dict | None:
    """
    Продлевает подписку пользователя на N дней (без оплаты) — например, за друга.

    Возвращает {'expiry_ms': ...} или None, если подписки в панели нет.
    """
    if days <= 0:
        return None
    sub = await get_paid_subscription(tg_id)
    if not sub or not sub.get("client"):
        return None

    client_row = dict(sub["client"])
    inbound = sub["inbound"]
    now_ms = int(time.time() * 1000)
    current_expiry = int(client_row.get("expiryTime") or 0)
    base_ms = max(now_ms, current_expiry)          # продлеваем от конца оплаченного срока
    new_expiry = base_ms + days * 86400 * 1000

    client_row["expiryTime"] = new_expiry
    client_row["enable"] = True
    client_row["comment"] = comment_with_new_expiry(client_row.get("comment"), new_expiry)

    async with XUIClient() as client:
        await client.update_client(inbound.get("id"), client_row)

    logger.info("Подписка %s продлена на %s дней (без оплаты) — реферальный бонус.", tg_id, days)
    return {"expiry_ms": new_expiry, "days": days}


async def reward_referrer(referrer_id: int, invited_id: int, order_id: str) -> str:
    """
    Начисляет бонус пригласившему: сразу к подписке либо в копилку до следующей покупки.

    Возвращает 'immediate' (дни уже в подписке) или 'pending' (лежат до следующей оплаты).
    """
    days = REFERRAL_BONUS_DAYS
    if days <= 0:
        return "disabled"
    extended = await extend_subscription_days(referrer_id, days)
    if extended:
        await referral_store.log_reward(referrer_id, invited_id, days, "immediate", order_id)
        try:
            await bot.send_message(
                referrer_id,
                f"🎉 <b>По твоей ссылке оплатили подписку!</b>\n\n"
                f"Начислил тебе <b>+{days} {days_word(days)}</b> — они уже в твоей подписке.\n"
                f"Срок: <b>{format_date(extended['expiry_ms'])}</b>\n\n"
                "Приглашай ещё — за каждого друга, который оплатит, снова +"
                f"{days} {days_word(days)}. Твоя ссылка: /invite",
                parse_mode="HTML",
            )
        except Exception as exc:
            logger.warning("Не удалось уведомить реферера %s: %s", referrer_id, exc)
        return "immediate"

    await referral_store.add_pending(referrer_id, days)
    await referral_store.log_reward(referrer_id, invited_id, days, "pending", order_id)
    total = referral_store.pending_days(referrer_id)
    try:
        await bot.send_message(
            referrer_id,
            f"🎉 <b>По твоей ссылке оплатили подписку!</b>\n\n"
            f"Начислил тебе <b>+{days} {days_word(days)}</b>. Подписки сейчас нет, поэтому дни копятся: "
            f"сейчас на счету <b>{total} {days_word(total)}</b> — прибавлю их автоматически "
            "при следующей покупке.\n\n"
            "Приглашай ещё: /invite",
            parse_mode="HTML",
        )
    except Exception as exc:
        logger.warning("Не удалось уведомить реферера %s: %s", referrer_id, exc)
    return "pending"


async def grant_referral_rewards(order: dict, info: dict, invite: dict | None) -> None:
    """
    Выдаёт реферальные бонусы после подтверждённой оплаты.

    Приглашённому дни уже добавлены при выдаче подписки (extra_days), здесь только
    уведомление и бонус пригласившему. Ошибки не роняют оплату: ключ важнее.
    """
    invited_id = int(order.get("tg_id") or 0)
    if invite:
        await referral_store.mark_first_payment(invited_id, order["id"])
        if REFERRAL_INVITED_BONUS_DAYS > 0:
            await referral_store.log_reward(invited_id, invited_id, REFERRAL_INVITED_BONUS_DAYS, "invited", order["id"])
            try:
                await bot.send_message(
                    invited_id,
                    f"🎁 <b>Тебя пригласил друг — держи +{REFERRAL_INVITED_BONUS_DAYS} "
                    f"{days_word(REFERRAL_INVITED_BONUS_DAYS)}</b> к подписке!\n\n"
                    "Хочешь так же? Приглашай своих друзей: /invite — за каждого, кто оплатит, "
                    f"+{REFERRAL_BONUS_DAYS} {days_word(REFERRAL_BONUS_DAYS)}.",
                    parse_mode="HTML",
                )
            except Exception as exc:
                logger.warning("Не удалось уведомить приглашённого %s: %s", invited_id, exc)

        referrer_id = int(invite.get("referrer") or 0)
        if referrer_id:
            try:
                await reward_referrer(referrer_id, invited_id, order["id"])
            except Exception as exc:
                logger.error("Не удалось начислить реферальный бонус %s: %s", referrer_id, exc)


def referral_kb(link: str, with_share: bool = True) -> InlineKeyboardMarkup:
    """Кнопки под текстом «Пригласи друга»."""
    rows = []
    if with_share and link:
        share_text = (
            f"Советую этот VPN: быстро, есть бесплатный тест на 24 часа. "
            f"Заходи по моей ссылке — бонус к подписке: {link}"
        )
        rows.append([InlineKeyboardButton(
            text="📤 Поделиться ссылкой",
            url=f"https://t.me/share/url?url={quote(link, safe='')}&text={quote(share_text, safe='')}",
        )])
    if link:
        rows.append([InlineKeyboardButton(text="📋 Скопировать ссылку",
                                          copy_text=CopyTextButton(text=link))])
    rows.append([InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile")])
    rows.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def send_referral_page(target, tg_id: int, *, edit: bool = False) -> None:
    """Показывает страницу реферальной программы (и для команды, и для кнопки)."""
    if not REFERRAL_ENABLED:
        text = (
            "🎁 <b>Реферальная программа сейчас выключена.</b>\n\n"
            "Администратору: включи переменную <b>REFERRAL_ENABLED=1</b> в Railway → Variables."
        )
        kb = back_kb()
    else:
        stats = referral_store.stats(tg_id)
        link = await referral_link(tg_id)
        link_line = (
            f"Твоя ссылка:\n<code>{escape(link)}</code>"
            if link else
            "⚠️ Не удалось получить ссылку: задай переменную <b>BOT_USERNAME</b> "
            "(username бота без @) в Railway → Variables."
        )
        pending_note = (
            f"\n🎁 <b>В копилке: {stats['pending_days']} "
            f"{days_word(stats['pending_days'])}</b> — добавлю к следующей подписке."
            if stats["pending_days"] else ""
        )
        text = (
            f"🎁 <b>Пригласи друга — получи {REFERRAL_BONUS_DAYS} "
            f"{days_word(REFERRAL_BONUS_DAYS)} бесплатно</b>\n\n"
            f"{link_line}\n\n"
            "<b>Как это работает:</b>\n"
            f"1. Отправь ссылку другу (кнопка ниже).\n"
            f"2. Друг получает VPN и, если понравится, покупает тариф.\n"
            f"3. Тебе — <b>+{REFERRAL_BONUS_DAYS} {days_word(REFERRAL_BONUS_DAYS)}</b>, другу — "
            f"<b>+{REFERRAL_INVITED_BONUS_DAYS} {days_word(REFERRAL_INVITED_BONUS_DAYS)}</b> "
            "к подписке.\n\n"
            f"<b>Твоя статистика:</b>\n"
            f"• Пришло по ссылке: <b>{stats['came']}</b>\n"
            f"• Из них оплатили: <b>{stats['paid']}</b>\n"
            f"• Начислено: <b>{stats['earned_days']} {days_word(stats['earned_days'])}</b>"
            f"{pending_note}\n\n"
            f"<b>Правила:</b>\n{referral_rules_text()}"
        )
        kb = referral_kb(link)

    if edit:
        try:
            await target.edit_text(text, reply_markup=kb, parse_mode="HTML")
            return
        except Exception:
            pass
    await target.answer(text, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)


@dp.message(Command("invite"))
async def cmd_invite(message: Message):
    """Реферальная программа: личная ссылка, статистика и правила."""
    referral_store.touch_user(message.from_user.id)
    if await terms_gate(message):
        return
    await send_referral_page(message, message.from_user.id)


@dp.callback_query(F.data == "invite")
async def cb_invite(cb: CallbackQuery):
    referral_store.touch_user(cb.from_user.id)
    await cb.answer()
    await send_referral_page(cb.message, cb.from_user.id)


async def handle_referral_start(message: Message, payload: str, defer_greeting: bool = False) -> None:
    """
    Обрабатывает переход по реферальной ссылке (/start ref_12345).

    defer_greeting=True — приглашённый ещё не принял соглашение: приглашение
    записываем и сообщаем пригласившему сейчас, а приветствие с бонусом покажем
    после кнопки «✅ Согласен» (текст берётся из referral_greet_text).
    """
    referrer_id = parse_referral_payload(payload)
    if referrer_id is None:
        return
    invited_id = message.from_user.id
    status = await referral_store.register(invited_id, referrer_id)

    if status == "ok":
        logger.info("Новый реферал: %s ← %s", invited_id, referrer_id)
        try:
            await bot.send_message(
                referrer_id,
                "👋 <b>По твоей ссылке пришёл друг!</b>\n\n"
                f"Как только он оплатит подписку — начислю тебе "
                f"<b>+{REFERRAL_BONUS_DAYS} {days_word(REFERRAL_BONUS_DAYS)}</b> автоматически.\n"
                "Статистика: /invite",
                parse_mode="HTML",
            )
        except Exception as exc:
            logger.warning("Не удалось сообщить рефереру %s о новом друге: %s", referrer_id, exc)
        if defer_greeting:
            pending_referral_greet[invited_id] = status
            return
    elif status == "self":
        if defer_greeting:
            pending_referral_greet[invited_id] = status
            return
    elif status == "unknown_referrer":
        logger.info("Реферальная ссылка с неизвестным приглашающим: %s", referrer_id)
        return

    await send_referral_greet(message.answer, invited_id, status)


def referral_greet_text(invited_id: int, status: str) -> str:
    """Приветствие приглашённого друга (после перехода по ссылке)."""
    if status == "self":
        return "🙂 Своя же ссылка не считается — пригласи друга, и бонус будет твоим."
    return (
        "🎁 <b>Тебя пригласили!</b> Друг подарил тебе "
        f"<b>+{REFERRAL_INVITED_BONUS_DAYS} {days_word(REFERRAL_INVITED_BONUS_DAYS)}</b> — "
        "они прибавятся к первой оплате любого тарифа.\n\n"
        + ("Начни с бесплатного теста на 24 часа: /test_vpn — "
           "или смотри тарифы: /start" if trial_available_for(invited_id)
           else "Смотри тарифы и подключайся: /start")
    )


async def send_referral_greet(answer, invited_id: int, status: str) -> None:
    """Отправляет приветствие приглашённого (answer — message.answer или cb.message.answer)."""
    try:
        await answer(referral_greet_text(invited_id, status), parse_mode="HTML")
    except Exception as exc:
        logger.warning("Не удалось поздороваться с приглашённым %s: %s", invited_id, exc)


async def send_pending_referral_greet(message: Message, invited_id: int) -> None:
    """Показывает отложенное приветствие друга — вызывается после принятия соглашения."""
    status = pending_referral_greet.pop(invited_id, None)
    if not status:
        return
    await send_referral_greet(message.answer, invited_id, status)





def payments_enabled() -> bool:
    """Включён ли приём оплаты (режим off выключает кнопки покупки)."""
    return PAYMENTS_MODE != "off"


def is_admin(user_id: int) -> bool:
    """
    Админ ли пользователь.

    Если в ADMIN_ID перечислено несколько ID — достаточно любого из них. Когда
    переменная не задана (или заполнена не числом), админ-команды открыты: так
    владелец не блокирует сам себя на первой настройке (бот предупреждает об этом
    при старте). Ровно так же ведут себя и остальные команды бота.
    """
    if not ADMIN_IDS:
        return True
    return user_id in ADMIN_IDS


def admin_denied_text(user_id: int) -> str:
    """Понятный отказ для админ-команды: свой ID и что поправить в Railway."""
    lines = [
        "⛔️ <b>Команда доступна только администратору.</b>",
        "",
        f"• Твой Telegram ID: <code>{user_id}</code>",
    ]
    admins = ", ".join(f"<code>{value}</code>" for value in ADMIN_IDS)
    lines.append(f"• В <b>ADMIN_ID</b> сейчас: {admins}")
    lines.append(
        "\nЕсли бот твой — поставь в <b>ADMIN_ID</b> свой ID "
        "(несколько админов можно перечислить через запятую: <code>111,222</code>) "
        "и дождись перезапуска сервиса."
    )
    return "\n".join(lines)


def test_pay_enabled() -> bool:
    """Разрешена ли проверка выдачи ключа без оплаты (см. PAYMENTS_ALLOW_TEST_PAY)."""
    return PAYMENTS_ALLOW_TEST_PAY


def admin_tools_enabled() -> bool:
    """Показывать ли служебные команды администратора (ADMIN_TOOLS=1)."""
    return ADMIN_TOOLS


def promo_enabled() -> bool:
    """Включён ли промо-тариф (PROMO_ENABLED=1 и сам тариф на месте)."""
    return PROMO_ENABLED and PROMO_KEY in TARIFFS


def promo_used(tg_id: int | None) -> bool:
    """
    Пользовался ли этот аккаунт промо (по журналу заказов).

    Промо выдаётся один раз: иначе бесплатные 15 дней можно оформлять бесконечно.
    PROMO_ONCE=0 снимает ограничение — для проверок на своём аккаунте.
    """
    if not PROMO_ONCE or tg_id is None:
        return False
    payment_store.load()
    for order in payment_store.orders.values():
        if (order.get("tariff") == PROMO_KEY and order.get("status") == "paid"
                and int(order.get("tg_id") or 0) == int(tg_id)):
            return True
    return False


def promo_visible(tg_id: int | None) -> bool:
    """Показывать ли промо-пункт в тарифах: включён и ещё не использован."""
    return promo_enabled() and not promo_used(tg_id)


def tariff_visible(tg_id: int | None, key: str, tariff: dict) -> bool:
    """
    Показывать ли тариф в списке.

    Платные — всегда; бесплатные — по своим правилам: промо видно всем (но один раз
    на аккаунт), а тестовые 24 часа — только тем, кому тест доступен и включён
    показ кнопок (TRIAL_BUTTON=1).
    """
    if tariff["price"] > 0:
        return True
    if key == PROMO_KEY:
        return promo_visible(tg_id)
    return trial_button_visible(tg_id)


def trial_available_for(user_id: int | None) -> bool:
    """Доступен ли этому пользователю бесплатный тест на 24 часа."""
    if TRIAL_PUBLIC:
        return True
    if user_id is None:
        return True
    return is_admin(user_id)


def trial_button_visible(user_id: int | None) -> bool:
    """
    Показывать ли кнопки/пункт бесплатного теста этому пользователю.

    Право на тест (TRIAL_PUBLIC) и вид кнопок (TRIAL_BUTTON) разделены: при
    TRIAL_BUTTON=0 кнопок нет ни у кого, включая администратора, но команда
    /test_vpn для админа продолжает работать.
    """
    return TRIAL_BUTTON and trial_available_for(user_id)


def test_tools_enabled() -> bool:
    """
    Показывать ли тестовые команды (/test_pay, /platega_check) и их кнопки.

    В боевом режиме их нет: команды не регистрируются вообще, кнопки не выводятся,
    в меню Telegram они не попадают. Включаются переменной PAYMENTS_ALLOW_TEST_PAY=1;
    TEST_TOOLS управляет принудительно.
    """
    if not ADMIN_TOOLS:
        return False          # админ-инструменты скрыты — прячем и проверки оплаты
    if TEST_TOOLS_RAW:
        return TEST_TOOLS_RAW in ("1", "true", "yes", "on")
    return test_pay_enabled()


def payments_mode_title() -> str:
    return {
        "stars": "Telegram Stars ⭐️",
        "provider": "оплата картой в Telegram (BotFather provider token)",
        "yookassa": "ЮKassa (карта / СБП по ссылке)",
        "platega": f"Platega (карта, СБП и кошельки, {PLATEGA_CURRENCY})",
        "off": "выключена",
    }.get(PAYMENTS_MODE, PAYMENTS_MODE)


def payments_diag_text() -> str:
    """
    Короткая диагностика оплаты для /myid: что настроено и почему молчат проверки.

    /myid доступна всегда, даже при ADMIN_TOOLS=0, поэтому именно здесь видно,
    из-за какой переменной /test_pay и /platega_check не отвечают.
    """
    lines = [f"💳 <b>Оплата:</b> {escape(payments_mode_title())} (<code>{PAYMENTS_MODE}</code>)"]

    lines.append(
        "• Тарифы: "
        + ", ".join(
            f"{TARIFF_LEVELS[level]['name']} ({TARIFF_KINDS[kind]['short']}) "
            f"{TARIFF_GRID[kind][level]['price']} ₽"
            for kind in TARIFF_KIND_ORDER for level in TARIFF_LEVEL_ORDER
        )
    )
    lines.append(
        "• Локации: "
        + ", ".join(f"{spot['title']} (<code>{spot['env']}</code>"
                    + (f"={spot['inbound_id']}" if spot['inbound_id'] else "")
                    + ")" for spot in configured_locations())
    )

    promo_tariff = TARIFFS.get(PROMO_KEY) or {}
    if promo_enabled():
        lines.append(
            f"• Промо-доступ: включён 🎉 {escape(promo_tariff.get('name', ''))} — "
            + ("один раз на аккаунт" if PROMO_ONCE else "без ограничения (PROMO_ONCE=0)")
        )
    else:
        lines.append("• Промо-доступ: выключен (<code>PROMO_ENABLED=0</code> или тариф удалён)")

    if PAYMENTS_MODE == "platega":
        lines.append(f"• Merchant ID: <code>{escape(PLATEGA_MERCHANT_ID or 'не задан ❌')}</code>")
        lines.append(f"• API-ключ (X-Secret): {'задан ✅' if PLATEGA_SECRET else 'НЕ задан ❌'}")
        lines.append(f"• API: <code>{escape(PLATEGA_API_URL)}</code>, валюта {escape(PLATEGA_CURRENCY)}")
        lines.append(
            "• Способ оплаты: "
            + (escape(PLATEGA_METHODS.get(PLATEGA_METHOD, str(PLATEGA_METHOD)))
               if PLATEGA_METHOD else "выбирает плательщик на странице Platega")
        )
        if PUBLIC_BASE_URL:
            lines.append(f"• Callback URL: <code>{escape(PUBLIC_BASE_URL + PLATEGA_WEBHOOK_PATH)}</code>")
        else:
            lines.append(
                "• Callback URL: ⚠️ нет публичного адреса — Railway → Settings → "
                "Networking → <b>Generate Domain</b> (или задай <code>PUBLIC_BASE_URL</code>)"
            )
        lines.append("• Защита callback: заголовки X-MerchantId + X-Secret")
    elif PAYMENTS_MODE == "stars":
        lines.append(f"• Цена в звёздах: 1 ⭐️ ≈ {STARS_RUB_RATE} ₽ (меняется <code>STARS_RUB_RATE</code>)")
    elif PAYMENTS_MODE == "yookassa":
        lines.append(f"• Магазин ЮKassa: <code>{escape(YOOKASSA_SHOP_ID or 'не задан')}</code>, "
                     f"ключ {'задан ✅' if YOOKASSA_SECRET_KEY else 'НЕ задан ❌'}")
    elif PAYMENTS_MODE == "provider":
        lines.append(f"• Токен BotFather: {'задан ✅' if PAYMENT_PROVIDER_TOKEN else 'НЕ задан ❌'}")

    # Диагностика настроек — только чтение, поэтому доступна и в боевом режиме.
    if admin_tools_enabled() and PAYMENTS_MODE == "platega":
        lines.append("• <code>/platega_check</code> — проверка настроек магазина: <b>доступна</b> ✅")
    elif PAYMENTS_MODE == "platega":
        lines.append(
            "• <code>/platega_check</code> — проверка настроек магазина: скрыта, "
            "нужна <code>ADMIN_TOOLS=1</code>"
        )
    # Выдача ключа без оплаты — это уже тестовый инструмент.
    if not ADMIN_TOOLS or TEST_TOOLS_RAW in ("0", "false", "no", "off"):
        lines.append(
            "• <code>/test_pay</code> — выдача ключа без оплаты: скрыта"
            + (" (<code>ADMIN_TOOLS=0</code>)" if not ADMIN_TOOLS else " (<code>TEST_TOOLS=0</code>)")
        )
    elif test_pay_enabled():
        lines.append("• <code>/test_pay</code> — выдача ключа без оплаты: <b>включена</b> ✅")
    else:
        lines.append(
            "• <code>/test_pay</code> — выдача ключа без оплаты: скрыта. "
            "Включить: <code>PAYMENTS_ALLOW_TEST_PAY=1</code>"
        )
    if not ADMIN_TOOLS:
        lines.append(
            "• Служебные команды (/payments, /panel_debug, /groups): скрыты "
            "(<code>ADMIN_TOOLS=0</code>)"
        )
    return "\n".join(lines)


def format_date(timestamp_ms: int) -> str:
    """Дата окончания подписки в часовом поясе бота."""
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=LOCAL_TZ).strftime("%d.%m.%Y")


def configured_locations() -> list[dict]:
    """Локации, доступные в боте, в порядке каталога."""
    return [{"key": key, **LOCATIONS[key]} for key in LOCATION_ORDER if key in LOCATIONS]


def tariff_tunnels(tariff: dict) -> int:
    """Сколько локаций реально входит в тариф (не больше, чем настроено серверов)."""
    declared = int(tariff.get("tunnels", 1) or 1)
    return max(1, min(declared, len(configured_locations())))


def tariff_locations(tariff: dict) -> list[dict]:
    """Список локаций тарифа: один сервер — выбранный клиентом, иначе первые N локаций."""
    locations = configured_locations()
    count = tariff_tunnels(tariff)
    return locations[:count]


def tariff_locations_label(tariff: dict) -> str:
    """«Стокгольм» или «все серверы (Стокгольм, Варшава)»."""
    spots = tariff_locations(tariff)
    if not spots:
        return "Все локации"
    if len(spots) == 1:
        return spots[0]["short"]
    return "все серверы (" + ", ".join(spot["short"] for spot in spots) + ")"


def location_display(tariff: dict, location_key: str | None = None) -> str:
    """Что показывать в строке «Сервер»: выбранную локацию или список локаций тарифа."""
    spot = location_by_key(location_key)
    if spot:
        return spot["title"]
    return tariff_locations_label(tariff)


def location_by_key(key: str | None) -> dict | None:
    if not key:
        return None
    meta = LOCATIONS.get(key)
    return {"key": key, **meta} if meta else None


def location_from_text(text: str) -> str | None:
    """Распознаёт локацию по callback-данным, коду или названию («warsaw», «варшава»)."""
    value = (text or "").strip().lower()
    if not value:
        return None
    if value in LOCATIONS:
        return value
    for key, meta in LOCATIONS.items():
        if value == str(meta["short"]).lower() or value in meta["aliases"]:
            return key
    for key, meta in LOCATIONS.items():
        if value and (value in str(meta["short"]).lower() or any(value in alias for alias in meta["aliases"])):
            return key
    return None


def tariff_price_label(tariff: dict) -> str:
    """Цена тарифа в валюте текущего режима оплаты."""
    if tariff["price"] <= 0:
        return "Бесплатно"
    if PAYMENTS_MODE == "stars":
        return f"{tariff.get('stars', 0)} ⭐️"
    return f"{tariff['price']} ₽"


def new_order(tg_id: int, tariff_key: str, location_key: str | None = None) -> dict:
    """
    Создаёт заказ со статусом pending.

    location_key — выбранный сервер для тарифов с одним туннелем (тарифы на несколько
    туннелей получают все локации сразу, поэтому там он не нужен).
    """
    tariff = TARIFFS[tariff_key]
    now = int(time.time())
    currency = "XTR" if PAYMENTS_MODE == "stars" else "RUB"

    order = {
        "id": f"{tariff_key}-{tg_id}-{now}-{secrets.token_hex(3)}",
        "tg_id": tg_id,
        "tariff": tariff_key,
        "tariff_name": tariff["name"],
        "tariff_kind": tariff.get("kind", ""),
        "tariff_level": tariff.get("level", 0),
        "days": tariff["days"],
        "traffic_gb": tariff["traffic_gb"],
        "ip_limit": tariff["ip_limit"],
        "tunnels": tariff.get("tunnels", 1),
        "location": location_key or None,
        "amount_rub": tariff["price"],
        "amount_stars": tariff.get("stars", 0),
        "currency": currency,
        "mode": PAYMENTS_MODE,
        "status": "pending",
        "created_at": now,
    }
    return order


def order_amount(order: dict) -> int:
    """Сумма заказа в минимальных единицах: копейки для RUB, звёзды для XTR."""
    if order["currency"] == "XTR":
        return int(order["amount_stars"])
    return int(order["amount_rub"]) * 100


# --- клиент ЮKassa ---

class YooKassaClient:
    """Минимальный клиент API ЮKassa (https://yookassa.ru/developers/api)."""

    def __init__(
        self,
        shop_id: str,
        secret_key: str,
        api_url: str = YOOKASSA_API_URL,
        oauth_token: str = "",
    ):
        self.shop_id = shop_id
        self.secret_key = secret_key
        self.oauth_token = oauth_token
        self.api_url = api_url.rstrip("/")

    def _auth(self) -> aiohttp.BasicAuth:
        return aiohttp.BasicAuth(self.shop_id, self.secret_key)

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        headers = {"Content-Type": "application/json", **(kwargs.pop("headers", {}))}
        auth = self._auth()
        if self.oauth_token:
            # OAuth-токен нужен для API вебхуков; для платежей он тоже подходит
            headers["Authorization"] = f"Bearer {self.oauth_token}"
            auth = None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as session:
                async with session.request(
                    method,
                    f"{self.api_url}{path}",
                    auth=auth,
                    headers=headers,
                    **kwargs,
                ) as resp:
                    raw = await resp.text()
                    status = resp.status
        except Exception as exc:
            raise PaymentError(
                f"❌ ЮKassa недоступна: <code>{escape(str(exc))}</code>\n"
                "Проверь YOOKASSA_API_URL и доступность api.yookassa.ru из Railway."
            ) from exc

        if status >= 400:
            try:
                data = json.loads(raw)
                msg = data.get("description") or data.get("code") or raw[:200]
            except ValueError:
                msg = raw[:200]
            raise PaymentError(
                f"❌ ЮKassa вернула ошибку HTTP {status}: <code>{escape(str(msg))}</code>\n\n"
                "Проверь <b>YOOKASSA_SHOP_ID</b> и <b>YOOKASSA_SECRET_KEY</b> "
                "(Интеграция → Ключи API в личном кабинете ЮKassa)."
            )
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise PaymentError(f"❌ ЮKassa вернула не JSON: <code>{escape(_snip(raw, 200))}</code>") from exc

    async def create_payment(self, order: dict) -> dict:
        """
        Создаёт платёж и возвращает ответ ЮKassa (в нём confirmation.confirmation_url).

        Ключ идемпотентности = id заказа: повторный запрос не создаст второй платёж.
        """
        payload = {
            "amount": {"value": f"{order['amount_rub']:.2f}", "currency": "RUB"},
            "capture": True,
            "confirmation": {"type": "redirect", "return_url": f"{PUBLIC_BASE_URL or 'https://t.me'}"},
            "description": f"VPN «{order['tariff_name']}» для Telegram {order['tg_id']}",
            "metadata": {"order_id": order["id"], "tg_id": str(order["tg_id"]), "tariff": order["tariff"]},
        }
        # Чек по 54-ФЗ — только если он включён (YOOKASSA_VAT_CODE > 0)
        if YOOKASSA_VAT_CODE > 0:
            payload["receipt"] = {
                "customer": {"account": str(order["tg_id"])},
                "items": [{
                    "description": f"VPN {order['tariff_name']} ({order['days']} дн.)"[:128],
                    "quantity": "1.00",
                    "amount": {"value": f"{order['amount_rub']:.2f}", "currency": "RUB"},
                    "vat_code": YOOKASSA_VAT_CODE,
                    "payment_subject": "service",
                    "payment_mode": "full_payment",
                }],
            }
        return await self._request(
            "POST", "/payments", json=payload, headers={"Idempotence-Key": order["id"]}
        )

    async def get_payment(self, payment_id: str) -> dict:
        return await self._request("GET", f"/payments/{quote(payment_id, safe='')}")

    async def list_webhooks(self) -> list:
        data = await self._request("GET", "/webhooks")
        return data.get("items") if isinstance(data, dict) else []

    async def ensure_webhook(self, url: str) -> bool:
        """
        Регистрирует вебхук payment.succeeded, если его ещё нет.

        Требует OAuth-токен: при Basic-авторизации ЮKassa не даёт управлять
        вебхуками через API (только личный кабинет), поэтому без токена метод
        ничего не делает и возвращает False.
        """
        if not self.oauth_token:
            logger.info(
                "OAuth-токен ЮKassa не задан — вебхук нужно добавить в личном кабинете: "
                "Интеграция → HTTP-уведомления → %s (событие payment.succeeded).",
                url,
            )
            return False
        try:
            hooks = await self.list_webhooks()
        except PaymentError as exc:
            logger.warning("Не удалось получить список вебхуков ЮKassa: %s", exc)
            hooks = []
        for hook in hooks or []:
            if hook.get("event") == "payment.succeeded" and hook.get("url") == url:
                logger.info("Вебхук ЮKassa уже настроен: %s", url)
                return True
        try:
            await self._request("POST", "/webhooks", json={"event": "payment.succeeded", "url": url})
            logger.info("Вебхук ЮKassa зарегистрирован: %s", url)
            return True
        except PaymentError as exc:
            logger.warning("Не удалось зарегистрировать вебхук ЮKassa: %s", exc)
            return False


def provider_mode_title() -> str:
    """Описание платёжного токена BotFather: тестовый он или боевой."""
    if not PAYMENT_PROVIDER_TOKEN:
        return "токен не задан"
    return "тестовый токен 🧪" if PROVIDER_TEST_MODE else "боевой токен"


async def recheck_order_payment(order: dict) -> tuple[str, str]:
    """
    Переспрашивает платёж у платёжной системы, если вебхук не дошёл:
    Platega — GET /transaction/{id}, ЮKassa — GET /payments/{id}.

    Возвращает (состояние, подробности):
      • 'paid'     — оплата подтверждена;
      • 'pending'  — платёж ещё не завершён;
      • 'canceled' — платёж отменён/истёк;
      • 'error'    — не удалось проверить (текст ошибки для пользователя).
    """
    if order.get("mode") == "platega":
        transaction_id = str(order.get("payment_id") or "").strip()
        if not transaction_id:
            return "error", "Платёж ещё не создан, нажми «Оплатить»."
        try:
            data = await platega_transaction(transaction_id)
        except PaymentError as exc:
            return "error", str(exc)
        except Exception as exc:
            logger.warning("Не удалось проверить платёж Platega %s: %s", transaction_id, exc)
            return "error", "❌ Не удалось связаться с Platega. Попробуй ещё раз через минуту."
        status = str(data.get("status") or "").strip().upper()
        if status == "CONFIRMED":
            amount = (data.get("paymentDetails") or {}).get("amount")
            if not platega_amount_matches(order, amount):
                return "error", "⚠️ Сумма оплаты не совпала с заказом — напиши в поддержку."
            return "paid", status
        if status in ("CANCELED", "CHARGEBACKED"):
            return "canceled", status
        return "pending", status or "PENDING"

    # ЮKassa
    payment_id = order.get("payment_id")
    if not payment_id:
        return "error", "Платёж ещё не создан, нажми «Оплатить»."
    try:
        payment = await make_yookassa_client().get_payment(payment_id)
    except PaymentError as exc:
        return "error", str(exc)
    status = str(payment.get("status") or "")
    if status == "succeeded" and payment.get("paid"):
        paid_value = str((payment.get("amount") or {}).get("value") or "")
        if paid_value:
            try:
                if round(float(paid_value) * 100) != order_amount(order):
                    return "error", "⚠️ Сумма оплаты не совпала с заказом — напиши в поддержку."
            except ValueError:
                pass
        return "paid", status
    if status == "canceled":
        return "canceled", status
    return "pending", status


def telegram_receipt_provider_data(order: dict) -> str | None:
    """
    Данные чека 54-ФЗ для provider_data (формат ЮKassa).

    Telegram передаёт их платёжному провайдеру вместе со счётом. Включается
    переменной TELEGRAM_SEND_RECEIPT=1 — только если у магазина есть фискализация.
    """
    if not TELEGRAM_SEND_RECEIPT:
        return None
    receipt = {
        "receipt": {
            "items": [{
                "description": f"VPN {order['tariff_name']} ({order['days']} дн.)"[:128],
                "quantity": "1.00",
                "amount": {"value": f"{order['amount_rub']:.2f}", "currency": "RUB"},
                "vat_code": TELEGRAM_RECEIPT_VAT_CODE,
                "payment_subject": "service",
                "payment_mode": "full_payment",
            }],
        }
    }
    return json.dumps(receipt, ensure_ascii=False)



# --- Platega ---
# Оплата по ссылке: бот создаёт транзакцию через API (POST /v2/transaction/process) и
# присылает клиенту ссылку на платёжную страницу Platega. Об оплате Platega сообщает
# callback-уведомлением на наш вебхук: в заголовках X-MerchantId и X-Secret (те же
# значения, что в переменных бота), в теле — id транзакции, сумма, валюта, статус
# (CONFIRMED / CANCELED / CHARGEBACKED) и наш payload (номер заказа).
# Дополнительно статус можно переспросить у API: GET /transaction/{id}.

def platega_configured() -> bool:
    """Заданы ли Merchant ID и API-ключ Platega."""
    return bool(PLATEGA_MERCHANT_ID and PLATEGA_SECRET)


def platega_headers() -> dict:
    """Заголовки авторизации Platega: X-MerchantId + X-Secret."""
    return {
        "X-MerchantId": PLATEGA_MERCHANT_ID,
        "X-Secret": PLATEGA_SECRET,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def platega_amount(order: dict) -> float | int:
    """Сумма заказа для API: целое число, если сумма целая (500, а не 500.0)."""
    price = float(order.get("amount_rub") or 0)
    return int(price) if price == int(price) else round(price, 2)


def platega_amount_matches(order: dict, amount) -> bool:
    """Совпадает ли оплаченная сумма с заказом (сравниваем в копейках)."""
    try:
        paid_kop = round(float(str(amount).replace(",", ".")) * 100)
    except (TypeError, ValueError):
        return False
    return abs(paid_kop - order_amount(order)) <= 1


def platega_credentials_valid(merchant_id: str | None, secret: str | None) -> bool:
    """
    Совпадают ли присланные Platega заголовки с нашими.

    У Platega нет отдельной подписи уведомления: и запросы, и callback защищены
    одной парой X-MerchantId / X-Secret, поэтому сравниваем их (в постоянном
    времени, чтобы по ответам нельзя было подбирать ключ посимвольно).
    """
    if not platega_configured():
        return False
    # Сравниваем байты: compare_digest не принимает строки с не-ASCII (а в мусорном
    # запросе может прийти что угодно), зато так сравнение остаётся постоянным по времени.
    return (
        hmac.compare_digest(str(merchant_id or "").encode(), PLATEGA_MERCHANT_ID.encode())
        and hmac.compare_digest(str(secret or "").encode(), PLATEGA_SECRET.encode())
    )


async def platega_back_url() -> str:
    """Куда вернуть клиента после оплаты: чат с ботом."""
    username = await get_bot_username()
    return f"https://t.me/{username}" if username else (PUBLIC_BASE_URL or "https://t.me")


async def platega_create_payment(order: dict) -> dict:
    """
    Создаёт транзакцию в Platega и возвращает данные для оплаты.

    Ответ API: transactionId, status, url (в v2) или redirect (в v1), expiresIn.
    При ошибке поднимает PaymentError с понятным текстом для пользователя.
    """
    if not platega_configured():
        raise PaymentError(
            "⚠️ Оплата через Platega не настроена: не хватает Merchant ID или API-ключа.\n\n"
            "Администратору: добавь в Railway → Variables <b>PLATEGA_MERCHANT_ID</b> и "
            "<b>PLATEGA_SECRET</b> (кабинет Platega → Настройки → Интеграция → API). "
            "Проверить: команда /platega_check."
        )

    back_url = await platega_back_url()
    body = {
        "paymentDetails": {"amount": platega_amount(order), "currency": PLATEGA_CURRENCY},
        "description": f"Оплата подписки {order.get('tariff_name') or order.get('tariff') or ''}".strip()[:120],
        "return": PLATEGA_RETURN_URL or back_url,
        "failedUrl": PLATEGA_FAILED_URL or back_url,
        # payload возвращается в callback — по нему находим заказ в журнале бота,
        # даже если журнал переехал; orderId виден в кабинете Platega.
        "payload": str(order["id"]),
        "orderId": str(order["id"]),
        "metadata": {
            "userId": str(order.get("tg_id") or ""),
            "userName": str(order.get("tg_username") or order.get("tg_id") or "telegram"),
        },
    }
    if PLATEGA_METHOD:
        body["paymentMethod"] = PLATEGA_METHOD

    url = f"{PLATEGA_API_URL}/v2/transaction/process"
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body, headers=platega_headers()) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    logger.error("Platega вернула %s на создание платежа: %s", resp.status, _snip(text, 300))
                    reason = _snip(text, 200)
                    if resp.status in (401, 403):
                        reason = "Platega отклонила Merchant ID или API-ключ — проверь переменные"
                    raise PaymentError(
                        "❌ Platega не создала платёж (HTTP {status}).\n"
                        "Причина: <code>{reason}</code>\n\n"
                        "Попробуй ещё раз через минуту; если повторяется — /platega_check или поддержка."
                        .format(status=resp.status, reason=escape(reason))
                    )
                data = json.loads(text or "{}")
    except PaymentError:
        raise
    except asyncio.TimeoutError:
        raise PaymentError(
            "❌ Platega не ответила вовремя. Попробуй ещё раз через минуту — "
            "если повторяется, напиши в поддержку."
        )
    except Exception as exc:
        logger.error("Не удалось создать платёж в Platega: %s", exc)
        raise PaymentError(
            "❌ Не удалось создать платёж в Platega: <code>{reason}</code>\n\n"
            "Попробуй ещё раз через минуту или напиши в поддержку.".format(
                reason=escape(_snip(str(exc), 160))
            )
        )

    if not platega_payment_url(data):
        logger.error("Platega не вернула ссылку на оплату: %s", _snip(json.dumps(data, ensure_ascii=False), 300))
        raise PaymentError(
            "❌ Platega не вернула ссылку на оплату. Попробуй ещё раз через минуту "
            "или напиши в поддержку."
        )
    return data


def platega_payment_url(data: dict) -> str:
    """Ссылка на оплату из ответа API: у v2 это url, у v1 — redirect."""
    return str(data.get("url") or data.get("redirect") or "").strip()


async def platega_transaction(transaction_id: str) -> dict:
    """Статус и детали транзакции: GET /transaction/{id} (PENDING/CONFIRMED/CANCELED/CHARGEBACKED)."""
    if not platega_configured():
        raise PaymentError("Platega не настроена: не хватает PLATEGA_MERCHANT_ID / PLATEGA_SECRET.")
    url = f"{PLATEGA_API_URL}/transaction/{quote(str(transaction_id), safe='')}"
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=platega_headers()) as resp:
            text = await resp.text()
            if resp.status >= 400:
                logger.warning("Platega вернула %s на статус транзакции %s: %s",
                               resp.status, transaction_id, _snip(text, 200))
                raise PaymentError("Не удалось получить статус платежа в Platega.")
            return json.loads(text or "{}")


async def platega_balance() -> str:
    """Быстрая проверка ключей: запрос балансов магазина (GET /balance/all)."""
    url = f"{PLATEGA_API_URL}/balance/all"
    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=platega_headers()) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise PaymentError(f"HTTP {resp.status}: {_snip(text, 120)}")
            return _snip(text, 200)


async def process_platega_callback(
    payload_body: dict, merchant_id: str | None, secret: str | None
) -> tuple[int, str]:
    """
    Обрабатывает callback Platega об изменении статуса транзакции.

    Возвращает (код ответа, пояснение): 200 — уведомление принято и обработано
    (Platega больше не повторяет), 4xx — отказ (она повторит попытку до 3 раз, что
    полезно, если панель 3x-ui оказалась недоступна в момент оплаты).

    Статусы: CONFIRMED — деньги пришли, выдаём ключ; CANCELED — платёж отменён или
    истёк; CHARGEBACKED — деньги вернули клиенту (ключ не отзываем автоматически,
    но админ получает предупреждение, чтобы решить вопрос через /revoke).
    """
    if not platega_credentials_valid(merchant_id, secret):
        logger.warning("Platega: callback с чужими заголовками X-MerchantId/X-Secret отклонён.")
        return 401, "заголовки X-MerchantId / X-Secret не совпали"

    transaction_id = str(payload_body.get("id") or "").strip()
    status = str(payload_body.get("status") or "").strip().upper()
    order_id = str(payload_body.get("payload") or "").strip()

    order = await payment_store.get(order_id) if order_id else None
    if order is None and transaction_id:
        # payload мог не дойти — ищем заказ по id транзакции в журнале.
        order = next(
            (o for o in payment_store.orders.values()
             if str(o.get("payment_id") or "") == transaction_id),
            None,
        )
    if order is None:
        logger.error("Platega: callback по неизвестному заказу %r (транзакция %s)",
                     order_id, transaction_id)
        return 404, f"заказ {order_id!r} не найден в журнале бота"

    if status == "CANCELED":
        if order.get("status") != "paid":
            await payment_store.update(order["id"], status="canceled",
                                       payment_id=transaction_id or order.get("payment_id"))
        logger.info("Platega: платёж по заказу %s отменён (транзакция %s)", order["id"], transaction_id)
        return 200, "платёж отменён"

    if status == "CHARGEBACKED":
        await payment_store.update(order["id"], chargeback=True, chargeback_at=int(time.time()))
        logger.warning("Platega: возврат средств по заказу %s (транзакция %s)", order["id"], transaction_id)
        await notify_admins(
            "↩️ <b>Platega: возврат средств по оплаченному заказу.</b>\n\n"
            f"• Заказ: <code>{escape(order['id'])}</code>\n"
            f"• Тариф: {escape(order.get('tariff_name') or '—')}, {order.get('amount_rub')} ₽\n"
            f"• Пользователь: TG <code>{order['tg_id']}</code>\n"
            f"• Транзакция: <code>{escape(transaction_id)}</code>\n\n"
            "Деньги вернулись клиенту. Подписку можно снять командой /revoke — "
            "решение о доступе за тобой."
        )
        return 200, "возврат средств отмечен"

    if status != "CONFIRMED":
        # PENDING и прочие промежуточные статусы: ничего не выдаём, ждём подтверждения.
        logger.info("Platega: промежуточный статус %s по заказу %s", status or "—", order["id"])
        return 200, f"статус {status or '—'} — ждём оплату"

    if not platega_amount_matches(order, payload_body.get("amount")):
        logger.error(
            "Platega: сумма %s не совпадает с заказом %s (%s ₽)",
            payload_body.get("amount"), order["id"], order["amount_rub"],
        )
        return 400, "сумма платежа не совпадает с заказом"

    currency = str(payload_body.get("currency") or PLATEGA_CURRENCY).strip().upper()
    if currency and currency != PLATEGA_CURRENCY:
        logger.error("Platega: валюта %s не совпадает с ожидаемой %s (заказ %s)",
                     currency, PLATEGA_CURRENCY, order["id"])
        return 400, "валюта платежа не совпадает с заказом"

    was_canceled = order.get("status") == "canceled"
    if was_canceled:
        # Клиент отменил заказ, но всё-таки оплатил по старой ссылке: деньги списаны,
        # поэтому ключ выдаём, а не отказываем. Предупредим и клиента, и админа в логах.
        logger.warning(
            "Platega: оплата по отменённому заказу %s — принимаю деньги и выдаю ключ "
            "(при необходимости верните оплату в кабинете Platega и снимите подписку /revoke).",
            order["id"],
        )
    if order.get("status") == "paid":
        # Platega может повторить callback — ключ уже выдан, просто подтверждаем приём.
        logger.info("Platega: повторный callback по заказу %s — уже оплачен", order["id"])
        await payment_store.update(order["id"], payment_id=transaction_id or order.get("payment_id"))
        return 200, "заказ уже оплачен, повторный callback подтверждён"

    await payment_store.update(
        order["id"],
        payment_id=transaction_id or order["id"],
        payment_method=str(payload_body.get("paymentMethod") or ""),
    )

    try:
        await fulfill_order(
            order,
            charge_id=f"platega-{transaction_id or order['id']}",
            provider_charge_id=transaction_id,
        )
    except Exception as exc:
        logger.error("Platega: выдача по заказу %s не удалась: %s — ждём повтор callback",
                     order["id"], exc)
        return 500, f"выдача ключа не удалась: {exc}"

    if was_canceled:
        await payment_store.update(order["id"], canceled_then_paid=True)
        try:
            await bot.send_message(
                order["tg_id"],
                "⚠️ <b>Оплата пришла по заказу, который был отменён.</b>\n\n"
                "Деньги списаны, поэтому ключ выдан — доступ уже работает.\n"
                f"<i>Номер заказа: <code>{escape(order['id'])}</code></i>\n\n"
                "Если подписка не нужна, напиши в поддержку: оформим возврат.",
                parse_mode="HTML",
            )
        except Exception as exc:
            logger.warning("Не удалось предупредить об оплате отменённого заказа %s: %s", order["id"], exc)

    return 200, "оплата принята, ключ выдан"


def make_yookassa_client() -> YooKassaClient:
    return YooKassaClient(
        YOOKASSA_SHOP_ID,
        YOOKASSA_SECRET_KEY,
        oauth_token=YOOKASSA_OAUTH_TOKEN,
    )


# --- выдача подписки в 3x-ui ---

def _paid_client_payload(
    telegram_id: int,
    client_uuid: str,
    now_ms: int,
    inbound: dict,
    tariff: dict,
    expires_ms: int,
    comment: str,
    sub_id: str = "",
    group_name: str = "",
) -> dict:
    """Payload платного клиента: лимиты и срок берутся из тарифа."""
    stream = as_dict(inbound.get("streamSettings"))
    network = stream.get("network", "tcp")
    security = stream.get("security", "reality")
    flow = "xtls-rprx-vision" if (network == "tcp" and security in ("reality", "tls")) else ""

    payload = {
        "id": client_uuid,
        "email": f"tg-paid-{telegram_id}",
        "flow": flow,
        "enable": True,
        "limitIp": int(tariff["ip_limit"]),
        "totalGB": int(tariff["traffic_gb"]) * (1024 ** 3),   # 0 = безлимит
        "expiryTime": int(expires_ms),
        "tgId": int(telegram_id),
        "subId": sub_id or secrets.token_hex(8),
        "reset": 0,
        "comment": comment[:120],
    }
    if XUI_CLIENT_GROUP and group_name:
        payload["group"] = group_name
    return payload


def comment_has_payment_ref(comment: str | None, payment_ref: str) -> bool:
    """
    Проверяет, что подписка в панели уже выдана именно по этому платежу.

    Комментарий клиента выглядит как «basic до 17.10.2026 | platega-123456», поэтому
    сравниваем только хвост после «|»: иначе короткий ref вроде «2» совпал бы
    с цифрами в дате и бот зря решил бы, что ключ уже выдан.
    """
    ref = (payment_ref or "").strip()[:40]
    if not ref:
        return False
    text = str(comment or "").strip()
    if not text:
        return False
    tail = text.rsplit("|", 1)[-1].strip() if "|" in text else text
    return tail == ref


def order_charge_id(order: dict) -> str:
    """Идентификатор платежа заказа — тот же, что приходит в вебхуке и при проверке."""
    if order.get("mode") == "platega":
        # id транзакции Platega — он же приходит в callback и в проверке статуса.
        transaction_id = str(order.get("payment_id") or "").strip()
        return f"platega-{transaction_id}" if transaction_id else ""
    return str(order.get("payment_id") or "")


async def resolve_location_inbound(client, spot: dict) -> tuple[dict, bool, str]:
    """
    Находит подключение (inbound) для локации.

    Приоритет: ID из переменной XUI_INBOUND_<ЛОКАЦИЯ> → название в панели
    (Стокгольм / Варшава) → общее подключение XUI_INBOUND_ID. Возвращает
    (inbound, auto_picked, откуда) — откуда потом видно в /panel_debug.
    """
    inbound_id = int(spot.get("inbound_id") or 0)
    if inbound_id > 0:
        try:
            inbound = await client.get_inbound(inbound_id)
            if inbound and inbound.get("id"):
                return inbound, False, f"{spot.get('env')}={inbound_id}"
        except Exception as exc:
            logger.warning("Локация %s: подключение #%s недоступно (%s) — ищу дальше.",
                           spot.get("title"), inbound_id, exc)

    names = [spot.get("short", ""), *(spot.get("aliases") or ())]
    by_name = await client.find_inbound_by_name(names)
    if by_name is not None:
        return by_name, False, f"название «{by_name.get('remark')}» в панели"

    inbound, auto_picked = await client.find_suitable_inbound(XUI_INBOUND_ID)
    return inbound, auto_picked, "общее подключение XUI_INBOUND_ID"


async def activate_paid_subscription(
    telegram_id: int,
    tariff_key: str,
    *,
    order_id: str,
    payment_ref: str,
    extra_days: int = 0,
    location_key: str | None = None,
) -> dict:
    """
    Создаёт или продлевает платную подписку в 3x-ui по оплаченному заказу.

    Тариф на один туннель выдаётся в выбранной локации (Стокгольм или Варшава),
    тарифы на несколько туннелей — сразу во всех локациях, входящих в тариф.
    Если срок тарифа не ограничен (тип «по трафику»), expiryTime = 0: подписка
    действует, пока не израсходован трафик, а реферальные бонусы (дни) задают срок.

    Идемпотентно: если в комментарии клиента уже стоит этот платёж, повторная
    выдача не происходит (защита от дублей вебхука и перезапуска бота).
    extra_days — реферальный бонус приглашённого; к ним добавляются накопленные
    бонусы самого покупателя (он тоже мог приглашать друзей).
    Возвращает словарь с доступом, сроком и деталями подписки.
    """
    tariff = TARIFFS[tariff_key]
    target_email = f"tg-paid-{telegram_id}"
    bonus_days = max(0, int(extra_days))
    pending_bonus = referral_store.pending_days(telegram_id) if REFERRAL_ENABLED else 0
    bonus_days += pending_bonus

    # Срок: у тарифа «по трафику» его нет (0 = без ограничения), но бонусные дни
    # за друзей задают срок — иначе они бы просто потерялись.
    total_days = int(tariff["days"]) + bonus_days
    limited = total_days > 0 or int(tariff["days"]) > 0
    now_ms = int(time.time() * 1000)
    if total_days > 0:
        comment = f"{tariff_key} до {format_date(now_ms + total_days * 86400 * 1000)} | {payment_ref[:40]}"
    else:
        comment = f"{tariff_key} без ограничения по времени | {payment_ref[:40]}"

    spots = tariff_locations(tariff)
    if int(tariff.get("tunnels", 1) or 1) <= 1:
        chosen = location_by_key(location_key) or spots[0]
        spots = [chosen]

    async with XUIClient() as client:
        group_name, group_state = await client.resolve_client_group()
        entries: list[dict] = []

        async def sub_link_for(sub_id: str | None) -> str | None:
            """Ссылка-подписка клиента (или None, если сервис подписок недоступен)."""
            if not sub_id:
                return None
            base, note = await get_subscription_base(client, sub_id=sub_id)
            if not base:
                logger.warning("Подписка %s: ссылка подписки недоступна — %s", target_email, note)
                return None
            return build_sub_link(base, sub_id)

        for spot in spots:
            inbound, auto_picked, source = await resolve_location_inbound(client, spot)
            inbound_id = inbound.get("id")
            params = extract_vless_params(inbound)

            settings = as_dict(inbound.get("settings"))
            clients = [c for c in (settings.get("clients") or []) if isinstance(c, dict)]
            existing = next((c for c in clients if str(c.get("email")) == target_email), None)

            # Уже выдан по этому платежу? (журнал мог не сохраниться — смотрим в панель)
            if existing is not None and comment_has_payment_ref(existing.get("comment"), payment_ref):
                logger.info("Подписка %s (%s) уже выдана по платежу %s — повторно не продлеваю.",
                            target_email, spot["title"], payment_ref)
                entries.append({
                    "location": spot.get("key"),
                    "location_title": spot.get("title"),
                    "inbound_id": inbound_id,
                    "inbound_remark": inbound.get("remark"),
                    "resolved_by": source,
                    "status": "already",
                    "auto_picked": auto_picked,
                    "link": build_vless_link(existing, inbound, params),
                    "sub_link": await sub_link_for(existing.get("subId")),
                    "expiry_ms": int(existing.get("expiryTime") or 0),
                    "existing": True,
                })
                continue

            # Продление считается от текущего срока, если он ещё не истёк
            base_ms = now_ms
            if existing is not None and bool(existing.get("enable", True)):
                existing_expiry = int(existing.get("expiryTime") or 0)
                if existing_expiry > now_ms:
                    base_ms = existing_expiry
            expires_ms = (base_ms + total_days * 86400 * 1000) if limited else 0

            payload = _paid_client_payload(
                telegram_id,
                (existing or {}).get("id") or str(uuid.uuid4()),
                now_ms,
                inbound,
                tariff,
                expires_ms,
                comment,
                sub_id=(existing or {}).get("subId") or "",
                group_name=group_name or "",
            )

            if existing is not None:
                await client.update_client(inbound_id, payload)
                status = "extended"
            else:
                await client.add_client(inbound_id, payload)
                status = "created"

            sub_link = await sub_link_for(payload.get("subId"))

            entries.append({
                "location": spot.get("key"),
                "location_title": spot.get("title"),
                "inbound_id": inbound_id,
                "inbound_remark": inbound.get("remark"),
                "resolved_by": source,
                "status": status if existing is None else "extended",
                "auto_picked": auto_picked,
                "link": build_vless_link(payload, inbound, params),
                "sub_link": sub_link,
                "expiry_ms": expires_ms,
                "existing": existing is not None,
            })

        # Дни за друзей потрачены — обнуляем копилку, чтобы не начислить их второй раз.
        if pending_bonus:
            await referral_store.clear_pending(telegram_id)
            logger.info("Заказу %s зачтены накопленные реферальные дни: +%s.", order_id, pending_bonus)

        group_note = ""
        if group_state in ("exists", "new"):
            group_note = _group_note(
                await client.add_clients_to_group([target_email], group_name, existed=(group_state == "exists")),
                group_name,
            )

    primary = entries[0]
    return {
        "email": target_email,
        "already": all(entry["status"] == "already" for entry in entries),
        "status": primary["status"],
        "expiry_ms": primary["expiry_ms"],
        "limited": limited,
        "link": primary["link"],
        "sub_link": primary["sub_link"],
        "entries": entries,
        "location": primary.get("location"),
        "location_title": primary.get("location_title"),
        "tariff": tariff,
        "inbound_id": primary["inbound_id"],
        "auto_picked": primary["auto_picked"],
        "group_note": group_note,
        "bonus_days": bonus_days,
    }


async def get_paid_subscription(telegram_id: int) -> dict | None:
    """
    Читает текущую подписку пользователя из панели (срок, трафик, статус).

    Тарифы на несколько туннелей живут в нескольких локациях: возвращаем запись
    из каждой (список «entries»), а поля верхнего уровня — по первой локации,
    чтобы старые вызовы продолжали работать.
    """
    target_email = f"tg-paid-{telegram_id}"
    async with XUIClient() as client:
        inbounds = await client.get_inbounds()
        entries = []
        for inbound in inbounds:
            settings = as_dict(inbound.get("settings"))
            for candidate in settings.get("clients") or []:
                if not isinstance(candidate, dict) or str(candidate.get("email")) != target_email:
                    continue
                stats = {}
                for stat in inbound.get("clientStats") or []:
                    if isinstance(stat, dict) and str(stat.get("email")) == target_email:
                        stats = stat
                        break
                used = int(stats.get("up") or 0) + int(stats.get("down") or 0)
                entries.append({
                    "client": candidate,
                    "inbound": inbound,
                    "inbound_id": inbound.get("id"),
                    "inbound_remark": inbound.get("remark"),
                    "location_title": inbound.get("remark") or f"сервер #{inbound.get('id')}",
                    "used_bytes": used,
                    "total_bytes": int(candidate.get("totalGB") or 0),
                    "expiry_ms": int(candidate.get("expiryTime") or 0),
                    "enable": bool(stats.get("enable", candidate.get("enable", True))),
                })
        if not entries:
            return None
        primary = entries[0]
        primary = dict(primary)
        primary["entries"] = entries
        return primary


def subscription_status_text(sub: dict | None) -> str:
    """Человеческое описание подписки для /profile (в т.ч. по всем локациям тарифа)."""
    if not sub:
        return "❌ Активной подписки нет."

    expiry_ms = sub["expiry_ms"]
    enabled = sub["enable"]
    expired = expiry_ms > 0 and expiry_ms <= int(time.time() * 1000)
    if expired:
        state = "⌛️ Истекла"
    elif not enabled:
        state = "⛔️ Отключена администратором"
    else:
        state = "✅ Активна"

    lines = [f"• Статус: <b>{state}</b>"]
    if expiry_ms > 0:
        left_days = max(0, (expiry_ms - int(time.time() * 1000)) // 86_400_000)
        date = format_date(expiry_ms)
        lines.append(f"• Действует до: <b>{date}</b> (осталось {left_days} дн.)")
    else:
        lines.append("• Срок: <b>без ограничения по времени</b> (тариф по трафику)")

    total = sub["total_bytes"]
    used = sub["used_bytes"]
    if total > 0:
        lines.append(f"• Трафик: <b>{_human_bytes(used)}</b> из {_human_bytes(total)}")
    else:
        lines.append(f"• Трафик: <b>{_human_bytes(used)}</b> (безлимит)")

    entries = sub.get("entries") or []
    if len(entries) > 1:
        titles = ", ".join(str(entry.get("location_title")) for entry in entries)
        lines.append(f"• Серверы: <b>{escape(titles)}</b>")
    return "\n".join(lines)


# --- запуск оплаты ---

def access_block(info: dict, *, heading: str = "") -> str:
    """
    Блок с доступом в сообщениях клиенту.

    Основное — ссылка-подписка: приложение само забирает по ней конфигурацию и
    обновляет её. У тарифа на несколько туннелей ссылок столько же, сколько локаций, —
    показываем каждую с названием сервера. Если сервис подписок в панели выключен
    или не отвечает, показываем ключ vless:// — он работает всегда и не оставит
    клиента без доступа (админ получает отдельное предупреждение).
    """
    entries = [entry for entry in (info.get("entries") or []) if entry.get("sub_link")]
    if len(entries) > 1:
        lines = [heading or "🔗 <b>Твои ссылки-подписки (нажми, чтобы скопировать):</b>"]
        for entry in entries:
            lines.append(
                f"\n{entry.get('location_title') or 'Сервер'}:\n"
                f"<code>{escape(entry['sub_link'])}</code>"
            )
        lines.append(
            "\n📥 <b>Как добавить:</b> в приложении выбери «Добавить подписку» / "
            "«Импорт из ссылки» и вставь ссылку нужного сервера — профиль появится сам "
            "и будет обновляться. В тариф входят оба сервера: можно добавить обе ссылки."
        )
        return "".join(lines) + "\n"

    sub_link = info.get("sub_link")
    if sub_link:
        return (
            f"{heading or '🔗 <b>Твоя ссылка-подписка (нажми, чтобы скопировать):</b>'}\n"
            f"<code>{escape(sub_link)}</code>\n\n"
            "📥 <b>Как добавить:</b> в приложении выбери «Добавить подписку» / "
            "«Импорт из ссылки» и вставь эту ссылку — профиль появится сам и будет "
            "обновляться, если на сервере что-то изменится."
        )
    return (
        "🔑 <b>Твой ключ (нажми, чтобы скопировать):</b>\n"
        f"<code>{escape(info.get('link') or '')}</code>\n\n"
        "📥 <b>Как добавить:</b> в приложении выбери «Импорт из буфера обмена» — "
        "ключ уже скопирован, останется вставить его."
    )


def order_paid_message(order: dict, info: dict) -> str:
    """Сообщение пользователю после успешной оплаты."""
    tariff = info["tariff"]
    expiry = format_date(info["expiry_ms"])
    title = (
        "♻️ <b>Подписка продлена!</b>"
        if info.get("status") == "extended"
        else "🎉 <b>Оплата получена, подписка активирована!</b>"
    )
    if info.get("already"):
        title = "✅ <b>Этот платёж уже учтён — подписка активна.</b>"
    if order.get("promo"):
        title = "🎉 <b>Промо-доступ активирован — бесплатно!</b>"
    elif order.get("simulated"):
        title = "🧪 <b>Проверка выдачи: подписка создана без оплаты.</b>"

    if info.get("expiry_ms"):
        term_line = f"⏳ <b>Действует до:</b> {expiry}\n"
    else:
        term_line = "⏳ <b>Срок:</b> без ограничения по времени — пока не израсходован трафик\n"
    served = ", ".join(str(entry.get("location_title")) for entry in (info.get("entries") or []))

    return (
        f"{title}\n\n"
        f"📦 <b>Тариф:</b> {tariff['name']}\n"
        + term_line
        + (f"🎁 <b>Бонус за друзей:</b> +{info['bonus_days']} "
           f"{days_word(info['bonus_days'])} к сроку\n" if info.get("bonus_days") else "")
        +
        f"📊 <b>Трафик:</b> {tariff['traffic']}\n"
        f"📱 <b>Устройств:</b> {tariff['ips']}\n"
        f"🌍 <b>Серверы:</b> {served or tariff['locations']}\n\n"
        + access_block(info) + "\n\n"
        "📲 <b>Как подключиться:</b> нажми кнопку под сообщением — покажу по шагам, "
        "что скачать и куда вставить ссылку (инструкции для iPhone, Android, Windows и macOS)."
        + (info.get("group_note") or "")
    )


async def notify_admins(text: str) -> None:
    """Отправляет сообщение всем администраторам (ADMIN_ID может содержать список)."""
    for admin_id in ADMIN_IDS:
        if admin_id == 0:
            continue
        try:
            await bot.send_message(admin_id, text, parse_mode="HTML")
        except Exception as exc:
            logger.warning("Не удалось уведомить админа %s: %s", admin_id, exc)


async def notify_payment_success(order: dict, info: dict) -> bool:
    """
    Отправляет покупателю ключ, а админу — уведомление о продаже.

    Возвращает True, если доступ доставлен. Если Telegram не принял сообщение
    (сбой сети, бот заблокирован), заказ не помечается уведомлённым — при
    повторной доставке платежа ключ будет отправлен снова.
    """
    delivered = True
    try:
        await bot.send_message(
            order["tg_id"],
            order_paid_message(order, info),
            parse_mode="HTML",
            reply_markup=key_actions_kb(order["tg_id"]),
        )
    except Exception as exc:
        delivered = False
        logger.error(
            "Не удалось отправить ключ пользователю %s (заказ %s): %s",
            order["tg_id"], order["id"], exc,
        )

    recipients = [admin_id for admin_id in ADMIN_IDS if admin_id != order["tg_id"]]
    if recipients:
        amount = (
            f"{order['amount_stars']} ⭐️" if order["currency"] == "XTR" else f"{order['amount_rub']} ₽"
        )
        if order.get("promo"):
            header = "🎁 <b>Промо-доступ выдан (бесплатно)</b>\n"
        elif order.get("simulated"):
            header = "🧪 <b>Тестовая выдача (оплата не производилась)</b>\n"
        else:
            header = f"💰 <b>Новая оплата:</b> {amount}\n"
        access_note = "" if info.get("sub_link") else (
            "\n⚠️ <b>Ссылки-подписки нет</b> — клиент получил ключ. "
            "Проверь в панели Settings → Subscription (включено ли, порт и путь) "
            "или задай <code>SUB_URL_BASE</code>. Подробнее: /panel_debug"
        )
        await notify_admins(
            header
            + f"• Тариф: {order['tariff_name']}\n"
            f"• Пользователь: <code>{order['tg_id']}</code>\n"
            f"• Заказ: <code>{order['id']}</code>\n"
            f"• Действует до: <code>{format_date(info['expiry_ms'])}</code>"
            + access_note
        )

    return delivered


async def fulfill_order(order: dict, *, charge_id: str, provider_charge_id: str | None = None) -> dict:
    """
    Помечает заказ оплаченным и выдаёт подписку. Повторные вызовы безопасны:
    ключ выдаётся один раз, но если выдача упала (панель недоступна) — попробует снова.
    """
    existing = await payment_store.find_by_charge(charge_id) if charge_id else None
    if existing is not None and existing["id"] != order["id"]:
        logger.warning("Платёж %s уже привязан к заказу %s — игнорирую дубль.", charge_id, existing["id"])
        return {"duplicate": True, "order": existing}

    order = await payment_store.update(
        order["id"],
        status="paid",
        paid_at=int(time.time()),
        charge_id=charge_id,
        provider_charge_id=provider_charge_id,
    ) or order

    if order.get("provisioned"):
        logger.info("Заказ %s уже выдан (provisioned) — повторная выдача не нужна.", order["id"])
        # Ключ мог не дойти (сбой сети у Telegram) — при повторной доставке платежа досылаем его
        if not order.get("notified") and int(order.get("expiry_ms") or 0) > 0:
            link = order.get("link")
            sub_link = order.get("sub_link")
            # Заказ мог быть выдан более старой версией бота: тогда пересобираем ключ
            # из панели, а ссылку-подписку считаем заново — старая могла собираться
            # на адресе панели и уже не работать.
            try:
                sub = await get_paid_subscription(order["tg_id"])
                if sub:
                    if not link:
                        async with XUIClient() as client:
                            params = extract_vless_params(sub["inbound"])
                        link = build_vless_link(sub["client"], sub["inbound"], params)
                    sub_id = sub["client"].get("subId")
                    if sub_id:
                        base, _note = await get_subscription_base(sub_id=str(sub_id), probe=False)
                        if base:
                            sub_link = build_sub_link(base, str(sub_id))
            except Exception as exc:
                logger.warning("Не удалось пересобрать доступ для заказа %s: %s", order["id"], exc)

            info = {
                "tariff": TARIFFS.get(order["tariff"], {}),
                "expiry_ms": int(order["expiry_ms"]),
                "already": True,
                "status": "extended",
                "link": link,
                "sub_link": sub_link,
            }
            if not info["link"]:
                logger.warning(
                    "Заказ %s выдан, но ключ не сохранился и недоступен в панели — досыл невозможен.",
                    order["id"],
                )
                return {"already_provisioned": True, "order": order}
            if await notify_payment_success(order, info):
                await payment_store.update(order["id"], notified=True)
                logger.info("Ключ по заказу %s дослан повторно.", order["id"])
                return {"order": order, "info": info}
        return {"already_provisioned": True, "order": order}

    # Реферальные бонусы считаем только по реальным (не тестовым) оплатам.
    referral_invite = None
    if REFERRAL_ENABLED and not order.get("simulated") and order.get("mode") != "test":
        referral_invite = referral_store.invite_pending(order["tg_id"], order)

    try:
        info = await activate_paid_subscription(
            order["tg_id"],
            order["tariff"],
            order_id=order["id"],
            payment_ref=charge_id or order["id"],
            extra_days=REFERRAL_INVITED_BONUS_DAYS if referral_invite else 0,
            location_key=order.get("location"),
        )
    except Exception as exc:
        logger.error("Не удалось выдать подписку по заказу %s: %s", order["id"], exc)
        try:
            await bot.send_message(
                order["tg_id"],
                "✅ Оплата получена, но выдача ключа задержалась — уже разбираюсь.\n"
                f"Напиши в поддержку и укажи номер заказа: <code>{order['id']}</code>",
                parse_mode="HTML",
            )
        except Exception:
            pass
        if ADMIN_IDS:
            try:
                await notify_admins(
                    f"⚠️ <b>Оплата есть, ключ не выдан!</b>\n"
                    f"• Заказ: <code>{order['id']}</code>\n"
                    f"• Пользователь: <code>{order['tg_id']}</code>\n"
                    f"• Ошибка: <code>{escape(str(exc)[:300])}</code>"
                )
            except Exception:
                pass
        raise

    await payment_store.update(
        order["id"],
        provisioned=True,
        expiry_ms=info["expiry_ms"],
        link=info.get("link"),          # сохраняем ключ: пригодится, если сообщение не дошло
        sub_link=info.get("sub_link"),
    )
    # Бонус пригласившему — после того, как подписка реально выдана.
    if referral_invite:
        try:
            await grant_referral_rewards(order, info, referral_invite)
        except Exception as exc:
            logger.error("Реферальные бонусы по заказу %s не начислены: %s", order["id"], exc)

    if not order.get("notified"):
        if await notify_payment_success(order, info):
            await payment_store.update(order["id"], notified=True)
        else:
            logger.warning(
                "Заказ %s выдан, но ключ не доставлен — отправлю снова при повторной "
                "доставке платежа. Пользователь может забрать ключ командой /profile.",
                order["id"],
            )
    return {"order": order, "info": info}


def new_test_order(tg_id: int, tariff_key: str, location_key: str | None = None) -> dict:
    """
    Заказ для проверки выдачи ключа без оплаты.

    Всё как у обычного заказа (тариф, срок, лимиты), но помечен тестовым: в выручку
    не попадает, уведомления об оплате его не трогают (они ищут только mode=platega).
    """
    order = new_order(tg_id, tariff_key,
                      location_key=location_key or (LOCATION_ORDER[0] if LOCATION_ORDER else None))
    order["mode"] = "test"
    order["currency"] = "TEST"
    order["simulated"] = True
    return order


def new_promo_order(tg_id: int) -> dict:
    """
    Заказ на промо-доступ: бесплатно, помечен promo и simulated.

    simulated — чтобы промо не попало в выручку и не начисляло реферальные бонусы
    (денег по нему не приходило), promo — чтобы сообщения и уведомления говорили
    о промо, а не о «проверке выдачи».
    """
    order = new_order(tg_id, PROMO_KEY, location_key=LOCATION_ORDER[0] if LOCATION_ORDER else None)
    order["mode"] = "promo"
    order["currency"] = "PROMO"
    order["simulated"] = True
    order["promo"] = True
    return order


async def grant_promo(chat_id: int, tg_id: int) -> dict:
    """
    Выдаёт промо-подписку (30 дней, 10 ГБ) бесплатно — один раз на аккаунт.

    Идёт тем же путём, что платный тариф: клиент tg-paid-<id> в 3x-ui, ключ в чат,
    срок и лимиты из тарифа. Отказы: промо выключено, уже активировано, у аккаунта
    есть действующая подписка (иначе промо переписало бы её лимиты на 10 ГБ).
    """
    if not promo_enabled():
        raise PaymentError(
            "🎉 <b>Промо-доступ сейчас закрыт.</b>\n\n"
            "Актуальные тарифы — в разделе «💰 Тарифы»."
        )
    if promo_used(tg_id):
        raise PaymentError(
            "🎉 <b>Промо-доступ уже активирован на этом аккаунте.</b>\n\n"
            "Он даётся один раз. Продлить доступ можно платным тарифом — "
            "дни промо при этом сохранятся."
        )
    existing = await get_paid_subscription(tg_id)
    if existing:
        now_ms = int(time.time() * 1000)
        still_active = existing["expiry_ms"] > now_ms and existing["enable"]
        if still_active:
            raise PaymentError(
                "🎉 <b>У тебя уже есть действующая подписка</b> — промо-доступ для новых аккаунтов.\n\n"
                "Промо не активирую, чтобы не менять условия твоего текущего тарифа."
            )
        # Подписка была, но закончилась: промо тоже не выдаём — иначе у аккаунта
        # с историей оплат сбрасывался бы лимит трафика на 10 ГБ.
        raise PaymentError(
            "🎉 <b>Промо-доступ даётся только новым пользователям.</b>\n\n"
            "У этого аккаунта уже была подписка — она, кстати, приостановлена. "
            "Продлить доступ можно в разделе «💰 Тарифы»."
        )

    order = await payment_store.create(new_promo_order(tg_id))
    logger.info("Промо-доступ: заказ %s, пользователь %s", order["id"], tg_id)
    result = await fulfill_order(order, charge_id=f"promo-{order['id']}")
    if not result.get("info"):
        logger.warning("Промо-заказ %s не потребовал новой выдачи (%s)", order["id"], list(result))
    return result


async def simulate_successful_payment(chat_id: int, tg_id: int, tariff_key: str,
                                      location_key: str | None = None) -> dict:
    """
    Прогоняет путь выдачи ключа, как после реальной оплаты, — но без денег.

    Создаёт заказ и вызывает тот же fulfill_order, что и вебхук/вебхук-обработчики
    оплаты: клиент появляется в 3x-ui, пользователю уходит настоящее сообщение
    с ключом. Отличие только в пометке «тест» и кнопке удаления.
    """
    # Проверочная выдача не должна перезаписывать метку настоящей подписки:
    # у такого клиента в комментарии стоит реальный платёж, и «тестовое» удаление
    # потом снесло бы весь ключ. Поэтому сначала убеждаемся, что подписки нет.
    existing = await get_paid_subscription(tg_id)
    if existing:
        raise PaymentError(
            f"🧪 <b>У этого аккаунта уже есть платная подписка</b> (<code>tg-paid-{tg_id}</code>).\n\n"
            "Проверять выдачу на нём нельзя: тест продлил бы настоящий ключ, а кнопка удаления "
            "убрала бы его целиком.\n\n"
            "<b>Варианты:</b>\n"
            f"1. Сначала удали подписку: <code>/revoke {tg_id}</code> — и повтори /test_pay.\n"
            "2. Проверь выдачу на другом аккаунте: там эта команда создаст ключ тем же путём."
        )

    order = await payment_store.create(new_test_order(tg_id, tariff_key, location_key))
    charge_id = f"test-{order['id']}"
    logger.info(
        "Проверка выдачи без оплаты: заказ %s, тариф %s, пользователь %s", order["id"], tariff_key, tg_id
    )
    result = await fulfill_order(order, charge_id=charge_id)
    info = result.get("info") or {}
    if not result.get("info"):
        # fulfil_order вернул already_provisioned/duplicate — ключ уже был выдан ранее
        logger.warning("Проверка выдачи: заказ %s не потребовал новой выдачи (%s)", order["id"], result.keys())

    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🗑 Удалить тестовую подписку", callback_data=f"testpay_del_{order['id']}")],
            [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
        ]
    )
    expiry = format_date(int(info.get("expiry_ms") or 0)) if info.get("expiry_ms") else "—"
    await bot.send_message(
        chat_id,
        "🧪 <b>Проверка выдачи ключа (оплата не производилась).</b>\n\n"
        f"• Заказ: <code>{order['id']}</code>\n"
        f"• Тариф: {TARIFFS[tariff_key]['name']}\n"
        f"• Клиент в панели: <code>tg-paid-{tg_id}</code>\n"
        f"• Действует до: <b>{expiry}</b>\n\n"
        "Бот прошёл ровно тот же путь, что и после настоящей оплаты: создал клиента в 3x-ui "
        "и отправил ключ. Денег при этом не потрачено, в выручку заказ не попал.\n"
        "Если у аккаунта <b>уже была</b> платная подписка — тест её продлил: кнопка ниже удалит ключ целиком.",
        reply_markup=keyboard,
        parse_mode="HTML",
    )
    return result


# Куда стучаться за внешним (исходящим) IP сервиса. Нужен, если платёжная система,
# провайдер или партнёрский сервис просит белый список адресов.
EGRESS_IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
)


async def fetch_egress_ip(timeout: float = 5.0, urls: tuple[str, ...] | None = None) -> str:
    """
    Внешний (исходящий) IP, с которого сервис ходит в интернет.

    На Railway адрес динамический: он выдаётся из общего пула и меняется при каждом
    деплое и рестарте. Свой постоянный адрес даёт только Railway Pro (Static Outbound
    IPs) или внешний прокси с фиксированным IP — если платёжка требует whitelist,
    надёжнее положиться на подпись запроса, а не на адрес.

    Пустая строка — определить не удалось (нет сети или сервисы недоступны).
    """
    for url in urls or EGRESS_IP_URLS:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(url, headers={"User-Agent": BROWSER_UA}) as resp:
                    if resp.status != 200:
                        continue
                    ip = (await resp.text()).strip()
                    if 0 < len(ip) <= 45 and " " not in ip and "<" not in ip:
                        return ip
        except Exception as exc:
            logger.debug("Не удалось определить исходящий IP через %s: %s", url, exc)
    return ""


def egress_ip_line(ip: str) -> str:
    """Строка про исходящий IP для диагностики: что это и зачем нужен."""
    if not ip:
        return "• <b>Исходящий IP:</b> ⚠️ определить не удалось (нет сети или сервисы недоступны)"
    return (
        f"• <b>Исходящий IP:</b> <code>{escape(ip)}</code> "
        "<i>(с этого адреса бот обращается к платёжным системам и внешним API; "
        "на Railway он меняется при каждом деплое)</i>"
    )


async def platega_self_check() -> str:
    """
    Проверяет настройки Platega без денег: ключи, API, вебхук и адрес сервиса.

    Ничего не создаёт и не оплачивает: запрашивает балансы магазина (GET /balance/all) —
    это подтверждает, что Merchant ID и API-ключ приняты, — и, если известен публичный
    адрес, стучится в свой /healthz. Так видно, что связка настроена, ещё до первой
    реальной оплаты.
    """
    lines = ["🔍 <b>Проверка Platega</b>", ""]

    lines.append(f"• Merchant ID: <code>{escape(PLATEGA_MERCHANT_ID or '—')}</code>")
    lines.append(f"• API-ключ (X-Secret): {'задан ✅' if PLATEGA_SECRET else 'НЕ задан ❌'}")
    lines.append(f"• API: <code>{escape(PLATEGA_API_URL)}</code>")
    lines.append(f"• Валюта: <b>{escape(PLATEGA_CURRENCY)}</b>")
    lines.append(
        "• Способ оплаты: "
        + (f"<b>{escape(PLATEGA_METHODS.get(PLATEGA_METHOD, str(PLATEGA_METHOD)))}</b> "
           f"(<code>PLATEGA_METHOD={PLATEGA_METHOD}</code>)"
           if PLATEGA_METHOD
           else "плательщик выбирает на странице Platega")
    )
    egress_ip = await fetch_egress_ip()
    lines.append(
        "• Исходящий IP бота: "
        + (f"<code>{escape(egress_ip)}</code>" if egress_ip else "⚠️ определить не удалось")
        + " — если Platega просит белый список адресов, укажи этот; "
        "на Railway он меняется при каждом деплое"
    )

    if not platega_configured():
        lines += [
            "",
            "❌ <b>Магазин настроен не полностью.</b>",
            "",
            "Возьми в кабинете Platega → <b>Настройки → Интеграция → API</b> два значения: "
            "<b>Merchant ID</b> (UUID) и <b>API-ключ</b>, затем добавь их в Railway → Variables:",
            "<code>PLATEGA_MERCHANT_ID</code> и <code>PLATEGA_SECRET</code>, "
            "и поставь <code>PAYMENTS_MODE=platega</code>.",
        ]
        return "\n".join(lines)

    # 1. Ключи: запрос балансов магазина. Денег не двигает, но проверяет авторизацию.
    try:
        balance = await platega_balance()
        lines.append("")
        lines.append(f"• Связь с API: ✅ ключи приняты, ответ <code>{escape(balance)}</code>")
    except Exception as exc:
        lines.append("")
        lines.append(
            "• Связь с API: ❌ "
            f"<code>{escape(_snip(str(exc), 160))}</code>\n"
            "  Проверь <code>PLATEGA_MERCHANT_ID</code> и <code>PLATEGA_SECRET</code> "
            "(кабинет Platega → Настройки → Интеграция → API) и доступность "
            f"<code>{escape(PLATEGA_API_URL)}</code> с сервера бота."
        )

    # 2. Вебхук: этот адрес должен быть вписан в кабинете Platega (Callback URLs) и отвечать.
    notify_url = f"{PUBLIC_BASE_URL}{PLATEGA_WEBHOOK_PATH}" if PUBLIC_BASE_URL else ""
    if not notify_url:
        lines += [
            "",
            "⚠️ <b>PUBLIC_BASE_URL не задан</b> — Platega некуда присылать callback об оплате.",
            "Railway → сервис бота → Settings → Networking → <b>Generate Domain</b>, "
            "адрес подхватится сам (можно задать вручную переменной <code>PUBLIC_BASE_URL</code>).",
        ]
    else:
        lines.append(f"• Callback URL (вписать в кабинет Platega): <code>{escape(notify_url)}</code>")
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{PUBLIC_BASE_URL}/healthz") as resp:
                    payload = await resp.json()
            ok = bool(payload.get("ok")) and str(payload.get("mode")) == PAYMENTS_MODE
            lines.append(
                "• Самопроверка сервера: "
                + (f"✅ отвечает, режим <code>{escape(str(payload.get('mode')))}</code>" if ok
                   else f"⚠️ ответ неожиданный: <code>{escape(_snip(json.dumps(payload, ensure_ascii=False), 120))}</code>")
            )
        except Exception as exc:
            lines.append(f"• Самопроверка сервера: ⚠️ {escape(_snip(str(exc), 120))}")

    # 3. Что вписать в кабинет Platega.
    back_url = await platega_back_url()
    lines += [
        "",
        "<b>Поля в кабинете Platega:</b>",
        f"• Callback URL (Настройки → Callback URLs): <code>{escape(notify_url or 'нужен PUBLIC_BASE_URL')}</code>",
        f"• Return URL (успех): <code>{escape(PLATEGA_RETURN_URL or back_url)}</code>",
        f"• Failed URL (неудача): <code>{escape(PLATEGA_FAILED_URL or back_url)}</code>",
        "",
        "<b>Требования Platega к адресу callback:</b>",
        "1. Только <b>HTTPS</b> с доверенным сертификатом (самоподписанные и приватные "
        "адреса не принимаются) — домен Railway подходит, домен нужен публичный.",
        "2. Бот отвечает на callback <code>200</code> — если ответа нет в течение 60 секунд, "
        "Platega отменит запрос и повторит его до 3 раз с интервалом 5 минут.",
        "3. Заголовки <code>X-MerchantId</code> и <code>X-Secret</code> в callback должны "
        "совпадать с переменными бота — иначе бот ответит <code>401</code> и ключ не выдаст.",
        "",
        (
            "Дальше: /test_pay — выдача ключа тем же путём, что и после настоящей оплаты."
            if test_pay_enabled()
            else "Дальше: первая настоящая оплата самого дешёвого тарифа. После неё заказ в "
                 "<code>/payments</code> станет «✅ оплачен», а ключ придёт в чат. "
                 "Хочешь прогонять выдачу без денег и в бою — <code>PAYMENTS_ALLOW_TEST_PAY=1</code>."
        ),
    ]
    return "\n".join(lines)


async def start_checkout(chat_id: int, tg_id: int, tariff_key: str,
                         location_key: str | None = None) -> None:
    """
    Начинает оплату выбранного тарифа в текущем режиме PAYMENTS_MODE.

    location_key — выбранный сервер для тарифов с одним туннелем (Стокгольм/Варшава);
    тарифы на несколько туннелей получают все локации сразу.
    stars/provider — нативный счёт Telegram; platega и yookassa — ссылка
    на страницу оплаты.
    """
    if terms_gate_needed(tg_id):
        raise PaymentError(
            "📄 Сначала подтверди пользовательское соглашение.\n\n"
            "Открой /start и нажми кнопку «✅ Согласен — продолжить» — после этого оплата "
            "и выдача ключа станут доступны."
        )

    tariff = TARIFFS[tariff_key]
    if tariff["price"] <= 0:
        if tariff_key == PROMO_KEY:
            raise PaymentError(
                "🎉 Промо-доступ бесплатный — он активируется кнопкой в разделе «💰 Тарифы».\n\n"
                "Оплата для него не нужна."
            )
        if trial_available_for(tg_id):
            raise PaymentError("Этот тариф бесплатный — просто получи тестовый ключ командой /test_vpn.")
        raise PaymentError("Этот тариф бесплатный и сейчас недоступен. Выбери платный тариф — ключ придёт сразу после оплаты.")

    if not payments_enabled():
        raise PaymentError(
            "💳 <b>Приём оплаты пока не настроен.</b>\n\n"
            "Администратору: задай <b>PAYMENTS_MODE</b> (platega / stars / provider / yookassa) "
            "в Railway → Variables. Пошаговая инструкция — в README и команде /payments."
        )

    if PAYMENTS_MODE in ("stars", "provider"):
        order = await payment_store.create(new_order(tg_id, tariff_key, location_key))
        provider_token = PAYMENT_PROVIDER_TOKEN if PAYMENTS_MODE == "provider" else None
        if PAYMENTS_MODE == "provider" and not provider_token:
            raise PaymentError(
                "⚠️ Оплата картой не настроена: не задан <b>PAYMENT_PROVIDER_TOKEN</b>.\n\n"
                "Получи токен в @BotFather → Bot Settings → Payments и добавь его в Railway."
            )
        price = LabeledPrice(
            label=f"{tariff['name']}"[:32],
            amount=order_amount(order),
        )

        # Данные чека 54-ФЗ — только если включено (фискализация подключена)
        provider_data = telegram_receipt_provider_data(order) if PAYMENTS_MODE == "provider" else None
        if PAYMENTS_MODE == "provider" and PROVIDER_TEST_MODE:
            # Тестовый токен: подсказываем тестовую карту, чтобы владелец проверил оплату
            try:
                await bot.send_message(
                    chat_id,
                    "🧪 <b>Тестовый платёжный режим.</b>\n"
                    "Для оплаты используй тестовую карту <code>5555 5555 5555 4477</code> "
                    "(срок — любой в будущем, CVC — любые 3 цифры). "
                    "Реальные деньги не спишутся.",
                    parse_mode="HTML",
                )
            except Exception as exc:
                logger.warning("Не удалось отправить подсказку тестового режима: %s", exc)

        await bot.send_invoice(
            chat_id=chat_id,
            title=tariff["name"][:32],
            description=(
                f"VPN доступ: {tariff['traffic']}, {tariff['ips']} устройств, "
                f"{days_label(tariff['days'])}. Сервер: {location_display(tariff, location_key)}. "
                "Доступ придёт сразу после оплаты."
            )[:255],
            payload=order["id"],
            currency=order["currency"],
            prices=[price],
            provider_token=provider_token,
            provider_data=provider_data,
            need_email=bool(provider_data),
            send_email_to_provider=bool(provider_data),
        )
        logger.info(
            "Счёт выставлен: заказ %s (%s) для %s%s",
            order["id"], order["currency"], tg_id,
            " с чеком 54-ФЗ" if provider_data else "",
        )
        return

    # Platega: создаём транзакцию и отдаём ссылку на оплату (карта, СБП, кошельки)
    if PAYMENTS_MODE == "platega":
        order = await payment_store.create(new_order(tg_id, tariff_key, location_key))
        try:
            data = await platega_create_payment(order)
        except Exception:
            # Платёж не создан — заказ в журнале не нужен, помечаем неудачным.
            await payment_store.update(order["id"], status="failed")
            raise
        transaction_id = str(data.get("transactionId") or data.get("id") or "")
        pay_url = platega_payment_url(data)
        await payment_store.update(order["id"], payment_id=transaction_id, payment_url=pay_url)

        expires = str(data.get("expiresIn") or "")
        keyboard = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text=f"💳 Оплатить {tariff['price']} ₽", url=pay_url)],
                [InlineKeyboardButton(text="🔄 Проверить оплату", callback_data=f"checkpay_{order['id']}")],
                [InlineKeyboardButton(text="❌ Отменить заказ", callback_data=f"cancelorder_{order['id']}")],
                [InlineKeyboardButton(text="◀️ К тарифам", callback_data="tariffs")],
            ]
        )
        await bot.send_message(
            chat_id,
            f"💳 <b>Оплата тарифа {tariff['name']}</b>\n\n"
            f"• Сумма: <b>{tariff['price']} ₽</b>\n"
            f"{tariff_terms_line(tariff)}\n"
            f"• Сервер: <b>{location_display(tariff, location_key)}</b>\n\n"
            "Нажми «Оплатить» — откроется платёжная страница Platega: карта, СБП, "
            "электронные кошельки и криптовалюта. Ключ придёт автоматически после "
            "подтверждения оплаты.\n"
            + (f"<i>Ссылка действует {escape(expires)}</i>\n" if expires else "")
            + f"<i>Номер заказа: <code>{order['id']}</code></i>",
            reply_markup=keyboard,
            parse_mode="HTML",
        )
        logger.info("Ссылка Platega создана: заказ %s на %s ₽ (транзакция %s)",
                    order["id"], tariff["price"], transaction_id or "—")
        return

    # ЮKassa: создаём платёж и отдаём ссылку на оплату
    order = await payment_store.create(new_order(tg_id, tariff_key, location_key))
    client = make_yookassa_client()
    payment = await client.create_payment(order)
    payment_id = payment.get("id")
    confirmation_url = (payment.get("confirmation") or {}).get("confirmation_url")
    if not confirmation_url:
        raise PaymentError(
            "❌ ЮKassa не вернула ссылку на оплату. "
            f"Ответ: <code>{escape(_snip(json.dumps(payment, ensure_ascii=False), 200))}</code>"
        )

    await payment_store.update(order["id"], payment_id=payment_id, payment_url=confirmation_url)
    test_note = "\n🧪 <i>Тестовый магазин ЮKassa — оплата тестовой картой.</i>" if YOOKASSA_TEST else ""
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=f"💳 Оплатить {tariff['price']} ₽", url=confirmation_url)],
            [InlineKeyboardButton(text="🔄 Проверить оплату", callback_data=f"checkpay_{order['id']}")],
            [InlineKeyboardButton(text="❌ Отменить заказ", callback_data=f"cancelorder_{order['id']}")],
            [InlineKeyboardButton(text="◀️ К тарифам", callback_data="tariffs")],
        ]
    )
    await bot.send_message(
        chat_id,
        f"💳 <b>Оплата тарифа {tariff['name']}</b>\n\n"
        f"• Сумма: <b>{tariff['price']} ₽</b>\n"
        f"{tariff_terms_line(tariff)}\n"
        f"• Сервер: <b>{location_display(tariff, location_key)}</b>\n\n"
        "Нажми «Оплатить» — откроется страница ЮKassa (карта, СБП и другие способы). "
        "Ключ придёт автоматически после успешной оплаты.\n"
        f"<i>Номер заказа: <code>{order['id']}</code></i>{test_note}",
        reply_markup=keyboard,
        parse_mode="HTML",
    )
    logger.info("Платёж ЮKassa создан: заказ %s, payment %s", order["id"], payment_id)



def make_webhook_app() -> web.Application:
    """HTTP-сервер для уведомлений об оплате (ЮKassa, Platega)."""

    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "mode": PAYMENTS_MODE})

    async def yookassa_webhook(request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "bad json"}, status=400)

        event = str(data.get("event") or "")
        obj = data.get("object") or {}
        payment_id = str(obj.get("id") or "")
        logger.info("Вебхук ЮKassa: event=%s payment=%s", event, payment_id)

        if event != "payment.succeeded":
            return web.json_response({"ok": True, "ignored": event})

        if not payment_id:
            return web.json_response({"ok": False, "error": "no payment id"}, status=400)

        # Телу уведомления не верим: переспрашиваем платёж в API ЮKassa
        try:
            client = make_yookassa_client()
            payment = await client.get_payment(payment_id)
        except PaymentError as exc:
            logger.error("Не удалось проверить платёж %s: %s", payment_id, exc)
            return web.json_response({"ok": False, "error": "verify failed"}, status=503)

        if payment.get("status") != "succeeded" or not payment.get("paid"):
            logger.warning("Платёж %s ещё не succeeded (%s) — пропускаю.", payment_id, payment.get("status"))
            return web.json_response({"ok": True, "skipped": payment.get("status")})

        metadata = payment.get("metadata") or {}
        order_id = str(metadata.get("order_id") or "")
        order = await payment_store.get(order_id) if order_id else None
        if order is None:
            logger.error("Вебхук по неизвестному заказу %r (payment %s)", order_id, payment_id)
            return web.json_response({"ok": True, "unknown_order": order_id})

        paid_value = str((payment.get("amount") or {}).get("value") or "")
        if paid_value and order["currency"] == "RUB":
            try:
                paid_kop = round(float(paid_value) * 100)
            except ValueError:
                paid_kop = -1
            if paid_kop != order_amount(order):
                logger.error(
                    "Сумма платежа %s не совпадает с заказом %s: %.2f vs %s ₽",
                    payment_id, order["id"], paid_kop / 100, order["amount_rub"],
                )
                return web.json_response({"ok": True, "amount_mismatch": True})

        try:
            await fulfill_order(order, charge_id=payment_id)
        except Exception as exc:
            logger.error("Выдача по заказу %s не удалась: %s — ЮKassa повторит вебхук.", order["id"], exc)
            return web.json_response({"ok": False, "error": "fulfill failed"}, status=503)

        return web.json_response({"ok": True})

    async def platega_webhook(request: web.Request) -> web.Response:
        """
        Callback Platega об изменении статуса транзакции (настраивается в кабинете).

        Platega присылает POST с заголовками X-MerchantId и X-Secret (проверяем их
        постоянным сравнением) и телом JSON: id, amount, currency, status, payload.
        Ответ 200 — «принято, больше не повторяй»; 4xx/5xx — Platega повторит запрос
        (до 3 раз с интервалом 5 минут), поэтому при сбое выдачи ключа отвечаем 5xx.
        """
        if request.method != "POST":
            # Платёжные системы иногда «прощупывают» адрес GET-запросом: отвечаем, что живы.
            return web.Response(text="platega webhook: use POST", status=405, content_type="text/plain")

        try:
            raw = await request.text()
            payload_body = json.loads(raw or "{}")
        except Exception:
            logger.warning("Вебхук Platega: тело не разобралось как JSON: %s", _snip(raw, 200))
            return web.Response(text="bad json", status=400, content_type="text/plain")
        if not isinstance(payload_body, dict):
            return web.Response(text="bad json", status=400, content_type="text/plain")

        merchant_id = request.headers.get("X-MerchantId")
        secret = request.headers.get("X-Secret")
        logger.info(
            "Вебхук Platega: транзакция=%s статус=%s заказ=%s сумма=%s",
            payload_body.get("id"), payload_body.get("status"),
            payload_body.get("payload"), payload_body.get("amount"),
        )
        code, note = await process_platega_callback(payload_body, merchant_id, secret)
        if 200 <= code < 300:
            logger.info("Вебхук Platega: %s", note)
        else:
            logger.warning("Вебхук Platega: отказ (%s) — %s", code, note)
        # 200 с пустым телом — «принято»; иначе Platega повторит запрос.
        return web.Response(status=code, content_type="text/plain", text="ok" if code == 200 else note)

    app = web.Application()
    app.router.add_get("/healthz", healthz)
    app.router.add_post("/yookassa/webhook", yookassa_webhook)
    app.router.add_post("/payments/yookassa", yookassa_webhook)   # алиас для удобства
    app.router.add_post(PLATEGA_WEBHOOK_PATH, platega_webhook)
    app.router.add_post("/payments/platega", platega_webhook)   # алиас для удобства
    app.router.add_get("/", healthz)
    return app


async def run_webhook_server() -> web.AppRunner | None:
    """
    Поднимает HTTP-сервер бота: /healthz всегда, /yookassa/webhook и
    /platega/webhook — для приёма уведомлений об оплате.

    Сервер слушает PORT и нужен Railway, чтобы контейнер считался живым,
    а в режимах yookassa и platega — ещё и для подтверждения оплаты.
    """
    runner = web.AppRunner(make_webhook_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", WEB_PORT)
    await site.start()
    logger.info("Веб-сервер бота запущен на 0.0.0.0:%s (health: /healthz)", WEB_PORT)

    if PAYMENTS_MODE == "platega":
        if PUBLIC_BASE_URL:
            logger.info(
                "Вебхук Platega: %s — впиши этот адрес в кабинет Platega → "
                "Настройки → Callback URLs.",
                f"{PUBLIC_BASE_URL}{PLATEGA_WEBHOOK_PATH}",
            )
        else:
            logger.warning(
                "PUBLIC_BASE_URL не задан — callback Platega некуда присылать. "
                "Railway → Settings → Networking → Generate Domain."
            )

    if PAYMENTS_MODE != "yookassa":
        logger.info("Вебхук ЮKassa не нужен: режим оплаты %s.", PAYMENTS_MODE)
        return runner

    if PUBLIC_BASE_URL:
        webhook_url = f"{PUBLIC_BASE_URL}/yookassa/webhook"
        try:
            if await make_yookassa_client().ensure_webhook(webhook_url):
                logger.info("Вебхук ЮKassa готов: %s", webhook_url)
            else:
                logger.info(
                    "Вебхук ЮKassa: добавь %s в личном кабинете (Интеграция → HTTP-уведомления) "
                    "или задай YOOKASSA_OAUTH_TOKEN для автонастройки.",
                    webhook_url,
                )
        except Exception as exc:
            logger.warning("Авторегистрация вебхука не удалась: %s", exc)
    else:
        logger.warning(
            "PUBLIC_BASE_URL не задан — вебхук ЮKassa не настроен. "
            "На Railway он подставляется автоматически из RAILWAY_PUBLIC_DOMAIN."
        )
    return runner

async def send_error_message(message: Message, error: Exception):
    """Понятное человеческое описание ошибок."""
    if isinstance(error, (XUIError, PaymentError)):
        await message.answer(str(error), parse_mode="HTML")
    elif isinstance(error, asyncio.TimeoutError):
        await message.answer(
            "⏳ <b>Панель 3x-ui не ответила вовремя (таймаут).</b>\n\n"
            "Проверь, что сервер не перегружен и порт панели открыт для внешних запросов.",
            parse_mode="HTML",
        )
    elif isinstance(error, aiohttp.ClientConnectorError):
        await message.answer(
            f"❌ <b>Не удалось соединиться с 3x-ui:</b>\n<code>{escape(str(error))}</code>\n\n"
            "Проверь правильность XUI_URL и сетевую доступность сервера.",
            parse_mode="HTML",
        )
    else:
        logger.exception("Непредвиденная ошибка: %s", error)
        await message.answer(
            f"❌ <b>Ошибка при работе с 3x-ui:</b>\n"
            f"<code>{escape(f'{type(error).__name__}: {error}')}</code>\n\n"
            "Проверь логи сервиса в Railway (Deployments -> View Logs).",
            parse_mode="HTML",
        )


# =========================
# КЛАВИАТУРЫ
# =========================

"""
Тарифные планы.

Каталог строится из трёх частей:

  • тип подписки (TARIFF_KINDS) — «по времени» (с ограничением по сроку) и «по трафику»
    (срок не истекает, ограничен только трафик);
  • уровень (TARIFF_LEVELS) — Новичок, Нетраннер, Кибер-самурай, Призрак: сколько
    устройств и сколько туннелей (локаций) доступно;
  • сетка цен и лимитов (TARIFF_GRID) — цена, трафик и срок для каждой пары
    «тип + уровень».

Клиент выбирает это в три шага: тип → уровень → сервер (сервер спрашиваем только у
тарифов с одним туннелем, остальным доступны все локации).

Для каждого платного тарифа:
  • price      — цена в рублях (0 = бесплатный тестовый/промо-доступ);
  • days       — срок подписки в днях (0 = без ограничения по времени);
  • traffic_gb — лимит трафика в ГиБ (0 = безлимит);
  • ip_limit   — сколько устройств (IP) разрешено;
  • tunnels    — сколько локаций (серверов) входит в тариф;
  • stars      — цена в звёздах Telegram (переопределяется переменной STARS_<ТАРИФ>).
"""

# Типы подписки: по времени (срок истекает) и по трафику (срок не истекает).
TARIFF_KINDS = {
    "traffic": {
        "title": "🔁 По трафику",
        "short": "по трафику",
        "hint": "Без ограничения по времени: подписка не истекает, пока не израсходован трафик.",
    },
    "time": {
        "title": "⏳ По времени",
        "short": "по времени",
        "hint": "С ограничением по времени: 15 или 30 дней, трафик — по уровню тарифа.",
    },
}
TARIFF_KIND_ORDER = ("time", "traffic")

# Уровни: название, лимит устройств и число туннелей (локаций).
TARIFF_LEVELS = {
    1: {"name": "Новичок", "devices": 1, "tunnels": 1},
    2: {"name": "Нетраннер", "devices": 3, "tunnels": 2},
    3: {"name": "Кибер-самурай", "devices": 5, "tunnels": 4},
    4: {"name": "Призрак", "devices": 6, "tunnels": 6},
}
TARIFF_LEVEL_ORDER = (1, 2, 3, 4)

# Сетка: тип → уровень → цена, трафик (ГБ), срок (дней; 0 = без ограничения).
TARIFF_GRID = {
    "traffic": {
        1: {"price": 70, "traffic_gb": 10, "days": 0},
        2: {"price": 150, "traffic_gb": 50, "days": 0},
        3: {"price": 300, "traffic_gb": 100, "days": 0},
        4: {"price": 500, "traffic_gb": 200, "days": 0},
    },
    "time": {
        1: {"price": 70, "traffic_gb": 15, "days": 15},
        2: {"price": 130, "traffic_gb": 50, "days": 15},
        3: {"price": 250, "traffic_gb": 100, "days": 30},
        4: {"price": 450, "traffic_gb": 0, "days": 30},
    },
}


def traffic_label(traffic_gb: int) -> str:
    """«10 ГБ» или «Безлимит»."""
    return "Безлимит" if int(traffic_gb) <= 0 else f"{int(traffic_gb)} ГБ"


def days_label(days: int) -> str:
    """«15 дней» или «без ограничения по времени»."""
    if int(days) <= 0:
        return "без ограничения по времени"
    return f"{int(days)} {days_word(int(days))}"


def tariff_key(kind: str, level: int) -> str:
    """Ключ тарифа в сетке: time_2, traffic_4 и т.д."""
    return f"{kind}_{int(level)}"


def _build_plan(kind: str, level: int) -> dict:
    """Собирает описание одного платного тарифа из сетки."""
    meta = TARIFF_LEVELS[level]
    grid = TARIFF_GRID[kind][level]
    tunnels = meta["tunnels"]
    return {
        "name": f"{meta['name']} · {TARIFF_KINDS[kind]['short']}",
        "price": grid["price"],
        "days": grid["days"],
        "traffic": traffic_label(grid["traffic_gb"]),
        "traffic_gb": grid["traffic_gb"],
        "ips": meta["devices"],
        "ip_limit": meta["devices"],
        "tunnels": tunnels,
        "kind": kind,
        "level": level,
        "locations": ("Все локации" if tunnels > 1
                      else "1 локация на выбор"),
    }


TARIFFS = {
    "trial": {
        "name": "🎁 Тестовый период (24 ч)",
        "price": 0,
        "days": 1,
        "traffic": "1 ГБ",
        "traffic_gb": 1,
        "ips": 1,
        "ip_limit": 1,
        "tunnels": 1,
        "kind": "",
        "level": 0,
        "locations": "Стокгольм",
    },
    "promo": {
        "name": "🎉 Промо-доступ (15 дней)",
        "price": 0,
        "days": 15,
        "traffic": "10 ГБ",
        "traffic_gb": 10,
        "ips": 1,
        "ip_limit": 1,
        "tunnels": 1,
        "kind": "",
        "level": 0,
        "locations": "Стокгольм",
    },
}
for _kind in TARIFF_KIND_ORDER:
    for _level in TARIFF_LEVEL_ORDER:
        TARIFFS[tariff_key(_kind, _level)] = _build_plan(_kind, _level)


def paid_tariff_keys() -> list[str]:
    """Ключи платных тарифов в порядке каталога (тип → уровень)."""
    return [tariff_key(kind, level)
            for kind in TARIFF_KIND_ORDER for level in TARIFF_LEVEL_ORDER]


def tariff_by_key(key: str) -> dict | None:
    """Тариф по ключу: поддерживает и «time_2», и короткую запись «time 2»."""
    key = (key or "").strip().lower().replace(" ", "_").replace("-", "_")
    return TARIFFS.get(key)


def tariff_title(tariff: dict) -> str:
    """Название тарифа для сообщений: «Новичок · по времени»."""
    return tariff.get("name", "")


def tariff_specs_line(tariff: dict) -> str:
    """Одна строка характеристик: «15 ГБ · 15 дней · 1 устройство · Стокгольм»."""
    parts = [
        tariff.get("traffic", ""),
        days_label(tariff.get("days", 0)),
        f"{tariff['ips']} {devices_word(tariff['ips'])}",
    ]
    return " · ".join(part for part in parts if part)


def tariff_terms_line(tariff: dict) -> str:
    """Строка для счёта и подтверждения оплаты: срок, трафик, устройства."""
    return (
        f"⏳ <b>Срок:</b> {days_label(tariff.get('days', 0))}\n"
        f"📊 <b>Трафик:</b> {tariff.get('traffic', '')}\n"
        f"📱 <b>Устройств:</b> {tariff.get('ips', 0)}"
    )


def _stars_price(tariff_key_value: str, tariff: dict) -> int:
    """Цена тарифа в звёздах: переменная STARS_<ТАРИФ> либо пересчёт из рублей."""
    override = (os.getenv(f"STARS_{tariff_key_value.upper()}") or "").strip()
    if override.isdigit() and int(override) > 0:
        return int(override)
    if tariff["price"] <= 0:
        return 0
    return max(1, round(tariff["price"] / STARS_RUB_RATE))


for _key, _tariff in TARIFFS.items():
    if _tariff["price"] > 0:
        _tariff["stars"] = _stars_price(_key, _tariff)




# =========================
# ИНСТРУКЦИЯ ПО ПОДКЛЮЧЕНИЮ (пошагово, со ссылками на приложения)
# =========================

# Ссылки только на официальные источники: сайты разработчиков, App Store, Google Play, GitHub.
APP_LINKS = {
    "happ": "https://happ.su/",
    "happ_desktop": "https://github.com/Happ-proxy/happ-desktop/releases/latest",
    "v2rayng": "https://github.com/2dust/v2rayNG/releases",
    "v2rayng_play": "https://play.google.com/store/apps/details?id=com.v2ray.ang",
    "v2rayn": "https://github.com/2dust/v2rayN/releases",
    "hiddify": "https://hiddify.com/#app",
    "hiddify_gh": "https://github.com/hiddify/hiddify-app/releases",
    "streisand": "https://apps.apple.com/ru/app/streisand/id6450534064",
    "incy": "https://apps.apple.com/ru/app/incy/id6756943388",
    "foxray": "https://apps.apple.com/ru/app/foxray/id6448898396",
    "v2box": "https://apps.apple.com/ru/app/v2box-v2ray-client/id6446814690",
    "v2raytun": "https://apps.apple.com/ru/app/v2raytun/id6476628951",
    "shadowrocket": "https://apps.apple.com/ru/app/shadowrocket/id932747118",
    "check_ip": "https://2ip.ru/",
    "whoer": "https://whoer.net/ru",
}

PLATFORM_TITLES = {
    "ios": "📱 iPhone / iPad",
    "android": "🤖 Android",
    "windows": "💻 Windows",
    "macos": "🍎 macOS",
    "tv": "📺 Android TV / приставка",
}


def _a(key: str, text: str) -> str:
    """Ссылка на приложение для вставки в текст инструкции."""
    return f'<a href="{APP_LINKS[key]}">{text}</a>'


def install_menu_kb() -> InlineKeyboardMarkup:
    """Меню выбора устройства — начало пошаговой инструкции."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=PLATFORM_TITLES["ios"], callback_data="help_ios"),
                InlineKeyboardButton(text=PLATFORM_TITLES["android"], callback_data="help_android"),
            ],
            [
                InlineKeyboardButton(text=PLATFORM_TITLES["windows"], callback_data="help_windows"),
                InlineKeyboardButton(text=PLATFORM_TITLES["macos"], callback_data="help_macos"),
            ],
            [InlineKeyboardButton(text=PLATFORM_TITLES["tv"], callback_data="help_tv")],
            [
                InlineKeyboardButton(text="✅ Проверить подключение", callback_data="help_check"),
                InlineKeyboardButton(text="🆘 Не работает", callback_data="help_trouble"),
            ],
            [
                InlineKeyboardButton(text="🔗 Показать мою подписку", callback_data="profile"),
                InlineKeyboardButton(text="◀️ Меню", callback_data="main_menu"),
            ],
        ]
    )


def install_step_kb(platform: str) -> InlineKeyboardMarkup:
    """Кнопки под инструкцией конкретного устройства."""
    rows = [
        [InlineKeyboardButton(text="✅ Проверить подключение", callback_data="help_check")],
        [InlineKeyboardButton(text="🆘 Не работает", callback_data="help_trouble")],
        [InlineKeyboardButton(text="🔗 Моя подписка", callback_data="profile")],
        [InlineKeyboardButton(text="◀️ Другое устройство", callback_data="help_menu")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


INSTALL_INTRO = (
    "📲 <b>Подключение VPN: пошагово</b>\n\n"
    "Выбери своё устройство — покажу, что скачать и куда вставить ссылку-подписку. "
    "Займёт 2–3 минуты.\n\n"
    "🔗 <i>Ссылка уже у тебя: она в сообщении после оплаты и в разделе "
    "«👤 Мой профиль» — нажми на неё, чтобы скопировать.</i>"
)


def install_text(platform: str) -> str:
    """Пошаговая инструкция для устройства: ссылки, шаги и проверка результата."""
    if platform == "ios":
        return (
            "📱 <b>iPhone / iPad — пошагово</b>\n\n"
            "<b>Шаг 1. Установи приложение</b> (подойдёт любое):\n"
            f"• {_a('streisand', 'Streisand')} — самый простой вариант, бесплатно;\n"
            f"• {_a('incy', 'INCY')} — современный клиент, есть в российском App Store;\n"
            f"• {_a('v2box', 'V2Box')} — поддерживает VLESS и ссылки подписки;\n"
            f"• {_a('happ', 'Happ')} — сайт разработчика (в российском App Store его нет, "
            "понадобится зарубежный Apple ID).\n\n"
            "<b>Шаг 2. Скопируй ссылку-подписку</b>\n"
            "Открой «👤 Мой профиль» → нажми на ссылку <code>…/sub/…</code>, она скопируется.\n\n"
            "<b>Шаг 3. Добавь подписку в приложение</b>\n"
            "Открой приложение → «+» (плюс) → «Добавить подписку» / «Add subscription» → "
            "вставь ссылку.\n"
            "<i>Streisand и Happ: «Добавить» → «Импорт из ссылки». Если приложение не умеет "
            "подписки — вставь вместо неё ключ из «Мой профиль» через «Импорт из буфера».</i>\n\n"
            "<b>Шаг 4. Подключись</b>\n"
            "Выбери профиль → нажми кнопку подключения. iOS попросит разрешение "
            "«Добавить конфигурацию VPN» → <b>Разрешить</b> и подтверди Face ID / паролем.\n\n"
            "<b>Шаг 5. Проверь</b>\n"
            f"Открой {_a('check_ip', '2ip.ru')} — страна должна быть Нидерланды или Германия, "
            "а не твоя домашняя. Если так — всё работает. ✅"
        )

    if platform == "android":
        return (
            "🤖 <b>Android — пошагово</b>\n\n"
            "<b>Шаг 1. Установи приложение</b> (подойдёт любое):\n"
            f"• {_a('v2rayng_play', 'v2rayNG (Google Play)')} — самый популярный;\n"
            f"• {_a('v2rayng', 'v2rayNG (APK с GitHub)')} — если Play недоступен;\n"
            f"• {_a('happ', 'Happ')} — современный, простой интерфейс.\n\n"
            "<b>Шаг 2. Скопируй ссылку-подписку</b>\n"
            "«👤 Мой профиль» → нажми на ссылку <code>…/sub/…</code> — она попадёт в буфер.\n\n"
            "<b>Шаг 3. Добавь подписку</b>\n"
            "v2rayNG: три точки справа сверху → «Группы» → «+» → «Добавить подписку» → вставь "
            "ссылку.\nHapp: «Добавить» → «Импорт из ссылки».\n\n"
            "<b>Шаг 4. Подключись</b>\n"
            "Нажми круг со значком «V» внизу → Android спросит про VPN → <b>Разрешить/OK</b>.\n\n"
            "<b>Шаг 5. Проверь</b>\n"
            f"Открой {_a('check_ip', '2ip.ru')} — страна должна быть Нидерланды или Германия.\n\n"
            "<i>Чтобы VPN не отключался в фоне: Настройки → Батарея → «Без ограничений» "
            "для приложения, а в его настройках включи «Always-on VPN».</i>"
        )

    if platform == "windows":
        return (
            "💻 <b>Windows — пошагово</b>\n\n"
            "<b>Шаг 1. Установи приложение</b> (любое из списка):\n"
            f"• {_a('happ', 'Happ for Windows')} — скачай установщик с официального сайта "
            f"(или {_a('happ_desktop', 'выпуски на GitHub')});\n"
            f"• {_a('v2rayn', 'v2rayN')} — классика, открытый код (GitHub Releases, файл "
            "<code>v2rayN-windows-64.zip</code>);\n"
            f"• {_a('hiddify', 'Hiddify')} — простой интерфейс.\n\n"
            "<b>Шаг 2. Скопируй ссылку-подписку</b>\n"
            "В боте: «👤 Мой профиль» → нажми на ссылку <code>…/sub/…</code> "
            "(или выдели мышкой и Ctrl+C).\n\n"
            "<b>Шаг 3. Добавь подписку</b>\n"
            "Happ: «Добавить» → «Импорт из ссылки».\n"
            "v2rayN: меню «Подписка» → «Добавить подписку» → вставь ссылку → "
            "«Обновить подписки без прокси».\n\n"
            "<b>Шаг 4. Подключись</b>\n"
            "v2rayN: правый клик по серверу → «Установить как активный» → включи "
            "«Режим системного прокси» (или TUN) в меню «Настройки»/«Режим».\n"
            "Happ: нажми большую кнопку подключения.\n\n"
            "<b>Шаг 5. Проверь</b>\n"
            f"Открой в браузере {_a('check_ip', '2ip.ru')} — страна должна быть Нидерланды/Германия.\n\n"
            "<i>Если сайты не открываются: проверь, что включён «Системный прокси» (v2rayN) "
            "или режим TUN, и что антивирус/брандмауэр не блокирует приложение.</i>"
        )

    if platform == "macos":
        return (
            "🍎 <b>macOS — пошагово</b>\n\n"
            "<b>Шаг 1. Установи приложение</b>:\n"
            f"• {_a('happ', 'Happ для macOS')} — с официального сайта;\n"
            f"• {_a('v2box', 'V2Box (App Store)')};\n"
            f"• {_a('foxray', 'FoXray (App Store)')};\n"
            f"• {_a('v2rayn', 'v2rayN')} — для Apple Silicon и Intel.\n\n"
            "<b>Шаг 2. Скопируй ссылку-подписку</b>\n"
            "«👤 Мой профиль» → нажми на ссылку <code>…/sub/…</code>.\n\n"
            "<b>Шаг 3. Добавь подписку</b>\n"
            "Открой приложение → «+» → «Добавить подписку» / «Add subscription» → вставь ссылку.\n\n"
            "<b>Шаг 4. Подключись</b>\n"
            "Нажми «Подключить». macOS спросит: «Разрешить добавление конфигурации VPN?» → "
            "Разрешить, затем System Settings → ввести пароль/Touch ID.\n\n"
            "<b>Шаг 5. Проверь</b>\n"
            f"Открой {_a('check_ip', '2ip.ru')} — страна должна быть Нидерланды/Германия.\n\n"
            "<i>Если macOS жалуется на «неопознанного разработчика»: правый клик по приложению → "
            "«Открыть» → «Открыть всё равно» (это про подпись, а не про безопасность).</i>"
        )

    # Android TV / приставка
    return (
        "📺 <b>Android TV / приставка — пошагово</b>\n\n"
        "<b>Шаг 1. Установи приложение</b>:\n"
        f"• {_a('v2rayng', 'v2rayNG (APK)')} — установи через USB-флешку или приложение "
        "«Downloader» (его можно поставить из Google Play на телевизоре);\n"
        f"• {_a('hiddify', 'Hiddify')} — есть сборка для Android TV.\n\n"
        "<b>Шаг 2. Возьми ссылку-подписку</b>\n"
        "Проще всего: «👤 Мой профиль» → нажми на ссылку-подписку, а затем перешли её себе "
        "в Telegram на телевизоре (вводить пультом долго — лучше через буфер обмена).\n\n"
        "<b>Шаг 3. Добавь подписку</b>\n"
        "v2rayNG → три точки → «Группы» → «+» → «Добавить подписку» → вставь ссылку.\n\n"
        "<b>Шаг 4. Подключись и проверь</b>\n"
        "Нажми «V» → Разрешить VPN → открой браузер на телевизоре и зайди на "
        f"{_a('check_ip', '2ip.ru')}.\n\n"
        "<i>Пульт без мыши? Подключи USB-мышь — с ней настройка занимает минуту.</i>"
    )


def install_check_text() -> str:
    """Как убедиться, что VPN реально работает."""
    return (
        "✅ <b>Проверка подключения</b>\n\n"
        "1. Убедись, что VPN включён: в приложении горит «Подключено», "
        "а в шторке телефона/трее есть значок VPN.\n"
        f"2. Открой {_a('check_ip', '2ip.ru')} — страна должна смениться на "
        "Нидерланды или Германию.\n"
        f"3. Для строгой проверки — {_a('whoer', 'whoer.net')}: там видно и IP, и "
        "утечки DNS.\n"
        "4. Открой сайт, который раньше не грузился (например, YouTube или Instagram) — "
        "он должен открыться.\n\n"
        "<b>Нормальные признаки:</b>\n"
        "• скорость немного ниже, чем без VPN, — это нормально;\n"
        "• первый сайт открывается 1–2 секунды дольше — тоже нормально.\n\n"
        "Если IP не сменился — вернись в инструкцию своего устройства: "
        "чаще всего подписка добавлена, но кнопка «Подключить» не нажата."
    )


def install_trouble_text() -> str:
    """Что делать, если не работает — чек-лист от частого к редкому."""
    return (
        "🆘 <b>Не работает? Идём по порядку</b>\n\n"
        "1️⃣ <b>Подписка добавлена, но не подключается.</b> Нажми «Подключить» в приложении "
        "и разреши создание VPN-подключения (системное окно). Без разрешения туннель не встанет.\n"
        "2️⃣ <b>Пишет «ошибка» или «таймаут».</b> Выключи VPN → включи режим полёта на 5 секунд → "
        "выключи → подключись снова. Помогает в 8 случаях из 10.\n"
        "3️⃣ <b>Работает на мобильном интернете, но не на Wi-Fi.</b> Значит, Wi-Fi сеть блокирует "
        "VPN — попробуй другую сеть или мобильный интернет.\n"
        "4️⃣ <b>Подключено, но сайты не открываются.</b> Проверь, что в приложении включён "
        "режим «VPN/TUN» (не «прокси только для выбранных приложений»), и выключи "
        "другие VPN/антивирусные прокси.\n"
        "5️⃣ <b>Отключается в фоне (Android).</b> Настройки → Приложения → твой клиент → "
        "Батарея → «Без ограничений»; в клиенте включи «Always-on VPN».\n"
        "6️⃣ <b>Истёк срок подписки.</b> Проверь «👤 Мой профиль» — если дата прошла, "
        "продли в «💰 Тарифы» (доступ придёт сразу после оплаты).\n"
        "7️⃣ <b>Ничего не помогло.</b> Напиши в поддержку: приложи скриншот экрана приложения "
        "с ошибкой и свой Telegram ID (команда /myid).\n\n"
        "💡 Переустановка доступа: «👤 Мой профиль» → «🔄 Сбросить и получить заново» — "
        "выдам свежую ссылку-подписку."
    )


def main_menu_kb(tg_id: int | None = None) -> InlineKeyboardMarkup:
    """
    Главное меню.

    Кнопка бесплатного теста показывается только тем, кому тест доступен и включён
    показ кнопок (TRIAL_BUTTON=1 + TRIAL_PUBLIC=1 или администратор) — чтобы
    пользователь не упирался в отказ.
    """
    rows = []
    if trial_button_visible(tg_id):
        rows.append([InlineKeyboardButton(text="🔑 Получить тестовый VPN (24 часа)",
                                          callback_data="get_test_key_btn")])
    rows += [
            [
                InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs"),
                InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
            ],
            [InlineKeyboardButton(text="📲 Как подключиться (пошагово)", callback_data="help_menu")],
            [InlineKeyboardButton(text=f"🎁 Пригласить друга — +{REFERRAL_BONUS_DAYS} "
                                        f"{days_word(REFERRAL_BONUS_DAYS)}", callback_data="invite")],
            [
                InlineKeyboardButton(text="💬 Поддержка", callback_data="support"),
                InlineKeyboardButton(text="📄 Соглашение", callback_data="terms"),
            ],
            [InlineKeyboardButton(text="🔒 Политика конфиденциальности", callback_data="privacy")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def tariffs_intro(tg_id: int | None = None) -> str:
    """Первый экран тарифов: бесплатные предложения и шаг выбора типа подписки."""
    text = "💰 <b>Тарифные планы</b>\n\n"
    text += ("Выбери подписку в три шага: <b>тип</b> (по времени или по трафику) → "
             "<b>уровень</b> (Новичок, Нетраннер, Кибер-самурай, Призрак) → "
             "<b>сервер</b> для тарифов с одним туннелем.\n\n")
    free_items = []
    promo = TARIFFS.get(PROMO_KEY) or {}
    if promo_visible(tg_id):
        free_items.append(
            f"• 🎉 <b>Промо-доступ</b> — {traffic_label(promo.get('traffic_gb', 0))} "
            f"на {days_label(promo.get('days', PROMO_DAYS))} (один раз на аккаунт)"
        )
    trial = TARIFFS.get("trial") or {}
    if tariff_visible(tg_id, "trial", trial):
        free_items.append(f"• 🎁 <b>Тестовый период</b> — 24 часа, {trial.get('traffic', '')}")
    if free_items:
        text += "<b>Бесплатно</b>\n" + "\n".join(free_items) + "\n\n"
    text += "<b>Платные тарифы</b>\n"
    for kind in TARIFF_KIND_ORDER:
        meta = TARIFF_KINDS[kind]
        prices = [TARIFF_GRID[kind][level]["price"] for level in TARIFF_LEVEL_ORDER]
        text += (f"• <b>{meta['title']}</b> — от {min(prices)} ₽\n"
                 f"  <i>{meta['hint']}</i>\n")
    return text


def tariffs_kb(tg_id: int | None = None) -> InlineKeyboardMarkup:
    """
    Кнопки тарифов: бесплатные предложения, затем шаг 1 — выбор типа подписки.

    Бесплатный тестовый пункт показываем только тем, кому тест доступен и включён
    показ кнопок (TRIAL_BUTTON=1) — иначе пользователь нажмёт «Бесплатно» и получит
    отказ, а бот выглядит не как рабочий сервис.
    """
    buttons = []
    if promo_visible(tg_id):
        promo = TARIFFS.get(PROMO_KEY) or {}
        buttons.append([InlineKeyboardButton(
            text=f"🎉 Промо-доступ — {promo.get('traffic', '')} на "
                 f"{days_label(promo.get('days', PROMO_DAYS))} бесплатно",
            callback_data="buy_promo",
        )])
    if tariff_visible(tg_id, "trial", TARIFFS.get("trial") or {}):
        buttons.append([InlineKeyboardButton(text="🎁 Тестовый период (24 ч) — Бесплатно",
                                             callback_data="buy_trial")])
    buttons.append([InlineKeyboardButton(text="━━ Выбрать тариф ━━", callback_data="noop")])
    for kind in TARIFF_KIND_ORDER:
        buttons.append([InlineKeyboardButton(
            text=TARIFF_KINDS[kind]["title"],
            callback_data=f"tkind_{kind}",
        )])
    if PAYMENTS_MODE == "yookassa":
        buttons.append([InlineKeyboardButton(text="🔄 Проверить оплату", callback_data="check_payment_help")])
    buttons.append([InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def kind_levels_text(kind: str) -> str:
    """Второй экран: что входит в уровни выбранного типа подписки."""
    meta = TARIFF_KINDS[kind]
    text = f"{meta['title']}: <b>выбери уровень</b>\n\n"
    text += f"<i>{meta['hint']}</i>\n\n"
    for level in TARIFF_LEVEL_ORDER:
        tariff = TARIFFS[tariff_key(kind, level)]
        plan = TARIFF_LEVELS[level]
        text += (
            f"<b>{plan['name']}</b> — <b>{tariff_price_label(tariff)}</b>\n"
            f"  📊 {tariff['traffic']} | ⏳ {days_label(tariff['days'])}\n"
            f"  📱 {plan['devices']} {devices_word(plan['devices'])} | "
            f"🌍 {plan['tunnels']} {tunnels_word(plan['tunnels'])}\n\n"
        )
    return text


def tunnels_word(count: int) -> str:
    """«1 туннель», «2 туннеля», «6 туннелей»."""
    value = abs(int(count))
    if value % 100 in (11, 12, 13, 14):
        return "туннелей"
    if value % 10 == 1:
        return "туннель"
    if value % 10 in (2, 3, 4):
        return "туннеля"
    return "туннелей"


def kind_levels_kb(kind: str) -> InlineKeyboardMarkup:
    """Кнопки второго экрана: четыре уровня выбранного типа подписки."""
    rows = []
    for level in TARIFF_LEVEL_ORDER:
        tariff = TARIFFS[tariff_key(kind, level)]
        plan = TARIFF_LEVELS[level]
        rows.append([InlineKeyboardButton(
            text=f"{plan['name']} — {tariff_price_label(tariff)}",
            callback_data=f"tlvl_{kind}_{level}",
        )])
    rows.append([InlineKeyboardButton(text="◀️ Назад к типам", callback_data="tariffs")])
    rows.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def server_pick_text(kind: str, level: int) -> str:
    """Третий экран: выбор сервера для тарифа на один туннель."""
    tariff = TARIFFS[tariff_key(kind, level)]
    return (
        f"{TARIFF_LEVELS[level]['name']} · {TARIFF_KINDS[kind]['short']} — "
        f"<b>{tariff_price_label(tariff)}</b>\n\n"
        f"📊 {tariff['traffic']} | ⏳ {days_label(tariff['days'])} | "
        f"📱 {tariff['ips']} {devices_word(tariff['ips'])}\n\n"
        "<b>Выбери сервер:</b>"
    )


def server_pick_kb(kind: str, level: int) -> InlineKeyboardMarkup:
    """Кнопки выбора сервера (только для тарифов с одним туннелем)."""
    rows = [[InlineKeyboardButton(text=LOCATIONS[key]["title"],
                                  callback_data=f"tlocs_{kind}_{level}_{key}")]
            for key in LOCATION_ORDER]
    rows.append([InlineKeyboardButton(text="◀️ Назад к уровням", callback_data=f"tkind_{kind}")])
    rows.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def tariff_confirm_text(tariff: dict, location_key: str | None) -> str:
    """Подтверждение перед оплатой: что именно покупает клиент."""
    plan = TARIFF_LEVELS.get(tariff.get("level") or 0, {})
    locations = location_display(tariff, location_key)
    return (
        f"🧾 <b>Твой тариф</b>\n\n"
        f"• Тип: <b>{TARIFF_KINDS[tariff['kind']]['title']}</b>\n"
        f"• Уровень: <b>{plan.get('name', '')}</b>\n"
        f"• Цена: <b>{tariff_price_label(tariff)}</b>\n"
        f"• Срок: <b>{days_label(tariff['days'])}</b>\n"
        f"• Трафик: <b>{tariff['traffic']}</b>\n"
        f"• Устройств: <b>{tariff['ips']}</b>\n"
        f"• Туннелей: <b>{tariff['tunnels']}</b>\n"
        f"• Сервер: <b>{locations}</b>\n\n"
        "Нажми «Оплатить», чтобы перейти к оплате."
    )


def tariff_confirm_kb(tariff_key_value: str, location_key: str | None = None) -> InlineKeyboardMarkup:
    """Кнопка оплаты выбранного тарифа (с сервером, если он выбирался)."""
    data = f"buyat_{tariff_key_value}" + (f"_{location_key}" if location_key else "")
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить", callback_data=data)],
        [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
    ])


def back_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")]]
    )


def key_actions_kb(tg_id: int | None = None) -> InlineKeyboardMarkup:
    """
    Кнопки под выданным ключом.

    «Сбросить и получить заново» — служебная операция (только для администратора),
    поэтому обычным пользователям кнопка не показывается: вместо отказа в ответ на
    нажатие они видят понятный набор действий.
    """
    rows = [
        [InlineKeyboardButton(text="📲 Как подключиться (пошагово)", callback_data="help_menu")],
        [InlineKeyboardButton(text="🔗 Моя подписка", callback_data="profile")],
    ]
    if tg_id is None or is_admin(tg_id):
        rows.append([InlineKeyboardButton(text="🔄 Сбросить и получить заново",
                                          callback_data="reset_my_vpn")])
    else:
        rows.append([InlineKeyboardButton(text="💬 Поддержка", callback_data="support")])
    rows.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


# =========================
# ОБРАБОТЧИКИ КОМАНД
# =========================

@dp.message(Command("start"))
async def cmd_start(message: Message):
    """Первый экран: соглашение (один раз) → приветствие и главное меню."""
    uid = message.from_user.id
    referral_store.touch_user(uid)

    # Переход по реферальной ссылке: t.me/<бот>?start=ref_12345
    parts = (message.text or "").split(maxsplit=1)
    payload = parts[1] if len(parts) > 1 else ""

    if terms_gate_needed(uid):
        # Приглашение засчитываем сразу (друг уже оплатил ожидания), а приветствие
        # приглашённому покажем после кнопки «✅ Согласен» — чтобы порядок был логичным.
        if payload:
            await handle_referral_start(message, payload, defer_greeting=True)
        await show_terms_gate(message)
        return

    await message.answer(welcome_text(uid), reply_markup=main_menu_kb(uid), parse_mode="HTML")

    if payload:
        await handle_referral_start(message, payload)


def welcome_text(tg_id: int) -> str:
    """Приветствие /start: показывается после принятия соглашения и по кнопке «Меню»."""
    trial_line = (
        "🎁 Бесплатный тестовый доступ на 24 часа — кнопка ниже.\n"
        if trial_button_visible(tg_id) else ""
    )
    return (
        "👋 <b>Добро пожаловать в быстрый и надёжный VPN!</b>\n\n"
        "Мы используем современный протокол <b>VLESS Reality</b>, "
        "который неотличим от обычного интернет-трафика и работает стабильно.\n\n"
        + trial_line +
        "💰 Платные тарифы — раздел «Тарифы» (оплата и моментальная выдача доступа).\n"
        "📲 Подключение по шагам (со ссылками на приложения) — /help.\n"
        "👤 Статус подписки и продление — /profile.\n"
        "📄 Условия сервиса, оплаты и возврата — /terms.\n"
        "🔒 Политика конфиденциальности — /privacy."
    )


@dp.message(Command("myid"))
async def cmd_myid(message: Message):
    user_id = message.from_user.id
    admins = ", ".join(f"<code>{value}</code>" for value in ADMIN_IDS) or "не заданы"

    if not ADMIN_IDS:
        reason = (
            f"заполнена некорректно (<code>{escape(ADMIN_ID_RAW)}</code> — нужен числовой ID, "
            "а не @username)"
            if ADMIN_ID_RAW else "не задана"
        )
        status_text = (
            f"⚠️ Переменная <b>ADMIN_ID</b> {reason}, поэтому админ-команды сейчас открыты для всех.\n"
            "Отправь в Railway → Variables → <b>ADMIN_ID</b> свой ID ниже "
            "(несколько админов — через запятую: <code>111,222</code>)."
        )
    elif user_id in ADMIN_IDS:
        extra = f" (в списке {len(ADMIN_IDS)} админ(ов))" if len(ADMIN_IDS) > 1 else ""
        if admin_tools_enabled():
            visible = "/payments, /panel_debug, /groups, /totp, /inbounds, /reset_vpn, /revoke"
            if test_tools_enabled():
                visible += ", /test_pay, /platega_check"
            status_text = f"✅ Ты администратор{extra} — служебные команды включены: {visible}."
        else:
            status_text = (
                f"✅ Ты администратор{extra}. Служебные команды сейчас <b>скрыты</b> "
                "(<code>ADMIN_TOOLS=0</code>), поэтому в боте их не видно и они не отвечают.\n"
                "Нужны /payments, /panel_debug, /groups, /totp? Поставь в Railway → Variables "
                "<b>ADMIN_TOOLS=1</b> и подожди 1–2 минуты (перезапуск). Обратно — "
                "<code>ADMIN_TOOLS=0</code> или удалить переменную."
            )
        if trial_available_for(user_id) and not trial_button_visible(user_id):
            status_text += (
                "\n\n🔑 Кнопки тестового ключа скрыты (<code>TRIAL_BUTTON=0</code>), "
                "но команда /test_vpn работает: 24 часа, 1 ГиБ. "
                "Вернуть кнопки в меню и тарифы — <code>TRIAL_BUTTON=1</code>."
            )
        # Владельцу видно состояние оплаты: именно тут понятно, почему /test_pay
        # и /platega_check молчат или что не хватает для приёма денег.
        status_text += "\n\n" + payments_diag_text()
        # И какой контакт поддержки видят клиенты: переменная перекрывает стандартный.
        support_source = (
            "из переменной <code>SUPPORT_USERNAME</code>"
            if (os.getenv("SUPPORT_USERNAME") or "").strip()
            else "стандартный, переменная не задана"
        )
        status_text += (
            f"\n\n💬 <b>Поддержка для клиентов:</b> "
            f"<a href=\"{support_link()}\">@{escape(SUPPORT_USERNAME)}</a> "
            f"— {support_source}."
        )
    else:
        status_text = (
            f"ℹ️ Ты не в списке администраторов. Сейчас там: {admins}.\n"
            "Если бот твой — поставь в <b>ADMIN_ID</b> свой ID (несколько админов — через запятую: "
            "<code>111,222</code>).\n"
            "<i>Частая причина отказа: в переменной указан @username вместо числового ID.</i>"
        )

    await message.answer(
        f"👤 <b>Твой Telegram ID:</b> <code>{user_id}</code>\n\n"
        f"<b>Админы бота (ADMIN_ID):</b> {admins}\n"
        f"<b>Статус:</b> {status_text}\n\n"
        "<i>После изменения переменной в Railway подожди 1-2 минуты — сервис перезапустится сам.</i>",
        parse_mode="HTML",
    )


async def cmd_inbounds(message: Message):
    """Показывает список подключений в панели (только для админа)."""
    # Если ADMIN_ID не настроен, разрешаем вызов, чтобы владелец мог увидеть inbounds
    if not is_admin(message.from_user.id):
        await message.answer(
            "⛔️ <b>Команда /inbounds доступна только администратору.</b>\n\n"
            + admin_denied_text(message.from_user.id),
            parse_mode="HTML",
        )
        return

    wait_msg = await message.answer("⏳ Опрашиваю панель 3x-ui...")
    try:
        async with XUIClient() as client:
            items = await client.get_inbounds()

        await wait_msg.delete()

        if not items:
            await message.answer("❌ В панели 3x-ui нет созданных входящих подключений.")
            return

        lines = ["✅ <b>Входящие подключения (Inbounds) в панели:</b>\n"]
        for item in items:
            iid = item.get("id")
            remark = item.get("remark") or "Без названия"
            proto = item.get("protocol") or "?"
            port = item.get("port") or "?"
            stream = as_dict(item.get("streamSettings"))
            net = stream.get("network", "-")
            sec = stream.get("security", "-")

            is_perfect = (proto == "vless" and net == "tcp" and sec == "reality")
            mark = "⭐️ [РЕКОМЕНДУЕТСЯ]" if is_perfect else ""

            lines.append(
                f"🔹 <b>ID:</b> <code>{iid}</code> | <b>{escape(remark)}</b> {mark}\n"
                f"   Протокол: <code>{proto}</code> | Транспорт: <code>{net} + {sec}</code> | Порт: <code>{port}</code>\n"
            )

        lines.append(
            "💡 Чтобы зафиксировать конкретное подключение для выдачи ключей, укажи его ID в Railway:\n"
            "<b>XUI_INBOUND_ID</b>=ID"
        )
        await message.answer("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


@dp.message(Command("test_vpn"))
async def cmd_test_vpn(message: Message):
    """Выдаёт тестовый VPN-ключ."""
    if await terms_gate(message):
        return
    # Тестовый доступ открыт админу всегда; обычным пользователям — только при TRIAL_PUBLIC=1
    if not trial_available_for(message.from_user.id):
        await message.answer(
            "🎁 Бесплатный тестовый доступ сейчас недоступен.\n\n"
            "Актуальные тарифы и цены — в разделе «💰 Тарифы»: доступ приходит сразу "
            "после оплаты. Если нужна помощь — напиши в поддержку.",
            parse_mode="HTML",
            reply_markup=back_kb(),
        )
        return

    wait_msg = await message.answer("⏳ Подключаюсь к 3x-ui и готовлю доступ...")

    try:
        async with vpn_lock:
            link, status, inbound, auto_picked, sub_link, group_note = await get_or_create_test_key(
                message.from_user.id
            )

        try:
            await wait_msg.delete()
        except Exception:
            pass

        inbound_id = inbound.get("id", "?")
        inbound_remark = inbound.get("remark") or f"Подключение #{inbound_id}"

        if status == "created":
            title = "🎉 <b>Тестовый доступ активирован — 24 часа!</b>"
        elif status == "updated":
            title = "♻️ <b>Срок тестового доступа истёк — продлил ещё на 24 часа!</b>"
        else:
            title = "🔐 <b>Твой действующий тестовый доступ:</b>"

        auto_note = ""
        if auto_picked:
            auto_note = (
                f"\n\nℹ️ <i>Бот автоматически выбрал подключение #{inbound_id} ({inbound_remark}). "
                f"Чтобы зафиксировать его, можешь указать XUI_INBOUND_ID={inbound_id} в Railway.</i>"
            )

        admin_note = ""
        if ADMIN_ID == 0:
            admin_note = (
                f"\n\n💡 <b>Подсказка:</b> твой Telegram ID <code>{message.from_user.id}</code>. "
                "Запиши его в Railway -> Variables -> <b>ADMIN_ID</b>."
            )

        msg_text = (
            f"{title}\n\n"
            f"⏳ <b>Срок:</b> 24 часа\n"
            f"📦 <b>Трафик:</b> 1 ГиБ\n"
            f"📱 <b>Устройств:</b> 1\n"
            f"📡 <b>Подключение:</b> #{inbound_id} ({escape(inbound_remark)})\n\n"
            + access_block({"link": link, "sub_link": sub_link}) + "\n\n"
            "📲 <b>Дальше по шагам:</b> нажми «Как подключиться» под этим сообщением — "
            "покажу, какое приложение скачать на твоё устройство и куда вставить ссылку "
            "(или ключ, если приложение не умеет подписки)."
            f"{group_note}"
            f"{auto_note}"
            f"{admin_note}"
        )

        await message.answer(msg_text, reply_markup=key_actions_kb(message.from_user.id), parse_mode="HTML")

    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


async def cmd_reset_vpn(message: Message):
    """Удаляет тестового клиента из 3x-ui (для пересоздания)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    wait_msg = await message.answer("⏳ Удаляю клиента из панели 3x-ui...")
    try:
        async with vpn_lock:
            removed = await delete_test_key(message.from_user.id)

        await wait_msg.delete()
        if removed:
            await message.answer(
                "🗑 <b>Тестовый клиент успешно удалён из 3x-ui!</b>\n\n"
                "Теперь можешь отправить команду /test_vpn — выдам доступ заново.",
                parse_mode="HTML",
            )
        else:
            await message.answer(
                "ℹ️ Тестового клиента в 3x-ui не обнаружено — можно сразу отправлять /test_vpn.",
                parse_mode="HTML",
            )
    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


async def cmd_groups(message: Message):
    """Показывает группы клиентов в панели 3x-ui (только для админа)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    wait_msg = await message.answer("⏳ Запрашиваю группы в панели 3x-ui...")
    try:
        async with XUIClient() as client:
            groups = await client.list_groups()

        try:
            await wait_msg.delete()
        except Exception:
            pass

        if groups is None:
            await message.answer(
                "⚠️ <b>Эта версия панели 3x-ui не поддерживает группы клиентов.</b>\n\n"
                "Группы появились в 3x-ui 3.2 — обнови панель, и бот сможет складывать своих клиентов "
                "в отдельную группу (переменная <b>XUI_CLIENT_GROUP</b>).",
                parse_mode="HTML",
            )
            return

        if not groups:
            await message.answer(
                "ℹ️ В панели 3x-ui пока нет ни одной группы клиентов.\n\n"
                "Задай имя группы в Railway → Variables → <b>XUI_CLIENT_GROUP</b> — бот создаст её "
                "автоматически при выдаче следующего ключа.",
                parse_mode="HTML",
            )
            return

        bot_group = XUIClient.group_exists(groups) if XUI_CLIENT_GROUP else None

        lines = ["🏷 <b>Группы клиентов в панели 3x-ui:</b>\n"]
        for group in groups:
            name = str(group.get("name") or "")
            count = group.get("clientCount")
            mark = " ⬅️ <i>использует бот</i>" if bot_group and name == bot_group else ""
            used = _human_bytes(group.get("trafficUsed")) if group.get("trafficUsed") else None
            details = f"{count} клиент(ов)" if count is not None else "—"
            if used:
                details += f", трафик: {used}"
            lines.append(f"• <code>{escape(name)}</code> — {details}{mark}")

        if not XUI_CLIENT_GROUP:
            lines.append(
                "\n💡 Задай <b>XUI_CLIENT_GROUP</b> в Railway → Variables с названием нужной группы — "
                "клиенты бота будут попадать в неё (например <code>bot-test</code>)."
            )
        elif bot_group:
            exact = "" if bot_group == XUI_CLIENT_GROUP else f" <i>(в переменной — «{escape(XUI_CLIENT_GROUP)}»)</i>"
            lines.append(
                f"\n✅ Клиенты бота добавляются в существующую группу "
                f"<code>{escape(bot_group)}</code>{exact}."
            )
        else:
            similar = XUIClient.similar_groups(groups)
            hint = (
                "\n🔍 Похожие названия: " + ", ".join(f"<code>{escape(name)}</code>" for name in similar)
                if similar
                else ""
            )
            lines.append(
                f"\n⚠️ Группы <code>{escape(XUI_CLIENT_GROUP)}</code> в панели нет — панель создаст её "
                "при выдаче следующего ключа.\n"
                "<i>Если нужна уже существующая группа, задай её название в XUI_CLIENT_GROUP точно так, "
                "как оно указано в списке выше.</i>"
                f"{hint}"
            )

        await message.answer("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


async def cmd_panel_debug(message: Message):
    """Сетевая диагностика связи между Railway и 3x-ui."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    if not XUI_URL:
        await message.answer("❌ XUI_URL не задан в Railway Variables.")
        return

    if not XUI_2FA_SECRET:
        two_factor_state = "не задан"
    elif totp_secret_problem(XUI_2FA_SECRET):
        two_factor_state = f"⚠️ некорректный ({totp_secret_problem(XUI_2FA_SECRET)})"
    else:
        two_factor_state = "задан ✅"
    secret_tail = f"…{XUI_2FA_SECRET[-4:]}" if len(XUI_2FA_SECRET) > 4 else "—"

    admins_note = (
        ", ".join(str(value) for value in ADMIN_IDS) if ADMIN_IDS
        else "⚠️ не задан (админ-команды открыты всем — укажи свой ID)"
    )
    egress_ip = await fetch_egress_ip()
    lines = [
        "🔍 <b>Диагностика подключения к 3x-ui:</b>\n",
        f"• <b>Админы (ADMIN_ID):</b> <code>{escape(admins_note)}</code> — твой ID <code>{message.from_user.id}</code>",
        f"• <b>URL:</b> <code>{escape(XUI_URL)}</code>",
        egress_ip_line(egress_ip),
        f"• <b>Прокси:</b> <code>{escape(str(XUI_PROXY or 'нет'))}</code>",
        f"• <b>Логин:</b> <code>{escape(XUI_USERNAME or 'не задан')}</code>",
        f"• <b>API Token:</b> <code>{'задан' if XUI_TOKEN else 'не задан'}</code>",
        f"• <b>XUI_2FA_SECRET:</b> <code>{escape(two_factor_state)}</code>"
        + (f" <i>(оканчивается на <code>{secret_tail}</code>)</i>" if two_factor_state == "задан ✅" else ""),
        "",
    ]

    ssl_ctx = _ssl_context() if XUI_URL.startswith("https://") else None

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=20),
        connector=aiohttp.TCPConnector(ssl=ssl_ctx),
    ) as session:
        # GET /
        try:
            async with session.get(
                f"{XUI_URL}/",
                headers={"User-Agent": BROWSER_UA},
                allow_redirects=True,
                proxy=XUI_PROXY,
            ) as resp:
                body = await resp.text()
                lines.append(f"1. <b>GET /</b> -> HTTP {resp.status} (Server: {resp.headers.get('Server', '-')})")
                lines.append(f"   Определено: <i>{classify_body(body)}</i>")
        except Exception as exc:
            lines.append(f"1. <b>GET /</b> -> ❌ Ошибка соединения: <code>{escape(str(exc))}</code>")

        # GET /csrf-token
        try:
            async with session.get(
                f"{XUI_URL}/csrf-token",
                headers={"User-Agent": BROWSER_UA, "Accept": "application/json"},
                proxy=XUI_PROXY,
            ) as resp:
                body = await resp.text()
                lines.append(f"2. <b>GET /csrf-token</b> -> HTTP {resp.status}: {_snip(body, 80)}")
        except Exception as exc:
            lines.append(f"2. <b>GET /csrf-token</b> -> ❌ {escape(str(exc))}")

        # POST /login (тест) — заодно проверяем, не требует ли панель код 2FA
        try:
            async with session.post(
                f"{XUI_URL}/login",
                json={"username": "___test___", "password": "___test___"},
                headers={"User-Agent": BROWSER_UA, "Accept": "application/json"},
                proxy=XUI_PROXY,
            ) as resp:
                body = await resp.text()
                lines.append(f"3. <b>POST /login</b> -> HTTP {resp.status}: {_snip(body, 80)}")
        except Exception as exc:
            lines.append(f"3. <b>POST /login</b> -> ❌ {escape(str(exc))}")

        # POST /getTwoFactorEnable — узнаём у панели, включена ли 2FA
        try:
            async with session.post(
                f"{XUI_URL}/getTwoFactorEnable",
                headers={"User-Agent": BROWSER_UA, "Accept": "application/json"},
                proxy=XUI_PROXY,
            ) as resp:
                body = await resp.text()
                lines.append(f"4. <b>POST /getTwoFactorEnable</b> -> HTTP {resp.status}: {_snip(body, 80)}")
                panel_2fa = None
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict) and "obj" in parsed:
                        panel_2fa = bool(parsed.get("obj"))
                except ValueError:
                    pass
                secret_ok = bool(XUI_2FA_SECRET) and not totp_secret_problem(XUI_2FA_SECRET)
                if panel_2fa is True and secret_ok:
                    lines.append("   ✅ <i>2FA включена, XUI_2FA_SECRET задан — бот передаёт код автоматически.</i>")
                elif panel_2fa is True:
                    lines.append("   ⚠️ <i>В панели включена 2FA, а XUI_2FA_SECRET не задан/некорректен — вход не удастся.</i>")
                elif panel_2fa is False:
                    lines.append("   ✅ <i>2FA в панели выключена.</i>")
        except Exception as exc:
            lines.append(f"4. <b>POST /getTwoFactorEnable</b> -> ❌ {escape(str(exc))}")

        # Текущий код 2FA по секрету из переменной (для проверки, что секрет верный)
        if XUI_2FA_SECRET and not totp_secret_problem(XUI_2FA_SECRET):
            now = time.time()
            lines.append(
                f"5. <b>Код 2FA из XUI_2FA_SECRET:</b> "
                f"<code>{totp_code(XUI_2FA_SECRET, at=now)}</code> (осталось {totp_seconds_left(now):.0f} сек)"
            )
            lines.append(
                "   <i>Сравни с кодом в Google Authenticator. Если не совпадает — секрет другой.</i>"
            )
        elif XUI_2FA_SECRET:
            lines.append(f"5. <b>XUI_2FA_SECRET:</b> ⚠️ {escape(str(totp_secret_problem(XUI_2FA_SECRET)))}")
        else:
            lines.append("5. <b>XUI_2FA_SECRET:</b> не задан — вход только по логину/паролю или XUI_TOKEN.")

        # Проверяем, поддерживает ли панель группы клиентов и попадёт ли туда клиент бота
        try:
            async with XUIClient() as client:
                groups = await client.list_groups()
        except Exception as exc:
            groups = None
            lines.append(f"6. <b>Группы клиентов</b> -> ❌ {escape(str(exc))}")
        else:
            if groups is None:
                lines.append(
                    "6. <b>Группы клиентов</b> -> ⚠️ панель не поддерживает группы (нужна 3x-ui 3.2+)"
                )
            elif not XUI_CLIENT_GROUP:
                lines.append(
                    f"6. <b>Группы клиентов</b> -> доступны ({len(groups)} шт.), но <b>XUI_CLIENT_GROUP</b> не задана"
                )
            else:
                found = XUIClient.group_exists(groups)
                if found:
                    exact = "" if found == XUI_CLIENT_GROUP else f" (в панели называется «{escape(found)}»)"
                    lines.append(
                        f"6. <b>Группа бота:</b> <code>{escape(XUI_CLIENT_GROUP)}</code> -> "
                        f"✅ найдена в панели, клиенты попадут в неё{exact}"
                    )
                else:
                    similar = XUIClient.similar_groups(groups)
                    hint = (
                        " Похожие: " + ", ".join(f"<code>{escape(n)}</code>" for n in similar) + "."
                        if similar
                        else ""
                    )
                    lines.append(
                        f"6. <b>Группа бота:</b> <code>{escape(XUI_CLIENT_GROUP)}</code> -> "
                        f"⚠️ в панели не найдена, будет создана новая (проверь название).{hint}"
                    )

        # 7. Платёжные настройки
        lines.append("")
        lines.append(f"7. <b>Оплата:</b> {escape(payments_mode_title())} (<code>{PAYMENTS_MODE}</code>)")
        if PAYMENTS_MODE == "provider":
            lines.append(f"   Provider token: {'задан ✅' if PAYMENT_PROVIDER_TOKEN else 'НЕ задан ❌'} — {provider_mode_title()}")
            lines.append("   Чек 54-ФЗ: " + ("передаётся в provider_data" if TELEGRAM_SEND_RECEIPT else "не передаётся (TELEGRAM_SEND_RECEIPT=0)"))
        elif PAYMENTS_MODE == "yookassa":
            lines.append(
                f"   ЮKassa: shop <code>{escape(YOOKASSA_SHOP_ID or '—')}</code>, "
                f"ключ {'задан ✅' if YOOKASSA_SECRET_KEY else 'НЕ задан ❌'}"
                + (" (тестовый магазин 🧪)" if YOOKASSA_TEST else "")
            )
            webhook_url = (PUBLIC_BASE_URL + "/yookassa/webhook") if PUBLIC_BASE_URL else ""
            if webhook_url:
                lines.append(f"   Вебхук: <code>{escape(webhook_url)}</code>")
            else:
                lines.append("   Вебхук: ⚠️ PUBLIC_BASE_URL не задан (Railway подставляет его сам)")
            if YOOKASSA_OAUTH_TOKEN and webhook_url:
                try:
                    hooks = await make_yookassa_client().list_webhooks()
                    marked = any(
                        h.get("event") == "payment.succeeded" and h.get("url") == webhook_url for h in hooks or []
                    )
                    lines.append("   Вебхук в ЮKassa: " + ("✅ зарегистрирован" if marked else "⚠️ не найден"))
                except Exception as exc:
                    lines.append(f"   Вебхук: ❌ {escape(_snip(str(exc), 120))}")
            else:
                lines.append(
                    "   Настройка: кабинет ЮKassa → Интеграция → HTTP-уведомления → "
                    "URL выше, событие <b>payment.succeeded</b>"
                )
        elif PAYMENTS_MODE == "platega":
            lines.append(f"   Merchant ID: <code>{escape(PLATEGA_MERCHANT_ID or '—')}</code>")
            lines.append("   API-ключ: " + ("задан ✅" if PLATEGA_SECRET else "НЕ задан ❌"))
            lines.append(
                f"   API: <code>{escape(PLATEGA_API_URL)}</code>, валюта {escape(PLATEGA_CURRENCY)}, "
                "способ оплаты: "
                + (escape(PLATEGA_METHODS.get(PLATEGA_METHOD, str(PLATEGA_METHOD)))
                   if PLATEGA_METHOD else "выбирает плательщик")
            )
            webhook_url = (PUBLIC_BASE_URL + PLATEGA_WEBHOOK_PATH) if PUBLIC_BASE_URL else ""
            if webhook_url:
                lines.append(f"   Callback URL: <code>{escape(webhook_url)}</code> (метод POST)")
            else:
                lines.append("   Callback URL: ⚠️ PUBLIC_BASE_URL не задан (Railway подставляет его сам)")
            lines.append("   Защита callback: заголовки X-MerchantId + X-Secret")
            if test_tools_enabled():
                lines.append("   Проверка без оплаты: /test_pay ✅, связка с Platega: /platega_check")
            elif admin_tools_enabled():
                lines.append("   Диагностика магазина без денег: /platega_check")

        elif PAYMENTS_MODE == "stars":
            lines.append(f"   Курс: 1 ⭐️ ≈ {STARS_RUB_RATE} ₽ (STARS_RUB_RATE)")

        stats = payment_store.stats()
        lines.append(
            f"   Заказов: {stats['orders_total']}, оплачено: {stats['paid_count']}, "
            f"выручка: {stats['rub']} ₽ / {stats['stars']} ⭐️"
        )

    # Локации: какие серверы бот видит и куда попадёт клиент
    lines.append("")
    lines.append("🌍 <b>Локации (серверы):</b>")
    try:
        async with XUIClient() as client:
            inbounds = await client.get_inbounds()
            for key in LOCATION_ORDER:
                spot = LOCATIONS[key]
                try:
                    inbound, auto_picked, source = await resolve_location_inbound(client, spot)
                    lines.append(
                        f"   {spot['title']}: подключение #{inbound.get('id')} "
                        f"«{escape(str(inbound.get('remark') or '—'))}» — "
                        f"<i>{escape(source)}</i>"
                    )
                except Exception as exc:
                    lines.append(f"   {spot['title']}: ❌ {escape(str(exc)[:120])}")
            lines.append(
                "   В панели: "
                + ", ".join(f"#{item.get('id')} «{escape(str(item.get('remark') or '—'))}»"
                            for item in inbounds[:8])
            )
            declared = max(TARIFF_LEVELS[level]["tunnels"] for level in TARIFF_LEVEL_ORDER)
            if len(configured_locations()) < declared:
                lines.append(
                    f"   ⚠️ В тарифах указано до {declared} туннелей, а локаций настроено "
                    f"{len(configured_locations())}. Чтобы включить остальные, добавь "
                    "подключения в панели и переменные XUI_INBOUND_&lt;ЛОКАЦИЯ&gt;."
                )
    except Exception as exc:
        lines.append(f"   ❌ Не удалось прочитать подключения: {escape(str(exc)[:120])}")

    # Ссылка-подписка: клиенты получают её вместо ключа, поэтому проверяем адрес
    lines.append("")
    lines.append("📥 <b>Сервис подписок (ссылка для клиентов):</b>")
    try:
        if SUB_URL_BASE:
            lines.append(f"   Задан SUB_URL_BASE: <code>{escape(SUB_URL_BASE)}</code>")
        async with XUIClient() as client:
            settings = await fetch_panel_settings(client)
            if not settings:
                lines.append("   ⚠️ Панель не отдала настройки подписок — бот соберёт адрес сам.")
            elif settings.get("subEnable") is False:
                lines.append("   ⚠️ Сервис подписок <b>выключен</b> в панели "
                             "(Settings → Subscription → Enable). Клиенты получат ключ vless.")
            else:
                lines.append(
                    f"   Панель: порт <code>{escape(str(settings.get('subPort')))}</code>, "
                    f"путь <code>{escape(str(settings.get('subPath')))}</code>, "
                    f"домен <code>{escape(str(settings.get('subDomain') or '—'))}</code>, "
                    f"URI <code>{escape(str(settings.get('subURI') or '—'))}</code>"
                )
            candidates = subscription_candidates(settings)
        for base, source in candidates[:3]:
            ok, detail = await _check_sub_link(build_sub_link(base, "test-address"))
            lines.append(
                f"   {'✅' if ok else '❌'} <code>{escape(base)}</code> — {escape(source)}"
                + ("" if ok else f" ({escape(detail)})")
            )
        if candidates:
            lines.append(f"   Бот использует: <code>{escape(candidates[0][0])}</code>/&lt;Sub ID&gt;")
    except Exception as exc:
        lines.append(f"   ❌ Не удалось проверить: <code>{escape(str(exc))}</code>")

    await message.answer("\n".join(lines)[:4000], parse_mode="HTML")


async def cmd_totp(message: Message):
    """Показывает текущий код Google Authenticator для входа в панель (только админ)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    if not XUI_2FA_SECRET:
        await message.answer(
            "ℹ️ Переменная <b>XUI_2FA_SECRET</b> не задана, поэтому код 2FA бот не считает.\n\n"
            "Добавь секрет из 3x-ui → Settings → Security → Two-factor authentication "
            "(кнопка показа секрета или QR-код) в Railway → Variables, и эта команда "
            "будет показывать актуальный код.",
            parse_mode="HTML",
        )
        return

    problem = totp_secret_problem(XUI_2FA_SECRET)
    if problem:
        await message.answer(
            f"⚠️ <b>XUI_2FA_SECRET заполнен некорректно:</b> <i>{escape(problem)}</i>\n\n"
            "Скопируй секрет заново из 3x-ui → Settings → Security → Two-factor authentication "
            "(можно вставить и целиком ссылку <code>otpauth://…</code> из QR-кода).",
            parse_mode="HTML",
        )
        return

    now = time.time()
    left = totp_seconds_left(now)
    bar = "▰" * int(left / TOTP_PERIOD * 10) + "▱" * (10 - int(left / TOTP_PERIOD * 10))
    await message.answer(
        "🔐 <b>Код Google Authenticator для панели 3x-ui:</b>\n\n"
        f"<code>{totp_code(XUI_2FA_SECRET, at=now)}</code>\n"
        f"{bar} <i>осталось {left:.0f} сек</i>\n\n"
        f"<i>Секрет оканчивается на <code>…{XUI_2FA_SECRET[-4:]}</code>. "
        "Код обновляется каждые 30 секунд и подходит для входа в панель из браузера.</i>\n\n"
        "⚠️ <i>Не пересылай этот код и не показывай его другим: он даёт доступ к панели.</i>",
        parse_mode="HTML",
    )


# =========================
# ОБРАБОТЧИКИ КНОПОК МЕНЮ
# =========================

@dp.callback_query(F.data == "main_menu")
async def cb_main_menu(cb: CallbackQuery):
    await cb.answer()
    if terms_gate_needed(cb.from_user.id):
        # Кнопка осталась от старого бота: соглашение всё ещё не подтверждено
        await show_terms_gate(cb.message)
        return
    await cb.message.edit_text(
        "🏠 <b>Главное меню:</b>\n\nВыбери необходимое действие ниже 👇",
        reply_markup=main_menu_kb(cb.from_user.id),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "get_test_key_btn")
async def cb_get_test_key(cb: CallbackQuery):
    if not trial_available_for(cb.from_user.id):
        await cb.answer("Бесплатный тест сейчас недоступен — смотри тарифы.", show_alert=True)
        return
    await cb.answer()
    # Вызываем логику выдачи ключа
    await cmd_test_vpn(cb.message)


@dp.callback_query(F.data == "reset_my_vpn")
async def cb_reset_my_vpn(cb: CallbackQuery):
    await cb.answer("Сбрасываю ключ...", show_alert=False)
    await cmd_reset_vpn(cb.message)


@dp.callback_query(F.data == "noop")
async def cb_noop(cb: CallbackQuery):
    """Разделитель в кнопках — просто гасим нажатие."""
    await cb.answer()


@dp.callback_query(F.data == "tariffs")
async def cb_tariffs(cb: CallbackQuery):
    """Шаг 1: бесплатные предложения и выбор типа подписки."""
    await cb.answer()
    if terms_gate_needed(cb.from_user.id):
        await show_terms_gate(cb.message)
        return
    text = tariffs_intro(cb.from_user.id)

    text += ("\n📄 <i>Оплачивая любой тариф, ты принимаешь условия сервиса — /terms, "
             "политику конфиденциальности — /privacy.</i>\n\n")

    if not payments_enabled():
        text += "ℹ️ <i>Приём оплаты временно недоступен — администратор настраивает платёжную систему.</i>\n"
    elif PAYMENTS_MODE == "stars":
        text += ("⭐️ <i>Оплата в звёздах Telegram: они уже есть в твоём аккаунте или покупаются в пару нажатий. "
                 "Ключ придёт сразу после оплаты.</i>")
    elif PAYMENTS_MODE == "platega":
        text += ("💳 <i>Оплата картой, через СБП или электронный кошелёк на защищённой "
                 "странице Platega. Ключ придёт автоматически после оплаты.</i>")
    elif PAYMENTS_MODE == "yookassa":
        text += ("💳 <i>Оплата картой или через СБП на защищённой странице ЮKassa. "
                 "Ключ придёт автоматически после оплаты.</i>")
    else:
        text += ("💳 <i>Оплата картой прямо в Telegram — без перехода на другие сайты. "
                 "Ключ придёт сразу после оплаты.</i>")

    await cb.message.edit_text(text, reply_markup=tariffs_kb(cb.from_user.id), parse_mode="HTML")


@dp.callback_query(F.data.startswith("tkind_"))
async def cb_tariff_kind(cb: CallbackQuery):
    """Шаг 2: уровни выбранного типа подписки (по времени / по трафику)."""
    await cb.answer()
    kind = cb.data.removeprefix("tkind_")
    if kind not in TARIFF_KINDS:
        await cb.answer("Такого типа подписки нет.", show_alert=True)
        return
    try:
        await cb.message.edit_text(kind_levels_text(kind), reply_markup=kind_levels_kb(kind),
                                   parse_mode="HTML")
    except Exception:
        await cb.message.answer(kind_levels_text(kind), reply_markup=kind_levels_kb(kind),
                                parse_mode="HTML")


@dp.callback_query(F.data.startswith("tlvl_"))
async def cb_tariff_level(cb: CallbackQuery):
    """Шаг 3 для многотуннельных тарифов — сразу подтверждение; для одного туннеля — выбор сервера."""
    await cb.answer()
    parts = cb.data.removeprefix("tlvl_").split("_")
    if len(parts) != 2 or not parts[1].isdigit():
        await cb.answer("Не понял выбор — начни заново из тарифов.", show_alert=True)
        return
    kind, level = parts[0], int(parts[1])
    plan = TARIFFS.get(tariff_key(kind, level))
    if plan is None:
        await cb.answer("Такого тарифа нет.", show_alert=True)
        return

    if plan["tunnels"] > 1:
        # Доступны все локации — сервер выбирать не нужно.
        text = tariff_confirm_text(plan, None)
        keyboard = tariff_confirm_kb(tariff_key(kind, level), None)
    else:
        text = server_pick_text(kind, level)
        keyboard = server_pick_kb(kind, level)

    try:
        await cb.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")
    except Exception:
        await cb.message.answer(text, reply_markup=keyboard, parse_mode="HTML")


@dp.callback_query(F.data.startswith("tlocs_"))
async def cb_tariff_location(cb: CallbackQuery):
    """Шаг 3 (один туннель): выбор сервера — Стокгольм или Варшава."""
    await cb.answer()
    parts = cb.data.removeprefix("tlocs_").split("_")
    if len(parts) != 3 or not parts[1].isdigit() or parts[2] not in LOCATIONS:
        await cb.answer("Не понял выбор сервера — начни заново из тарифов.", show_alert=True)
        return
    kind, level, location_key = parts[0], int(parts[1]), parts[2]
    plan = TARIFFS.get(tariff_key(kind, level))
    if plan is None:
        await cb.answer("Такого тарифа нет.", show_alert=True)
        return

    text = tariff_confirm_text(plan, location_key)
    keyboard = tariff_confirm_kb(tariff_key(kind, level), location_key)
    try:
        await cb.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")
    except Exception:
        await cb.message.answer(text, reply_markup=keyboard, parse_mode="HTML")


@dp.callback_query(F.data == "check_payment_help")
async def cb_check_payment_help(cb: CallbackQuery):
    await cb.answer(
        "Открой счёт на оплату в разделе «Тарифы» — там есть кнопка «Проверить оплату».",
        show_alert=True,
    )


@dp.callback_query(F.data.startswith("buyat_"))
async def cb_buy_at(cb: CallbackQuery):
    """
    Оплата выбранного тарифа с выбранным сервером: кнопка «💳 Оплатить» после трёх шагов.

    Данные кнопки: buyat_<тариф>[_<локация>] — например buyat_time_1_warsaw.
    """
    payload = cb.data.removeprefix("buyat_")
    location_key = None
    for key in LOCATIONS:
        suffix = f"_{key}"
        if payload.endswith(suffix):
            payload, location_key = payload[: -len(suffix)], key
            break
    tariff_key = payload

    tariff = TARIFFS.get(tariff_key)
    if not tariff:
        await cb.answer("Тариф не найден.", show_alert=True)
        return
    if tariff.get("tunnels", 1) <= 1 and not location_key:
        # Защита от старой кнопки: сервер у такого тарифа выбрать обязательно.
        await cb.answer("Выбери сервер заново — открой «Тарифы».", show_alert=True)
        return

    await cb.answer("Готовлю оплату...")
    try:
        await start_checkout(cb.message.chat.id, cb.from_user.id, tariff_key, location_key)
    except PaymentError as exc:
        await cb.message.answer(str(exc), parse_mode="HTML")
    except Exception as exc:
        logger.exception("Ошибка при создании оплаты: %s", exc)
        await cb.message.answer(
            "❌ Не удалось создать счёт на оплату.\n"
            "Попробуй ещё раз через минуту или напиши в поддержку /start → «Поддержка».",
            parse_mode="HTML",
        )


@dp.callback_query(F.data.startswith("buy_"))
async def cb_buy(cb: CallbackQuery):
    """Покупка тарифа: выставляет счёт или создаёт платёж (без выбора сервера)."""
    tariff_key = cb.data.removeprefix("buy_")

    if tariff_key == "trial":
        if not trial_available_for(cb.from_user.id):
            await cb.answer("Бесплатный тест сейчас недоступен — смотри платные тарифы.", show_alert=True)
            return
        await cb.answer()
        await cmd_test_vpn(cb.message)
        return

    if tariff_key == PROMO_KEY:
        if not promo_enabled():
            await cb.answer("Промо-доступ сейчас закрыт.", show_alert=True)
            return
        await cb.answer("Активирую промо-доступ...")
        try:
            await grant_promo(cb.message.chat.id, cb.from_user.id)
        except PaymentError as exc:
            await cb.message.answer(str(exc), parse_mode="HTML")
        except Exception as exc:
            logger.exception("Не удалось выдать промо-доступ: %s", exc)
            await cb.message.answer(
                "❌ Не получилось активировать промо-доступ. Попробуй ещё раз через минуту "
                "или напиши в поддержку.",
                parse_mode="HTML",
            )
        return

    tariff = TARIFFS.get(tariff_key)
    if not tariff:
        await cb.answer("Тариф не найден.", show_alert=True)
        return

    # Кнопки «buy_*» приходят из старых сообщений и от промо/теста: сервер не выбран —
    # для тарифа на один туннель берём локацию по умолчанию (первую в каталоге).
    location_key = None
    await cb.answer("Готовлю оплату...")
    try:
        await start_checkout(cb.message.chat.id, cb.from_user.id, tariff_key, location_key)
    except PaymentError as exc:
        await cb.message.answer(str(exc), parse_mode="HTML")
    except Exception as exc:
        logger.exception("Ошибка при создании оплаты: %s", exc)
        await cb.message.answer(
            "❌ Не удалось создать счёт на оплату.\n"
            "Попробуй ещё раз через минуту или напиши в поддержку /start → «Поддержка».",
            parse_mode="HTML",
        )


@dp.pre_checkout_query()
async def on_pre_checkout(query: PreCheckoutQuery):
    """
    Telegram спрашивает подтверждение перед списанием (ответ нужен в течение 10 секунд).

    Здесь только быстрые проверки по журналу заказов — без обращения к панели 3x-ui.
    """
    order = await payment_store.get(query.invoice_payload or "")
    if order is None:
        await query.answer(ok=False, error_message="Счёт устарел — создай новый в меню «Тарифы».")
        return
    if order.get("status") == "paid":
        await query.answer(ok=False, error_message="Этот счёт уже оплачен.")
        return
    if query.total_amount != order_amount(order):
        await query.answer(ok=False, error_message="Сумма счёта изменилась — создай новый в меню «Тарифы».")
        return
    await query.answer(ok=True)


@dp.message(F.successful_payment)
async def on_successful_payment(message: Message):
    """Telegram подтвердил оплату (Stars или платёжный провайдер) — выдаём ключ."""
    payment = message.successful_payment
    order = await payment_store.get(payment.invoice_payload or "")
    if order is None:
        logger.error("Оплата по неизвестному заказу: payload=%r", payment.invoice_payload)
        await message.answer(
            "✅ Оплата получена, но заказ не найден в журнале.\n"
            "Напиши в поддержку — разберёмся вручную.\n"
            f"<i>Номер платежа: <code>{escape(str(payment.telegram_payment_charge_id))}</code></i>",
            parse_mode="HTML",
        )
        return

    if order["tg_id"] != message.from_user.id and not is_admin(message.from_user.id):
        logger.warning(
            "Платёж по заказу %s пришёл от %s, а заказ создан для %s",
            order["id"], message.from_user.id, order["tg_id"],
        )

    try:
        result = await fulfill_order(
            order,
            charge_id=payment.telegram_payment_charge_id,
            provider_charge_id=payment.provider_payment_charge_id,
        )
    except Exception as exc:
        logger.exception("Выдача после оплаты не удалась: %s", exc)
        return

    info = result.get("info")
    if not info:
        # Платёж уже обработан ранее — просто подтверждаем пользователю
        await message.answer("✅ Этот платёж уже учтён, подписка активна. Проверить срок: /profile")
        return

    # Сюда попадаем только при новой оплате: notify_payment_success уже отправил ключ,
    # поэтому дублировать его не нужно — достаточно короткого подтверждения при ошибке доставки.
    logger.info("Заказ %s оплачен и выдан (режим %s).", order["id"], order["mode"])


@dp.callback_query(F.data.startswith("cancelorder_"))
async def cb_cancel_order(cb: CallbackQuery):
    """
    Отмена неоплаченного заказа.

    Заказ получает статус canceled и пропадает из ожидающих: клиенту больше не нужно
    ничего оплачивать, а ссылка в сообщении убирается, чтобы не заплатил случайно.
    Важно: платёжную страницу Platega это не «закрывает». Если клиент всё-таки
    оплатит по старой ссылке, деньги списываются — в этом случае бот выдаст ключ
    (см. process_platega_callback), чтобы оплата не пропала.
    """
    order_id = cb.data.removeprefix("cancelorder_")
    order = await payment_store.get(order_id)

    if order is None or order["tg_id"] != cb.from_user.id:
        await cb.answer("Заказ не найден.", show_alert=True)
        return
    if order.get("status") == "paid":
        await cb.answer("Заказ уже оплачен — отменить его нельзя.", show_alert=True)
        return
    if order.get("status") == "canceled":
        await cb.answer("Заказ уже отменён.", show_alert=True)
        return

    await payment_store.update(order_id, status="canceled", canceled_at=int(time.time()))
    logger.info("Заказ %s отменён пользователем %s", order_id, cb.from_user.id)
    await cb.answer("Заказ отменён")

    text = (
        "❌ <b>Заказ отменён</b>\n\n"
        "Оплачивать его больше не нужно — если деньги ещё не списаны, ничего не произойдёт.\n"
        f"<i>Номер заказа: <code>{escape(order_id)}</code></i>\n\n"
        "Захочешь вернуться — выбери тариф заново."
    )
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs")],
            [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
        ]
    )
    try:
        await cb.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")
    except Exception as exc:
        # Сообщение могло быть уже удалено или быть старше 48 часов — тогда просто пишем новое.
        logger.info("Не удалось отредактировать сообщение заказа %s: %s", order_id, exc)
        try:
            await cb.message.answer(text, reply_markup=keyboard, parse_mode="HTML")
        except Exception:
            pass


@dp.callback_query(F.data.startswith("checkpay_"))
async def cb_check_payment(cb: CallbackQuery):
    """
    Ручная проверка оплаты (ЮKassa, Platega) — если вебхук не дошёл.

    У Platega статус можно переспросить у API (GET /transaction/{id}), поэтому
    такая проверка полностью повторяет обработку callback.
    """
    order_id = cb.data.removeprefix("checkpay_")
    order = await payment_store.get(order_id)

    if order is None or order["tg_id"] != cb.from_user.id:
        await cb.answer("Заказ не найден.", show_alert=True)
        return

    if order.get("status") == "paid":
        await cb.answer("Оплата уже подтверждена ✅", show_alert=True)
        return

    if order.get("status") == "canceled":
        await cb.answer("Заказ отменён — оплата по нему не нужна.", show_alert=True)
        return

    await cb.answer("Проверяю оплату...")
    state, details = await recheck_order_payment(order)

    if state == "paid":
        try:
            result = await fulfill_order(
                order,
                charge_id=order_charge_id(order) or details,
            )
        except Exception as exc:
            logger.exception("Ручная проверка оплаты: выдача не удалась: %s", exc)
            await cb.message.answer(
                "✅ Оплата прошла, но выдача ключа задержалась — уже разбираюсь. "
                f"Номер заказа: <code>{order_id}</code>",
                parse_mode="HTML",
            )
            return
        if not result.get("info"):
            await cb.message.answer("✅ Оплата уже учтена, ключ выдан ранее. Проверить: /profile")
        return

    if state == "canceled":
        await payment_store.update(order_id, status="canceled")
        await cb.message.answer(
            "❌ Платёж отменён или счёт истёк.\nПопробуй ещё раз: меню «Тарифы» → выбери тариф.",
            parse_mode="HTML",
        )
        return

    if state == "error":
        await cb.message.answer(details, parse_mode="HTML")
        return

    if order.get("mode") == "platega":
        await cb.message.answer(
            "⏳ <b>Platega ещё не подтвердила оплату.</b>\n\n"
            "Подтверждение приходит на сервер бота — обычно это 5–15 секунд после платежа. "
            "Если деньги уже списались:\n"
            "1. подожди минуту и нажми «Проверить оплату» ещё раз — бот сам спросит статус "
            "у Platega;\n"
            "2. напиши в поддержку — проверим платёж по номеру заказа "
            f"<code>{order_id}</code>.",
            parse_mode="HTML",
        )
        return

    await cb.message.answer(
        f"⏳ Платёж пока в статусе <b>{escape(str(details))}</b> — оплата ещё не завершена.\n"
        "Если ты только что оплатил, подожди минуту и нажми «Проверить оплату» снова.",
        parse_mode="HTML",
    )


async def cmd_payments(message: Message):
    """Статистика оплат и диагностика платёжного режима (только админ)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    stats = payment_store.stats()
    lines = [
        "💳 <b>Оплата подписок:</b>\n",
        f"• Режим: <b>{escape(payments_mode_title())}</b> (<code>{PAYMENTS_MODE}</code>)",
        f"• Журнал заказов: <code>{escape(PAYMENT_STORE_FILE)}</code>",
    ]

    if PAYMENTS_MODE == "provider":
        lines.append(f"• Provider token: {'задан ✅' if PAYMENT_PROVIDER_TOKEN else 'НЕ задан ❌'} "
                     f"({provider_mode_title()})")
        lines.append(f"• Чек 54-ФЗ: {'передаётся' if TELEGRAM_SEND_RECEIPT else 'не передаётся'}")
    if PAYMENTS_MODE == "yookassa":
        lines.append(f"• Shop ID: <code>{escape(YOOKASSA_SHOP_ID or 'не задан')}</code>"
                     f" {'(тестовый магазин 🧪)' if YOOKASSA_TEST else ''}")
        lines.append(f"• Секретный ключ: {'задан ✅' if YOOKASSA_SECRET_KEY else 'НЕ задан ❌'}")
        if PUBLIC_BASE_URL:
            lines.append(f"• Вебхук: <code>{escape(PUBLIC_BASE_URL + '/yookassa/webhook')}</code>"
                         + (" (автонастройка ✅)" if YOOKASSA_OAUTH_TOKEN else " (добавляется в кабинете ЮKassa)"))
        else:
            lines.append("• Вебхук: ⚠️ PUBLIC_BASE_URL не задан")
    if PAYMENTS_MODE == "platega":
        lines.append(f"• Merchant ID: <code>{escape(PLATEGA_MERCHANT_ID or 'не задан')}</code>")
        lines.append(f"• API-ключ (X-Secret): {'задан ✅' if PLATEGA_SECRET else 'НЕ задан ❌'}")
        lines.append(f"• API: <code>{escape(PLATEGA_API_URL)}</code>, "
                     f"валюта {escape(PLATEGA_CURRENCY)}")
        lines.append("• Способ оплаты: "
                     + (escape(PLATEGA_METHODS.get(PLATEGA_METHOD, str(PLATEGA_METHOD)))
                        if PLATEGA_METHOD else "выбирает плательщик на странице Platega"))
        lines.append(f"• Callback URL: <code>{escape(PUBLIC_BASE_URL + PLATEGA_WEBHOOK_PATH)}</code>"
                     if PUBLIC_BASE_URL else "• Callback URL: ⚠️ PUBLIC_BASE_URL не задан")
        lines.append("• Защита callback: заголовки X-MerchantId + X-Secret")

    if PAYMENTS_MODE == "stars":
        lines.append(f"• Курс пересчёта: 1 ⭐️ ≈ {STARS_RUB_RATE} ₽ (меняется через STARS_RUB_RATE)")
    tariff = TARIFFS.get(PROMO_KEY) or {}
    if promo_enabled():
        lines.append(
            f"• Промо-доступ: включён 🎉 {escape(tariff.get('name', ''))} — "
            + ("один раз на аккаунт" if PROMO_ONCE else "без ограничения (PROMO_ONCE=0)")
        )
    else:
        lines.append("• Промо-доступ: выключен (<code>PROMO_ENABLED=0</code> или тариф удалён)")

    if test_tools_enabled():
        lines.append("• Проверка без оплаты: /test_pay ✅ (ключ выдаётся тем же путём, что после оплаты)")
    elif PAYMENTS_MODE == "platega" and admin_tools_enabled():
        lines.append("• Диагностика магазина без денег: /platega_check")

    lines += [
        "",
        f"• Заказов всего: <b>{stats['orders_total']}</b>, оплачено: <b>{stats['paid_count']}</b>",
        f"• Выручка: <b>{stats['rub']} ₽</b> / <b>{stats['stars']} ⭐️</b>",
    ]
    if stats.get("promo_count"):
        lines.append(
            f"• Промо-доступов выдано: <b>{stats['promo_count']}</b> "
            "(бесплатно, в выручку не входит)"
        )
    if stats["by_tariff"]:
        breakdown = ", ".join(f"{TARIFFS.get(k, {}).get('name', k)}: {v}" for k, v in stats["by_tariff"].items())
        lines.append(f"• По тарифам: {escape(breakdown)}")

    recent = payment_store.recent(5)
    if recent:
        lines.append("\n<b>Последние заказы:</b>")
        for order in recent:
            icons = {"paid": "✅", "pending": "⏳", "canceled": "❌", "failed": "⚠️"}
            amount = f"{order['amount_stars']} ⭐️" if order["currency"] == "XTR" else f"{order['amount_rub']} ₽"
            lines.append(
                f"{icons.get(order.get('status'), '❔')} <code>{escape(order['id'])}</code> — "
                f"{escape(order.get('tariff_name', '?'))}, {amount}, TG <code>{order['tg_id']}</code>"
                + (" <i>(ключ выдан)</i>" if order.get("provisioned") else "")
            )

    if not payments_enabled():
        lines.append(
            "\n⚠️ <b>Оплата выключена.</b> Задай PAYMENTS_MODE=stars или platega "
            "(проще всего), provider либо yookassa — инструкция в README."
        )

    # Кнопки проверок показываем только в тестовом режиме — в боевом их нет.
    keyboard = []
    if test_tools_enabled():
        keyboard.append([InlineKeyboardButton(text="🧪 Проверить выдачу ключа без оплаты",
                                              callback_data="testpay_menu")])
        if PAYMENTS_MODE == "platega":
            keyboard.append([InlineKeyboardButton(text="🔍 Проверить Platega (без денег)",
                                                  callback_data="platega_check")])

    await message.answer(
        "\n".join(lines)[:4000],
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard) if keyboard else None,
    )


# =========================
# ПРОВЕРКА ВЫДАЧИ КЛЮЧА БЕЗ ОПЛАТЫ (только для админа)
# =========================

def test_pay_kb() -> InlineKeyboardMarkup:
    """Кнопки выбора тарифа и сервера для проверочной выдачи."""
    buttons = []
    for key in paid_tariff_keys():
        data = TARIFFS[key]
        label = f"{data['name']} — {days_label(data['days'])}, {data['traffic']}"
        if data.get("tunnels", 1) > 1:
            buttons.append([InlineKeyboardButton(text=label, callback_data=f"testpay_run_{key}")])
            continue
        # Однотуннельный тариф: сервер выбирается, поэтому кнопка на каждую локацию.
        for spot in configured_locations():
            buttons.append([InlineKeyboardButton(
                text=f"{label} ({spot['short']})",
                callback_data=f"testpay_run_{key}_{spot['key']}",
            )])
    buttons.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def test_pay_intro() -> str:
    return (
        "🧪 <b>Проверка выдачи ключа без оплаты</b>\n\n"
        "Выбери тариф — бот прогонит ровно тот путь, что и после настоящей оплаты: "
        "создаст клиента в 3x-ui и пришлёт сообщение с ключом. Деньги не списываются, "
        "в выручку заказ не попадёт, счёт в платёжной системе не создаётся.\n\n"
        "<i>Инструкция: команда /test_pay &lt;тариф&gt; [сервер], тарифы — "
        + ", ".join(f"<code>{key}</code>" for key in paid_tariff_keys())
        + "; серверы — " + ", ".join(f"<code>{spot['key']}</code>" for spot in configured_locations())
        + ".</i>"
    )


async def cmd_test_pay(message: Message):
    """Проверяет выдачу ключа без реальной оплаты (только админ)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return
    if not test_pay_enabled():
        await message.answer(
            "🧪 Проверка без оплаты выключена.\n\n"
            "Включи переменную <b>PAYMENTS_ALLOW_TEST_PAY=1</b> в Railway → Variables. "
            "После проверки переменную можно убрать.",
            parse_mode="HTML",
        )
        return

    args = (message.text or "").split()
    if len(args) < 2:
        await message.answer(test_pay_intro(), reply_markup=test_pay_kb(), parse_mode="HTML")
        return

    tariff_key = args[1].strip().lower()
    if tariff_key not in TARIFFS or TARIFFS[tariff_key]["price"] <= 0:
        await message.answer(
            f"❓ Неизвестный тариф: <code>{escape(tariff_key)}</code>\n"
            "Доступные: " + ", ".join(f"<code>{key}</code>" for key in paid_tariff_keys()),
            parse_mode="HTML",
        )
        return

    # Второй аргумент — сервер: /test_pay time_1 warsaw
    location_key = location_from_text(args[2]) if len(args) > 2 else None
    if len(args) > 2 and location_key is None:
        await message.answer(
            "❓ Неизвестный сервер. Доступные: "
            + ", ".join(f"<code>{spot['key']}</code>" for spot in configured_locations()),
            parse_mode="HTML",
        )
        return

    wait_msg = await message.answer("🧪 Выдаю тестовый ключ (оплата не требуется)...")
    try:
        await simulate_successful_payment(message.chat.id, message.from_user.id, tariff_key,
                                          location_key)
    except Exception as exc:
        logger.error("Проверка выдачи без оплаты не удалась: %s", exc)
        await send_error_message(message, exc)
    finally:
        try:
            await wait_msg.delete()
        except Exception:
            pass


async def cb_testpay_menu(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        await cb.answer("Только для администратора — /myid покажет твой ID.", show_alert=True)
        return
    if not test_pay_enabled():
        await cb.answer("Проверка без оплаты выключена (PAYMENTS_ALLOW_TEST_PAY=1).", show_alert=True)
        return
    await cb.answer()
    await cb.message.answer(test_pay_intro(), reply_markup=test_pay_kb(), parse_mode="HTML")


async def cb_testpay_run(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        await cb.answer("Только для администратора — /myid покажет твой ID.", show_alert=True)
        return
    if not test_pay_enabled():
        await cb.answer("Проверка без оплаты выключена (PAYMENTS_ALLOW_TEST_PAY=1).", show_alert=True)
        return
    payload = cb.data.removeprefix("testpay_run_")
    location_key = None
    for key in LOCATIONS:
        if payload.endswith(f"_{key}"):
            payload, location_key = payload[: -len(f"_{key}")], key
            break
    tariff_key = payload
    if tariff_key not in TARIFFS or TARIFFS[tariff_key]["price"] <= 0:
        await cb.answer("Такого тарифа нет.", show_alert=True)
        return
    await cb.answer("Выдаю тестовый ключ...")
    try:
        await simulate_successful_payment(cb.message.chat.id, cb.from_user.id, tariff_key, location_key)
    except Exception as exc:
        logger.error("Проверка выдачи без оплаты не удалась: %s", exc)
        await cb.message.answer(f"❌ Не получилось: <code>{escape(_snip(str(exc), 300))}</code>", parse_mode="HTML")


async def cb_testpay_del(cb: CallbackQuery):
    """Удаляет подписку, созданную проверочной выдачей."""
    if not is_admin(cb.from_user.id):
        await cb.answer("Только для администратора — /myid покажет твой ID.", show_alert=True)
        return
    order_id = cb.data.removeprefix("testpay_del_")
    order = await payment_store.get(order_id)
    if not order or not order.get("simulated"):
        await cb.answer("Тестовый заказ не найден.", show_alert=True)
        return

    await cb.answer("Удаляю тестовую подписку...")
    email = f"tg-paid-{order['tg_id']}"
    reference = f"test-{order_id}"

    try:
        async with XUIClient() as client:
            inbounds = await client.get_inbounds()
            removed = 0
            foreign = False
            for inbound in inbounds:
                settings = as_dict(inbound.get("settings"))
                for candidate in settings.get("clients") or []:
                    if not isinstance(candidate, dict) or str(candidate.get("email")) != email:
                        continue
                    if comment_has_payment_ref(candidate.get("comment"), reference):
                        await client.delete_client(inbound.get("id"), email, candidate.get("id"))
                        removed += 1
                    else:
                        # По этому клиенту выдана не тестовая подписка — чужое не удаляем.
                        foreign = True
                    break
    except Exception as exc:
        logger.error("Не удалось удалить тестовую подписку %s: %s", order_id, exc)
        await cb.message.answer(f"❌ Не получилось удалить: <code>{escape(_snip(str(exc), 300))}</code>", parse_mode="HTML")
        return

    await payment_store.update(order_id, status="canceled")
    if removed:
        await cb.message.answer(
            f"🗑 Тестовая подписка <code>{email}</code> удалена из панели. "
            "Выдача ключа проверена — теперь можно принимать настоящие оплаты.",
            parse_mode="HTML",
        )
    elif foreign:
        await cb.message.answer(
            f"ℹ️ У клиента <code>{email}</code> подписка выдана не тестовым заказом — удалять не стал. "
            "Если нужно снять ключ, используй /revoke.",
            parse_mode="HTML",
        )
    else:
        await cb.message.answer(
            f"ℹ️ Подписки <code>{email}</code> в панели уже нет — заказ помечен отменённым.",
            parse_mode="HTML",
        )


async def cmd_platega_check(message: Message):
    """Проверяет настройки Platega без денег: ключи, API, адрес callback."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return
    if PAYMENTS_MODE != "platega":
        await message.answer(
            "ℹ️ Команда нужна для приёма оплаты через Platega. Сейчас режим оплаты: "
            f"<b>{escape(payments_mode_title())}</b>.",
            parse_mode="HTML",
        )
        return

    wait_msg = await message.answer("🔍 Проверяю настройки Platega (без оплаты)...")
    try:
        text = await platega_self_check()
    except Exception as exc:
        logger.error("Проверка Platega не удалась: %s", exc)
        await send_error_message(message, exc)
        return
    finally:
        try:
            await wait_msg.delete()
        except Exception:
            pass
    await message.answer(text, parse_mode="HTML")


async def cb_platega_check(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        await cb.answer("Только для администратора — /myid покажет твой ID.", show_alert=True)
        return
    await cb.answer("Проверяю настройки Platega...")
    try:
        text = await platega_self_check()
    except Exception as exc:
        logger.error("Проверка Platega не удалась: %s", exc)
        text = f"❌ Не получилось: <code>{escape(_snip(str(exc), 300))}</code>"
    await cb.message.answer(text, parse_mode="HTML")


async def delete_paid_clients(client, email: str) -> int:
    """
    Удаляет клиента с этим email во всех подключениях панели.

    Тарифы на несколько туннелей создают клиента в каждой локации — возврат
    или блокировка должны снимать доступ везде, а не только на первом сервере.
    """
    inbounds = await client.get_inbounds()
    removed = 0
    for inbound in inbounds:
        settings = as_dict(inbound.get("settings"))
        for candidate in settings.get("clients") or []:
            if isinstance(candidate, dict) and str(candidate.get("email")) == email:
                await client.delete_client(inbound.get("id"), email, candidate.get("id"))
                removed += 1
                break
    return removed


async def cmd_revoke(message: Message):
    """Удаляет платную подписку (для возвратов и блокировок)."""
    if not is_admin(message.from_user.id):
        await message.answer(admin_denied_text(message.from_user.id), parse_mode="HTML")
        return

    args = (message.text or "").split()
    target = args[1] if len(args) > 1 else str(message.from_user.id)
    if not target.isdigit():
        await message.answer("Использование: <code>/revoke [telegram_id]</code>", parse_mode="HTML")
        return

    wait_msg = await message.answer(f"⏳ Удаляю платную подписку пользователя <code>{target}</code>...")
    try:
        async with XUIClient() as client:
            email = f"tg-paid-{target}"
            removed = await delete_paid_clients(client, email)

        try:
            await wait_msg.delete()
        except Exception:
            pass

        if removed:
            await message.answer(
                f"🗑 <b>Подписка <code>{email}</code> удалена из панели "
                f"({removed} {tunnels_word(removed)}: все локации тарифа).</b>\n\n"
                "<i>Если это возврат по оплате — сделай возврат в личном кабинете "
                "платёжной системы (ЮKassa) или через @BotFather для Stars.</i>",
                parse_mode="HTML",
            )
        else:
            await message.answer(f"ℹ️ Подписки <code>{email}</code> в панели нет.", parse_mode="HTML")
    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


@dp.callback_query(F.data == "profile")
async def cb_profile(cb: CallbackQuery):
    await cb.answer("Загружаю данные подписки...")
    await send_profile(cb.message, cb.from_user.id)


async def send_profile(message: Message, user_id: int):
    """Показывает статус подписки: срок, трафик, ключ."""
    try:
        sub = await get_paid_subscription(user_id)
    except Exception as exc:
        logger.warning("Не удалось прочитать подписку %s: %s", user_id, exc)
        sub = None
        sub_error = True
    else:
        sub_error = False

    lines = [
        "👤 <b>Твой профиль:</b>\n",
        f"• Telegram ID: <code>{user_id}</code>",
        "",
        "💳 <b>Подписка:</b>",
        subscription_status_text(sub),
    ]

    if sub_error:
        lines.append("<i>Не удалось получить данные из панели — попробуй позже.</i>")

    entries = (sub or {}).get("entries") or []
    if entries:
        try:
            async with XUIClient() as client:
                for entry in entries:
                    inbound = entry["inbound"]
                    params = extract_vless_params(inbound)
                    entry["link"] = build_vless_link(entry["client"], inbound, params)
                    entry["sub_link"] = None
                    sub_id = entry["client"].get("subId")
                    if sub_id:
                        base, _note = await get_subscription_base(client, sub_id=str(sub_id),
                                                                  probe=False)
                        if base:
                            entry["sub_link"] = build_sub_link(base, str(sub_id))
            info = {"link": entries[0].get("link"), "sub_link": entries[0].get("sub_link"),
                    "entries": entries}
            lines += ["", access_block(info, heading="🔗 <b>Твоя ссылка-подписка:</b>")]
        except Exception:
            pass

    profile_rows = [[InlineKeyboardButton(text="💰 Продлить / сменить тариф", callback_data="tariffs")]]
    # Бесплатный тест предлагаем только тем, кому он доступен (TRIAL_PUBLIC=1 или админ).
    if trial_button_visible(user_id):
        profile_rows.append([InlineKeyboardButton(text="🔑 Тестовый ключ (24 ч)",
                                                  callback_data="get_test_key_btn")])
    profile_rows.append([InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")])

    keyboard = InlineKeyboardMarkup(inline_keyboard=profile_rows)
    await message.answer("\n".join(lines), reply_markup=keyboard, parse_mode="HTML")


@dp.message(Command("profile"))
async def cmd_profile(message: Message):
    if await terms_gate(message):
        return
    await send_profile(message, message.from_user.id)


@dp.message(Command("help"))
async def cmd_help(message: Message):
    """Пошаговая инструкция по подключению: устройство → приложение → ключ → проверка."""
    if await terms_gate(message):
        return
    await message.answer(INSTALL_INTRO, reply_markup=install_menu_kb(), parse_mode="HTML")


@dp.message(Command("install"))
async def cmd_install(message: Message):
    """Псевдоним /help — многие ищут инструкцию словом «install»."""
    await cmd_help(message)


@dp.callback_query(F.data == "help_menu")
async def cb_help_menu(cb: CallbackQuery):
    await cb.answer()
    try:
        await cb.message.edit_text(INSTALL_INTRO, reply_markup=install_menu_kb(), parse_mode="HTML")
    except Exception:
        await cb.message.answer(INSTALL_INTRO, reply_markup=install_menu_kb(), parse_mode="HTML")


@dp.callback_query(F.data.startswith("help_"))
async def cb_help_platform(cb: CallbackQuery):
    """Инструкция для выбранного устройства (help_ios, help_android, help_check, ...)."""
    key = cb.data.removeprefix("help_")
    if key == "check":
        await cb.answer("Показываю проверку подключения…")
        text, kb = install_check_text(), install_step_kb(key)
    elif key == "trouble":
        await cb.answer("Открываю чек-лист…")
        text, kb = install_trouble_text(), install_step_kb(key)
    elif key in PLATFORM_TITLES:
        await cb.answer()
        text, kb = install_text(key), install_step_kb(key)
    else:
        await cb.answer()
        text, kb = INSTALL_INTRO, install_menu_kb()

    try:
        await cb.message.edit_text(text, reply_markup=kb, parse_mode="HTML",
                                   disable_web_page_preview=True)
    except Exception:
        await cb.message.answer(text, reply_markup=kb, parse_mode="HTML",
                                disable_web_page_preview=True)


@dp.callback_query(F.data == "activation")
async def cb_activation(cb: CallbackQuery):
    """Старая кнопка «Инструкция по настройке» — открывает новое меню устройств."""
    await cb.answer()
    try:
        await cb.message.edit_text(INSTALL_INTRO, reply_markup=install_menu_kb(), parse_mode="HTML")
    except Exception:
        await cb.message.answer(INSTALL_INTRO, reply_markup=install_menu_kb(), parse_mode="HTML")


# =========================
# ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ
# =========================

def support_link() -> str:
    """Ссылка на поддержку (username задаётся переменной SUPPORT_USERNAME)."""
    return f"https://t.me/{SUPPORT_USERNAME}"


def terms_operator_text() -> str:
    """Кто оказывает услугу — подставляется в соглашение (без точки на конце)."""
    return (TERMS_OPERATOR or "администрация сервиса").strip().rstrip(".")


def terms_header() -> str:
    """Шапка соглашения: заголовок, название сервиса, дата редакции и исполнитель."""
    operator_line = f"\nИсполнитель: {escape(terms_operator_text())}." if TERMS_OPERATOR else ""
    return (
        "📄 <b>ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ</b>\n"
        f"<i>Сервис «{escape(SERVICE_NAME)}» · редакция от {escape(TERMS_UPDATED)}</i>"
        f"{operator_line}\n"
    )


def terms_body() -> str:
    """
    Разделы 1–10 пользовательского соглашения (новая редакция от 22.09.2026).

    Текст соответствует файлу TERMS.md в репозитории: 10 разделов, ссылка на политику
    конфиденциальности в п. 8.3. Формулировки чуть сжаты, чтобы документ умещался
    в одно сообщение Telegram (лимит 4096 символов).
    """
    return (
        "<b>1. Общие положения</b>\n"
        f"1.1. Настоящее Соглашение регулирует использование онлайн-сервиса «{escape(SERVICE_NAME)}» — "
        "VPN-доступа через Telegram-бота (далее — «Сервис»).\n"
        "1.2. Используя Сервис (запуск бота, оплата, получение доступа), Пользователь принимает "
        "условия Соглашения в полном объёме.\n"
        "1.3. При несогласии с условиями Пользователь обязан прекратить использование Сервиса.\n\n"

        "<b>2. Характер услуг и цифровых товаров</b>\n"
        "2.1. Сервис предоставляет цифровые товары и услуги нематериального характера: доступ к VPN "
        "по подписке (срок, трафик, устройства), конфигурации и ссылки-подписки, инструкции "
        "и поддержку.\n"
        "2.2. Материалы Сервиса могут включать открытые и авторские материалы, обзоры, подборки "
        "и рекомендации.\n"
        "2.3. Ценность услуг — в систематизации, анализе, подаче, сопровождении и обновлениях, "
        "а не в эксклюзивности отдельных элементов.\n"
        "2.4. Уникальность и недоступность материалов вне Сервиса не гарантируется.\n\n"

        "<b>3. Отказ от гарантий и ответственности</b>\n"
        "3.1. Сервис предоставляется на условиях «AS IS» («как есть»).\n"
        "3.2. Не гарантируются: соответствие ожиданиям, финансовые результаты, бесперебойная "
        "и безошибочная работа.\n"
        "3.3. Администрация не отвечает за убытки (включая упущенную выгоду), последствия "
        "применения материалов, действия третьих лиц, сбои и ограничения доступа.\n"
        "3.4. Решения о применении материалов и услуг Пользователь принимает самостоятельно "
        "и на свой риск.\n\n"

        "<b>4. Законность использования</b>\n"
        "4.1. Сервис не предназначен для содействия противоправной деятельности.\n"
        "4.2. Пользователь использует Сервис в рамках применимого законодательства и правил "
        "третьих сторон.\n"
        "4.3. Ответственность за законность использования лежит на Пользователе.\n\n"

        "<b>5. Интеллектуальная собственность</b>\n"
        "5.1. Материалы Сервиса охраняются законодательством об интеллектуальной собственности.\n"
        "5.2. Копировать, распространять и передавать третьим лицам материалы Сервиса "
        "без разрешения правообладателя запрещено.\n"
        "5.3. Нарушение этих прав может повлечь ограничение доступа без компенсации.\n\n"

        "<b>6. Ограничение доступа</b>\n"
        "6.1. Доступ может быть ограничен при нарушении Соглашения, злоупотреблениях (передача "
        "доступа третьим лицам, обход лимитов), требованиях законодательства или платёжных "
        "провайдеров.\n"
        "6.2. Ограничение доступа не отменяет обязательств, возникших ранее.\n"
        "6.3. Администрация вправе отказать в обслуживании при повышенных рисках для Сервиса "
        "или третьих лиц.\n\n"

        "<b>7. Платежи и возвраты</b>\n"
        "7.1. Оплата производится на условиях, указанных в Сервисе до момента оплаты; платёж "
        "обрабатывает подключённый к Сервису платёжный провайдер.\n"
        "7.2. Возврат после предоставления доступа не производится: товары и услуги "
        "нематериальны (кроме случаев ниже).\n"
        "7.3. Возврат возможен, если услуга не оказана по технической вине Сервиса или доступ "
        "не был предоставлен.\n"
        "7.4. Обращение по возврату — в поддержку в течение 24 часов с момента оплаты.\n"
        "7.5. Решение о возврате принимается Администрацией индивидуально.\n"
        "7.6. Возврат платежа (chargeback) без обращения в поддержку не инициируется.\n\n"

        "<b>8. Конфиденциальность</b>\n"
        "8.1. Собираются только минимально необходимые технические данные для работы Сервиса.\n"
        "8.2. Применяются разумные меры защиты, но абсолютная безопасность при передаче через "
        "интернет не гарантируется.\n"
        "8.3. Подробно — в Политике конфиденциальности: /privacy.\n\n"

        "<b>9. Изменение условий</b>\n"
        "9.1. Администрация вправе вносить изменения в Соглашение.\n"
        "9.2. Актуальная версия публикуется в Сервисе.\n"
        "9.3. Продолжение использования означает согласие с новой редакцией.\n\n"

        "<b>10. Контактная информация</b>\n"
        "10.1. Поддержка в боте: "
        f"<a href=\"{support_link()}\">@{escape(SUPPORT_USERNAME)}</a>, "
        f"<a href=\"mailto:{escape(SUPPORT_EMAIL)}\">{escape(SUPPORT_EMAIL)}</a>. "
        "Ответ — в течение 24 часов в рабочие дни.\n\n"
        "Запуская бота или вводя /start, Пользователь принимает условия Соглашения."
    )


def privacy_header() -> str:
    """Шапка политики конфиденциальности."""
    return (
        "🔒 <b>ПОЛИТИКА КОНФИДЕНЦИАЛЬНОСТИ</b>\n"
        f"<i>Сервис «{escape(SERVICE_NAME)}» · редакция от {escape(TERMS_UPDATED)}</i>\n"
    )


def privacy_body() -> str:
    """
    Разделы 1–7 политики конфиденциальности (соответствует PRIVACY.md в репозитории).

    Платёжный провайдер назван обобщённо («платёжные системы»), поэтому смена кассы
    не требует новой редакции документа.
    """
    return (
        "<b>1. Общие положения</b>\n"
        "1.1. Настоящая Политика конфиденциальности (далее — «Политика») регулирует порядок "
        f"обработки и защиты информации, которую Пользователь передаёт при использовании сервиса "
        f"«{escape(SERVICE_NAME)}» — Telegram-бота и связанного с ним VPN-доступа (далее — «Сервис»).\n"
        "1.2. Используя Сервис, Пользователь подтверждает согласие с условиями Политики. Если "
        "условия не подходят — Пользователь обязан прекратить использование Сервиса.\n\n"

        "<b>2. Сбор информации</b>\n"
        "2.1. Сервис может собирать: идентификаторы аккаунта (Telegram ID, имя пользователя, "
        "отображаемое имя); техническую информацию (IP-адрес и объём трафика подключений, данные "
        "об устройстве и операционной системе в объёме, который передают клиентское приложение "
        "и Telegram); историю взаимодействий с Сервисом (заказы и платежи, факт принятия "
        "соглашения, обращения в поддержку, реферальные связи).\n"
        "2.2. Паспортные данные, документы, фотографии и другая личная информация, кроме "
        "минимально необходимой для работы, не требуются.\n\n"

        "<b>3. Использование информации</b>\n"
        "3.1. Информация используется исключительно для: работы функционала (выдача и продление "
        "доступа, учёт тарифов, срока и лимитов трафика, статистика в профиле); связи "
        "с Пользователем (уведомления, напоминания об окончании подписки, поддержка); анализа "
        "и улучшения работы Сервиса (сводная статистика).\n\n"

        "<b>4. Передача информации третьим лицам</b>\n"
        "4.1. Данные не передаются третьим лицам, кроме случаев: требования закона; "
        "необходимость исполнения обязательств перед Пользователем (например, платёжные системы "
        "получают сумму и номер заказа для проведения платежа и возврата); согласие "
        "Пользователя.\n"
        "4.2. Данные обрабатывают технические партнёры (хостинг бота, сервер VPN, платформа "
        "Telegram) в объёме, необходимом для оказания услуги. Данные не продаются и не "
        "передаются для рекламы.\n\n"

        "<b>5. Хранение и защита данных</b>\n"
        "5.1. Данные хранятся срок, необходимый для целей обработки: пока Пользователь "
        "пользуется Сервисом, и столько, сколько нужно для расчётов, поддержки и требований "
        "закона. Историю платежей храним срок, необходимый для бухгалтерии и разбора спорных "
        "ситуаций, в том числе после окончания подписки.\n"
        "5.2. Принимаются разумные меры защиты (ограничение доступа к панели и хранилищам, "
        "служебные данные не публикуются), но абсолютная безопасность при передаче через "
        "интернет не гарантируется.\n"
        "5.3. Запросить сведения о своих данных или их удаление можно в поддержке: "
        f"<a href=\"{support_link()}\">@{escape(SUPPORT_USERNAME)}</a>. Вместе с удалением данных "
        "доступ к VPN отключается по запросу Пользователя.\n\n"

        "<b>6. Отказ от ответственности</b>\n"
        "6.1. Передача информации через интернет всегда сопряжена с рисками.\n"
        "6.2. Администрация не несёт ответственности за утрату, кражу или раскрытие данных, "
        "если это произошло по вине третьих лиц или самого Пользователя.\n\n"

        "<b>7. Изменения в Политике</b>\n"
        "7.1. Администрация вправе изменять условия Политики без предварительного уведомления.\n"
        "7.2. Продолжение использования Сервиса после изменений означает согласие с новой "
        "редакцией Политики."
    )


def document_messages(header: str, body: str) -> list[str]:
    """
    Собирает документ в одно сообщение, а если он не влезает — разбивает на несколько.

    Обычно соглашение и политика умещаются в лимит Telegram (4096 символов) и уходят
    одним сообщением с раскрывающейся цитатой. При длинных SERVICE_NAME и TERMS_OPERATOR
    (или если владелец дополнит текст) бот отправит документ несколькими сообщениями —
    клиент получит весь текст, а не ошибку отправки. Режем по границам разделов:
    теги внутри раздела закрыты, поэтому HTML не ломается.
    """
    wrapper_open, wrapper_close = "<blockquote expandable>", "</blockquote>"
    whole = f"{header}\n{wrapper_open}{body}{wrapper_close}"
    if len(whole) <= TELEGRAM_MESSAGE_LIMIT:
        return [whole]

    limit = TELEGRAM_MESSAGE_LIMIT - len(wrapper_open) - len(wrapper_close) - len(header) - 1
    chunks: list[str] = []
    current = ""
    for block in body.split("\n\n"):
        candidate = f"{current}\n\n{block}" if current else block
        if current and len(candidate) > limit:
            chunks.append(current)
            current = block
        else:
            current = candidate
    if current:
        chunks.append(current)
    return [f"{header}\n{wrapper_open}{chunk}{wrapper_close}" for chunk in chunks]


def terms_text() -> str:
    """
    Пользовательское соглашение — текст, который показывается при первом запуске и в /terms.

    Это ровно тот документ, что лежит в TERMS.md репозитория (10 разделов, п. 8.3
    ссылается на политику конфиденциальности). Документ упакован в <blockquote
    expandable>: в чате видно начало и «Показать полностью», тап разворачивает текст
    на месте; клиенты Telegram старше ~10.9 показывают цитату целиком — текст
    не теряется. Лимит Telegram (4096 символов) проверяется тестами, а при
    переполнении document_messages() разобьёт документ на несколько сообщений.
    """
    return f"{terms_header()}\n<blockquote expandable>{terms_body()}</blockquote>"


def privacy_text() -> str:
    """Политика конфиденциальности — текст команды /privacy (документ PRIVACY.md)."""
    return f"{privacy_header()}\n<blockquote expandable>{privacy_body()}</blockquote>"


async def send_document(message: Message, header: str, body: str,
                        reply_markup: InlineKeyboardMarkup | None = None) -> None:
    """Отправляет документ: одним сообщением, а при переполнении — несколькими."""
    chunks = document_messages(header, body)
    for index, chunk in enumerate(chunks):
        await message.answer(
            chunk,
            reply_markup=reply_markup if index == len(chunks) - 1 else None,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )


async def edit_or_send_document(cb: CallbackQuery, header: str, body: str,
                               reply_markup: InlineKeyboardMarkup | None = None) -> None:
    """
    Показывает документ по нажатию кнопки: заменяет текущее сообщение, а если текст
    не влезает в лимит или редактирование не удалось — отправляет новое сообщение.
    """
    whole = f"{header}\n<blockquote expandable>{body}</blockquote>"
    if len(whole) <= TELEGRAM_MESSAGE_LIMIT:
        try:
            await cb.message.edit_text(whole, reply_markup=reply_markup, parse_mode="HTML",
                                       disable_web_page_preview=True)
            return
        except Exception:
            pass
    await send_document(cb.message, header, body, reply_markup)


def terms_kb(tg_id: int | None = None) -> InlineKeyboardMarkup:
    """Кнопки под соглашением: принять (если ещё не принято), поддержка, тарифы, меню."""
    rows = []
    if terms_gate_needed(tg_id):
        rows.append([InlineKeyboardButton(text="✅ Согласен — продолжить", callback_data="accept_terms")])
    rows += [
        [InlineKeyboardButton(text="🔒 Политика конфиденциальности", callback_data="privacy")],
        [InlineKeyboardButton(text="💬 Поддержка", url=support_link())],
        [InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs")],
        [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def privacy_kb(tg_id: int | None = None) -> InlineKeyboardMarkup:
    """Кнопки под политикой конфиденциальности: соглашение, поддержка, меню."""
    rows = []
    if terms_gate_needed(tg_id):
        rows.append([InlineKeyboardButton(text="✅ Согласен — продолжить", callback_data="accept_terms")])
    rows += [
        [InlineKeyboardButton(text="📄 Пользовательское соглашение", callback_data="terms")],
        [InlineKeyboardButton(text="💬 Поддержка", url=support_link())],
        [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def terms_gate_needed(tg_id: int | None) -> bool:
    """Показывать ли экран соглашения: включён TERMS_ACCEPT и человек ещё не подтвердил."""
    if not TERMS_ACCEPT:
        return False
    return not terms_store.is_accepted(tg_id)


def terms_gate_prompt() -> str:
    """Сообщение с кнопкой под текстом соглашения — просьба подтвердить."""
    return (
        f"👋 <b>Привет!</b> Это бот сервиса «{escape(SERVICE_NAME)}».\n\n"
        "Один раз нужно принять пользовательское соглашение — оно выше. "
        "Если условия устраивают, нажми кнопку ниже: до подтверждения бот не открывает "
        "меню и тарифы, а оплата отклоняется (п. 1.2 и раздел 7 соглашения)."
    )


def terms_gate_kb() -> InlineKeyboardMarkup:
    """Кнопки под первым экраном: «Согласен», политика и поддержка."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="✅ Согласен — продолжить", callback_data="accept_terms")],
            [InlineKeyboardButton(text="🔒 Политика конфиденциальности", callback_data="privacy")],
            [InlineKeyboardButton(text="💬 Поддержка", url=support_link())],
        ]
    )


async def show_terms_gate(message: Message) -> None:
    """
    Показывает экран соглашения (вместо любой другой команды до подтверждения).

    Двумя сообщениями: сам документ занимает почти весь лимит Telegram на сообщение
    (4096 символов), поэтому текст идёт отдельно, а под ним — кнопка «✅ Согласен».
    """
    await send_document(message, terms_header(), terms_body())
    await message.answer(terms_gate_prompt(), reply_markup=terms_gate_kb(), parse_mode="HTML")


async def terms_gate(message: Message) -> bool:
    """
    Проверяет, принял ли пользователь соглашение.

    True — дальше по команде идти нельзя (экран соглашения уже отправлен).
    Используется в пользовательских командах: до подтверждения они не работают.
    """
    if not terms_gate_needed(message.from_user.id):
        return False
    await show_terms_gate(message)
    return True


@dp.callback_query(F.data == "accept_terms")
async def cb_accept_terms(cb: CallbackQuery):
    """Кнопка «✅ Согласен — продолжить»: отмечаем принятие и открываем главное меню."""
    uid = cb.from_user.id
    first_time = terms_store.accept(uid)
    if first_time:
        logger.info("Пользователь %s принял пользовательское соглашение.", uid)
    await cb.answer("✅ Спасибо! Соглашение принято." if first_time else "✅ Соглашение уже принято.")

    try:
        await cb.message.edit_text(welcome_text(uid), reply_markup=main_menu_kb(uid), parse_mode="HTML")
    except Exception:
        await cb.message.answer(welcome_text(uid), reply_markup=main_menu_kb(uid), parse_mode="HTML")

    # Если человек пришёл по ссылке друга — теперь, после соглашения, показываем его бонус
    await send_pending_referral_greet(cb.message, uid)


@dp.message(Command("terms"))
async def cmd_terms(message: Message):
    """Показывает пользовательское соглашение."""
    await send_document(message, terms_header(), terms_body(),
                        reply_markup=terms_kb(message.from_user.id))


@dp.callback_query(F.data == "terms")
async def cb_terms(cb: CallbackQuery):
    await cb.answer()
    await edit_or_send_document(cb, terms_header(), terms_body(), terms_kb(cb.from_user.id))


@dp.message(Command("privacy"))
async def cmd_privacy(message: Message):
    """Показывает политику конфиденциальности (на неё ссылается п. 8.3 соглашения)."""
    await send_document(message, privacy_header(), privacy_body(),
                        reply_markup=privacy_kb(message.from_user.id))


@dp.callback_query(F.data == "privacy")
async def cb_privacy(cb: CallbackQuery):
    await cb.answer()
    await edit_or_send_document(cb, privacy_header(), privacy_body(), privacy_kb(cb.from_user.id))


@dp.callback_query(F.data == "support")
async def cb_support(cb: CallbackQuery):
    await cb.answer()
    text = (
        "💬 <b>Служба заботы и поддержки:</b>\n\n"
        "Если возникли вопросы по настройке, напиши нам:\n"
        f"👉 Telegram: <a href='{support_link()}'>@{escape(SUPPORT_USERNAME)}</a>\n"
        f"✉️ Почта: <a href='mailto:{escape(SUPPORT_EMAIL)}'>{escape(SUPPORT_EMAIL)}</a>\n\n"
        "Время ответа — до 24 часов в рабочие дни.\n\n"
        "📄 Условия сервиса, оплаты и возврата — /terms.\n"
        "🔒 Политика конфиденциальности — /privacy.\n\n"
        "Мы всегда рады помочь!"
    )
    await cb.message.edit_text(text, reply_markup=back_kb(), parse_mode="HTML")


# =========================
# СЛУЖЕБНЫЕ КОМАНДЫ: РЕГИСТРАЦИЯ ПО ПЕРЕМЕННОЙ ADMIN_TOOLS
# =========================
# ADMIN_TOOLS=0 (по умолчанию) — служебных команд в боте нет: пользователи видят
# только рабочие разделы. ADMIN_TOOLS=1 — всё возвращается для обслуживания.
ADMIN_COMMANDS = {
    "inbounds": cmd_inbounds,
    "reset_vpn": cmd_reset_vpn,
    "groups": cmd_groups,
    "panel_debug": cmd_panel_debug,
    "totp": cmd_totp,
    "payments": cmd_payments,
    "revoke": cmd_revoke,
}

if admin_tools_enabled():
    for _command, _handler in ADMIN_COMMANDS.items():
        dp.message.register(_handler, Command(_command))
    logger.info("Служебные команды администратора включены (ADMIN_TOOLS=1): /%s.",
                ", /".join(ADMIN_COMMANDS))
else:
    logger.info(
        "Служебные команды администратора скрыты (ADMIN_TOOLS=0). "
        "Включить при необходимости: ADMIN_TOOLS=1 в Railway → Variables."
    )

# Диагностика связки с Platega: ничего не создаёт и не оплачивает, только читает
# настройки и запрашивает балансы магазина. Доступна администратору и в боевом
# режиме — именно там она и нужна, поэтому флагов тестового режима не требует.
if admin_tools_enabled() and PAYMENTS_MODE == "platega":
    dp.message.register(cmd_platega_check, Command("platega_check"))
    dp.callback_query.register(cb_platega_check, F.data == "platega_check")
    logger.info("Проверка настроек Platega доступна администратору: /platega_check.")
elif admin_tools_enabled():
    logger.info(
        "Проверка /platega_check не нужна: режим оплаты %s, а не platega.", PAYMENTS_MODE
    )

# Проверка выдачи ключа без оплаты — отдельный флаг TEST_TOOLS и только когда
# включены служебные команды: в боевом виде она не регистрируется вообще.
if test_tools_enabled():
    dp.message.register(cmd_test_pay, Command("test_pay"))
    dp.callback_query.register(cb_testpay_menu, F.data == "testpay_menu")
    dp.callback_query.register(cb_testpay_run, F.data.startswith("testpay_run_"))
    dp.callback_query.register(cb_testpay_del, F.data.startswith("testpay_del_"))
    logger.info("Проверка выдачи ключа без оплаты включена: /test_pay (только для администратора).")
else:
    # Тишина в ответ на /test_pay — это не поломка, а флаг ниже. Пишем в лог,
    # что именно мешает: видно в Railway → Deployments → Logs.
    logger.info(
        "Проверка выдачи ключа без оплаты скрыта: /test_pay не зарегистрирована. "
        "Включить: ADMIN_TOOLS=1 и (PAYMENTS_ALLOW_TEST_PAY=1 или TEST_TOOLS=1). "
        "Сейчас: ADMIN_TOOLS=%s, TEST_TOOLS=%r, режим оплаты %s.",
        int(ADMIN_TOOLS), TEST_TOOLS_RAW or "авто", PAYMENTS_MODE,
    )


# =========================
# ЗАПУСК БОТА
# =========================

def bot_commands() -> list[BotCommand]:
    """
    Список команд для меню Telegram — собирается по переменным ADMIN_TOOLS,
    TRIAL_PUBLIC, TRIAL_BUTTON и TEST_TOOLS.
    """
    # Пользовательские команды — всегда.
    commands = [BotCommand(command="start", description="🏠 Главное меню")]
    if TRIAL_PUBLIC and TRIAL_BUTTON:
        commands.append(BotCommand(command="test_vpn", description="🔗 Бесплатный доступ на 24 часа"))
    commands += [
        BotCommand(command="profile", description="👤 Моя подписка и ключ"),
        BotCommand(command="help", description="📲 Как подключиться (пошагово)"),
        BotCommand(command="invite", description="🎁 Пригласить друга и получить дни"),
        BotCommand(command="terms", description="📄 Условия сервиса"),
        BotCommand(command="privacy", description="🔒 Политика конфиденциальности"),
        BotCommand(command="myid", description="👤 Узнать свой Telegram ID"),
    ]
    # Служебные команды — только при ADMIN_TOOLS=1; в боевом виде их в меню нет.
    if admin_tools_enabled():
        commands += [
            BotCommand(command="payments", description="💳 Оплаты (для администратора)"),
            BotCommand(command="panel_debug", description="🔍 Диагностика панели"),
            BotCommand(command="groups", description="🏷 Группы клиентов в 3x-ui"),
            BotCommand(command="inbounds", description="📡 Список подключений 3x-ui"),
            BotCommand(command="totp", description="🔐 Код 2FA для входа в панель"),
            BotCommand(command="reset_vpn", description="🔄 Сбросить тестовый ключ"),
        ]
        if TRIAL_BUTTON and not TRIAL_PUBLIC:
            commands.insert(1, BotCommand(command="test_vpn", description="🔗 Тестовый доступ (24 часа)"))
    # Тестовые команды проверки оплаты — отдельный флаг TEST_TOOLS.
    if test_tools_enabled():
        commands += [
            BotCommand(command="test_pay", description="🧪 Проверить выдачу ключа без оплаты"),
            BotCommand(command="platega_check", description="🔍 Проверить Platega без денег"),
        ]
    return commands


async def on_startup():
    """Регистрирует подсказки команд в меню Telegram."""
    try:
        await bot.set_my_commands(bot_commands())
    except Exception as exc:
        logger.warning("Не удалось зарегистрировать команды в меню: %s", exc)


async def main():
    if ADMIN_ID == 0:
        logger.warning(
            "⚠️ ADMIN_ID не задан. Отправь боту /myid и укажи свой ID в Railway -> Variables. "
            "Пока переменная пуста, админ-команды (/panel_debug, /groups, /test_pay) открыты для всех."
            if not ADMIN_ID_RAW else
            f"⚠️ ADMIN_ID='{ADMIN_ID_RAW}' не содержит числового Telegram ID "
            "(например, указан @username или лишний текст). Админ-команды пока открыты всем — "
            "отправь боту /myid и укажи полученный ID в Railway -> Variables."
        )

    payment_store.load()
    logger.info("Приём оплаты: %s.", payments_mode_title())
    if PAYMENTS_MODE == "platega":
        if platega_configured():
            logger.info(
                "Platega в боевом режиме: платежи настоящие. Проверка настроек — /platega_check."
            )
        else:
            logger.warning(
                "Platega настроена не полностью: нужны PLATEGA_MERCHANT_ID и PLATEGA_SECRET. "
                "Чего не хватает — видно в /myid."
            )

    runner = None
    try:
        runner = await run_webhook_server()
    except Exception as exc:
        logger.error("Не удалось поднять веб-сервер бота (порт %s): %s", WEB_PORT, exc)

    logger.info("VPN-бот успешно запущен и ожидает сообщений...")
    try:
        await on_startup()
        await dp.start_polling(bot)
    finally:
        if runner is not None:
            await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
