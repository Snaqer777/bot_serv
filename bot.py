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
from datetime import timezone
from email.utils import parsedate_to_datetime
from html import escape
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
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

ADMIN_ID = _int_env("ADMIN_ID")

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
        inbound, auto_picked = await client.find_suitable_inbound(XUI_INBOUND_ID)
        inbound_id = inbound.get("id")
        params = extract_vless_params(inbound)

        settings = as_dict(inbound.get("settings"))
        clients = settings.get("clients") or []
        target_email = f"tg-test-{telegram_id}"

        existing = next(
            (
                c for c in clients
                if isinstance(c, dict)
                and (str(c.get("email")) == target_email or str(c.get("tgId")) == str(telegram_id))
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
                sub_id = existing.get("subId")
                sub_link = f"{XUI_URL}/sub/{sub_id}" if sub_id else None
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
            sub_id = payload.get("subId")
            sub_link = f"{XUI_URL}/sub/{sub_id}" if sub_id else None
            group_note = _group_note(await assign_group(), group_name)
            return link, "updated", inbound, auto_picked, sub_link, group_note

        # Клиента ещё нет — регистрируем нового
        new_uuid = str(uuid.uuid4())
        payload = _test_client_payload(telegram_id, new_uuid, now_ms, inbound, group_name or "")
        await client.add_client(inbound_id, payload)

        link = build_vless_link(payload, inbound, params)
        sub_id = payload.get("subId")
        sub_link = f"{XUI_URL}/sub/{sub_id}" if sub_id else None
        group_note = _group_note(await assign_group(), group_name)
        return link, "created", inbound, auto_picked, sub_link, group_note


async def delete_test_key(telegram_id: int) -> bool:
    """Удаляет тестового клиента из 3x-ui."""
    async with XUIClient() as client:
        inbound, _ = await client.find_suitable_inbound(XUI_INBOUND_ID)
        inbound_id = inbound.get("id")
        settings = as_dict(inbound.get("settings"))
        clients = settings.get("clients") or []
        target_email = f"tg-test-{telegram_id}"

        existing = next(
            (
                c for c in clients
                if isinstance(c, dict)
                and (str(c.get("email")) == target_email or str(c.get("tgId")) == str(telegram_id))
            ),
            None,
        )

        if not existing:
            # На случай, если в inbound кэш устарел, пробуем удалить напрямую по email
            return await client.delete_client(inbound_id, target_email, None)

        return await client.delete_client(inbound_id, target_email, existing.get("id"))


async def send_error_message(message: Message, error: Exception):
    """Понятное человеческое описание ошибок."""
    if isinstance(error, XUIError):
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

TARIFFS = {
    "trial": {
        "name": "🎁 Тестовый период (24 ч)",
        "price": 0,
        "traffic": "1 ГБ",
        "ips": 1,
        "locations": "Все локации",
    },
    "basic": {
        "name": "⚡️ Базовый (1 месяц)",
        "price": 149,
        "traffic": "Безлимит",
        "ips": 2,
        "locations": "Нидерланды, Германия",
    },
    "standard": {
        "name": "🚀 Стандарт (3 месяца)",
        "price": 390,
        "traffic": "Безлимит",
        "ips": 3,
        "locations": "Все локации",
    },
    "premium": {
        "name": "👑 Премиум (1 год)",
        "price": 1190,
        "traffic": "Безлимит",
        "ips": 5,
        "locations": "Все локации + высокий приоритет",
    },
}


def main_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔑 Получить тестовый VPN (24 часа)", callback_data="get_test_key_btn")],
            [
                InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs"),
                InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
            ],
            [InlineKeyboardButton(text="📋 Инструкция по настройке", callback_data="activation")],
            [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")],
        ]
    )


def tariffs_kb() -> InlineKeyboardMarkup:
    buttons = []
    for key, data in TARIFFS.items():
        price_text = "Бесплатно" if data["price"] == 0 else f"{data['price']} ₽"
        buttons.append([InlineKeyboardButton(text=f"{data['name']} — {price_text}", callback_data=f"buy_{key}")])
    buttons.append([InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def back_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")]]
    )


def key_actions_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Сбросить и получить заново", callback_data="reset_my_vpn")],
            [InlineKeyboardButton(text="📋 Инструкция по подключению", callback_data="activation")],
            [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
        ]
    )


# =========================
# ОБРАБОТЧИКИ КОМАНД
# =========================

@dp.message(Command("start"))
async def cmd_start(message: Message):
    text = (
        "👋 <b>Добро пожаловать в быстрый и надёжный VPN!</b>\n\n"
        "Мы используем современный протокол <b>VLESS Reality</b>, "
        "который неотличим от обычного интернет-трафика и работает стабильно.\n\n"
        "✨ Ты можешь бесплатно протестировать VPN прямо сейчас командой /test_vpn "
        "или нажав кнопку ниже 👇"
    )
    await message.answer(text, reply_markup=main_menu_kb(), parse_mode="HTML")


@dp.message(Command("myid"))
async def cmd_myid(message: Message):
    user_id = message.from_user.id
    is_admin = (user_id == ADMIN_ID)
    status_text = "✅ Ты уже администратор" if is_admin else "ℹ️ Укажи его в Railway -> Variables -> <b>ADMIN_ID</b>"

    await message.answer(
        f"👤 <b>Твой Telegram ID:</b> <code>{user_id}</code>\n\n"
        f"<b>Статус:</b> {status_text}\n\n"
        "<i>После добавления ADMIN_ID в Railway подожди 1-2 минуты для перезапуска бота.</i>",
        parse_mode="HTML",
    )


@dp.message(Command("inbounds"))
async def cmd_inbounds(message: Message):
    """Показывает список подключений в панели (только для админа)."""
    # Если ADMIN_ID не настроен, разрешаем вызов, чтобы владелец мог увидеть inbounds
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer(
            f"⛔️ Команда /inbounds доступна только администратору.\n\n"
            f"Твой ID: <code>{message.from_user.id}</code> (добавь в Railway в ADMIN_ID).",
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
    # Если ADMIN_ID задан и пользователь не админ
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer(
            f"⛔️ Команда /test_vpn доступна только администратору.\n\n"
            f"Твой Telegram ID: <code>{message.from_user.id}</code>\n"
            "Укажи этот ID в Railway -> Variables -> <b>ADMIN_ID</b> и дождись перезапуска сервиса.",
            parse_mode="HTML",
        )
        return

    wait_msg = await message.answer("⏳ Подключаюсь к 3x-ui и генерирую ключ...")

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
            title = "🎉 <b>Новый тестовый VPN-клиент успешно создан в 3x-ui!</b>"
        elif status == "updated":
            title = "♻️ <b>Срок твоего ключа истёк — доступ продлён ещё на 24 часа!</b>"
        else:
            title = "🔐 <b>Твой действующий тестовый VPN-ключ:</b>"

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

        sub_text = ""
        if sub_link:
            sub_text = f"\n🌐 <b>Ссылка подписки:</b> <code>{escape(sub_link)}</code>\n"

        msg_text = (
            f"{title}\n\n"
            f"⏳ <b>Срок:</b> 24 часа\n"
            f"📦 <b>Трафик:</b> 1 ГиБ\n"
            f"📱 <b>Устройств:</b> 1\n"
            f"📡 <b>Подключение:</b> #{inbound_id} ({escape(inbound_remark)})\n\n"
            f"🔑 <b>Твой VLESS-ключ (нажми на него, чтобы скопировать):</b>\n"
            f"<code>{escape(link)}</code>\n"
            f"{sub_text}\n"
            "<b>Как подключиться за 1 минуту:</b>\n"
            "1. Скопируй ключ выше (одно нажатие).\n"
            "2. Установи приложение на телефон/ПК:\n"
            "   • <b>iPhone/iPad:</b> Happ, Streisand, FoXray, V2Box\n"
            "   • <b>Android:</b> v2rayNG, Happ, V2Box\n"
            "   • <b>Windows/Mac:</b> Happ, v2rayN, V2Box\n"
            "3. Открой приложение → нажми <b>«+»</b> → <b>«Импорт из буфера обмена»</b>.\n"
            "4. Нажми <b>Подключить</b>."
            f"{group_note}"
            f"{auto_note}"
            f"{admin_note}"
        )

        await message.answer(msg_text, reply_markup=key_actions_kb(), parse_mode="HTML")

    except Exception as exc:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await send_error_message(message, exc)


@dp.message(Command("reset_vpn"))
async def cmd_reset_vpn(message: Message):
    """Удаляет тестового клиента из 3x-ui (для пересоздания)."""
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Команда доступна только администратору.")
        return

    wait_msg = await message.answer("⏳ Удаляю клиента из панели 3x-ui...")
    try:
        async with vpn_lock:
            removed = await delete_test_key(message.from_user.id)

        await wait_msg.delete()
        if removed:
            await message.answer(
                "🗑 <b>Тестовый клиент успешно удалён из 3x-ui!</b>\n\n"
                "Теперь можешь отправить команду /test_vpn для генерации нового ключа с нуля.",
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


@dp.message(Command("groups"))
async def cmd_groups(message: Message):
    """Показывает группы клиентов в панели 3x-ui (только для админа)."""
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Команда доступна только администратору.")
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


@dp.message(Command("panel_debug"))
async def cmd_panel_debug(message: Message):
    """Сетевая диагностика связи между Railway и 3x-ui."""
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Команда доступна только администратору.")
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

    lines = [
        "🔍 <b>Диагностика подключения к 3x-ui:</b>\n",
        f"• <b>URL:</b> <code>{escape(XUI_URL)}</code>",
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

    await message.answer("\n".join(lines)[:4000], parse_mode="HTML")


@dp.message(Command("totp"))
async def cmd_totp(message: Message):
    """Показывает текущий код Google Authenticator для входа в панель (только админ)."""
    if ADMIN_ID > 0 and message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Команда доступна только администратору.")
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
    await cb.message.edit_text(
        "🏠 <b>Главное меню:</b>\n\nВыбери необходимое действие ниже 👇",
        reply_markup=main_menu_kb(),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "get_test_key_btn")
async def cb_get_test_key(cb: CallbackQuery):
    await cb.answer()
    # Вызываем логику выдачи ключа
    await cmd_test_vpn(cb.message)


@dp.callback_query(F.data == "reset_my_vpn")
async def cb_reset_my_vpn(cb: CallbackQuery):
    await cb.answer("Сбрасываю ключ...", show_alert=False)
    await cmd_reset_vpn(cb.message)


@dp.callback_query(F.data == "tariffs")
async def cb_tariffs(cb: CallbackQuery):
    await cb.answer()
    text = "💰 <b>Доступные тарифные планы:</b>\n\n"
    for key, data in TARIFFS.items():
        price = "Бесплатно" if data["price"] == 0 else f"{data['price']} ₽"
        text += (
            f"• <b>{data['name']}</b>: <b>{price}</b>\n"
            f"  📦 Трафик: {data['traffic']} | 📱 Устройств: {data['ips']} | 🌍 {data['locations']}\n\n"
        )
    await cb.message.edit_text(text, reply_markup=tariffs_kb(), parse_mode="HTML")


@dp.callback_query(F.data.startswith("buy_"))
async def cb_buy(cb: CallbackQuery):
    tariff_key = cb.data.removeprefix("buy_")
    if tariff_key == "trial":
        await cb.answer()
        await cmd_test_vpn(cb.message)
        return

    tariff = TARIFFS.get(tariff_key)
    if not tariff:
        await cb.answer("Тариф не найден.", show_alert=True)
        return

    await cb.answer()
    text = (
        f"💳 <b>Выбран тариф: {tariff['name']}</b> ({tariff['price']} ₽)\n\n"
        "ℹ️ <i>Платёжная система находится в процессе интеграции.</i>\n\n"
        "Чтобы начать пользоваться VPN прямо сейчас бесплатно, нажми команду /test_vpn "
        "или кнопку ниже."
    )
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔑 Получить тестовый доступ (24 ч)", callback_data="get_test_key_btn")],
            [InlineKeyboardButton(text="◀️ К тарифам", callback_data="tariffs")],
        ]
    )
    await cb.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")


@dp.callback_query(F.data == "profile")
async def cb_profile(cb: CallbackQuery):
    await cb.answer()
    user_id = cb.from_user.id
    text = (
        f"👤 <b>Твой профиль:</b>\n\n"
        f"• Telegram ID: <code>{user_id}</code>\n"
        f"• Статус: активный пользователь\n\n"
        "🎁 Ты можешь в любой момент получить рабочий тестовый ключ на 24 часа по команде /test_vpn!"
    )
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔑 Мой тестовый ключ", callback_data="get_test_key_btn")],
            [InlineKeyboardButton(text="◀️ Главное меню", callback_data="main_menu")],
        ]
    )
    await cb.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")


@dp.callback_query(F.data == "activation")
async def cb_activation(cb: CallbackQuery):
    await cb.answer()
    text = (
        "📋 <b>Инструкция по настройке VPN</b>\n\n"
        "<b>🍎 iOS (iPhone / iPad)</b>\n"
        "1. Установи <b>Happ</b>, <b>Streisand</b> или <b>FoXray</b> из App Store.\n"
        "2. Скопируй ключ (команда /test_vpn).\n"
        "3. Открой приложение → нажми «+» → «Импорт из буфера».\n"
        "4. Выбери сервер и нажми «Подключить».\n\n"
        "<b>🤖 Android</b>\n"
        "1. Установи <b>v2rayNG</b> или <b>Happ</b> из Google Play.\n"
        "2. Скопируй ключ из бота.\n"
        "3. Открой v2rayNG → нажми «+» → «Импорт профиля из буфера обмена».\n"
        "4. Нажми кнопку подключения (круг со значком «V» снизу).\n\n"
        "<b>💻 Windows / macOS</b>\n"
        "1. Скачай <b>Happ</b> или <b>v2rayN</b>.\n"
        "2. Добавь ссылку через буфер обмена (Ctrl+V или Add from clipboard).\n"
        "3. Включи системный прокси (Set system proxy / Tun Mode)."
    )
    await cb.message.edit_text(text, reply_markup=back_kb(), parse_mode="HTML")


@dp.callback_query(F.data == "support")
async def cb_support(cb: CallbackQuery):
    await cb.answer()
    text = (
        "💬 <b>Служба заботы и поддержки:</b>\n\n"
        "Если возникли вопросы по настройке, напиши нам:\n"
        "👉 <a href='https://t.me/Suppr_XYZ'>@Suppr_XYZ</a>\n\n"
        "Мы всегда рады помочь!"
    )
    await cb.message.edit_text(text, reply_markup=back_kb(), parse_mode="HTML")


# =========================
# ЗАПУСК БОТА
# =========================

async def on_startup():
    """Регистрирует подсказки команд в меню Telegram."""
    try:
        commands = [
            BotCommand(command="test_vpn", description="🔑 Получить рабочий VPN-ключ"),
            BotCommand(command="start", description="🏠 Главное меню"),
            BotCommand(command="inbounds", description="📡 Список подключений 3x-ui"),
            BotCommand(command="reset_vpn", description="🔄 Сбросить тестовый ключ"),
            BotCommand(command="panel_debug", description="🔍 Диагностика панели"),
            BotCommand(command="totp", description="🔐 Код 2FA для входа в панель"),
            BotCommand(command="groups", description="🏷 Группы клиентов в 3x-ui"),
            BotCommand(command="myid", description="👤 Узнать свой Telegram ID"),
        ]
        await bot.set_my_commands(commands)
    except Exception as exc:
        logger.warning("Не удалось зарегистрировать команды в меню: %s", exc)


async def main():
    if ADMIN_ID == 0:
        logger.warning(
            "⚠️ ADMIN_ID не задан. Отправь боту /myid и укажи свой ID в Railway -> Variables."
        )
    logger.info("VPN-бот успешно запущен и ожидает сообщений...")
    await on_startup()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
