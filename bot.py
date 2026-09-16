import asyncio
import json
import logging
import os
import secrets
import ssl
import time
import uuid

from contextlib import asynccontextmanager
from html import escape
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
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


def _int_env(name, default=0):
    """Безопасно читает целое число из переменной окружения."""
    try:
        return int(os.getenv(name) or default)
    except (TypeError, ValueError):
        logger.warning("Переменная %s не является числом, беру %s", name, default)
        return default


# --- Telegram ---
BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip()
if not BOT_TOKEN:
    raise SystemExit(
        "BOT_TOKEN не задан! Добавь его в Railway -> Variables и перезапусти сервис."
    )

ADMIN_ID = _int_env("ADMIN_ID")

# --- Панель 3x-ui ---
# ВАЖНО: XUI_URL копируй из адресной строки браузера, как ты открываешь панель:
#   https://1.2.3.4:2053            (если панель БЕЗ секретного пути)
#   https://1.2.3.4:2053/abc123     (если панель С секретным путём webBasePath)
# Без слеша на конце.
XUI_URL = (os.getenv("XUI_URL") or "").strip().rstrip("/")
XUI_USERNAME = (os.getenv("XUI_USERNAME") or "").strip()
XUI_PASSWORD = os.getenv("XUI_PASSWORD") or ""
XUI_INBOUND_ID = _int_env("XUI_INBOUND_ID")

# --- Необязательные переопределения ---
# По умолчанию адрес сервера в ключе = хост из XUI_URL, порт = порт inbound.
VPN_HOST = (os.getenv("VPN_HOST") or "").strip()
VPN_PORT = _int_env("VPN_PORT")

# Reality-параметры по умолчанию автоматически читаются из настроек inbound.
# Эти переменные нужны ТОЛЬКО если хочешь переопределить их вручную.
REALITY_PUBLIC_KEY = (os.getenv("REALITY_PUBLIC_KEY") or "").strip()
REALITY_SNI = (os.getenv("REALITY_SNI") or "").strip()
REALITY_SHORT_ID = (os.getenv("REALITY_SHORT_ID") or "").strip()
REALITY_FP = (os.getenv("REALITY_FP") or "").strip()

# --- Параметры тестового ключа ---
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


TARIFFS = {
    "school": {
        "name": "Школьник", "price": 99, "traffic": "50 ГБ",
        "ips": 1, "locations": "1 (Стокгольм)",
    },
    "basic": {
        "name": "Базовый", "price": 249, "traffic": "Безлимит",
        "ips": 3, "locations": "2 (Стокгольм...)",
    },
    "family": {
        "name": "Семейный", "price": 399, "traffic": "Безлимит",
        "ips": 5, "locations": "3 локации",
    },
    "premium": {
        "name": "Премиум", "price": 599, "traffic": "Безлимит",
        "ips": 10, "locations": "Все локации",
    },
}


# =========================
# РАБОТА С API 3X-UI
# =========================

class XUIError(Exception):
    """Ошибка, текст которой можно безопасно показать пользователю бота."""


def as_dict(value):
    """3x-ui отдаёт settings/streamSettings JSON-строкой — распаковываем."""
    if isinstance(value, str):
        value = json.loads(value)

    if value is None:
        return {}

    if not isinstance(value, dict):
        raise XUIError(
            "Неожиданный формат настроек в ответе 3x-ui. "
            "Возможно, версия панели несовместима."
        )
    return value


def _ssl_context():
    # Панели часто работают на самоподписанном HTTPS-сертификате,
    # поэтому проверку сертификата отключаем.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@asynccontextmanager
async def xui_session():
    """
    Открывает авторизованную сессию к панели 3x-ui.

    Почему старый код не работал: он логинился в /panel/api/login —
    такого endpoint нет в актуальных 3x-ui (там логин на /login/).
    Здесь пробуем все варианты, поддерживается и старый, и новый API.
    """
    if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
        raise XUIError(
            "Не заданы переменные панели. Добавь в Railway -> Variables:\n"
            "XUI_URL, XUI_USERNAME, XUI_PASSWORD — и дождись перезапуска бота."
        )

    if not XUI_URL.startswith(("http://", "https://")):
        raise XUIError(
            "XUI_URL должен начинаться с http:// или https://, "
            f"сейчас: «{XUI_URL}»"
        )

    ssl_ctx = _ssl_context() if XUI_URL.startswith("https://") else None

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=40),
        connector=aiohttp.TCPConnector(ssl=ssl_ctx),
    ) as session:
        # Прогрев: проверяем, что панель вообще доступна из Railway.
        try:
            await session.get(
                f"{XUI_URL}/",
                headers={"User-Agent": BROWSER_UA},
                allow_redirects=True,
            )
        except Exception as exc:
            raise XUIError(
                f"Панель 3x-ui не отвечает по адресу:\n{XUI_URL}\n\n"
                f"Ошибка: {exc}\n\n"
                "Проверь:\n"
                "• Сервер с панелью включён и панель доступна из интернета\n"
                "• Порт панели открыт в фаерволе (не только порт VPN)\n"
                "• XUI_URL совпадает с адресом панели (включая секретный путь, если он есть)"
            ) from exc

        errors = []
        for login_path in ("/login/", "/login", "/panel/api/login"):
            try:
                async with session.post(
                    f"{XUI_URL}{login_path}",
                    json={"username": XUI_USERNAME, "password": XUI_PASSWORD},
                    headers={
                        "User-Agent": BROWSER_UA,
                        "Accept": "application/json",
                        "Origin": f"{urlsplit(XUI_URL).scheme}://{urlsplit(XUI_URL).netloc}",
                        "Referer": f"{XUI_URL}/",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                ) as resp:
                    raw = await resp.text()

                if resp.status in (404, 405):
                    errors.append(f"{login_path} -> HTTP {resp.status}")
                    continue

                try:
                    data = json.loads(raw)
                except ValueError:
                    errors.append(f"{login_path} -> не JSON (HTTP {resp.status})")
                    continue

                if data.get("success"):
                    logger.info("Вход в панель 3x-ui выполнен (%s)", login_path)
                    break

                # Панель ответила осмысленно — значит endpoint верный,
                # а логин/пароль неверные.
                raise XUIError(
                    "Панель 3x-ui отклонила логин/пароль.\n"
                    f"Ответ панели: {data.get('msg') or raw[:200]}\n\n"
                    "Проверь XUI_USERNAME и XUI_PASSWORD в Railway.\n"
                    "Если в панели включён двухфакторный код (login secret / 2FA) — "
                    "отключи его, бот его не поддерживает."
                )
            except XUIError:
                raise
            except aiohttp.ClientError as exc:
                errors.append(f"{login_path} -> {exc}")
        else:
            raise XUIError(
                "Не удалось авторизоваться в панели ни по одному адресу:\n"
                + "\n".join(errors)
                + "\n\nЧаще всего причина — в XUI_URL не указан секретный путь "
                "(webBasePath). Скопируй адрес из браузера так, как ты "
                "открываешь панель, напр. https://1.2.3.4:2053/abc123"
            )

        yield session


async def xui_api(session, method, path, **kwargs):
    """Запрос к API панели (сессия уже авторизована)."""
    headers = {
        "User-Agent": BROWSER_UA,
        "Accept": "application/json, text/plain, */*",
        "Origin": f"{urlsplit(XUI_URL).scheme}://{urlsplit(XUI_URL).netloc}",
        "Referer": f"{XUI_URL}/panel/",
        "X-Requested-With": "XMLHttpRequest",
    }
    headers.update(kwargs.pop("headers", {}))

    async with session.request(
        method, f"{XUI_URL}{path}", headers=headers, **kwargs
    ) as resp:
        status = resp.status
        raw = await resp.text()

    try:
        result = json.loads(raw)
    except ValueError as exc:
        raise XUIError(
            f"Панель вернула не JSON на {path} (HTTP {status}).\n"
            f"Тело: {raw[:300]}"
        ) from exc

    if status >= 400:
        raise XUIError(f"3x-ui: HTTP {status} на {path}. {raw[:300]}")

    if not isinstance(result, dict) or result.get("success") is not True:
        msg = result.get("msg") if isinstance(result, dict) else None
        raise XUIError(f"3x-ui отклонила {method} {path}: {msg or raw[:300]}")

    return result.get("obj")


def panel_host():
    """Хост из XUI_URL — используется как адрес сервера в ссылке по умолчанию."""
    try:
        return urlsplit(XUI_URL).hostname or ""
    except ValueError:
        return ""


def get_connection_params(inbound):
    """Достаём параметры VLESS-TCP-Reality прямо из настроек inbound."""
    if inbound.get("protocol") != "vless":
        raise XUIError(
            f"Подключение #{XUI_INBOUND_ID} — это «{inbound.get('protocol')}», "
            "а нужен VLESS. Посмотри список командой /inbounds и укажи "
            "другой XUI_INBOUND_ID."
        )

    stream = as_dict(inbound.get("streamSettings"))
    network = stream.get("network") or "tcp"
    security = stream.get("security") or "none"

    if network != "tcp" or security != "reality":
        raise XUIError(
            f"Подключение #{XUI_INBOUND_ID} настроено как {network} + {security}.\n"
            "Автогенерация ключей поддерживает только VLESS + TCP + Reality.\n"
            "Выбери или создай такое подключение (/inbounds)."
        )

    rs = as_dict(stream.get("realitySettings"))
    inner = as_dict(rs.get("settings"))  # в новых версиях publicKey/fp лежат тут

    public_key = (
        REALITY_PUBLIC_KEY
        or str(rs.get("publicKey") or "")
        or str(inner.get("publicKey") or "")
    ).strip()

    server_names = [str(x) for x in (rs.get("serverNames") or []) if x]
    short_ids = [str(x) for x in (rs.get("shortIds") or []) if x]

    sni = REALITY_SNI or (server_names[0] if server_names else "")
    sid = REALITY_SHORT_ID or (short_ids[0] if short_ids else "")
    fp = REALITY_FP or str(inner.get("fingerprint") or "") or "chrome"
    spx = str(inner.get("spiderX") or "") or "/"

    if not public_key:
        raise XUIError(
            "Не нашёл публичный ключ Reality в настройках подключения. "
            "Открой его в панели и пересохрани, либо задай "
            "REALITY_PUBLIC_KEY в Railway вручную."
        )
    if not sni:
        raise XUIError(
            "Не нашёл SNI (serverNames пуст). Задай REALITY_SNI в Railway."
        )

    return {"pbk": public_key, "sni": sni, "sid": sid, "fp": fp, "spx": spx}


def build_vless_link(client, inbound, params):
    """Собирает рабочую ссылку vless:// из данных клиента и inbound."""
    host = VPN_HOST or panel_host()

    if not host or any(char in host for char in "/?#@"):
        raise XUIError(
            "Не удалось определить адрес сервера для ключа. "
            "Задай VPN_HOST в Railway (домен или IP без https:// и порта)."
        )

    try:
        port = VPN_PORT or int(inbound.get("port"))
    except (TypeError, ValueError) as exc:
        raise XUIError("Не удалось определить порт VPN.") from exc

    if not 1 <= port <= 65535:
        raise XUIError(f"Некорректный порт VPN: {port}")

    query_params = {
        "type": "tcp",
        "encryption": "none",
        "security": "reality",
        "pbk": params["pbk"],
        "fp": params["fp"],
        "sni": params["sni"],
    }
    if params["sid"]:
        query_params["sid"] = params["sid"]
    if params["spx"]:
        query_params["spx"] = params["spx"]
    if client.get("flow"):
        query_params["flow"] = client["flow"]

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6

    query = urlencode(query_params, quote_via=quote)
    label = quote(client.get("email") or "VPN", safe="")

    return f"vless://{client['id']}@{host}:{port}?{query}#{label}"


def _test_client_payload(telegram_id, client_uuid, now_ms):
    return {
        "id": client_uuid,
        "email": f"tg-test-{telegram_id}",
        "flow": "xtls-rprx-vision",
        "enable": True,
        "limitIp": TEST_IP_LIMIT,
        "totalGB": TEST_TRAFFIC_BYTES,
        "expiryTime": now_ms + TEST_HOURS * 60 * 60 * 1000,
        "tgId": str(telegram_id),
        "subId": secrets.token_hex(8),
        "reset": 0,
    }


def _require_inbound_id():
    if XUI_INBOUND_ID <= 0:
        raise XUIError(
            "XUI_INBOUND_ID пока не задан.\n\n"
            "1) Отправь мне /inbounds — покажу список подключений.\n"
            "2) В Railway -> Variables укажи ID нужного VLESS+Reality "
            "подключения в XUI_INBOUND_ID.\n"
            "3) Дождись перезапуска и повтори команду."
        )


async def get_test_key(telegram_id):
    """
    Создаёт (или возвращает существующего) тестового клиента в панели.
    Возвращает (ссылка, статус): created / updated / exists.
    """
    _require_inbound_id()

    async with xui_session() as session:
        inbound = await xui_api(
            session, "GET", f"/panel/api/inbounds/get/{XUI_INBOUND_ID}"
        )

        if not isinstance(inbound, dict) or not inbound.get("id"):
            raise XUIError(
                f"Подключение с ID {XUI_INBOUND_ID} не найдено. "
                "Проверь XUI_INBOUND_ID (список: /inbounds)."
            )

        conn = get_connection_params(inbound)
        settings = as_dict(inbound.get("settings"))
        clients = settings.get("clients") or []

        email = f"tg-test-{telegram_id}"
        client = next(
            (
                c for c in clients
                if isinstance(c, dict) and str(c.get("email")) == email
            ),
            None,
        )

        now_ms = int(time.time() * 1000)

        if client is not None:
            expiry = int(client.get("expiryTime") or 0)
            enabled = bool(client.get("enable", True))

            if enabled and (expiry <= 0 or expiry > now_ms):
                # Ключ жив — отдаём как есть, ничего не меняем.
                return build_vless_link(client, inbound, conn), "exists"

            # Истёк или выключен — обновляем доступ (сохраняем UUID).
            payload = _test_client_payload(telegram_id, client["id"], now_ms)
            body = {
                "id": XUI_INBOUND_ID,
                "settings": json.dumps({"clients": [payload]}),
            }
            try:
                await xui_api(
                    session,
                    "POST",
                    f"/panel/api/inbounds/updateClient/{client['id']}",
                    json=body,
                )
            except XUIError:
                # Запасной путь для старых версий панели: удалить + создать.
                await xui_api(
                    session,
                    "POST",
                    f"/panel/api/inbounds/delClient/{XUI_INBOUND_ID}/{client['id']}",
                )
                await xui_api(
                    session, "POST", "/panel/api/inbounds/addClient", json=body
                )

            logger.info("Тестовый доступ обновлён: %s", email)
            return build_vless_link(payload, inbound, conn), "updated"

        # Клиента ещё нет — создаём нового.
        payload = _test_client_payload(telegram_id, str(uuid.uuid4()), now_ms)
        await xui_api(
            session,
            "POST",
            "/panel/api/inbounds/addClient",
            json={
                "id": XUI_INBOUND_ID,
                "settings": json.dumps({"clients": [payload]}),
            },
        )

        logger.info("Тестовый клиент создан: %s", email)
        return build_vless_link(payload, inbound, conn), "created"


async def delete_test_client(telegram_id):
    """Удаляет тестового клиента из панели. True, если клиент был."""
    _require_inbound_id()

    async with xui_session() as session:
        inbound = await xui_api(
            session, "GET", f"/panel/api/inbounds/get/{XUI_INBOUND_ID}"
        )
        settings = as_dict(inbound.get("settings"))

        email = f"tg-test-{telegram_id}"
        client = next(
            (
                c for c in (settings.get("clients") or [])
                if isinstance(c, dict) and str(c.get("email")) == email
            ),
            None,
        )

        if client is None:
            return False

        await xui_api(
            session,
            "POST",
            f"/panel/api/inbounds/delClient/{XUI_INBOUND_ID}/{client['id']}",
        )
        logger.info("Тестовый клиент удалён: %s", email)
        return True


async def send_xui_error(message, error):
    if isinstance(error, XUIError):
        text = str(error)
    elif isinstance(error, asyncio.TimeoutError):
        text = (
            "Панель 3x-ui не ответила вовремя.\n"
            "Проверь её доступность и повтори команду."
        )
    elif isinstance(error, aiohttp.ClientConnectorError):
        text = (
            "Не удалось подключиться к панели 3x-ui.\n"
            "Проверь XUI_URL и что порт панели открыт в фаерволе."
        )
    else:
        logger.error("Ошибка 3x-ui: %s: %s", type(error).__name__, error)
        text = (
            "Не удалось выполнить запрос к 3x-ui.\n"
            f"Тип ошибки: {type(error).__name__}: {error}"
        )

    await message.answer(text, parse_mode=None)


# =========================
# СЕРВИСНЫЕ КОМАНДЫ
# =========================

@dp.message(Command("myid"), F.chat.type == "private")
async def cmd_myid(message: Message):
    await message.answer(
        f"Твой Telegram ID: `{message.from_user.id}`\n\n"
        "Укажи его в Railway -> Variables -> ADMIN_ID "
        "и дождись перезапуска бота.",
        parse_mode="Markdown",
    )


@dp.message(
    Command("inbounds"),
    F.chat.type == "private",
    F.from_user.id == ADMIN_ID,
    F.from_user.id != 0,
)
async def cmd_inbounds(message: Message):
    try:
        async with xui_session() as session:
            items = await xui_api(session, "GET", "/panel/api/inbounds/list")

        if not items:
            await message.answer("В панели нет входящих подключений.")
            return

        await message.answer(
            "✅ Авторизация в панели прошла успешно!\n\n"
            "Входящие подключения 3x-ui:"
        )

        for item in items:
            try:
                stream = as_dict(item.get("streamSettings"))
                ok = (
                    item.get("protocol") == "vless"
                    and stream.get("network") == "tcp"
                    and stream.get("security") == "reality"
                )
                text = (
                    f"ID: {item.get('id')}\n"
                    f"Название: {item.get('remark') or '-'}\n"
                    f"Протокол: {item.get('protocol')}\n"
                    f"Транспорт: {stream.get('network', '?')} "
                    f"+ {stream.get('security', '?')}\n"
                    f"Порт: {item.get('port', '?')}\n"
                    f"Подходит для /test_vpn: {'✅ да' if ok else '—'}"
                )
            except Exception:
                text = f"ID: {item.get('id')} (не смог разобрать настройки)"

            await message.answer(text[:4000], parse_mode=None)

        await message.answer(
            "Запиши ID подходящего подключения в Railway -> Variables -> "
            "XUI_INBOUND_ID, дождись перезапуска и отправь /test_vpn."
        )

    except Exception as error:
        await send_xui_error(message, error)


@dp.message(
    Command("test_vpn"),
    F.chat.type == "private",
    F.from_user.id == ADMIN_ID,
    F.from_user.id != 0,
)
async def cmd_test_vpn(message: Message):
    status_message = await message.answer("⏳ Обращаюсь к панели 3x-ui...")

    try:
        async with vpn_lock:
            link, status = await get_test_key(message.from_user.id)

        if status == "created":
            title = (
                "✅ Тестовый клиент создан!\n"
                "⏳ Срок: 24 часа | 📦 Трафик: 1 ГиБ | 1 устройство"
            )
        elif status == "updated":
            title = (
                "♻️ Старый ключ истёк или был отключён — доступ продлён "
                "ещё на 24 часа."
            )
        else:
            title = "🔐 Твой действующий тестовый ключ (без изменений)."

        await status_message.delete()
        await message.answer(
            f"{title}\n\n"
            f"<code>{escape(link)}</code>\n\n"
            "Скопируй ссылку и импортируй её в VPN-приложение "
            "(Happ, v2box, Streisand, V2rayTun и т.п.).",
            parse_mode="HTML",
            protect_content=True,
        )

    except Exception as error:
        try:
            await status_message.delete()
        except Exception:
            pass
        await send_xui_error(message, error)


@dp.message(
    Command("reset_vpn"),
    F.chat.type == "private",
    F.from_user.id == ADMIN_ID,
    F.from_user.id != 0,
)
async def cmd_reset_vpn(message: Message):
    try:
        async with vpn_lock:
            removed = await delete_test_client(message.from_user.id)

        if removed:
            await message.answer(
                "🗑 Тестовый клиент удалён из панели. "
                "Отправь /test_vpn для нового ключа."
            )
        else:
            await message.answer(
                "Тестового клиента в панели нет — можно сразу /test_vpn."
            )

    except Exception as error:
        await send_xui_error(message, error)


# =========================
# МЕНЮ, ТАРИФЫ, CALLBACK'И
# =========================

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="🔐 Подключить VPN", callback_data="connect_vpn",
        )],
        [
            InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
            InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs"),
        ],
        [InlineKeyboardButton(
            text="📋 Инструкция по активации", callback_data="activation",
        )],
        [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")],
    ])


def tariffs_kb():
    keyboard = []
    for key, data in TARIFFS.items():
        keyboard.append([InlineKeyboardButton(
            text=f"{data['name']} — {data['price']} ₽",
            callback_data=f"buy_{key}",
        )])
    keyboard.append([InlineKeyboardButton(
        text="◀️ Назад в меню", callback_data="main_menu",
    )])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="◀️ Назад в меню", callback_data="main_menu",
        )]
    ])


@dp.message(Command("start"))
async def cmd_start(message: Message):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="✅ Я принимаю условия", callback_data="accept_license",
        )]
    ])

    await message.answer(
        "📄 <b>Лицензионное соглашение</b>\n\n"
        "1. Использование только для легальной деятельности.\n"
        "2. Запрещена передача ключей третьим лицам.\n"
        "3. Администрация не несет ответственности "
        "за действия пользователей.\n\n"
        "<i>Нажмите кнопку ниже для продолжения.</i>",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "accept_license")
async def accept_license(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "✅ Условия приняты. Выберите действие:",
        reply_markup=main_menu_kb(),
    )


@dp.callback_query(F.data == "main_menu")
async def main_menu(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "🏠 Главное меню:",
        reply_markup=main_menu_kb(),
    )


@dp.callback_query(F.data == "tariffs")
async def tariffs(cb: CallbackQuery):
    await cb.answer()

    text = "<b>Выберите тариф:</b>\n\n"
    for data in TARIFFS.values():
        text += (
            f"• {data['name']} — {data['price']}₽ | "
            f"{data['traffic']} | {data['ips']} устр. | "
            f"{data['locations']}\n"
        )

    await cb.message.edit_text(
        text, reply_markup=tariffs_kb(), parse_mode="HTML",
    )


@dp.callback_query(F.data.startswith("buy_"))
async def buy(cb: CallbackQuery):
    tariff_key = cb.data.removeprefix("buy_")
    tariff = TARIFFS.get(tariff_key)

    if tariff is None:
        await cb.answer("Тариф не найден.", show_alert=True)
        return

    await cb.answer()

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="💳 Оплатить (заглушка)", callback_data="fake_pay",
        )],
        [InlineKeyboardButton(text="◀️ Назад", callback_data="tariffs")],
    ])

    await cb.message.edit_text(
        f"💳 <b>{tariff['name']}</b> — {tariff['price']}₽\n\n"
        "<i>Оплата пока не подключена.</i>",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "fake_pay")
async def fake_pay(cb: CallbackQuery):
    await cb.answer(
        "Это демонстрация. Деньги не списываются, доступ не выдаётся.",
        show_alert=True,
    )
    await cb.message.edit_text(
        "🧪 Демо оплаты.\n\n"
        "Реальная оплата пока не подключена.\n"
        "Тестовая выдача ключа доступна администратору командой /test_vpn.",
        reply_markup=back_kb(),
    )


@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "👤 Профиль:\n\n"
        "Платные подписки пока не подключены.\n"
        "Тестовый ключ администратора выдаётся командой /test_vpn.",
        reply_markup=back_kb(),
    )


@dp.callback_query(F.data == "connect_vpn")
async def connect(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "🔐 Для подключения выбери тариф 👇\n\n"
        "Оплата пока не подключена.",
        reply_markup=tariffs_kb(),
    )


@dp.callback_query(F.data == "activation")
async def activation(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "📋 <b>Инструкция по активации</b>\n\n"
        "<b>🍎 iOS (iPhone / iPad)</b>\n"
        "1. Скачай Happ, INCY или Wispy из App Store\n"
        "2. Открой приложение → нажми «+» (добавить)\n"
        "3. Выбери «Импорт из буфера обмена»\n"
        "4. Нажми «Подключить» и разреши VPN в iOS\n\n"
        "<b>🤖 Android</b>\n"
        "1. Скачай v2box или Happ из Google Play\n"
        "2. Открой → нажми «+»\n"
        "3. Жми «Импорт из буфера обмена»\n"
        "4. Сохрани профиль → кнопка «Старт»\n\n"
        "<b>💻 Windows / Mac</b>\n"
        "1. Скачай v2raytun или Happ\n"
        "2. «Add» → «Import URL» → вставь ссылку\n"
        "3. Нажми «Connect» и разреши VPN в системе\n\n"
        "<i>Не работает? Пиши в поддержку 👇</i>",
        reply_markup=back_kb(),
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "💬 <b>Поддержка</b>\n\n"
        "По всем вопросам пиши сюда:\n"
        "👉 <a href='https://t.me/Suppr_XYZ'>@Suppr_XYZ</a>\n\n"
        "Отвечаем обычно в течение часа.",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


# =========================
# ЗАПУСК
# =========================

async def main():
    if ADMIN_ID == 0:
        logger.warning(
            "ADMIN_ID не настроен. Отправь боту /myid и добавь "
            "свой ID в Railway -> Variables."
        )
    logger.info("Бот запущен")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
