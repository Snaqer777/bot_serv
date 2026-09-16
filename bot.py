import asyncio
import json
import logging
import os
import re
import secrets
import ssl
import time
import uuid

from contextlib import asynccontextmanager
from html import escape
from urllib.parse import quote, urlencode

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


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден!")

ADMIN_ID = int(os.getenv("ADMIN_ID") or "0")

XUI_URL = os.getenv("XUI_URL", "").strip().rstrip("/")
XUI_USERNAME = os.getenv("XUI_USERNAME", "")
XUI_PASSWORD = os.getenv("XUI_PASSWORD", "")
XUI_INBOUND_ID = int(os.getenv("XUI_INBOUND_ID") or "0")

VPN_HOST = os.getenv("VPN_HOST", "").strip()
REALITY_PUBLIC_KEY = os.getenv("REALITY_PUBLIC_KEY", "").strip()
REALITY_SNI = os.getenv("REALITY_SNI", "").strip()
REALITY_SHORT_ID = os.getenv("REALITY_SHORT_ID", "").strip()

TEST_HOURS = 24
TEST_TRAFFIC_BYTES = 1024 ** 3

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
test_lock = asyncio.Lock()


TARIFFS = {
    "school": {
        "name": "Школьник", "price": 99,
        "traffic": "50 ГБ", "ips": 1,
        "locations": "1 (Стокгольм)",
    },
    "basic": {
        "name": "Базовый", "price": 249,
        "traffic": "Безлимит", "ips": 3,
        "locations": "2 (Стокгольм...)",
    },
    "family": {
        "name": "Семейный", "price": 399,
        "traffic": "Безлимит",
        "ips": 5,
        "locations": "3 локации",
    },
    "premium": {
        "name": "Премиум", "price": 599,
        "traffic": "Безлимит",
        "ips": 10,
        "locations": "Все локации",
    },
}


class XUIError(Exception):
    pass


def as_dict(value):
    if isinstance(value, str):
        value = json.loads(value)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise XUIError("Неожиданный формат настроек 3x-ui.")
    return value


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _browser_headers():
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Origin": XUI_URL,
        "Referer": f"{XUI_URL}/panel/",
        "Accept": "application/json, text/plain, */*",
    }


async def xui_request(session, method, path, csrf_token=None, **kwargs):
    url = f"{XUI_URL}{path}"
    headers = kwargs.pop("headers", {})
    headers.update(_browser_headers())
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token

    async with session.request(method, url, headers=headers, **kwargs) as response:
        if response.status >= 400:
            body = ""
            try:
                body = (await response.text())[:400]
            except Exception:
                pass
            raise XUIError(
                f"HTTP {response.status} для {path}\n"
                f"Тело: {body}"
            )

        try:
            result = await response.json(content_type=None)
        except ValueError as exc:
            text = await response.text()
            raise XUIError(f"Не JSON в ответе на {path}.") from exc

    if not isinstance(result, dict):
        raise XUIError("Неожиданный ответ API.")

    if result.get("success") is not True:
        raise XUIError(
            f"3x-ui отклонила {path}. msg: {result.get('msg', '')}"
        )

    return result.get("obj")


def extract_csrf_token(html: str):
    patterns = [
        r'<meta[^>]+csrf-token[^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+csrf-token',
        r'csrfToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'"csrfToken"\s*:\s*"([^"]+)"',
        r'"csrf-token"\s*:\s*"([^"]+)"',
        r'window\.csrfToken\s*=\s*"([^"]+)"',
        r'globalThis\.csrfToken\s*=\s*"([^"]+)"',
        r'csrf[_-]?token["\']?\s*:\s*"([^"]+)"',
        r'X-CSRF-Token["\']?\s*:\s*"([^"]+)"',
        r'token["\']?\s*:\s*"([^"]+)"',
    ]
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
    m = re.findall(r'"([^"]{20,})"', html)
    for cand in m:
        if len(cand) > 30 and re.match(r'^[A-Za-z0-9_\-\.]+$', cand):
            pass
    return None


@asynccontextmanager
async def xui_session():
    if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
        raise XUIError("Добавь XUI_URL, XUI_USERNAME, XUI_PASSWORD.")

    if not XUI_URL.startswith(("https://", "http://")):
        raise XUIError("XUI_URL: нужен http:// или https://")

    ssl_context = _ssl_ctx() if XUI_URL.startswith("https://") else None

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=40),
        connector=aiohttp.TCPConnector(ssl=ssl_context),
    ) as session:
        async with session.get(
            f"{XUI_URL}/panel/",
            headers=_browser_headers(),
        ) as resp:
            html = await resp.text()

        csrf_token = extract_csrf_token(html)

        if not csrf_token:
            raise XUIError(
                "CSRF-токен не найден. 3x-ui v2.6.x изменил структуру."
            )

        await xui_request(
            session, "POST", "/login",
            csrf_token=csrf_token,
            json={"username": XUI_USERNAME, "password": XUI_PASSWORD},
        )
        yield session


def get_reality_parameters(inbound):
    if not REALITY_PUBLIC_KEY:
        raise XUIError("Не найден REALITY_PUBLIC_KEY")
    if not REALITY_SNI:
        raise XUIError("Не найден REALITY_SNI")
    if not REALITY_SHORT_ID:
        raise XUIError("Не найден REALITY_SHORT_ID")

    return {
        "public_key": REALITY_PUBLIC_KEY,
        "sni": REALITY_SNI,
        "short_id": REALITY_SHORT_ID,
        "spider_x": "/",
    }


def build_vless_link(client, inbound, reality):
    if not VPN_HOST:
        raise XUIError("Не найден VPN_HOST")

    try:
        port = int(os.getenv("VPN_PORT") or inbound["port"])
    except (ValueError, TypeError, KeyError):
        raise XUIError("Не удалось определить порт VPN.")

    host = VPN_HOST
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    params = {
        "type": "tcp",
        "encryption": "none",
        "security": "reality",
        "pbk": reality["public_key"],
        "fp": "chrome",
        "sni": reality["sni"],
        "sid": reality["short_id"],
        "spx": reality["spider_x"],
    }
    if client.get("flow"):
        params["flow"] = client["flow"]

    query = urlencode(params, quote_via=quote)
    return f"vless://{client['id']}@{host}:{port}?{query}#VPN"


async def create_or_get_test_client(telegram_id):
    if XUI_INBOUND_ID <= 0:
        raise XUIError("Сначала отправь /inbounds")

    async with xui_session() as session:
        inbound = await xui_request(
            session, "GET",
            f"/panel/api/inbounds/get/{XUI_INBOUND_ID}",
        )

        reality = get_reality_parameters(inbound)
        settings = as_dict(inbound.get("settings"))
        email = f"tg-test-{telegram_id}-{XUI_INBOUND_ID}"

        client = next(
            (i for i in (settings.get("clients") or []) if i.get("email") == email),
            None,
        )

        created = client is None
        now_ms = int(time.time() * 1000)

        if created:
            client = {
                "id": str(uuid.uuid4()),
                "email": email,
                "flow": "xtls-rprx-vision",
                "enable": True,
                "limitIp": 1,
                "totalGB": TEST_TRAFFIC_BYTES,
                "expiryTime": now_ms + TEST_HOURS * 3600 * 1000,
                "subId": secrets.token_hex(8),
                "reset": 0,
            }
        else:
            if not client.get("enable", True):
                raise XUIError(f"Клиент {email} выключен.")
            exp = int(client.get("expiryTime") or 0)
            if 0 < exp <= now_ms:
                raise XUIError("Срок теста истёк.")

        link = build_vless_link(client, inbound, reality)

        if created:
            await xui_request(
                session, "POST", "/panel/api/inbounds/addClient",
                json={"id": XUI_INBOUND_ID,
                      "settings": json.dumps({"clients": [client]})},
            )
        return link, created


async def show_xui_error(message, error):
    if isinstance(error, XUIError):
        text = str(error)
    elif isinstance(error, asyncio.TimeoutError):
        text = "Таймаут соединения"
    else:
        text = f"Ошибка: {type(error).__name__}: {error}"
    await message.answer(text, parse_mode=None)


@dp.message(Command("myid"), F.chat.type == "private")
async def my_id(message: Message):
    await message.answer(f"Твой Telegram ID: {message.from_user.id}")


@dp.message(Command("debug_panel"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def debug_panel(message: Message):
    try:
        ssl_context = _ssl_ctx() if XUI_URL.startswith("https://") else None
        async with aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=ssl_context),
        ) as session:
            async with session.get(f"{XUI_URL}/panel/", headers=_browser_headers()) as resp:
                html = await resp.text()
        token = extract_csrf_token(html)
        await message.answer(f"HTML длина: {len(html)}\nНайден CSRF: {token is not None}\nТокен: {token}")
        preview = html[:3500]
        for i in range(0, len(preview), 4000):
            await message.answer(f"<code>{escape(preview[i:i+4000])}</code>", parse_mode="HTML")
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("inbounds"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def list_inbounds(message: Message):
    try:
        async with xui_session() as session:
            items = await xui_request(session, "GET", "/panel/api/inbounds/list")
        if not items:
            await message.answer("Нет inbound'ов.")
            return
        await message.answer("Авторизация прошла УСПЕШНО!")
        for item in items:
            st = as_dict(item.get("streamSettings"))
            await message.answer(
                f"ID: {item['id']}\n"
                f"Название: {item.get('remark','')}\n"
                f"Протокол: {item.get('protocol','?')}\n"
                f"Транспорт: {st.get('network','?')}\n"
                f"Защита: {st.get('security','?')}\n"
                f"Порт: {item.get('port','?')}",
                parse_mode=None,
            )
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("test_vpn"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def test_vpn(message: Message):
    try:
        async with test_lock:
            link, created = await create_or_get_test_client(message.from_user.id)
        title = "КЛИЕНТ СОЗДАН! 24ч | 1ГБ" if created else "Существующий ключ"
        await message.answer(
            f"{title}\n\n<code>{escape(link)}</code>",
            parse_mode="HTML", protect_content=True,
        )
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("start"))
async def cmd_start(message: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Принимаю условия", callback_data="accept_license")]
    ])
    await message.answer(
        "Лицензионное соглашение",
        reply_markup=kb,
    )


@dp.callback_query(F.data == "accept_license")
async def accept_license(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Принято.", reply_markup=main_menu_kb())


@dp.callback_query(F.data == "main_menu")
async def main_menu_cb(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Меню", reply_markup=main_menu_kb())


def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Подключить VPN", callback_data="connect_vpn")],
        [InlineKeyboardButton(text="Профиль", callback_data="profile"),
         InlineKeyboardButton(text="Тарифы", callback_data="tariffs")],
        [InlineKeyboardButton(text="Поддержка", callback_data="support")],
    ])


def tariffs_kb():
    kb = []
    for key, data in TARIFFS.items():
        kb.append([InlineKeyboardButton(text=f"{data['name']} — {data['price']} ₽", callback_data=f"buy_{key}")])
    kb.append([InlineKeyboardButton(text="Назад", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Назад", callback_data="main_menu")]
    ])


@dp.callback_query(F.data == "tariffs")
async def tariffs_cb(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Тарифы", reply_markup=tariffs_kb())


@dp.callback_query(F.data == "profile")
async def profile_cb(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Профиль", reply_markup=back_kb())


@dp.callback_query(F.data == "connect_vpn")
async def connect_cb(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Выбери тариф", reply_markup=tariffs_kb())


@dp.callback_query(F.data == "support")
async def support_cb(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("Поддержка: @Suppr_XYZ", reply_markup=back_kb())


async def main():
    if ADMIN_ID == 0:
        logger.warning("ADMIN_ID не настроен")
    logger.info("Бот запущен")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
