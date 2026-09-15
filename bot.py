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


# =========================
# НАСТРОЙКИ
# =========================

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
        "traffic": "Безлимит", "ips": 5,
        "locations": "3 локации",
    },
    "premium": {
        "name": "Премиум", "price": 599,
        "traffic": "Безлимит",
        "ips": 10,
        "locations": "Все локации",
    },
}


# =========================
# 3X-UI API
# =========================

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
    }


async def xui_request(session, method, path, **kwargs):
    url = f"{XUI_URL}{path}"
    headers = kwargs.pop("headers", {})
    headers.update(_browser_headers())

    async with session.request(method, url, headers=headers, **kwargs) as response:
        if response.status >= 400:
            body = ""
            try:
                body = (await response.text())[:300]
            except Exception:
                pass
            raise XUIError(
                f"HTTP {response.status} для {path}\n"
                f"URL: {url}\n"
                f"Тело: {body}"
            )

        try:
            result = await response.json(content_type=None)
        except ValueError as exc:
            raise XUIError(f"Не JSON в ответе на {path}.") from exc

    if not isinstance(result, dict):
        raise XUIError("Неожиданный ответ API.")

    if result.get("success") is not True:
        raise XUIError(
            f"3x-ui отклонила {path}. msg: {result.get('msg', '')}"
        )

    return result.get("obj")


@asynccontextmanager
async def xui_session():
    if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
        raise XUIError("Добавь XUI_URL, XUI_USERNAME, XUI_PASSWORD.")

    if not XUI_URL.startswith(("https://", "http://")):
        raise XUIError("XUI_URL: нужен http:// или https://")

    ssl_context = _ssl_ctx() if XUI_URL.startswith("https://") else None

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=25),
        connector=aiohttp.TCPConnector(ssl=ssl_context),
    ) as session:
        # Обязательно получаем cookies перед логином
        await session.get(
            f"{XUI_URL}/panel/",
            headers=_browser_headers(),
        )
        # Логинимся через JSON (новая версия 3x-ui)
        await xui_request(
            session, "POST", "/login",
            json={"username": XUI_USERNAME, "password": XUI_PASSWORD},
        )
        yield session


def get_reality_parameters(inbound):
    if inbound.get("protocol") != "vless":
        raise XUIError("Inbound не VLESS.")
    if not inbound.get("enable"):
        raise XUIError("Inbound выключен.")

    stream = as_dict(inbound.get("streamSettings"))

    if stream.get("network") not in ("tcp", "raw") or stream.get("security") != "reality":
        raise XUIError("Нужен VLESS + TCP/RAW + Reality.")

    tcp_settings = as_dict(stream.get("tcpSettings") or stream.get("rawSettings"))
    header = as_dict(tcp_settings.get("header"))
    if header.get("type", "none") != "none":
        raise XUIError("Нужен TCP без HTTP-заголовка.")

    reality = as_dict(stream.get("realitySettings"))
    client_settings = as_dict(reality.get("settings"))

    public_key = (
        os.getenv("REALITY_PUBLIC_KEY")
        or client_settings.get("publicKey")
        or reality.get("publicKey")
    )
    server_names = reality.get("serverNames") or []
    short_ids = reality.get("shortIds") or []

    sni = os.getenv("REALITY_SNI") or (server_names[0] if server_names else "")
    short_id = os.getenv("REALITY_SHORT_ID")
    if short_id is None:
        short_id = short_ids[0] if short_ids else None

    if not public_key or not sni or short_id is None:
        raise XUIError(
            "Не хватает параметров Reality.\n"
            "Добавь REALITY_PUBLIC_KEY, REALITY_SNI, REALITY_SHORT_ID."
        )
    if "*" in sni:
        raise XUIError("REALITY_SNI: без *.")

    return {
        "public_key": public_key,
        "sni": sni,
        "short_id": short_id,
        "spider_x": client_settings.get("spiderX") or "/",
    }


def build_vless_link(client, inbound, reality):
    if not VPN_HOST:
        raise XUIError("Укажи VPN_HOST в Railway.")

    try:
        port = int(os.getenv("VPN_PORT") or inbound["port"])
    except (ValueError, TypeError, KeyError) as exc:
        raise XUIError("Не удалось определить порт.") from exc

    if not 1 
