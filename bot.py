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
        "traffic": "Безлимит", "ips": 10,
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
        "Content-Type": "application/x-www-form-urlencoded",
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
        # Сначала GET на панель — получаем session cookie
        await session.get(
            f"{XUI_URL}/panel/",
            headers=_browser_headers(),
        )
        # Потом login
        await xui_request(
            session, "POST", "/login",
            data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
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

    if not 1 <= port <= 65535:
        raise XUIError("Некорректный порт.")

    host = VPN_HOST
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    params = {
        "type": "tcp", "encryption": "none", "security": "reality",
        "pbk": reality["public_key"], "fp": "chrome",
        "sni": reality["sni"], "sid": reality["short_id"],
        "spx": reality["spider_x"],
    }
    if client.get("flow"):
        params["flow"] = client["flow"]

    query = urlencode(params, quote_via=quote)
    return f"vless://{client['id']}@{host}:{port}?{query}#VPN"


async def create_or_get_test_client(telegram_id):
    if XUI_INBOUND_ID <= 0:
        raise XUIError("Сначала /inbounds, потом XUI_INBOUND_ID.")

    async with xui_session() as session:
        inbound = await xui_request(
            session, "GET",
            f"/panel/api/inbounds/get/{XUI_INBOUND_ID}",
        )
        if not isinstance(inbound, dict):
            raise XUIError("Inbound не найден.")

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
                raise XUIError(
                    f"Срок истёк. Удали {email} в панели, повтори /test_vpn."
                )

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
        text = "Таймаут. Проверь доступность панели."
    else:
        logger.error("Ошибка: %s: %s", type(error).__name__, error)
        text = f"Ошибка: {type(error).__name__}: {error}"
    await message.answer(text, parse_mode=None)


# =========================
# КОМАНДЫ
# =========================

@dp.message(Command("myid"), F.chat.type == "private")
async def my_id(message: Message):
    await message.answer(f"ID: {message.from_user.id}")


@dp.message(Command("myip"), F.chat.type == "private")
async def my_ip(message: Message):
    async with aiohttp.ClientSession() as s:
        async with s.get("https://api.ipify.org") as r:
            ip = await r.text()
    await message.answer(f"IP сервера: {ip}")


@dp.message(Command("debug_login"), F.chat.type == "private")
async def debug_login(message: Message):
    """Пробует login 4 способами, показывает заголовки ответа."""
    ssl_context = _ssl_ctx() if XUI_URL.startswith("https://") else None
    base = XUI_URL.rstrip("/")
    results = []

    # Способ 1: POST /login без заголовков
    try:
        async with aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=ssl_context),
        ) as s:
            async with s.post(
                f"{base}/login",
                data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
            ) as r:
                body = (await r.text())[:200]
                results.append(
                    f"1) POST /login (без заголовков)\n"
                    f"   {r.status}\n"
                    f"   Headers: {dict(r.headers)}\n"
                    f"   Body: {body}"
                )
    except Exception as e:
        results.append(f"1) POST /login → {type(e).__name__}: {e}")

    # Способ 2: POST /login с Origin + Referer
    try:
        async with aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=ssl_context),
        ) as s:
            async with s.post(
                f"{base}/login",
                data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
                headers={
                    "Origin": base,
                    "Referer": f"{base}/panel/",
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ) as r:
                body = (await r.text())[:200]
                results.append(
                    f"2) POST /login (Origin+Referer)\n"
                    f"   {r.status}\n"
                    f"   Headers: {dict(r.headers)}\n"
                    f"   Body: {body}"
                )
    except Exception as e:
        results.append(f"2) POST /login (Origin) → {type(e).__name__}: {e}")

    # Способ 3: GET /panel/ → POST /login (с cookie)
    try:
        async with aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=ssl_context),
        ) as s:
            # GET чтобы получить cookie
            async with s.get(f"{base}/panel/", headers={"User-Agent": "Mozilla/5.0"}) as r:
                cookies = dict(s.cookie_jar)
                results.append(
                    f"3) GET /panel/ → {r.status}\n"
                    f"   Cookies: {cookies}"
                )

            # POST с теми же cookie
            async with s.post(
                f"{base}/login",
                data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
                headers={
                    "Origin": base,
                    "Referer": f"{base}/panel/",
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ) as r:
                body = (await r.text())[:200]
                results.append(
                    f"   POST /login (с cookie) → {r.status}\n"
                    f"   Headers: {dict(r.headers)}\n"
                    f"   Body: {body}"
                )
    except Exception as e:
        results.append(f"3) GET+POST → {type(e).__name__}: {e}")

    # Способ 4: POST /login с JSON
    try:
        async with aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=ssl_context),
        ) as s:
            async with s.post(
                f"{base}/login",
                json={"username": XUI_USERNAME, "password": XUI_PASSWORD},
                headers={
                    "Origin": base,
                    "Referer": f"{base}/panel/",
                    "User-Agent": "Mozilla/5.0",
                },
            ) as r:
                body = (await r.text())[:200]
                results.append(
                    f"4) POST /login (JSON)\n"
                    f"   {r.status}\n"
                    f"   Headers: {dict(r.headers)}\n"
                    f"   Body: {body}"
                )
    except Exception as e:
        results.append(f"4) POST /login (JSON) → {type(e).__name__}: {e}")

    full = "Отладка login:\n\n" + "\n\n".join(results)
    for i in range(0, len(full), 4000):
        await message.answer(full[i:i+4000], parse_mode=None)


@dp.message(Command("inbounds"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def list_inbounds(message: Message):
    try:
        async with xui_session() as session:
            items = await xui_request(session, "GET", "/panel/api/inbounds/list")
        if not items:
            await message.answer("Нет inbound'ов.")
            return
        await message.answer("Inbound'ы:")
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
        await message.answer("Запиши ID в XUI_INBOUND_ID → перезапусти → /test_vpn.")
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("test_vpn"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def test_vpn(message: Message):
    try:
        async with test_lock:
            link, created = await create_or_get_test_client(message.from_user.id)
        title = "✅ Создан! 24ч, 1ГиБ." if created else "🔐 Существующий ключ."
        await message.answer(
            f"{title}\n\n<code>{escape(link)}</code>",
            parse_mode="HTML", protect_content=True,
        )
    except Exception as error:
        await show_xui_error(message, error)


# =========================
# МЕНЮ
# =========================

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔐 Подключить VPN", callback_data="connect_vpn")],
        [InlineKeyboardButton(text="👤 Профиль", callback_data="profile"),
         InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs")],
        [InlineKeyboardButton(text="📋 Инструкция", callback_data="activation")],
        [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")],
    ])


def tariffs_kb():
    kb = [[InlineKeyboardButton(text=f"{d['name']} — {d['price']} ₽", callback_data=f"buy_{k}")]
          for k, d in TARIFFS.items()]
    kb.append([InlineKeyboardButton(text="◀️ Назад", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="◀️ Назад", callback_data="main_menu")]
    ])


@dp.message(Command("start"))
async def cmd_start(message: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Принимаю", callback_data="accept_license")]
    ])
    await message.answer(
        "📄 <b>Соглашение</b>\n\n"
        "1. Легальное использование.\n"
        "2. Запрещена передача ключей.\n"
        "3. Админ не несёт ответственности.\n\n<i>Нажми ниже.</i>",
        reply_markup=kb, parse_mode="HTML",
    )


@dp.callback_query(F.data == "accept_license")
async def accept_license(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("✅ Выбери:", reply_markup=main_menu_kb())


@dp.callback_query(F.data == "main_menu")
async def main_menu(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("🏠 Меню:", reply_markup=main_menu_kb())


@dp.callback_query(F.data == "tariffs")
async def tariffs(cb: CallbackQuery):
    await cb.answer()
    text = "<b>Тарифы:</b>\n\n"
    for d in TARIFFS.values():
        text += f"• {d['name']} — {d['price']}₽ | {d['traffic']} | {d['ips']} устр.\n"
    await cb.message.edit_text(text, reply_markup=tariffs_kb(), parse_mode="HTML")


@dp.callback_query(F.data.startswith("buy_"))
async def buy(cb: CallbackQuery):
    t = TARIFFS.get(cb.data.removeprefix("buy_"))
    if not t:
        await cb.answer("Не найден.", show_alert=True)
        return
    await cb.answer()
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить (демо)", callback_data="fake_pay")],
        [InlineKeyboardButton(text="◀️ Назад", callback_data="tariffs")],
    ])
    await cb.message.edit_text(
        f"💳 <b>{t['name']}</b> — {t['price']}₽\n<i>Оплата не подключена.</i>",
        reply_markup=kb, parse_mode="HTML",
    )


@dp.callback_query(F.data == "fake_pay")
async def fake_pay(cb: CallbackQuery):
    await cb.answer("Демо.", show_alert=True)
    await cb.message.edit_text("🧪 Демо.", reply_markup=back_kb())


@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("👤 Подписки не подключены.", reply_markup=back_kb())


@dp.callback_query(F.data == "connect_vpn")
async def connect(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("🔐 Выбери тариф:", reply_markup=tariffs_kb())


@dp.callback_query(F.data == "activation")
async def activation(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "📋 <b>Активация</b>\n\n"
        "1. Установи клиент (VLESS+Reality).\n"
        "2. Скопируй vless://...\n"
        "3. Импорт из буфера.\n"
        "4. Подключить.\n"
        "5. Подтверди VPN.",
        reply_markup=back_kb(), parse_mode="HTML",
    )


@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "💬 <a href='https://t.me/Suppr_XYZ'>@Suppr_XYZ</a>",
        reply_markup=back_kb(), parse_mode="HTML",
    )


# =========================
# ЗАПУСК
# =========================

async def main():
    if ADMIN_ID == 0:
        logger.warning("ADMIN_ID=0. Отправь /myid.")
    logger.info("Бот запущен")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
