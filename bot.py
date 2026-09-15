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
            raise XUIError(f"Не JSON в ответе на {path}.\n{text[:200]}") from exc

    if not isinstance(result, dict):
        raise XUIError("Неожиданный ответ API.")

    if result.get("success") is not True:
        raise XUIError(
            f"3x-ui отклонила {path}. msg: {result.get('msg', '')}"
        )

    return result.get("obj")


def extract_csrf_token(html: str) -> str | None:
    m = re.search(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
    m = re.search(r'csrfToken\s*[:=]\s*["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
    m = re.search(r'token\s*:\s*["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
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
        timeout=aiohttp.ClientTimeout(total=30),
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
                "Не удалось получить CSRF-токен с панели 3x-ui."
            )

        await xui_request(
            session, "POST", "/login",
            csrf_token=csrf_token,
            json={"username": XUI_USERNAME, "password": XUI_PASSWORD},
        )
        yield session


def get_reality_parameters(inbound):
    # БРО! В НОВОЙ 3X-UI API НЕ ОТДАЁТ REALITY ПАРАМЕТРЫ
    # Поэтому ТОЛЬКО берём их из ENV переменных Railway

    public_key = os.getenv("REALITY_PUBLIC_KEY", "").strip()
    sni = os.getenv("REALITY_SNI", "").strip()
    short_id = os.getenv("REALITY_SHORT_ID", "").strip()

    if not public_key:
        raise XUIError(
            "❌ НЕ ХВАТАЕТ REALITY_PUBLIC_KEY!\n\n"
            "Ты НЕ добавил Public Key в Railway Variables."
        )
    if not sni:
        raise XUIError(
            "❌ НЕ ХВАТАЕТ REALITY_SNI!\n\n"
            "Ты НЕ добавил Server Names (SNI) в Railway Variables."
        )
    if not short_id:
        raise XUIError(
            "❌ НЕ ХВАТАЕТ REALITY_SHORT_ID!\n\n"
            "Ты НЕ добавил Short ID в Railway Variables."
        )

    return {
        "public_key": public_key,
        "sni": sni,
        "short_id": short_id,
        "spider_x": "/",
    }


def build_vless_link(client, inbound, reality):
    if not VPN_HOST or VPN_HOST == "":
        raise XUIError(
            "❌ НЕ ХВАТАЕТ VPN_HOST!\n\n"
            "Добавь VPN_HOST в Railway Variables.\n"
            "Значение: 138.124.110.74"
        )

    try:
        port = int(os.getenv("VPN_PORT") or inbound["port"])
    except (ValueError, TypeError, KeyError) as exc:
        raise XUIError("Не удалось определить порт VPN.") from exc

    if not 1 <= port <= 65535:
        raise XUIError("Некорректный порт VPN.")

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
        raise XUIError("Сначала отправь /inbounds, потом добавь XUI_INBOUND_ID в Railway")

    if not VPN_HOST:
        raise XUIError("❌ Добавь VPN_HOST=138.124.110.74 в Railway Variables!")

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
        text = f"❌ ОШИБКА: {type(error).__name__}\n\n{str(error)}"
    await message.answer(text, parse_mode=None)


# =========================
# КОМАНДЫ
# =========================

@dp.message(Command("myid"), F.chat.type == "private")
async def my_id(message: Message):
    await message.answer(f"Твой Telegram ID: {message.from_user.id}")


@dp.message(Command("debug_inbound"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def debug_inbound(message: Message):
    try:
        async with xui_session() as session:
            inbound = await xui_request(
                session, "GET",
                f"/panel/api/inbounds/get/{XUI_INBOUND_ID}",
            )
        text = json.dumps(inbound, indent=2, ensure_ascii=False)
        for i in range(0, len(text), 4000):
            await message.answer(f"<code>{escape(text[i:i+4000])}</code>", parse_mode="HTML")
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
        await message.answer("✅ АВТОРИЗАЦИЯ ПРОШЛА!\n\nВходящие подключения:")
        for item in items:
            st = as_dict(item.get("streamSettings"))
            await message.answer(
                f"🆔 ID: {item['id']}\n"
                f"📝 Название: {item.get('remark','')}\n"
                f"⚙️ Протокол: {item.get('protocol','?')}\n"
                f"🚀 Транспорт: {st.get('network','?')}\n"
                f"🔒 Защита: {st.get('security','?')}\n"
                f"🔌 Порт: {item.get('port','?')}",
                parse_mode=None,
            )
        await message.answer("🎉 Запиши ID в Railway → XUI_INBOUND_ID → перезапусти → /test_vpn")
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("test_vpn"), F.chat.type == "private", F.from_user.id == ADMIN_ID)
async def test_vpn(message: Message):
    try:
        async with test_lock:
            link, created = await create_or_get_test_client(message.from_user.id)
        title = "✅ КЛИЕНТ СОЗДАН!\n⏰ 24 часа | 📊 1 ГиБ" if created else "🔐 Существующий тестовый ключ"
        await message.answer(
            f"{title}\n\n<code>{escape(link)}</code>\n\n📱 Импортируй в VPN-приложение!",
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
        [InlineKeyboardButton(text="✅ Принимаю условия", callback_data="accept_license")]
    ])
    await message.answer(
        "📄 <b>Лицензионное соглашение</b>\n\n"
        "1. Только легальное использование.\n"
        "2. Запрещена передача ключей.\n"
        "3. Админ не несёт ответственности.\n\n<i>Нажми ниже.</i>",
        reply_markup=kb, parse_mode="HTML",
    )


@dp.callback_query(F.data == "accept_license")
async def accept_license(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("✅ Принято. Выбери действие:", reply_markup=main_menu_kb())


@dp.callback_query(F.data == "main_menu")
async def main_menu(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("🏠 Главное меню:", reply_markup=main_menu_kb())


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
    await cb.message.edit_text("🧪 Демо оплата.", reply_markup=back_kb())


@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("👤 Профиль\n\nПодписки не подключены.", reply_markup=back_kb())


@dp.callback_query(F.data == "connect_vpn")
async def connect(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("🔐 Выбери тариф:", reply_markup=tariffs_kb())


@dp.callback_query(F.data == "activation")
async def activation(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "📋 <b>Активация</b>\n\n"
        "1. Установи клиент с поддержкой VLESS + Reality\n"
        "2. Скопируй ссылку vless://...\n"
        "3. Импортируй в приложение\n"
        "4. Подключись",
        reply_markup=back_kb(), parse_mode="HTML",
    )


@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "💬 Поддержка:\n👉 <a href='https://t.me/Suppr_XYZ'>@Suppr_XYZ</a>",
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
