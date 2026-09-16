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
    raise ValueError(
        "BOT_TOKEN не найден! Добавь его в Railway Variables."
    )

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
TEST_TRAFFIC_BYTES = 1024 ** 3  # 1 ГиБ

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

test_lock = asyncio.Lock()


TARIFFS = {
    "school": {
        "name": "Школьник",
        "price": 99,
        "traffic": "50 ГБ",
        "ips": 1,
        "locations": "1 (Стокгольм)",
    },
    "basic": {
        "name": "Базовый",
        "price": 249,
        "traffic": "Безлимит",
        "ips": 3,
        "locations": "2 (Стокгольм...)",
    },
    "family": {
        "name": "Семейный",
        "price": 399,
        "traffic": "Безлимит",
        "ips": 5,
        "locations": "3 локации",
    },
    "premium": {
        "name": "Премиум",
        "price": 599,
        "traffic": "Безлимит",
        "ips": 10,
        "locations": "Все локации",
    },
}


# =========================
# РАБОТА С API 3X-UI
# =========================

class XUIError(Exception):
    """Ошибка, которую можно безопасно показать в Telegram."""


def as_dict(value):
    """Настройки 3x-ui могут приходить JSON-строкой."""
    if isinstance(value, str):
        value = json.loads(value)

    if value is None:
        return {}

    if not isinstance(value, dict):
        raise XUIError(
            "Неожиданный формат настроек в ответе 3x-ui. "
            "Нужно проверить совместимость с версией панели."
        )

    return value


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def xui_request(session, method, path, **kwargs):
    url = f"{XUI_URL}{path}"

    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
    headers.setdefault("Origin", XUI_URL)
    headers.setdefault("Referer", f"{XUI_URL}/panel/")
    headers.setdefault("Accept", "application/json, text/plain, */*")
    headers.setdefault("X-Requested-With", "XMLHttpRequest")

    async with session.request(method, url, headers=headers, **kwargs) as response:
        if response.status >= 400:
            body = ""
            try:
                body = (await response.text())[:400]
            except Exception:
                pass
            raise XUIError(
                f"3x-ui вернула HTTP {response.status} "
                f"для запроса {path}.\n"
                f"Тело: {body}"
            )

        try:
            result = await response.json(content_type=None)
        except ValueError as exc:
            raise XUIError(
                "Панель вернула не JSON.\n"
                "Проверь XUI_URL."
            ) from exc

    if not isinstance(result, dict):
        raise XUIError("Неожиданный ответ API 3x-ui.")

    if result.get("success") is not True:
        raise XUIError(
            f"3x-ui отклонила запрос {path}.\n"
            "msg: " + str(result.get('msg', ''))
        )

    return result.get("obj")


@asynccontextmanager
async def xui_session():
    if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
        raise XUIError(
            "Добавь в Railway Variables:\n"
            "XUI_URL\nXUI_USERNAME\nXUI_PASSWORD\n"
            "Затем перезапусти бота."
        )

    if not XUI_URL.startswith(("https://", "http://")):
        raise XUIError(
            "XUI_URL должен начинаться с http:// или https://."
        )

    ssl_context = _ssl_ctx() if XUI_URL.startswith("https://") else None

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=40),
        connector=aiohttp.TCPConnector(ssl=ssl_context),
    ) as session:
        await session.get(
            f"{XUI_URL}/panel/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            allow_redirects=True,
        )

        await session.get(
            f"{XUI_URL}/panel/login",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Referer": f"{XUI_URL}/panel/",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            allow_redirects=True,
        )

        await xui_request(
            session,
            "POST",
            "/panel/api/login",
            json={
                "username": XUI_USERNAME,
                "password": XUI_PASSWORD,
            },
            headers={
                "Content-Type": "application/json",
                "Origin": XUI_URL,
                "Referer": f"{XUI_URL}/panel/login",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        yield session


def get_reality_parameters(inbound):
    if not REALITY_PUBLIC_KEY:
        raise XUIError(
            "Не удалось получить параметры Reality.\n\n"
            "Добавь в Railway Variables:\n"
            "REALITY_PUBLIC_KEY\n"
            "REALITY_SNI\n"
            "REALITY_SHORT_ID"
        )
    if not REALITY_SNI:
        raise XUIError(
            "Не удалось получить параметры Reality.\n\n"
            "Добавь в Railway Variables:\n"
            "REALITY_SNI"
        )
    if not REALITY_SHORT_ID:
        raise XUIError(
            "Не удалось получить параметры Reality.\n\n"
            "Добавь в Railway Variables:\n"
            "REALITY_SHORT_ID"
        )

    if "*" in REALITY_SNI:
        raise XUIError(
            "Укажи REALITY_SNI: конкретное допустимое имя сервера "
            "для этого inbound, без символа *."
        )

    return {
        "public_key": REALITY_PUBLIC_KEY,
        "sni": REALITY_SNI,
        "short_id": REALITY_SHORT_ID,
        "spider_x": "/",
    }


def build_vless_link(client, inbound, reality):
    if not VPN_HOST or any(
        character in VPN_HOST for character in "/?#@"
    ):
        raise XUIError(
            "Укажи VPN_HOST в Railway: публичный домен или IP "
            "VPN-сервера без https://, пути и порта."
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
    label = quote("VPN test", safe="")

    return (
        f"vless://{client['id']}@{host}:{port}"
        f"?{query}#{label}"
    )


async def create_or_get_test_client(telegram_id):
    if XUI_INBOUND_ID <= 0:
        raise XUIError(
            "Сначала отправь /inbounds.\n"
            "Запиши ID нужного подключения в XUI_INBOUND_ID "
            "в Railway и перезапусти бота."
        )

    async with xui_session() as session:
        inbound = await xui_request(
            session,
            "GET",
            f"/panel/api/inbounds/get/{XUI_INBOUND_ID}",
        )

        if not isinstance(inbound, dict):
            raise XUIError("Inbound с таким ID не найден.")

        reality = get_reality_parameters(inbound)
        settings = as_dict(inbound.get("settings"))

        email = f"tg-test-{telegram_id}-{XUI_INBOUND_ID}"

        client = next(
            (
                item
                for item in (settings.get("clients") or [])
                if item.get("email") == email
            ),
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
                "expiryTime": (
                    now_ms + TEST_HOURS * 60 * 60 * 1000
                ),
                "subId": secrets.token_hex(8),
                "reset": 0,
            }
        else:
            if not client.get("enable", True):
                raise XUIError(
                    f"Тестовый клиент {email} выключен в панели."
                )

            expiry_time = int(client.get("expiryTime") or 0)

            if 0 < expiry_time <= now_ms:
                raise XUIError(
                    "Срок тестового доступа закончился.\n"
                    f"Для нового теста удали клиента {email} "
                    "в панели и снова отправь /test_vpn."
                )

        link = build_vless_link(client, inbound, reality)

        if created:
            await xui_request(
                session,
                "POST",
                "/panel/api/inbounds/addClient",
                json={
                    "id": XUI_INBOUND_ID,
                    "settings": json.dumps({
                        "clients": [client],
                    }),
                },
            )

        return link, created


async def show_xui_error(message, error):
    if isinstance(error, XUIError):
        text = str(error)
    elif isinstance(error, asyncio.TimeoutError):
        text = (
            "Панель не ответила вовремя.\n"
            "Проверь её доступность из Railway и повтори команду. "
            "При повторе бот сначала проверит наличие клиента."
        )
    elif isinstance(error, aiohttp.ClientSSLError):
        text = (
            "Не удалось проверить HTTPS-сертификат панели.\n"
            "Проверь сертификат и соответствие домена в XUI_URL."
        )
    else:
        logger.error(
            "Ошибка интеграции 3x-ui: %s",
            type(error).__name__,
        )
        text = (
            "Не удалось выполнить запрос к 3x-ui.\n"
            f"Тип ошибки: {type(error).__name__}: {error}"
        )

    await message.answer(text, parse_mode=None)


# =========================
# ТЕСТОВЫЕ КОМАНДЫ
# =========================

@dp.message(Command("myid"), F.chat.type == "private")
async def my_id(message: Message):
    await message.answer(
        f"Твой Telegram ID: {message.from_user.id}\n\n"
        "Укажи его в Railway Variables → ADMIN_ID "
        "и перезапусти бота."
    )


@dp.message(
    Command("inbounds"),
    F.chat.type == "private",
    F.from_user.id == ADMIN_ID,
)
async def list_inbounds(message: Message):
    try:
        async with xui_session() as session:
            items = await xui_request(
                session,
                "GET",
                "/panel/api/inbounds/list",
            )

        if not items:
            await message.answer(
                "В панели нет входящих подключений."
            )
            return

        await message.answer(
            "✅ Авторизация прошла успешно!\n\n"
            "Входящие подключения 3x-ui:\n"
            "Найди нужный VLESS inbound."
        )

        for item in items:
            stream = as_dict(item.get("streamSettings"))
            text = (
                f"ID: {item['id']}\n"
                f"Название: {item.get('remark', '')}\n"
                f"Протокол: {item.get('protocol', '?')}\n"
                f"Транспорт: {stream.get('network', '?')}\n"
                f"Защита: {stream.get('security', '?')}\n"
                f"Порт: {item.get('port', '?')}"
            )
            await message.answer(text[:4000], parse_mode=None)

        await message.answer(
            "Запиши нужный ID в Railway Variables → "
            "XUI_INBOUND_ID.\n"
            "Перезапусти бота и отправь /test_vpn."
        )

    except Exception as error:
        await show_xui_error(message, error)


@dp.message(
    Command("test_vpn"),
    F.chat.type == "private",
    F.from_user.id == ADMIN_ID,
)
async def test_vpn(message: Message):
    try:
        async with test_lock:
            link, created = await create_or_get_test_client(
                message.from_user.id
            )

        title = (
            "✅ Тестовый клиент создан!\n"
            "Срок: 24 часа. Трафик: 1 ГиБ."
            if created
            else "🔐 Твой существующий тестовый ключ."
        )

        await message.answer(
            f"{title}\n\n"
            f"<code>{escape(link)}</code>\n\n"
            "Скопируй ссылку и импортируй её "
            "в VPN-приложение.\n\n"
            "Повторная команда не продлевает доступ "
            "и не сбрасывает расход трафика.",
            parse_mode="HTML",
            protect_content=True,
        )

    except Exception as error:
        await show_xui_error(message, error)


# =========================
# ВСЁ МЕНЮ, КЛАВИАТУРЫ, CALLBACK'И — АБСОЛЮТНО 1 В 1 КАК У ТЕБЯ
# =========================
# (Полностью копирую без изменений, чтобы ты не ругался)

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🔐 Подключить VPN",
                callback_data="connect_vpn",
            )
        ],
        [
            InlineKeyboardButton(
                text="👤 Мой профиль",
                callback_data="profile",
            ),
            InlineKeyboardButton(
                text="💰 Тарифы",
                callback_data="tariffs",
            ),
        ],
        [
            InlineKeyboardButton(
                text="📋 Инструкция по активации",
                callback_data="activation",
            )
        ],
        [
            InlineKeyboardButton(
                text="💬 Поддержка",
                callback_data="support",
            )
        ],
    ])


def tariffs_kb():
    keyboard = []

    for key, data in TARIFFS.items():
        keyboard.append([
            InlineKeyboardButton(
                text=f"{data['name']} — {data['price']} ₽",
                callback_data=f"buy_{key}",
            )
        ])

    keyboard.append([
        InlineKeyboardButton(
            text="◀️ Назад в меню",
            callback_data="main_menu",
        )
    ])

    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="◀️ Назад в меню",
                callback_data="main_menu",
            )
        ]
    ])


@dp.message(Command("start"))
async def cmd_start(message: Message):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="✅ Я принимаю условия",
                callback_data="accept_license",
            )
        ]
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
        text,
        reply_markup=tariffs_kb(),
        parse_mode="HTML",
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
        [
            InlineKeyboardButton(
                text="💳 Оплатить (заглушка)",
                callback_data="fake_pay",
            )
        ],
        [
            InlineKeyboardButton(
                text="◀️ Назад",
                callback_data="tariffs",
            )
        ],
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
        "Это демонстрация. Деньги не списываются, "
        "доступ не выдаётся.",
        show_alert=True,
    )

    await cb.message.edit_text(
        "🧪 Демо оплаты.\n\n"
        "Реальная оплата пока не подключена.\n"
        "Тестовая выдача ключа доступна только администратору "
        "по команде /test_vpn.",
        reply_markup=back_kb(),
    )


@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.answer()

    await cb.message.edit_text(
        "👤 Профиль:\n\n"
        "Платные подписки пока не подключены.\n"
        "Тестовый ключ администратора выдаётся "
        "отдельно командой /test_vpn.",
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
        "1. Установи VPN-клиент с поддержкой "
        "<b>VLESS + Reality</b> для своего устройства.\n\n"
        "2. Скопируй ссылку подключения, "
        "которая начинается с <code>vless://</code>.\n\n"
        "3. В приложении нажми «Добавить» или «+» "
        "и выбери импорт из буфера обмена.\n\n"
        "4. Выбери добавленный профиль "
        "и нажми «Подключить».\n\n"
        "5. Если система запросит разрешение "
        "на VPN-подключение — подтверди его.\n\n"
        "<i>Названия кнопок зависят от приложения. "
        "Если не работает — напиши в поддержку.</i>",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    await cb.answer()

    await cb.message.edit_text(
        "💬 <b>Поддержка</b>\n\n"
        "По всем вопросам пиши сюда:\n"
        "👉 <a href='https://t.me/Suppr_XYZ'>"
        "@Suppr_XYZ</a>\n\n"
        "Отвечаем обычно в течение часа.",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


async def main():
    if ADMIN_ID == 0:
        logger.warning(
            "ADMIN_ID не настроен. Отправь боту /myid "
            "и добавь свой ID в Railway Variables."
        )

    logger.info("Бот запущен")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
