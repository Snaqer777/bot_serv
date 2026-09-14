import asyncio
import json
import logging
import os
import secrets
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


# =========================================================
# 1. НАСТРОЙКИ И ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ
# =========================================================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден! Добавь его в Railway Variables.")

ADMIN_ID = int(os.getenv("ADMIN_ID") or "0")

XUI_URL = os.getenv("XUI_URL", "").strip().rstrip("/")
XUI_USERNAME = os.getenv("XUI_USERNAME", "")
XUI_PASSWORD = os.getenv("XUI_PASSWORD", "")
XUI_INBOUND_ID = int(os.getenv("XUI_INBOUND_ID") or "0")

VPN_HOST = os.getenv("VPN_HOST", "").strip()

# Параметры для тестового ключа
TEST_HOURS = 24
TEST_TRAFFIC_BYTES = 1024 ** 3  # 1 ГиБ

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Блокировка от одновременных кликов
test_lock = asyncio.Lock()

# Тарифная сетка
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
        "locations": "2 локации",
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


# =========================================================
# 2. ИНТЕГРАЦИЯ С 3X-UI API
# =========================================================

class XUIError(Exception):
    """Кастомное исключение с понятным текстом для пользователя."""


def as_dict(value):
    """Безопасный парсинг JSON-строки или словаря."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {}

    if value is None or not isinstance(value, dict):
        return {}

    return value


async def xui_request(session: aiohttp.ClientSession, method: str, path: str, **kwargs):
    """Выполнение HTTP-запроса к API панели 3x-ui."""
    url = f"{XUI_URL}{path}"
    
    async with session.request(method, url, **kwargs) as response:
        if response.status >= 400:
            raise XUIError(
                f"3x-ui вернула HTTP {response.status} на запрос {path}.\n"
                "Проверь логин, пароль и URL панели."
            )

        try:
            result = await response.json(content_type=None)
        except ValueError as exc:
            raise XUIError(
                "Панель вернула не JSON-ответ.\n"
                "Проверь XUI_URL: нужен базовый адрес панели с секретным путём (без /panel/inbounds)."
            ) from exc

    if not isinstance(result, dict):
        raise XUIError("Неожиданный формат ответа от 3x-ui.")

    if result.get("success") is not True:
        msg = result.get("msg", "Запрос отклонен панелью")
        raise XUIError(f"Ошибка 3x-ui: {msg}")

    return result.get("obj")


@asynccontextmanager
async def xui_session():
    """Контекстный менеджер для авторизованной сессии в 3x-ui."""
    if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
        raise XUIError(
            "В Railway не заполнены переменные:\n"
            "XUI_URL, XUI_USERNAME или XUI_PASSWORD."
        )

    # Имитируем реальный браузер (защита от 403 Forbidden)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
    }

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=20),
        headers=headers,
    ) as session:
        # Авторизация в панели
        await xui_request(
            session,
            "POST",
            "/login",
            data={
                "username": XUI_USERNAME,
                "password": XUI_PASSWORD,
            },
        )
        yield session


def get_reality_parameters(inbound: dict):
    """Извлечение Reality параметров (pbk, sni, sid, spiderX)."""
    if inbound.get("protocol") != "vless":
        raise XUIError("Выбранный Inbound не является VLESS.")

    if not inbound.get("enable"):
        raise XUIError("Выбранный Inbound выключен в панели.")

    stream = as_dict(inbound.get("streamSettings"))
    reality = as_dict(stream.get("realitySettings"))
    client_settings = as_dict(reality.get("settings"))

    # Поиск публичного ключа Reality
    public_key = (
        os.getenv("REALITY_PUBLIC_KEY")
        or client_settings.get("publicKey")
        or reality.get("publicKey")
    )

    server_names = reality.get("serverNames") or []
    if isinstance(server_names, str):
        server_names = [s.strip() for s in server_names.split(",")]

    short_ids = reality.get("shortIds") or []
    if isinstance(short_ids, str):
        short_ids = [s.strip() for s in short_ids.split(",")]

    sni = os.getenv("REALITY_SNI") or (server_names[0] if server_names else "")
    short_id = os.getenv("REALITY_SHORT_ID")
    if short_id is None:
        short_id = short_ids[0] if short_ids else ""

    if not public_key or not sni:
        raise XUIError(
            "Не удалось автоматически извлечь Reality ключи из панели.\n"
            "Добавь в Railway Variables:\n"
            "REALITY_PUBLIC_KEY — публичный ключ Reality\n"
            "REALITY_SNI — Server Name (например: dl.google.com)\n"
            "REALITY_SHORT_ID — Short ID"
        )

    return {
        "public_key": public_key,
        "sni": sni,
        "short_id": short_id,
        "spider_x": client_settings.get("spiderX") or reality.get("spiderX") or "/",
    }


def build_vless_link(client: dict, inbound: dict, reality: dict) -> str:
    """Сборка рабочей ссылки подключения vless://..."""
    if not VPN_HOST:
        raise XUIError("Переменная VPN_HOST не заполнена в Railway Variables.")

    port = int(os.getenv("VPN_PORT") or inbound["port"])
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
    label = quote(f"VPN-{client.get('email', 'Key')}", safe="")

    return f"vless://{client['id']}@{host}:{port}?{query}#{label}"


async def create_or_get_test_client(telegram_id: int):
    """Поиск или создание клиента в выбранном Inbound."""
    if XUI_INBOUND_ID <= 0:
        raise XUIError("Сначала отправь /inbounds и установи XUI_INBOUND_ID в Railway.")

    async with xui_session() as session:
        inbound = await xui_request(
            session,
            "GET",
            f"/panel/api/inbounds/get/{XUI_INBOUND_ID}",
        )

        if not isinstance(inbound, dict):
            raise XUIError("Inbound с указанным ID не найден в панели.")

        reality = get_reality_parameters(inbound)
        settings = as_dict(inbound.get("settings"))

        email = f"tg-{telegram_id}"
        clients = settings.get("clients") or []
        
        client = next((c for c in clients if c.get("email") == email), None)
        created = client is None
        now_ms = int(time.time() * 1000)

        if created:
            client = {
                "id": str(uuid.uuid4()),
                "email": email,
                "flow": "xtls-rprx-vision",
                "enable": True,
                "limitIp": 2,
                "totalGB": TEST_TRAFFIC_BYTES,
                "expiryTime": now_ms + TEST_HOURS * 60 * 60 * 1000,
                "subId": secrets.token_hex(8),
                "reset": 0,
            }

            await xui_request(
                session,
                "POST",
                "/panel/api/inbounds/addClient",
                json={
                    "id": XUI_INBOUND_ID,
                    "settings": json.dumps({"clients": [client]}),
                },
            )
        else:
            if not client.get("enable", True):
                raise XUIError("Твой ключ отключен администратором в панели.")

        link = build_vless_link(client, inbound, reality)
        return link, created


async def show_xui_error(message: Message, error: Exception):
    """Обработчик и вывод ошибок пользователю."""
    if isinstance(error, XUIError):
        text = str(error)
    elif isinstance(error, asyncio.TimeoutError):
        text = "Панель 3x-ui не ответила вовремя (таймаут соединения)."
    else:
        logger.exception("Непредвиденная ошибка интеграции:")
        text = f"Произошла ошибка: {type(error).__name__}\n{error}"

    await message.answer(text, parse_mode=None)


# =========================================================
# 3. КЛАВИАТУРЫ И ИНТЕРФЕЙС
# =========================================================

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🔐 Подключить VPN", callback_data="connect_vpn")
        ],
        [
            InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
            InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs"),
        ],
        [
            InlineKeyboardButton(text="📋 Инструкция по активации", callback_data="activation")
        ],
        [
            InlineKeyboardButton(text="💬 Поддержка", callback_data="support")
        ],
    ])


def tariffs_kb():
    keyboard = []
    for key, data in TARIFFS.items():
        keyboard.append([
            InlineKeyboardButton(
                text=f"{data['name']} — {data['price']} ₽/мес",
                callback_data=f"buy_{key}",
            )
        ])
    keyboard.append([
        InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")
    ])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")
        ]
    ])


# =========================================================
# 4. ОБРАБОТЧИКИ КОМАНД И КНОПОК
# =========================================================

@dp.message(Command("myid"), F.chat.type == "private")
async def cmd_myid(message: Message):
    await message.answer(
        f"Твой Telegram ID: <code>{message.from_user.id}</code>\n\n"
        "Укажи его в <b>ADMIN_ID</b> в Railway Variables.",
        parse_mode="HTML",
    )


@dp.message(Command("inbounds"), F.chat.type == "private")
async def cmd_inbounds(message: Message):
    if ADMIN_ID != 0 and message.from_user.id != ADMIN_ID:
        return

    try:
        async with xui_session() as session:
            items = await xui_request(session, "GET", "/panel/api/inbounds/list")

        if not items:
            await message.answer("В панели нет подключений. Создай VLESS Inbound.")
            return

        text = "<b>Список ваших Inbounds в 3x-ui:</b>\n\n"
        for item in items:
            stream = as_dict(item.get("streamSettings"))
            text += (
                f"🔹 <b>ID: {item['id']}</b> | {item.get('remark', 'Без имени')}\n"
                f"Протокол: <code>{item.get('protocol')}</code> | Порт: <code>{item.get('port')}</code>\n"
                f"Сеть: {stream.get('network')} | Защита: {stream.get('security')}\n\n"
            )

        text += "Скопируй нужный <b>ID</b> в переменную <code>XUI_INBOUND_ID</code> в Railway."
        await message.answer(text, parse_mode="HTML")

    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("test_vpn"), F.chat.type == "private")
async def cmd_test_vpn(message: Message):
    if ADMIN_ID != 0 and message.from_user.id != ADMIN_ID:
        return

    try:
        async with test_lock:
            link, created = await create_or_get_test_client(message.from_user.id)

        title = "✅ <b>Ключ успешно создан!</b>" if created else "🔐 <b>Твой тестовый ключ:</b>"
        await message.answer(
            f"{title}\n\n"
            f"<code>{escape(link)}</code>\n\n"
            "Нажми на код ссылки выше, чтобы скопировать её, и импортируй в VPN-клиент (V2rayN, Happ, Streisand, Nekobox).",
            parse_mode="HTML",
        )
    except Exception as error:
        await show_xui_error(message, error)


@dp.message(Command("start"))
async def cmd_start(message: Message):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Принять условия", callback_data="accept_license")]
    ])
    await message.answer(
        "📄 <b>Лицензионное соглашение</b>\n\n"
        "1. Использование VPN только в законных целях.\n"
        "2. Запрещена перепродажа и спам.\n"
        "3. Нажмите кнопку ниже для продолжения.",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "accept_license")
@dp.callback_query(F.data == "main_menu")
async def menu_callback(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "🏠 <b>Главное меню:</b>\n\nВыберите нужный раздел 👇",
        reply_markup=main_menu_kb(),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "tariffs")
@dp.callback_query(F.data == "connect_vpn")
async def tariffs_callback(cb: CallbackQuery):
    await cb.answer()
    text = "<b>Доступные тарифы:</b>\n\n"
    for data in TARIFFS.values():
        text += f"• <b>{data['name']}</b> — {data['price']} ₽ | {data['traffic']} | {data['ips']} устр.\n"

    await cb.message.edit_text(text, reply_markup=tariffs_kb(), parse_mode="HTML")


@dp.callback_query(F.data.startswith("buy_"))
async def buy_callback(cb: CallbackQuery):
    tariff_key = cb.data.removeprefix("buy_")
    tariff = TARIFFS.get(tariff_key)

    if not tariff:
        await cb.answer("Тариф не найден.", show_alert=True)
        return

    await cb.answer()
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить (тест)", callback_data="fake_pay")],
        [InlineKeyboardButton(text="◀️ Назад к тарифам", callback_data="tariffs")],
    ])

    await cb.message.edit_text(
        f"Тариф: <b>{tariff['name']}</b>\n"
        f"Стоимость: <b>{tariff['price']} ₽/мес</b>\n\n"
        "<i>Подключение реального эквайринга настраивается после проверки ключей.</i>",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "fake_pay")
async def fake_pay_callback(cb: CallbackQuery):
    await cb.answer("Демо-режим оплаты.", show_alert=True)
    await cb.message.edit_text(
        "🧪 Оплата находится в режиме тестирования.\n\n"
        "Чтобы получить ключ, отправь команду /test_vpn (доступно админу).",
        reply_markup=back_kb(),
    )


@dp.callback_query(F.data == "profile")
async def profile_callback(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        f"👤 <b>Ваш профиль:</b>\n\n"
        f"ID: <code>{cb.from_user.id}</code>\n"
        f"Статус подписки: <i>Не активна</i>\n\n"
        "Для активации выберите тариф в меню.",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "activation")
async def activation_callback(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "📋 <b>Инструкция по подключению:</b>\n\n"
        "1. Скачайте приложение:\n"
        "   • <b>iOS:</b> Streisand / V2Box / FoXray\n"
        "   • <b>Android:</b> v2rayNG / Happ / Nekobox\n"
        "   • <b>Windows:</b> v2rayN / Nekoray\n\n"
        "2. Скопируйте ключ формата <code>vless://...</code>\n"
        "3. Откройте приложение и нажмите <b>«Импорт из буфера обмена» (+)</b>.\n"
        "4. Выберите добавленный сервер и нажмите <b>Подключить</b>.",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "support")
async def support_callback(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "💬 <b>Поддержка пользователей</b>\n\n"
        "Если у вас возникли вопросы по настройке:\n"
        "👉 Напишите администратору: @Suppr_XYZ",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


# =========================================================
# 5. ТОЧКА ВХОДА
# =========================================================

async def main():
    logger.info("Запуск бота...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
