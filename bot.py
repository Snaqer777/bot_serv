import asyncio
import json
import logging
import os
import secrets
import socket
import ssl
import time
import urllib.parse
import uuid

from html import escape
from urllib.parse import quote, urlencode

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
# 1. НАСТРОЙКИ И ПЕРЕМЕННЫЕ
# =========================================================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден! Добавь его в Railway Variables.")

ADMIN_ID = int(os.getenv("ADMIN_ID", "0").strip() or "0")

# Очищаем URL от лишних слешей и суффиксов
raw_url = os.getenv("XUI_URL", "").strip().rstrip("/")
if raw_url.endswith("/panel"):
    raw_url = raw_url[:-6].rstrip("/")

XUI_URL = raw_url
XUI_USERNAME = os.getenv("XUI_USERNAME", "").strip()
XUI_PASSWORD = os.getenv("XUI_PASSWORD", "").strip()
XUI_INBOUND_ID = int(os.getenv("XUI_INBOUND_ID", "0").strip() or "0")

VPN_HOST = os.getenv("VPN_HOST", "").strip()

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
# 2. НИЗКОУРОВНЕВЫЙ HTTP-КЛИЕНТ (RAW SOCKETS)
# =========================================================

class XUIError(Exception):
    """Понятная ошибка для пользователя."""


def as_dict(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {}
    if value is None or not isinstance(value, dict):
        return {}
    return value


class RawResponse:
    def __init__(self, status_code: int, status_text: str, headers: dict, body: bytes, raw_headers: str):
        self.status_code = status_code
        self.status_text = status_text
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body
        self.raw_headers = raw_headers
        self.text = body.decode("utf-8", errors="ignore")

    def json(self):
        return json.loads(self.text)


class RawHttpClient:
    """HTTP-клиент на чистых сокетах: обходит баги парсинга HTTP/0.0 и строгие проверки TLS."""

    def __init__(self):
        self.cookies = {}

    def request(self, method: str, url: str, body_data=None, content_type: str = None, max_redirects: int = 5) -> RawResponse:
        current_url = url

        for _ in range(max_redirects):
            parsed = urllib.parse.urlparse(current_url)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            payload_bytes = b""
            req_content_type = content_type

            if isinstance(body_data, dict):
                if content_type == "application/json":
                    payload_bytes = json.dumps(body_data).encode("utf-8")
                else:
                    payload_bytes = urllib.parse.urlencode(body_data).encode("utf-8")
                    req_content_type = "application/x-www-form-urlencoded"
            elif isinstance(body_data, str):
                payload_bytes = body_data.encode("utf-8")
            elif isinstance(body_data, bytes):
                payload_bytes = body_data

            origin_host = f"{scheme}://{host}:{port}" if parsed.port else f"{scheme}://{host}"
            base_ref = f"{origin_host}{parsed.path}" if parsed.path else f"{origin_host}/"

            req_headers = {
                "Host": f"{host}:{port}" if parsed.port else host,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": origin_host,
                "Referer": base_ref,
                "Connection": "close",
            }
            if req_content_type:
                req_headers["Content-Type"] = req_content_type
            if payload_bytes:
                req_headers["Content-Length"] = str(len(payload_bytes))

            if self.cookies:
                req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

            req_lines = [f"{method} {path} HTTP/1.1"]
            for k, v in req_headers.items():
                req_lines.append(f"{k}: {v}")
            raw_req = "\r\n".join(req_lines).encode("utf-8") + b"\r\n\r\n" + payload_bytes

            raw_sock = socket.create_connection((host, port), timeout=12)
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock

            sock.sendall(raw_req)

            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break
            sock.close()

            if b"\r\n\r\n" in response_data:
                header_part, body_part = response_data.split(b"\r\n\r\n", 1)
            else:
                header_part = response_data
                body_part = b""

            header_lines = header_part.decode("iso-8859-1", errors="ignore").split("\r\n")
            status_line = header_lines[0] if header_lines else "HTTP/1.1 200 OK"

            parts = status_line.split(" ", 2)
            status_code = 200
            status_text = "OK"
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                    status_text = parts[2] if len(parts) > 2 else ""
                except ValueError:
                    pass

            resp_headers = {}
            for line in header_lines[1:]:
                if ": " in line:
                    hk, hv = line.split(": ", 1)
                    resp_headers[hk.lower()] = hv
                    if hk.lower() == "set-cookie":
                        c_part = hv.split(";")[0]
                        if "=" in c_part:
                            ck, cv = c_part.split("=", 1)
                            self.cookies[ck.strip()] = cv.strip()

            if resp_headers.get("transfer-encoding", "").lower() == "chunked":
                decoded_body = b""
                idx = 0
                while idx < len(body_part):
                    c_end = body_part.find(b"\r\n", idx)
                    if c_end == -1:
                        break
                    chunk_size_str = body_part[idx:c_end].strip()
                    try:
                        chunk_size = int(chunk_size_str, 16)
                    except ValueError:
                        break
                    if chunk_size == 0:
                        break
                    d_start = c_end + 2
                    d_end = d_start + chunk_size
                    decoded_body += body_part[d_start:d_end]
                    idx = d_end + 2
                body_part = decoded_body

            resp = RawResponse(status_code, status_text, resp_headers, body_part, header_part.decode("utf-8", errors="ignore"))

            if status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                new_loc = resp.headers["location"]
                current_url = urllib.parse.urljoin(current_url, new_loc)
                if status_code in (301, 302, 303):
                    method = "GET"
                    body_data = None
                    content_type = None
                continue

            return resp

        raise XUIError("Превышено количество редиректов 3x-ui.")


class XUIClient:
    def __init__(self):
        if not XUI_URL or not XUI_USERNAME or not XUI_PASSWORD:
            raise XUIError("В Railway Variables не заполнены XUI_URL, XUI_USERNAME или XUI_PASSWORD.")
        self.base_url = XUI_URL
        self.http = RawHttpClient()

    def login(self):
        # 1. Запрашиваем корень панели для получения сессионных кук CSRF
        self.http.request("GET", f"{self.base_url}/")

        login_data = {
            "username": XUI_USERNAME,
            "password": XUI_PASSWORD,
            "loginSecret": "",
        }

        # 2. Отправляем Form-Data
        resp = self.http.request(
            "POST",
            f"{self.base_url}/login",
            body_data=login_data,
            content_type="application/x-www-form-urlencoded",
        )

        # 3. Если Form-Data не подошла, пробуем JSON
        if resp.status_code != 200 or len(self.http.cookies) == 0:
            resp = self.http.request(
                "POST",
                f"{self.base_url}/login",
                body_data=login_data,
                content_type="application/json",
            )

        if resp.status_code == 403:
            raise XUIError(
                "❌ 3x-ui вернула <b>HTTP 403</b> при входе.\n\n"
                "💡 Проверь логин/пароль в Railway Variables или выполни <code>x-ui restart</code> на сервере."
            )
        elif resp.status_code >= 400:
            raise XUIError(f"❌ Ошибка входа в 3x-ui (HTTP {resp.status_code}): {escape(resp.text[:200])}")

    def _request(self, path: str, method: str = "GET", data: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self.http.request(
            method=method,
            url=url,
            body_data=data,
            content_type="application/json" if data is not None else None,
        )

        if resp.status_code >= 400:
            raise XUIError(
                f"❌ 3x-ui вернула <b>HTTP {resp.status_code}</b> на запрос <code>{path}</code>.\n\n"
                f"Ответ: {escape(resp.text[:300])}"
            )

        try:
            result = resp.json()
        except Exception:
            raise XUIError(f"Панель вернула не JSON.\nОтвет: <code>{escape(resp.text[:200])}</code>")

        if isinstance(result, dict) and result.get("success") is not True:
            msg = result.get("msg", "Панель отклонила запрос")
            raise XUIError(f"Ошибка 3x-ui: <b>{escape(str(msg))}</b>")

        return result.get("obj") if isinstance(result, dict) else result

    def get_inbounds(self):
        self.login()
        return self._request("/panel/api/inbounds/list", method="GET")

    def get_inbound(self, inbound_id: int):
        self.login()
        return self._request(f"/panel/api/inbounds/get/{inbound_id}", method="GET")

    def add_client(self, inbound_id: int, client: dict):
        self.login()
        return self._request(
            "/panel/api/inbounds/addClient",
            method="POST",
            data={
                "id": inbound_id,
                "settings": json.dumps({"clients": [client]}),
            },
        )


def get_reality_parameters(inbound: dict):
    if inbound.get("protocol") != "vless":
        raise XUIError("Выбранный Inbound не использует протокол VLESS.")

    if not inbound.get("enable"):
        raise XUIError("Выбранный Inbound отключен в панели.")

    stream = as_dict(inbound.get("streamSettings"))
    reality = as_dict(stream.get("realitySettings"))
    client_settings = as_dict(reality.get("settings"))

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
            "Не удалось автоматически получить ключи Reality.\n"
            "Добавь в Railway Variables:\n"
            "<code>REALITY_PUBLIC_KEY</code> — Public Key\n"
            "<code>REALITY_SNI</code> — Server Name (например, google.com)\n"
            "<code>REALITY_SHORT_ID</code> — Short ID"
        )

    return {
        "public_key": public_key,
        "sni": sni,
        "short_id": short_id,
        "spider_x": client_settings.get("spiderX") or reality.get("spiderX") or "/",
    }


def build_vless_link(client: dict, inbound: dict, reality: dict) -> str:
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


def sync_create_or_get_client(telegram_id: int):
    if XUI_INBOUND_ID <= 0:
        raise XUIError("Сначала отправь /inbounds и укажи ID в XUI_INBOUND_ID в Railway.")

    client_api = XUIClient()
    inbound = client_api.get_inbound(XUI_INBOUND_ID)

    if not isinstance(inbound, dict):
        raise XUIError("Inbound с таким ID не найден в панели.")

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
        client_api.add_client(XUI_INBOUND_ID, client)
    else:
        if not client.get("enable", True):
            raise XUIError("Твой ключ отключен в панели.")

    link = build_vless_link(client, inbound, reality)
    return link, created


def sync_debug_raw() -> str:
    """Пошаговая диагностика с подробным выводом."""
    report = ["🔍 <b>Диагностика подключения 3x-ui</b>\n"]
    report.append(f"🌐 <b>URL:</b> <code>{XUI_URL}</code>")
    report.append(f"👤 <b>Логин:</b> <code>{XUI_USERNAME}</code>\n")

    http = RawHttpClient()

    # Шаг 1: GET / (получение CSRF / session cookies)
    try:
        r1 = http.request("GET", f"{XUI_URL}/")
        report.append(f"1️⃣ <b>GET /:</b> HTTP {r1.status_code} | Кук: {len(http.cookies)}")
    except Exception as e:
        report.append(f"1️⃣ <b>GET /:</b> Ошибка ({escape(str(e))})")

    # Шаг 2: POST /login с куками
    try:
        login_data = {
            "username": XUI_USERNAME,
            "password": XUI_PASSWORD,
            "loginSecret": "",
        }
        r2 = http.request("POST", f"{XUI_URL}/login", body_data=login_data, content_type="application/x-www-form-urlencoded")
        report.append(f"2️⃣ <b>POST /login:</b> HTTP {r2.status_code} | Кук в сессии: {len(http.cookies)}")
        report.append(f"   Ответ: <code>{escape(r2.text[:150]) or '(пусто)'}</code>")
    except Exception as e:
        report.append(f"2️⃣ <b>POST /login:</b> Ошибка ({escape(str(e))})")

    # Шаг 3: Получение списка Inbounds
    try:
        r3 = http.request("GET", f"{XUI_URL}/panel/api/inbounds/list")
        report.append(f"\n3️⃣ <b>GET inbounds:</b> HTTP {r3.status_code}")
        try:
            d = r3.json()
            if d.get("success") is True:
                inb = d.get("obj", [])
                report.append(f"   🎉 <b>УСПЕХ! Найдено подключений: {len(inb)}</b>")
            else:
                report.append(f"   Ответ: <code>{escape(r3.text[:150])}</code>")
        except Exception:
            report.append(f"   Сырой ответ: <code>{escape(r3.text[:100])}</code>")
    except Exception as e:
        report.append(f"\n3️⃣ <b>GET inbounds:</b> Ошибка ({escape(str(e))})")

    return "\n".join(report)


async def show_xui_error(message: Message, error: Exception):
    if isinstance(error, XUIError):
        text = str(error)
    else:
        logger.exception("Ошибка 3x-ui:")
        text = f"Произошла ошибка: <b>{type(error).__name__}</b>\n<code>{escape(str(error))}</code>"

    await message.answer(text, parse_mode="HTML")


# =========================================================
# 3. КЛАВИАТУРЫ
# =========================================================

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔐 Подключить VPN", callback_data="connect_vpn")],
        [
            InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
            InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs"),
        ],
        [InlineKeyboardButton(text="📋 Инструкция по активации", callback_data="activation")],
        [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")],
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
        [InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")]
    ])


# =========================================================
# 4. ХЕНДЛЕРЫ КОМАНД
# =========================================================

# Добавлены все варианты: /debug, /debug_raw, /debug_login, /test_login
@dp.message(Command("debug", "debug_raw", "debug_login", "test_login"), F.chat.type == "private")
async def cmd_debug_raw(message: Message):
    wait_msg = await message.answer("🔄 Выполняю диагностику GET+POST...")
    result_text = await asyncio.to_thread(sync_debug_raw)
    await wait_msg.edit_text(result_text, parse_mode="HTML")


@dp.message(Command("myid", "myip", "id", "ip"), F.chat.type == "private")
async def cmd_myid(message: Message):
    await message.answer(
        f"👤 <b>Твой Telegram ID:</b> <code>{message.from_user.id}</code>\n\n"
        f"Скопируй это число и вставь в переменную <b>ADMIN_ID</b> в Railway Variables.",
        parse_mode="HTML",
    )


@dp.message(Command("inbounds"), F.chat.type == "private")
async def cmd_inbounds(message: Message):
    if ADMIN_ID != 0 and message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Эта команда доступна только администратору бота.")
        return

    try:
        client_api = XUIClient()
        items = await asyncio.to_thread(client_api.get_inbounds)

        if not items:
            await message.answer("В панели нет подключений (inbounds). Создай VLESS Inbound.")
            return

        text = "<b>Список подключений в 3x-ui:</b>\n\n"
        for item in items:
            stream = as_dict(item.get("streamSettings"))
            text += (
                f"🔹 <b>ID: {item['id']}</b> | {item.get('remark', 'Без названия')}\n"
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
        await message.answer("⛔️ Эта команда доступна только администратору бота.")
        return

    try:
        async with test_lock:
            link, created = await asyncio.to_thread(
                sync_create_or_get_client, message.from_user.id
            )

        title = "✅ <b>Ключ успешно создан!</b>" if created else "🔐 <b>Твой тестовый ключ:</b>"
        await message.answer(
            f"{title}\n\n"
            f"<code>{escape(link)}</code>\n\n"
            "Нажми на ключ выше для копирования и вставь его в приложение (V2rayN, Happ, Streisand, Nekobox).",
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
        "1. Сервис предоставляется в ознакомительных целях.\n"
        "2. Запрещена противоправная деятельность.\n"
        "3. Нажмите кнопку ниже для продолжения.",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "accept_license")
@dp.callback_query(F.data == "main_menu")
async def menu_callback(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text(
        "🏠 <b>Главное меню:</b>\n\nВыберите нужное действие 👇",
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
        "<i>Платежная система подключается после завершения теста ключей.</i>",
        reply_markup=keyboard,
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "fake_pay")
async def fake_pay_callback(cb: CallbackQuery):
    await cb.answer("Демо-режим оплаты.", show_alert=True)
    await cb.message.edit_text(
        "🧪 Оплата находится в режиме тестирования.\n\n"
        "Для получения тестового ключа используй команду /test_vpn.",
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
        "💬 <b>Поддержка</b>\n\n"
        "Если у вас возникли вопросы по настройке:\n"
        "👉 Напишите администратору: @Suppr_XYZ",
        reply_markup=back_kb(),
        parse_mode="HTML",
    )


@dp.message(F.chat.type == "private")
async def fallback_text(message: Message):
    await message.answer(
        "🤖 Главные команды:\n"
        "/myid — узнать свой Telegram ID\n"
        "/inbounds — список подключений (для админа)\n"
        "/test_vpn — получить тестовый VPN-ключ\n"
        "/debug_login — диагностика подключения к 3x-ui\n"
        "/start — главное меню"
    )


# =========================================================
# 5. ТОЧКА ВХОДА
# =========================================================

async def main():
    logger.info("Бот успешно запущен и слушает команды.")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
