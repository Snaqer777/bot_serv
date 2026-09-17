"""
Тестовый стенд для бота: фейковая панель 3x-ui + загрузка bot.py с нужным окружением.

Запуск тестов:
    python tests/test_payments.py
    python tests/test_groups.py
    python tests/test_2fa.py

Зависимости для тестов: aiohttp, aiogram (как в requirements.txt) и pyotp (для test_2fa.py).
"""
import json
import os
import sys

from aiohttp import web

try:
    import pyotp
except ImportError:   # для test_2fa.py обязателен
    pyotp = None

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PANEL = {
    "two_factor": False,
    "totp_secret": None,          # секрет для проверки кода 2FA (или None)
    "supports_groups": True,      # False → эмулируем панель старее 3.2
    "groups": set(),              # таблица client_groups
    "clients": {},                # email -> payload клиента (+ group_name)
    "pending": {},                # email -> сколько запросов клиент ещё «не зарегистрирован»
    "register_delay": 0,          # задержка регистрации нового клиента в базе панели
    "reject_first_login": False,  # панель отклоняет первую попытку входа
    "reject_msg": "invalid 2fa code",
    "login_attempts": [],         # коды 2FA, которые присылал бот
    "calls": [],                  # журнал вызовов API
}

INBOUND = {
    "id": 1,
    "remark": "NL-Reality",
    "protocol": "vless",
    "port": 443,
    "settings": json.dumps({"clients": [], "decryption": "none"}),
    "streamSettings": json.dumps({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com"],
            "shortIds": ["0123456789abcdef"],
            "settings": {"publicKey": "PUBKEY", "fingerprint": "chrome", "spiderX": "/"},
        },
    }),
}

SERVER_TIME_SHIFT = 0  # сдвиг заголовка Date (для проверки учёта рассинхрона часов)


def reset(**kwargs):
    """Сброс состояния панели перед сценарием."""
    PANEL.update({
        "two_factor": False, "totp_secret": None, "supports_groups": True,
        "groups": set(), "clients": {}, "pending": {}, "register_delay": 0,
        "reject_first_login": False, "reject_msg": "invalid 2fa code",
        "login_attempts": [], "calls": [],
    })
    PANEL.update(kwargs)
    INBOUND["settings"] = json.dumps({"clients": [], "decryption": "none"})


# ---------------- эндпоинты ----------------

async def index(request):
    import time as _time
    from email.utils import formatdate
    resp = web.Response(text="<html><title>3x-ui</title></html>", content_type="text/html")
    resp.headers["Date"] = formatdate(_time.time() + SERVER_TIME_SHIFT, usegmt=True)
    return resp


async def csrf(request):
    if request.app.get("old_panel"):
        return web.Response(status=404, text="404 page not found")
    return web.json_response({"success": True, "obj": "test-csrf-token"})


async def two_factor_enable(request):
    if request.app.get("old_panel"):
        return web.Response(status=404, text="404 page not found")
    return web.json_response({"success": True, "obj": PANEL["two_factor"]})


async def login(request):
    try:
        body = await request.json()
    except Exception:
        body = dict(await request.post())

    code = body.get("twoFactorCode")
    PANEL["calls"].append(("login", body.get("username"), code))
    if code:
        PANEL["login_attempts"].append(code)

    # Как в настоящей панели: с API Token заголовком 2FA не требуется
    auth = request.headers.get("Authorization", "")
    token_ok = auth in ("Bearer panel-api-token", f'Bearer {PANEL.get("api_token") or ""}')
    if token_ok and auth != "Bearer ":
        return web.json_response({"success": True, "msg": "login success"})

    if PANEL["reject_first_login"]:
        PANEL["reject_first_login"] = False
        return web.json_response({"success": False, "msg": PANEL["reject_msg"]})

    if body.get("username") != "admin" or body.get("password") != "secret":
        return web.json_response({"success": False, "msg": "wrong username or password"})

    if PANEL["two_factor"]:
        if pyotp is None:
            return web.json_response({"success": False, "msg": "pyotp не установлен"})
        if not code or not pyotp.TOTP(PANEL["totp_secret"]).verify(str(code), valid_window=1):
            return web.json_response({"success": False, "msg": "invalid 2fa code"})

    return web.json_response({"success": True, "msg": "login success"})


async def inbounds_list(request):
    """Панель отдаёт клиентов из своего состояния; трафик — в clientStats."""
    INBOUND["settings"] = json.dumps({
        "clients": [
            {"id": c["id"], "email": c["email"], "flow": c.get("flow", ""), "enable": c.get("enable", True),
             "expiryTime": c.get("expiryTime", 0), "subId": c.get("subId", ""), "tgId": c.get("tgId", 0),
             "limitIp": c.get("limitIp", 0), "totalGB": c.get("totalGB", 0),
             "comment": c.get("comment", ""),
             **({"group": c["group_name"]} if c.get("group_name") else {})}
            for c in PANEL["clients"].values()
        ],
        "decryption": "none",
    })
    INBOUND["clientStats"] = [
        {"email": c["email"], "enable": c.get("enable", True), "up": c.get("up", 0), "down": c.get("down", 0)}
        for c in PANEL["clients"].values()
    ]
    return web.json_response({"success": True, "obj": [INBOUND]})


async def inbound_get(request):
    await inbounds_list(request)
    return web.json_response({"success": True, "obj": INBOUND})


async def clients_add(request):
    body = await request.json()
    client = dict(body["client"])
    email = client["email"]
    PANEL["calls"].append(("clients/add", email, client.get("group")))
    PANEL["clients"][email] = client
    if PANEL["register_delay"]:
        PANEL["pending"][email] = PANEL["register_delay"]
    # панель сохраняет группу клиента, если пришла в payload
    if PANEL["supports_groups"] and client.get("group"):
        PANEL["clients"][email]["group_name"] = client["group"]
        PANEL["groups"].add(client["group"])
    return web.json_response({"success": True, "obj": {}})


async def clients_update(request):
    email = request.match_info["email"]
    body = await request.json()
    PANEL["calls"].append(("clients/update", email, body.get("group")))
    PANEL["clients"][email] = dict(body)
    if PANEL["supports_groups"] and body.get("group"):
        PANEL["clients"][email]["group_name"] = body["group"]
        PANEL["groups"].add(body["group"])
    return web.json_response({"success": True, "obj": {}})


async def clients_get(request):
    email = request.match_info["email"]
    PANEL["calls"].append(("clients/get", email))
    if not PANEL["supports_groups"]:
        return web.Response(status=404, text="404 page not found")
    if email not in PANEL["clients"] or PANEL["pending"].get(email, 0) > 0:
        if PANEL["pending"].get(email, 0) > 0:
            PANEL["pending"][email] -= 1
        return web.json_response({"success": False, "msg": "client not found"})
    return web.json_response({
        "success": True,
        "obj": {"email": email, "group": PANEL["clients"][email].get("group_name", "")},
    })


async def clients_delete(request):
    email = request.match_info["email"]
    PANEL["calls"].append(("clients/del", email))
    PANEL["clients"].pop(email, None)
    return web.json_response({"success": True, "obj": {}})


async def groups_list(request):
    PANEL["calls"].append(("groups/list",))
    if not PANEL["supports_groups"]:
        return web.Response(status=404, text="404 page not found")
    return web.json_response({"success": True, "obj": [{"name": name} for name in sorted(PANEL["groups"])]})


async def groups_bulk_add(request):
    body = await request.json()
    emails = body.get("emails") or []
    group = body.get("group")
    PANEL["calls"].append(("groups/bulkAdd", emails, group))
    if not PANEL["supports_groups"]:
        return web.Response(status=404, text="404 page not found")

    affected = 0
    for email in emails:
        if email in PANEL["clients"] and PANEL["pending"].get(email, 0) == 0:
            PANEL["clients"][email]["group_name"] = group
            affected += 1
    if affected:
        PANEL["groups"].add(group)
    return web.json_response({"success": True, "obj": {"affected": affected, "group": group}})


def make_app(old_panel=False):
    app = web.Application()
    app["old_panel"] = old_panel
    app.router.add_get("/", index)
    app.router.add_get("/csrf-token", csrf)
    app.router.add_post("/getTwoFactorEnable", two_factor_enable)
    app.router.add_post("/login", login)
    app.router.add_post("/login/", login)
    app.router.add_get("/panel/api/inbounds/list", inbounds_list)
    app.router.add_get("/panel/api/inbounds/get/{id}", inbound_get)
    app.router.add_post("/panel/api/clients/add", clients_add)
    app.router.add_post("/panel/api/clients/update/{email}", clients_update)
    app.router.add_get("/panel/api/clients/get/{email}", clients_get)
    app.router.add_post("/panel/api/clients/del/{email}", clients_delete)
    app.router.add_get("/panel/api/clients/groups", groups_list)
    app.router.add_post("/panel/api/clients/groups/bulkAdd", groups_bulk_add)
    return app


class Msg:
    """Заглушка aiogram Message для проверки текстов ответов."""

    def __init__(self, uid=42):
        self.from_user = type("U", (), {"id": uid})()
        self.sent = []

    async def answer(self, text, **kwargs):
        self.sent.append(text)

    async def edit_text(self, text, **kwargs):
        self.sent.append(text)

    async def delete(self):
        pass

    @property
    def last(self):
        return self.sent[-1] if self.sent else ""


def load_bot(port=8742, group=None, secret=None, admins="42", host=None, env=None):
    """
    Загружает bot.py с нужным окружением (все зависимости от панели — через env).

    :param env: дополнительные переменные окружения (например, платёжные настройки).
        Значение None удаляет переменную, строка — задаёт её.
    """
    import importlib
    sys.path.insert(0, REPO_DIR)
    base = f"http://127.0.0.1:{port}"
    os.environ.update({
        "BOT_TOKEN": "123:TEST",
        "ADMIN_ID": admins,
        "XUI_URL": base,
        "XUI_USERNAME": "admin",
        "XUI_PASSWORD": "secret",
        "XUI_TOKEN": "",
        "XUI_INBOUND_ID": "1",
        "XUI_PROXY": "",
        "VPN_HOST": host or "",
    })
    for key, value in (("XUI_2FA_SECRET", secret), ("XUI_CLIENT_GROUP", group)):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    for key, value in (env or {}).items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    import bot
    return importlib.reload(bot)
