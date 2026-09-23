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
    # Клиенты по подключениям: inbound_id -> {email: payload}. Один и тот же email
    # может жить в нескольких локациях — так тариф на несколько туннелей выдаётся сразу
    # в обоих серверах (Стокгольм и Варшава).
    "inbound_clients": {},
    # Плоский вид «email -> payload» из первой локации: им пользуются тесты, которые
    # проверяют одного клиента (как было до появления выбора сервера).
    "clients": {},
    "pending": {},                # email -> сколько запросов клиент ещё «не зарегистрирован»
    "register_delay": 0,          # задержка регистрации нового клиента в базе панели
    "reject_first_login": False,  # панель отклоняет первую попытку входа
    "reject_msg": "invalid 2fa code",
    "login_attempts": [],         # коды 2FA, которые присылал бот
    "calls": [],                  # журнал вызовов API
    # Настройки сервиса подписок (Settings -> Subscription в панели):
    "sub": {
        "enable": True,           # subEnable: выключённый сервис подписок
        "port": None,             # subPort (None → порт самой панели, как в тестах)
        "path": "/sub/",          # subPath
        "domain": "",             # subDomain (публичный домен сервиса подписок)
        "uri": "",                # subURI (готовый внешний адрес)
    },
}

INBOUND = {
    "id": 1,
    "remark": "Stockholm-Reality",
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

# Вторая локация (Варшава): то же подключение VLESS Reality, другой порт и remark.
INBOUND2 = {
    "id": 2,
    "remark": "Warsaw-Reality",
    "protocol": "vless",
    "port": 8443,
    "settings": json.dumps({"clients": [], "decryption": "none"}),
    "streamSettings": json.dumps({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "www.cloudflare.com:443",
            "serverNames": ["www.cloudflare.com"],
            "shortIds": ["fedcba9876543210"],
            "settings": {"publicKey": "PUBKEY2", "fingerprint": "chrome", "spiderX": "/"},
        },
    }),
}

SERVER_TIME_SHIFT = 0  # сдвиг заголовка Date (для проверки учёта рассинхрона часов)


def clients_of(inbound_id: int) -> dict:
    """Клиенты конкретного подключения (создаёт пустую таблицу при первом обращении)."""
    return PANEL["inbound_clients"].setdefault(int(inbound_id), {})


def _sync_clients_view():
    """Пересобирает плоский вид email -> payload (первая локация по порядку)."""
    flat = {}
    for inbound_id in sorted(PANEL["inbound_clients"]):
        for email, client in PANEL["inbound_clients"][inbound_id].items():
            flat.setdefault(email, client)
    PANEL["clients"] = flat


def client_of(email: str, inbound_id: int | None = None):
    """Клиент по email: в конкретном подключении или в любом (первом найденном)."""
    if inbound_id is not None:
        return PANEL["inbound_clients"].get(int(inbound_id), {}).get(email)
    for inbound_id in sorted(PANEL["inbound_clients"]):
        found = PANEL["inbound_clients"][inbound_id].get(email)
        if found is not None:
            return found
    return None


def clients_named(email: str) -> list:
    """Все записи клиента с таким email — по одной на локацию."""
    return [row[email] for _inbound, row in sorted(PANEL["inbound_clients"].items()) if email in row]


def emails() -> list:
    """Уникальные email клиентов панели."""
    found = set()
    for row in PANEL["inbound_clients"].values():
        found.update(row)
    return sorted(found)


def inbounds_snapshot() -> list:
    """Подключения панели вместе с клиентами (как ответ /panel/api/inbounds/list)."""
    return [(inbound, dict(PANEL["inbound_clients"].get(inbound["id"], {})))
            for inbound in (INBOUND, INBOUND2)]


def reset(**kwargs):
    """Сброс состояния панели перед сценарием."""
    PANEL.update({
        "two_factor": False, "totp_secret": None, "supports_groups": True,
        "groups": set(), "clients": {}, "inbound_clients": {}, "pending": {}, "register_delay": 0,
        "reject_first_login": False, "reject_msg": "invalid 2fa code",
        "login_attempts": [], "calls": [],
        "sub": {"enable": True, "port": None, "path": "/sub/", "domain": "", "uri": ""},
    })
    PANEL.update(kwargs)
    INBOUND["settings"] = json.dumps({"clients": [], "decryption": "none"})
    INBOUND2["settings"] = json.dumps({"clients": [], "decryption": "none"})
    # clients=... в reset() — клиенты основной локации (Стокгольм): так сценарии
    # про группы могут «предзаполнить» панель клиентом.
    seed = kwargs.get("clients")
    if seed:
        PANEL["inbound_clients"] = {int(INBOUND["id"]): dict(seed)}
        _sync_clients_view()


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


def _inbound_view(inbound: dict, clients: dict) -> dict:
    """Копия подключения с клиентами и их трафиком (как отдаёт настоящая панель)."""
    view = dict(inbound)
    view["settings"] = json.dumps({
        "clients": [
            {"id": c["id"], "email": c["email"], "flow": c.get("flow", ""), "enable": c.get("enable", True),
             "expiryTime": c.get("expiryTime", 0), "subId": c.get("subId", ""), "tgId": c.get("tgId", 0),
             "limitIp": c.get("limitIp", 0), "totalGB": c.get("totalGB", 0),
             "comment": c.get("comment", ""),
             **({"group": c["group_name"]} if c.get("group_name") else {})}
            for c in clients.values()
        ],
        "decryption": "none",
    })
    view["clientStats"] = [
        {"email": c["email"], "enable": c.get("enable", True), "up": c.get("up", 0), "down": c.get("down", 0)}
        for c in clients.values()
    ]
    return view


async def inbounds_list(request):
    """Панель отдаёт клиентов из своего состояния; трафик — в clientStats."""
    views = [_inbound_view(INBOUND, clients_of(1)), _inbound_view(INBOUND2, clients_of(2))]
    return web.json_response({"success": True, "obj": views})


async def inbound_get(request):
    wanted = int(request.match_info["id"])
    for inbound in (INBOUND, INBOUND2):
        if int(inbound["id"]) == wanted:
            return web.json_response({"success": True,
                                      "obj": _inbound_view(inbound, clients_of(wanted))})
    await inbounds_list(request)
    return web.json_response({"success": True, "obj": INBOUND})


def _inbound_id_from_body(body: dict) -> int:
    """Локация из тела запроса: новые и старые форматы 3x-ui."""
    ids = body.get("inboundIds")
    if isinstance(ids, list) and ids:
        try:
            return int(ids[0])
        except (TypeError, ValueError):
            pass
    try:
        return int(body.get("id") or 1)
    except (TypeError, ValueError):
        return 1


async def clients_add(request):
    body = await request.json()
    client = dict(body["client"])
    email = client["email"]
    inbound_id = _inbound_id_from_body(body)
    PANEL["calls"].append(("clients/add", email, client.get("group"), inbound_id))
    clients_of(inbound_id)[email] = client
    _sync_clients_view()
    if PANEL["register_delay"]:
        PANEL["pending"][email] = PANEL["register_delay"]
    # панель сохраняет группу клиента, если пришла в payload
    if PANEL["supports_groups"] and client.get("group"):
        clients_of(inbound_id)[email]["group_name"] = client["group"]
        PANEL["groups"].add(client["group"])
    return web.json_response({"success": True, "obj": {}})


async def clients_update(request):
    email = request.match_info["email"]
    body = await request.json()
    PANEL["calls"].append(("clients/update", email, body.get("group")))
    for inbound_id, row in PANEL["inbound_clients"].items():
        if email in row:
            row[email] = dict(body)
            if PANEL["supports_groups"] and body.get("group"):
                row[email]["group_name"] = body["group"]
                PANEL["groups"].add(body["group"])
    _sync_clients_view()
    return web.json_response({"success": True, "obj": {}})


async def clients_get(request):
    email = request.match_info["email"]
    PANEL["calls"].append(("clients/get", email))
    if not PANEL["supports_groups"]:
        return web.Response(status=404, text="404 page not found")
    if client_of(email) is None or PANEL["pending"].get(email, 0) > 0:
        if PANEL["pending"].get(email, 0) > 0:
            PANEL["pending"][email] -= 1
        return web.json_response({"success": False, "msg": "client not found"})
    return web.json_response({
        "success": True,
        "obj": {"email": email, "group": client_of(email).get("group_name", "")},
    })


async def clients_delete(request):
    email = request.match_info["email"]
    PANEL["calls"].append(("clients/del", email))
    for row in PANEL["inbound_clients"].values():
        row.pop(email, None)
    _sync_clients_view()
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
        if client_of(email) is None or PANEL["pending"].get(email, 0) > 0:
            continue
        for row in PANEL["inbound_clients"].values():
            if email in row:
                row[email]["group_name"] = group
        affected += 1
    _sync_clients_view()
    if affected:
        PANEL["groups"].add(group)
    return web.json_response({"success": True, "obj": {"affected": affected, "group": group}})


async def setting_all(request):
    """Настройки панели (в реальной 3x-ui — POST /panel/api/setting/all)."""
    PANEL["calls"].append(("setting/all",))
    sub = PANEL["sub"]
    return web.json_response({
        "success": True,
        "obj": {
            "webPort": request.url.port,
            "subEnable": sub["enable"],
            "subPort": sub["port"] or request.url.port,
            "subPath": sub["path"],
            "subDomain": sub["domain"],
            "subURI": sub["uri"],
            "subEncrypt": True,
            "subShowInfo": True,
        },
    })


async def subscription(request):
    """Сервис подписок: отдаёт конфигурацию клиента по его Sub ID."""
    sub_id = request.match_info["sub_id"]
    PANEL["calls"].append(("sub/get", sub_id))
    if not PANEL["sub"]["enable"]:
        return web.Response(status=404, text="404 page not found")
    for row in PANEL["inbound_clients"].values():
        for email, client in row.items():
            if str(client.get("subId")) == sub_id:
                return web.Response(text=f"dmxlc3M6Ly97emlwfQ=={email}", content_type="text/plain")
    return web.Response(text="", content_type="text/plain")


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
    app.router.add_post("/panel/api/setting/all", setting_all)
    app.router.add_get("/panel/api/setting/all", setting_all)
    app.router.add_get("/sub/{sub_id}", subscription)
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
        # Экран «соглашение при первом запуске» в тестах выключен, чтобы не мешать
        # сценариям про панель и оплату. Включается явно: env={"TERMS_ACCEPT": "1"}
        # (так делают tests/test_production.py и tests/test_e2e.py).
        "TERMS_ACCEPT": "0",
    })
    # Локации: по умолчанию бот определяет сервер по названию подключения в панели
    # (как в боевой настройке), поэтому переменные XUI_INBOUND_<ЛОКАЦИЯ> сбрасываем.
    # Сценарии с привязкой по ID передают их через env.
    for key, value in (("XUI_2FA_SECRET", secret), ("XUI_CLIENT_GROUP", group),
                       ("XUI_INBOUND_STOCKHOLM", None), ("XUI_INBOUND_WARSAW", None)):
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
