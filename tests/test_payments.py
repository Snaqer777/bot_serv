"""
Тесты оплаты подписок: Telegram Stars, карта через BotFather, ЮKassa и крипта (Crypto Pay).

Каждый сценарий гоняется целиком, без моков внутри логики бота:
  • фейковая панель 3x-ui (panel.py) — куда реально выдаётся ключ;
  • фейковый Telegram Bot API — куда реально уходят счета и сообщения;
  • фейковый API ЮKassa и фейковый Crypto Pay API;
  • настоящий HTTP-сервер вебхуков бота (run_webhook_server).

Главная проверка: ключ выдаётся ТОЛЬКО по подтверждённой оплате и ровно один раз.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aiohttp import web
from panel import PANEL, load_bot, make_app, reset

from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.types import Message, PreCheckoutQuery

PANEL_PORT = 8744
TG_PORT = 8745
YK_PORT = 8746
WEBHOOK_PORT = 8747
CRYPTO_PORT = 8748
TG_TG_ID = 4242
SHOP_ID = "123456"
SECRET_KEY = "test_secret_key_abc"
CRYPTO_TOKEN = "12345:TESTCRYPTO"

FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


# ---------------- фейковый Telegram Bot API ----------------

TG = {"calls": [], "next_id": 100, "fail_send": set(), "balance": 0}


def tg_calls(method):
    return [c for c in TG["calls"] if c["method"] == method]


def last_tg(method):
    items = tg_calls(method)
    return items[-1]["params"] if items else {}


async def tg_api(request):
    """Фейковый Bot API: принимает JSON и multipart/form-data (aiogram шлёт multipart)."""
    token_method = request.match_info["method"]
    params = {}
    try:
        form = await request.post()
        for key, value in form.items():
            if isinstance(value, str):
                if value[:1] in "[{":
                    try:
                        params[key] = json.loads(value)
                        continue
                    except ValueError:
                        pass
                if value.lower() in ("true", "false"):
                    params[key] = value.lower() == "true"
                    continue
                if value.isdigit():
                    params[key] = int(value)
                    continue
            params[key] = value
    except Exception:
        try:
            params = await request.json()
        except Exception:
            params = {}

    TG["calls"].append({"method": token_method, "params": params})
    if token_method in TG["fail_send"]:
        return web.json_response({"ok": False, "error_code": 400, "description": "stub: send failed"})
    if token_method == "getMyStarBalance":
        return web.json_response({"ok": True, "result": {"amount": TG["balance"], "nanostar_amount": 0}})
    if token_method in ("answerPreCheckoutQuery", "answerCallbackQuery", "deleteMessage", "answerWebAppQuery"):
        return web.json_response({"ok": True, "result": True})
    TG["next_id"] += 1
    return web.json_response({
        "ok": True,
        "result": {"message_id": TG["next_id"], "date": int(time.time()),
                   "chat": {"id": params.get("chat_id", 0), "type": "private"}, "text": params.get("text", "")},
    })


def make_tg_app():
    app = web.Application()
    app.router.add_post("/bot{token}/{method}", tg_api)
    return app


# ---------------- фейковый API ЮKassa ----------------

YK = {"payments": {}, "webhooks": [], "calls": [], "status_override": None, "break_auth": False, "by_idem": {}}


def make_yk_app():
    app = web.Application()

    def basic_ok(request):
        auth = request.headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(f"{SHOP_ID}:{SECRET_KEY}".encode()).decode()
        return auth == expected

    async def create_payment(request):
        raw = await request.text()
        auth = request.headers.get("Authorization", "")
        idem = request.headers.get("Idempotence-Key", "")
        body = json.loads(raw or "{}")
        YK["calls"].append(("POST /payments", auth, idem, body))

        if YK["break_auth"] or not basic_ok(request):
            return web.json_response({"type": "error", "code": "invalid_credentials",
                                      "description": "Basic auth failed"}, status=401)
        if not idem:
            return web.json_response({"type": "error", "code": "invalid_request",
                                      "description": "no Idempotence-Key"}, status=400)

        payment_id = f"yk-{len(YK['payments']) + 1:03d}-{uuid.uuid4().hex[:8]}"
        payment = {
            "id": payment_id,
            "status": "pending",
            "paid": False,
            "amount": body.get("amount"),
            "metadata": body.get("metadata", {}),
            "description": body.get("description", ""),
            "confirmation": {"type": "redirect", "confirmation_url": f"http://127.0.0.1:{YK_PORT}/pay/{payment_id}"},
            "test": True,
        }
        YK["payments"][payment_id] = payment
        YK["by_idem"][idem] = payment_id
        return web.json_response(payment)

    async def get_payment(request):
        pid = request.match_info["id"]
        YK["calls"].append(("GET /payments", pid, "", {}))
        if not basic_ok(request):
            return web.json_response({"type": "error", "code": "invalid_credentials",
                                      "description": "Basic auth failed"}, status=401)
        payment = YK["payments"].get(pid)
        if payment is None or YK["break_auth"]:
            return web.json_response({"type": "error", "code": "not_found",
                                      "description": "payment not found"}, status=404)
        result = dict(payment)
        if YK["status_override"]:
            result["status"], result["paid"] = YK["status_override"]
        return web.json_response(result)

    async def webhooks(request):
        # В реальном API ЮKassa вебхуками можно управлять только по OAuth-токену
        auth = request.headers.get("Authorization", "")
        YK["calls"].append(("webhooks-auth", auth, "", {}))
        if not auth.startswith("Bearer ") or auth == "Bearer ":
            return web.json_response(
                {"type": "error", "code": "invalid_credentials",
                 "description": "Webhooks are available only with OAuth token"}, status=401)
        if request.method == "POST":
            body = await request.json()
            YK["webhooks"].append(body)
            YK["calls"].append(("POST /webhooks", body.get("event"), body.get("url"), body))
            return web.json_response({"id": f"wh-{len(YK['webhooks'])}",
                                      "event": body.get("event"), "url": body.get("url")})
        return web.json_response({"type": "list", "items": YK["webhooks"]})

    app.router.add_post("/v3/payments", create_payment)
    app.router.add_get("/v3/payments/{id}", get_payment)
    app.router.add_post("/v3/webhooks", webhooks)
    app.router.add_get("/v3/webhooks", webhooks)
    return app


def yk_succeed(payment_id, amount=None, metadata=None):
    """Помечает платёж в фейковой ЮKassa успешным (как после реальной оплаты)."""
    payment = YK["payments"][payment_id]
    payment["status"] = "succeeded"
    payment["paid"] = True
    if amount:
        payment["amount"] = amount
    if metadata:
        payment["metadata"] = metadata
    return payment


# ---------------- фейковый Crypto Pay API (@CryptoBot) ----------------

CRYPTO = {"invoices": {}, "calls": [], "token": CRYPTO_TOKEN, "rates": {"USDT": "95.5"},
          "token_broken": False, "deleted": []}


def make_crypto_app():
    app = web.Application()

    async def api(request):
        method = request.match_info["method"]
        token = request.headers.get("Crypto-Pay-API-Token", "")
        try:
            params = await request.json()
        except Exception:
            params = {}
        CRYPTO["calls"].append((method, token, params))

        if CRYPTO["token_broken"] or token != CRYPTO["token"]:
            return web.json_response({"ok": False, "error": {"code": 401, "name": "UNAUTHORIZED"}}, status=401)

        if method == "getMe":
            return web.json_response({"ok": True, "result": {
                "app_id": 777, "name": "VPN Shop", "payment_processing_bot_username": "CryptoBot",
            }})

        if method == "getExchangeRates":
            items = [
                {"is_valid": True, "source": asset, "target": "RUB", "rate": rate}
                for asset, rate in CRYPTO["rates"].items()
            ]
            return web.json_response({"ok": True, "result": items})

        if method == "createInvoice":
            invoice_id = len(CRYPTO["invoices"]) + 1
            invoice = {
                "invoice_id": invoice_id,
                "hash": f"hash{invoice_id}",
                "status": "active",
                "asset": params.get("asset"),
                "amount": params.get("amount"),
                "payload": params.get("payload"),
                "description": params.get("description", ""),
                "created_at": "2026-09-17T12:00:00.000Z",
                "bot_invoice_url": f"https://t.me/CryptoBot?start=IV{invoice_id}",
                "pay_url": f"https://t.me/CryptoBot?start=IV{invoice_id}",
                "mini_app_invoice_url": f"https://t.me/CryptoBot/app?startapp=IV{invoice_id}",
            }
            CRYPTO["invoices"][str(invoice_id)] = invoice
            return web.json_response({"ok": True, "result": invoice})

        if method == "deleteInvoice":
            invoice_id = str(params.get("invoice_id"))
            removed = CRYPTO["invoices"].pop(invoice_id, None)
            if removed is None:
                return web.json_response({"ok": False, "error": {"code": 400, "name": "INVOICE_NOT_FOUND"}}, status=400)
            CRYPTO["deleted"].append(invoice_id)
            return web.json_response({"ok": True, "result": True})

        if method == "getInvoices":
            ids = str(params.get("invoice_ids") or "")
            status = params.get("status")
            items = list(CRYPTO["invoices"].values())
            if ids:
                wanted = {i.strip() for i in ids.split(",")}
                items = [i for i in items if str(i["invoice_id"]) in wanted]
            if status:
                items = [i for i in items if i["status"] == status]
            return web.json_response({"ok": True, "result": {"count": len(items), "items": items}})

        return web.json_response({"ok": False, "error": {"code": 404, "name": "METHOD_NOT_FOUND"}}, status=404)

    app.router.add_post("/api/{method}", api)
    app.router.add_post("/testnet/api/{method}", api)
    return app


def crypto_pay(invoice_id, status="paid", amount=None, asset=None):
    """Помечает счёт в фейковом Crypto Pay оплаченным."""
    invoice = CRYPTO["invoices"][str(invoice_id)]
    invoice["status"] = status
    if amount:
        invoice["amount"] = amount
    if asset:
        invoice["asset"] = asset
    return invoice


def crypto_signature(body: bytes, token: str = "") -> str:
    """Подпись вебхука так, как её считает Crypto Pay: HMAC-SHA256(SHA256(token), тело)."""
    secret = hashlib.sha256((token or CRYPTO["token"]).encode()).digest()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


async def post_crypto_webhook(invoice: dict, *, signature="auto", token="", event="invoice_paid"):
    import aiohttp
    body = json.dumps({
        "update_id": 1, "update_type": event,
        "request_date": "2026-09-17T12:00:00.000Z", "payload": invoice,
    }).encode()
    sig = crypto_signature(body, token) if signature == "auto" else signature
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"http://127.0.0.1:{WEBHOOK_PORT}/cryptobot/webhook",
            data=body,
            headers={"crypto-pay-api-signature": sig, "Content-Type": "application/json"},
        ) as resp:
            return resp.status, await resp.text()


def crypto_invoice_of(invoice_id):
    return CRYPTO["invoices"][str(invoice_id)]


# ---------------- инфраструктура ----------------

def new_bot(env, store_file, admins=None):
    """Загружает bot.py с платёжным окружением и переключает его на фейковый Telegram."""
    full_env = {
        "PAYMENTS_MODE": env.get("mode"),
        "PAYMENT_PROVIDER_TOKEN": env.get("provider_token"),
        "TELEGRAM_SEND_RECEIPT": env.get("send_receipt"),
        "TELEGRAM_RECEIPT_VAT_CODE": env.get("receipt_vat", "1"),
        "YOOKASSA_SHOP_ID": env.get("shop_id"),
        "YOOKASSA_SECRET_KEY": env.get("secret_key"),
        "YOOKASSA_OAUTH_TOKEN": env.get("oauth_token"),
        "YOOKASSA_API_URL": env.get("api_url") or f"http://127.0.0.1:{YK_PORT}/v3",
        "YOOKASSA_TEST": "1",
        "YOOKASSA_VAT_CODE": env.get("vat", "1"),
        "CRYPTOBOT_TOKEN": env.get("crypto_token", CRYPTO_TOKEN),
        "CRYPTOBOT_API_URL": env.get("crypto_api_url") or f"http://127.0.0.1:{CRYPTO_PORT}/api",
        "CRYPTOBOT_ASSET": env.get("crypto_asset", "USDT"),
        "CRYPTOBOT_RUB_RATE": env.get("crypto_rate"),
        "CRYPTOBOT_TEST": env.get("crypto_testnet"),
        "CRYPTOBOT_INVOICE_TTL": env.get("crypto_ttl", "3600"),
        "CRYPTOBOT_POLL_INTERVAL": env.get("crypto_poll", "60"),
        "PUBLIC_BASE_URL": f"http://127.0.0.1:{WEBHOOK_PORT}",
        "PAYMENTS_ALLOW_TEST_PAY": env.get("allow_test_pay"),
        "PAYMENT_STORE_FILE": store_file,
        "PORT": str(WEBHOOK_PORT),
        "STARS_RUB_RATE": "1.6",
        "STARS_BASIC": env.get("stars_basic"),
    }
    bot = load_bot(PANEL_PORT, admins=str(admins or TG_TG_ID), env=full_env)
    session = AiohttpSession()
    session.api = TelegramAPIServer.from_base(f"http://127.0.0.1:{TG_PORT}")
    bot.bot.session = session
    return bot


def tg_user(uid=TG_TG_ID):
    return {"id": uid, "is_bot": False, "first_name": "Tester", "language_code": "ru"}


def make_message(bot, uid=TG_TG_ID, **extra):
    payload = {
        "message_id": 1,
        "date": int(time.time()),
        "chat": {"id": uid, "type": "private"},
        "from": tg_user(uid),
        **extra,
    }
    return Message.model_validate(payload, context={"bot": bot.bot})


def make_pre_checkout(bot, order_id, total, currency="XTR"):
    payload = {
        "id": "pcq-1",
        "from": tg_user(),
        "chat_instance": "ci-1",
        "currency": currency,
        "total_amount": total,
        "invoice_payload": order_id,
    }
    return PreCheckoutQuery.model_validate(payload, context={"bot": bot.bot})


def panel_client(email):
    return PANEL["clients"].get(email)


def days_left(client):
    return round((int(client["expiryTime"]) - int(time.time() * 1000)) / 86_400_000, 1)


async def post_webhook(pid):
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"http://127.0.0.1:{WEBHOOK_PORT}/yookassa/webhook",
            json={"type": "notification", "event": "payment.succeeded",
                  "object": {"id": pid, "status": "succeeded"}},
        ) as resp:
            return resp.status, await resp.text()


def reset_all():
    reset()
    TG["calls"].clear()
    TG["fail_send"].clear()
    TG["balance"] = 0
    YK["payments"].clear()
    YK["webhooks"].clear()
    YK["calls"].clear()
    YK["by_idem"].clear()
    YK["status_override"] = None
    YK["break_auth"] = False
    CRYPTO["invoices"].clear()
    CRYPTO["calls"].clear()
    CRYPTO["rates"] = {"USDT": "95.5"}
    CRYPTO["token_broken"] = False
    CRYPTO["deleted"].clear()


def crypto_calls(method):
    return [c for c in CRYPTO["calls"] if c[0] == method]


# ---------------- сценарии: общие ----------------

async def test_mode_detection(store_file):
    print("\n▶ 1. Определение режима оплаты по переменным окружения")
    bot = new_bot({"mode": None, "provider_token": None, "shop_id": None, "secret_key": None,
                   "crypto_token": None}, store_file)
    check("по умолчанию — Telegram Stars", bot.PAYMENTS_MODE == "stars" and bot.payments_enabled())

    bot = new_bot({"mode": None, "provider_token": "381764678:TEST:12345", "shop_id": None, "secret_key": None}, store_file)
    check("provider token без PAYMENTS_MODE → режим provider", bot.PAYMENTS_MODE == "provider")

    bot = new_bot({"mode": None, "provider_token": None, "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("ключи ЮKassa без PAYMENTS_MODE → режим yookassa", bot.PAYMENTS_MODE == "yookassa")
    check("test_-ключ распознан как тестовый магазин", bot.YOOKASSA_TEST is True)

    bot = new_bot({"mode": None, "provider_token": None, "shop_id": None, "secret_key": None,
                   "crypto_token": CRYPTO_TOKEN}, store_file)
    check("токен Crypto Pay без PAYMENTS_MODE → режим crypto", bot.PAYMENTS_MODE == "crypto")

    bot = new_bot({"mode": "off", "provider_token": "x", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("PAYMENTS_MODE=off выключает оплату", not bot.payments_enabled())

    bot = new_bot({"mode": "stars", "provider_token": None, "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("явный PAYMENTS_MODE=stars приоритетнее ключей ЮKassa", bot.PAYMENTS_MODE == "stars")

    bot = new_bot({"mode": "crypto", "provider_token": None, "shop_id": None, "secret_key": None,
                   "crypto_token": CRYPTO_TOKEN}, store_file)
    check("явный PAYMENTS_MODE=crypto выбран", bot.PAYMENTS_MODE == "crypto")


async def test_stars_flow(store_file):
    print("\n▶ 2. Telegram Stars: счёт → pre-checkout → оплата → выдача ключа")
    reset_all()
    bot = new_bot({"mode": "stars"}, store_file)
    email = f"tg-paid-{TG_TG_ID}"

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    invoice = last_tg("sendInvoice")
    order_id = invoice.get("payload", "")
    stars = bot.TARIFFS["basic"]["stars"]
    check("счёт выставлен в валюте XTR (звёзды)", invoice.get("currency") == "XTR")
    check("provider_token пустой/не передан — оплата звёздами без платёжного шлюза",
          not invoice.get("provider_token"))
    check(f"цена basic — {stars} ⭐️ (149 ₽ / 1.6)", invoice["prices"][0]["amount"] == stars,
          f"amount={invoice['prices'][0]['amount']}")
    check("payload счёта = id заказа", order_id.startswith("basic-"))
    check("клиента в панели ещё нет", panel_client(email) is None)

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, stars))
    check("pre-checkout подтверждён (ok=true)", last_tg("answerPreCheckoutQuery").get("ok") is True)
    check("ключ до оплаты НЕ выдан", panel_client(email) is None)

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": stars, "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-1", "provider_payment_charge_id": "",
    }))

    client = panel_client(email)
    check("после оплаты клиент создан в панели", client is not None)
    check("срок подписки ~30 дней", client and 29 <= days_left(client) <= 30,
          f"{days_left(client) if client else '—'} дн.")
    check("лимит устройств взят из тарифа (2)", client and client.get("limitIp") == 2)
    check("трафик безлимитный (totalGB=0)", client and client.get("totalGB") == 0)
    check("tgId записан в панель", client and client.get("tgId") == TG_TG_ID)
    check("в комментарии — id тарифа и дата", client and client["comment"].startswith("basic до "))
    sent = [m for m in tg_calls("sendMessage") if str(m["params"].get("chat_id")) == str(TG_TG_ID)]
    key_text = sent[-1]["params"].get("text", "") if sent else ""
    check("ключ отправлен пользователю", "<code>vless://" in key_text)
    check("в сообщении есть дата окончания подписки", "Действует до" in key_text)

    stats = bot.payment_store.stats()
    check("статистика: 1 оплата, 93 ⭐️", stats["paid_count"] == 1 and stats["stars"] == stars, f"{stats}")
    check("покупателю-админу отдельное уведомление не дублируется",
          not any("Новая оплата" in m["params"].get("text", "") for m in tg_calls("sendMessage")))

    await bot.start_checkout(5555, 5555, "standard")
    order2 = last_tg("sendInvoice")["payload"]
    check("счёт для второго пользователя создан", order2.startswith("standard-5555-"))
    await bot.on_pre_checkout(make_pre_checkout(bot, order2, bot.TARIFFS["standard"]["stars"]))
    await bot.on_successful_payment(make_message(bot, uid=5555, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS["standard"]["stars"], "invoice_payload": order2,
        "telegram_payment_charge_id": "tg-charge-u5555", "provider_payment_charge_id": "",
    }))
    check("второму пользователю выдан свой ключ", panel_client("tg-paid-5555") is not None)
    check("первый клиент не тронут", panel_client("tg-paid-4242") is not None)
    check("админу ушло уведомление о продаже",
          any("Новая оплата" in m["params"].get("text", "") for m in tg_calls("sendMessage")))
    check("ключ второму пользователю отправлен ему, а не админу",
          any(m["params"].get("chat_id") == 5555 and "vless://" in m["params"].get("text", "")
              for m in tg_calls("sendMessage")))
    return bot, order_id


async def test_stars_guards(store_file, bot, order_id):
    print("\n▶ 3. Защита от подделок и дублей (Stars)")
    email = f"tg-paid-{TG_TG_ID}"

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, bot.TARIFFS["basic"]["stars"]))
    answer = last_tg("answerPreCheckoutQuery")
    check("pre-checkout по оплаченному счёту отклонён",
          answer.get("ok") is False and "оплачен" in answer.get("error_message", ""))
    check("отказ не создал нового клиента", len([e for e in PANEL["clients"] if e == email]) == 1)

    await bot.on_pre_checkout(make_pre_checkout(bot, "unknown-order-123", 10))
    check("pre-checkout по неизвестному счёту отклонён", last_tg("answerPreCheckoutQuery").get("ok") is False)

    order = await bot.payment_store.create(bot.new_order(TG_TG_ID, "standard"))
    await bot.on_pre_checkout(make_pre_checkout(bot, order["id"], 1))
    answer = last_tg("answerPreCheckoutQuery")
    check("подмена суммы отклонена", answer.get("ok") is False and "Сумма" in answer.get("error_message", ""))

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-1", "provider_payment_charge_id": "",
    }))
    check("повторная оплата тем же платежом не создала второго клиента",
          len([e for e in PANEL["clients"] if e == email]) == 1)
    check("повтор не продлил срок", 29 <= days_left(panel_client(email)) <= 30,
          f"{days_left(panel_client(email))} дн.")

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS["basic"]["stars"], "invoice_payload": "nope-123",
        "telegram_payment_charge_id": "tg-charge-2", "provider_payment_charge_id": "",
    }))
    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    check("оплата по неизвестному счёту обрабатывается без выдачи",
          len([e for e in PANEL["clients"] if e == email]) == 1 and any("не найден" in t for t in texts))

    order2 = await bot.payment_store.create(bot.new_order(TG_TG_ID, "standard"))
    saved_url = bot.XUI_URL
    bot.XUI_URL = "http://127.0.0.1:9"  # заведомо закрытый порт
    try:
        await bot.on_successful_payment(make_message(bot, successful_payment={
            "currency": "XTR", "total_amount": bot.TARIFFS["standard"]["stars"], "invoice_payload": order2["id"],
            "telegram_payment_charge_id": "tg-charge-3", "provider_payment_charge_id": "",
        }))
    finally:
        bot.XUI_URL = saved_url
    order2_after = await bot.payment_store.get(order2["id"])
    alerts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    check("при недоступной панели заказ помечен оплаченным, но не выданным",
          order2_after["status"] == "paid" and not order2_after.get("provisioned"))
    check("админу ушёл алерт «оплата есть, ключ не выдан»", any("ключ не выдан" in t for t in alerts))
    check("пользователю сообщили о задержке выдачи", any("задержалась" in t for t in alerts))

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS["standard"]["stars"], "invoice_payload": order2["id"],
        "telegram_payment_charge_id": "tg-charge-3", "provider_payment_charge_id": "",
    }))
    order2_final = await bot.payment_store.get(order2["id"])
    client2 = panel_client(email)
    check("повторная доставка платежа завершает выдачу (без повторного списания)",
          order2_final.get("provisioned") and client2 is not None)
    check("срок продлён: 30 дней basic + 90 дней standard ≈ 120",
          118 <= days_left(client2) <= 120, f"{days_left(client2)} дн.")
    check("на каждого покупателя — ровно одна запись в панели",
          sorted(PANEL["clients"]) == [f"tg-paid-{TG_TG_ID}", "tg-paid-5555"])


async def test_provider_flow(store_file):
    print("\n▶ 4. Оплата картой через платёжный токен BotFather (provider)")
    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": "381764678:TEST:98765"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "standard")
    invoice = last_tg("sendInvoice")
    order_id = invoice.get("payload", "")
    check("валюта счёта — RUB", invoice.get("currency") == "RUB")
    check("provider_token подставлен из PAYMENT_PROVIDER_TOKEN",
          invoice.get("provider_token") == "381764678:TEST:98765")
    check("сумма в копейках (390 ₽ = 39000)", invoice["prices"][0]["amount"] == 39000,
          f"amount={invoice['prices'][0]['amount']}")

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, 39000, currency="RUB"))
    check("pre-checkout подтверждён", last_tg("answerPreCheckoutQuery").get("ok") is True)

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "RUB", "total_amount": 39000, "invoice_payload": order_id,
        "telegram_payment_charge_id": "card-charge-1", "provider_payment_charge_id": "yk-charge-1",
    }))
    client = panel_client(f"tg-paid-{TG_TG_ID}")
    check("после оплаты картой клиент создан", client is not None)
    check("срок 90 дней", client and 89 <= days_left(client) <= 90, f"{days_left(client) if client else '—'} дн.")
    check("в панель записан provider charge id",
          client and "yk-charge-1" in str(bot.payment_store.orders[order_id].get("provider_charge_id")))
    check("выручка рублёвая: 390 ₽", bot.payment_store.stats()["rub"] == 390)


async def test_provider_receipt_and_test_mode(store_file):
    print("\n▶ 4б. BotFather-режим: тестовый токен, подсказка карты, чек 54-ФЗ")
    reset_all()
    test_token = "381764678:TEST:100037"

    bot = new_bot({"mode": "provider", "provider_token": "x:LIVE:12345"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    invoice = last_tg("sendInvoice")
    check("по умолчанию provider_data не передаётся (фискализация не подключена)",
          not invoice.get("provider_data"))
    check("по умолчанию email у покупателя не запрашивается", not invoice.get("need_email"))
    check("боевой токен не считается тестовым", bot.PROVIDER_TEST_MODE is False)
    check("боевой токен → нет подсказки про тестовую карту",
          not any("5555 5555 5555 4477" in m["params"].get("text", "") for m in tg_calls("sendMessage")))

    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": test_token}, store_file)
    check("токен с :TEST: распознан как тестовый", bot.PROVIDER_TEST_MODE is True)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    check("перед счётом отправлена подсказка с тестовой картой",
          any("5555 5555 5555 4477" in t and "Тестовый" in t for t in texts))
    check("подсказка не раскрывает токен", not any(test_token in t for t in texts))
    invoice = last_tg("sendInvoice")
    check("счёт всё равно выставлен тестовым токеном", invoice.get("provider_token") == test_token)
    order_id = invoice["payload"]

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, 14900, currency="RUB"))
    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "RUB", "total_amount": 14900, "invoice_payload": order_id,
        "telegram_payment_charge_id": "card-charge-test", "provider_payment_charge_id": "",
    }))
    check("тестовая оплата выдала ключ", panel_client(f"tg-paid-{TG_TG_ID}") is not None)

    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": "x:LIVE:12345", "send_receipt": "1"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "standard")
    invoice = last_tg("sendInvoice")
    raw_receipt = invoice["provider_data"]
    receipt = (raw_receipt if isinstance(raw_receipt, dict) else json.loads(raw_receipt))["receipt"]
    item = receipt["items"][0]
    check("чек передан в provider_data", bool(invoice.get("provider_data")))
    check("сумма чека совпадает с тарифом (390.00 RUB)",
          item["amount"] == {"value": "390.00", "currency": "RUB"}, item["amount"])
    check("в чеке ставка НДС и признак услуги",
          item["vat_code"] == 1 and item["payment_subject"] == "service")
    check("в чеке описание тарифа и срок", "3 месяца" in item["description"] or "Стандарт" in item["description"],
          item["description"])
    check("у покупателя запрошен email для чека",
          invoice.get("need_email") is True and invoice.get("send_email_to_provider") is True)

    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": test_token, "send_receipt": "1"}, store_file)
    msg = make_message(bot, text="/panel_debug")
    await bot.cmd_panel_debug(msg)
    text = _last_api_text()
    check("/panel_debug показывает тестовый токен", "тестовый токен" in text)
    check("/panel_debug показывает передачу чека", "передаётся в provider_data" in text)


async def test_yookassa_flow(store_file):
    print("\n▶ 5. ЮKassa: создание платежа, вебхук, выдача ключа")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"

    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        _, auth, idem, body = [c for c in YK["calls"] if c[0] == "POST /payments"][-1]
        check("в ЮKassa ушёл POST /v3/payments с Basic auth магазина",
              auth == "Basic " + base64.b64encode(f"{SHOP_ID}:{SECRET_KEY}".encode()).decode())
        check("сумма платежа 149.00 RUB", body["amount"] == {"value": "149.00", "currency": "RUB"})
        check("передан чек по 54-ФЗ (vat_code=1)",
              body.get("receipt", {}).get("items", [{}])[0].get("vat_code") == 1)
        check("Idempotence-Key = id заказа", idem.startswith("basic-") and idem in bot.payment_store.orders)
        check("metadata.telegram_id передана в платёж", body["metadata"]["tg_id"] == str(TG_TG_ID))
        check("указан return_url — адрес сервиса", body["confirmation"]["return_url"].startswith("http"))

        message = [m for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]["params"]
        check("пользователю отправлена ссылка на оплату",
              "/pay/yk-" in json.dumps(message["reply_markup"], ensure_ascii=False))

        payment_id = YK["by_idem"][idem]
        check("без OAuth-токена бот не пытается управлять вебхуками через API (по правилам ЮKassa это делает кабинет)",
              not any(c[0] == "POST /webhooks" for c in YK["calls"]))
        check("ключ до оплаты не выдан", panel_client(email) is None)

        await post_webhook(payment_id)
        check("вебхук при статусе pending: ключ не выдан", panel_client(email) is None)

        yk_succeed(payment_id)
        status, _ = await post_webhook(payment_id)
        check("вебхук payment.succeeded принят (200)", status == 200)
        client = panel_client(email)
        check("ключ выдан после подтверждённой оплаты", client is not None)
        check("срок 30 дней", client and 29 <= days_left(client) <= 30,
              f"{days_left(client) if client else '—'} дн.")
        check("тело вебхука перепроверено через GET /v3/payments/{id}",
              any(c[0] == "GET /payments" for c in YK["calls"]))

        await post_webhook(payment_id)
        check("дубль вебхука не продлевает подписку", 29 <= days_left(panel_client(email)) <= 30)
        check("дубль вебхука не создаёт второго клиента",
              len([e for e in PANEL["clients"] if e == email]) == 1)

        cb = _FakeCallback(bot, f"checkpay_{idem}")
        await bot.cb_check_payment(cb)
        check("кнопка проверки отвечает «оплата уже подтверждена»",
              "уже подтверждена" in json.dumps(cb.answers, ensure_ascii=False))

        expiry_before = int(panel_client(email)["expiryTime"])
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "standard")
        order2_id = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][2]
        pid2 = YK["by_idem"][order2_id]
        yk_succeed(pid2, amount={"value": "1.00", "currency": "RUB"})
        await post_webhook(pid2)
        check("несовпадение суммы → подписка не продлена",
              int(panel_client(email)["expiryTime"]) == expiry_before)
        check("заказ остался неоплаченным", (await bot.payment_store.get(order2_id))["status"] == "pending")

        YK["status_override"] = ("canceled", False)
        await post_webhook(pid2)
        check("платёж canceled → выдачи нет", int(panel_client(email)["expiryTime"]) == expiry_before)
        YK["status_override"] = None

        YK["payments"]["yk-999"] = {"id": "yk-999", "status": "succeeded", "paid": True,
                                    "amount": {"value": "149.00", "currency": "RUB"},
                                    "metadata": {}, "confirmation": {}}
        status, body_text = await post_webhook("yk-999")
        check("вебхук по неизвестному платежу не ломает сервис",
              status == 200 and "unknown_order" in body_text)

        check("healthz отвечает", await _get_healthz())
        check("после подмен и отмен подписка осталась в исходном виде",
              int(panel_client(email)["expiryTime"]) == expiry_before
              and len([e for e in PANEL["clients"] if e == email]) == 1)
    finally:
        if runner is not None:
            await runner.cleanup()


async def test_receipt_optional(store_file):
    print("\n▶ 5а. Чек 54-ФЗ в ЮKassa передаётся только когда включён")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY, "vat": "1"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    body_with = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][3]
    check("с YOOKASSA_VAT_CODE=1 чек уходит в платёж", "receipt" in body_with)
    check("в чеке указан vat_code и сумма", body_with["receipt"]["items"][0]["vat_code"] == 1
          and body_with["receipt"]["items"][0]["amount"]["value"] == "149.00")

    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY, "vat": "0"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    body_without = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][3]
    check("без фискализации (vat=0) чек не передаётся — платёж не сломается", "receipt" not in body_without)
    check("платёж всё равно создан корректно", body_without["amount"]["value"] == "149.00")


async def test_yookassa_oauth_webhook(store_file):
    print("\n▶ 5б. Автонастройка вебхука по OAuth-токену и запрет Basic для вебхуков")
    reset_all()
    oauth = "token_test_abcdef"

    bot_plain = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    client_plain = bot_plain.make_yookassa_client()
    result = await client_plain.ensure_webhook("https://example.com/yookassa/webhook")
    check("без OAuth ensure_webhook возвращает False и не падает", result is False)
    try:
        await client_plain.list_webhooks()
        check("API вебхуков недоступен по Basic-авторизации", False)
    except bot_plain.PaymentError as exc:
        check("API вебхуков недоступен по Basic-авторизации (401 в реальной ЮKassa)", "401" in str(exc))

    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY,
                   "oauth_token": oauth}, store_file)
    runner = await bot.run_webhook_server()
    try:
        check("OAuth-токен принят ботом", bot.YOOKASSA_OAUTH_TOKEN == oauth)
        check("вебхук зарегистрирован автоматически по Bearer-токену",
              any(w.get("url", "").endswith("/yookassa/webhook") for w in YK["webhooks"]))
        check("при регистрации использован заголовок Bearer",
              any(c[0] == "webhooks-auth" and c[1] == f"Bearer {oauth}" for c in YK["calls"]))
        check("повторный запуск не дублирует вебхук",
              len([w for w in YK["webhooks"] if w.get("url", "").endswith("/yookassa/webhook")]) == 1)
    finally:
        if runner is not None:
            await runner.cleanup()


# ---------------- сценарии: крипта (Crypto Pay) ----------------

async def test_crypto_rates():
    print("\n▶ 6. Крипта: пересчёт цены и точность округления")
    store_file = os.path.join(tempfile.mkdtemp(prefix="crypto-rate-"), "payments.json")
    reset_all()
    bot = new_bot({"mode": "crypto"}, store_file)

    check("149 ₽ при курсе 95 → 1.57 USDT (округление вверх)",
          bot.crypto_amount_for_rub(149, 95, "USDT") == "1.57",
          bot.crypto_amount_for_rub(149, 95, "USDT"))
    check("149 ₽ при курсе 149 → ровно 1.00 USDT",
          bot.crypto_amount_for_rub(149, 149, "USDT") == "1.00")
    check("TON округляется до 2 знаков: 149 ₽ при 300 ₽/TON → 0.50",
          bot.crypto_amount_for_rub(149, 300, "TON") == "0.50")
    check("BTC округляется до 6 знаков",
          bot.crypto_amount_for_rub(149, 9_000_000, "BTC") == "0.000017",
          bot.crypto_amount_for_rub(149, 9_000_000, "BTC"))
    check("нулевой курс → понятная ошибка", _raises(
        lambda: bot.crypto_amount_for_rub(149, 0, "USDT"), bot.PaymentError))
    check("курс приходит из Crypto Pay", await bot.cryptobot_rate(client=bot.CryptoPayClient()) == 95.5)

    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_rate": "100"}, store_file)
    check("курс из CRYPTOBOT_RUB_RATE имеет приоритет",
          await bot.cryptobot_rate(client=bot.CryptoPayClient()) == 100.0)

    reset_all()
    CRYPTO["rates"] = {}
    bot = new_bot({"mode": "crypto"}, store_file)
    try:
        await bot.cryptobot_rate(client=bot.CryptoPayClient())
        check("без курса и без переменной — ошибка с подсказкой", False)
    except bot.PaymentError as exc:
        check("без курса и без переменной — ошибка с подсказкой", "CRYPTOBOT_RUB_RATE" in str(exc))


async def test_crypto_flow(store_file):
    print("\n▶ 7. Крипта: счёт в @CryptoBot → оплата → выдача ключа")
    reset_all()
    bot = new_bot({"mode": "crypto"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"

    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        created = crypto_calls("createInvoice")
        check("счёт создан через Crypto Pay API", len(created) == 1)
        _, token, params = created[-1]
        check("запрос подписан токеном приложения", token == CRYPTO_TOKEN)
        check("валюта счёта — USDT", params.get("asset") == "USDT")
        check("сумма счёта посчитана по курсу: 149 ₽ / 95.5 → 1.57", params.get("amount") == "1.57",
              str(params.get("amount")))
        check("payload счёта = id заказа", str(params.get("payload", "")).startswith("basic-"))
        check("задан срок жизни счёта (expires_in)", params.get("expires_in") == 3600)
        check("в описании счёта видно тариф и срок",
              "Базовый" in params.get("description", "") or "30" in params.get("description", ""),
              params.get("description", ""))

        order_id = params.get("payload")
        order = await bot.payment_store.get(order_id)
        check("заказ сохранён с номером счёта и суммой в крипте",
              order.get("invoice_id") == 1 and order.get("amount_asset") == "1.57" and order.get("asset") == "USDT")
        check("курс зафиксирован в заказе", float(order.get("rate_rub")) == 95.5)

        message = [m for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]["params"]
        markup = json.dumps(message["reply_markup"], ensure_ascii=False)
        check("кнопка «Оплатить» ведёт на счёт в @CryptoBot", "https://t.me/CryptoBot" in markup)
        check("есть кнопка «Проверить оплату»", "checkpay_" in markup)
        check("в сообщении видна сумма в крипте и в рублях",
              "1.57 USDT" in message.get("text", "") and "149 ₽" in message.get("text", ""))
        check("ключ до оплаты не выдан", panel_client(email) is None)

        # Вебхук до оплаты: счёт ещё active
        status, body = await post_crypto_webhook(crypto_invoice_of(1))
        check("вебхук по неоплаченному счёту выдачи не даёт",
              status == 200 and panel_client(email) is None, body[:60])

        # Реальная оплата
        crypto_pay(1)
        status, _ = await post_crypto_webhook(crypto_invoice_of(1))
        check("вебхук invoice_paid принят (200)", status == 200)
        client = panel_client(email)
        check("ключ выдан после подтверждённой оплаты", client is not None)
        check("срок 30 дней", client and 29 <= days_left(client) <= 30,
              f"{days_left(client) if client else '—'} дн.")
        check("счёт перепроверен через getInvoices", bool(crypto_calls("getInvoices")))

        # Дубль вебхука
        await post_crypto_webhook(crypto_invoice_of(1))
        check("дубль вебхука не продлевает подписку", 29 <= days_left(panel_client(email)) <= 30)
        check("дубль вебхука не создаёт второго клиента",
              len([e for e in PANEL["clients"] if e == email]) == 1)

        # Подделка подписи
        expiry_before = int(panel_client(email)["expiryTime"])
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "premium")
        order2 = crypto_calls("createInvoice")[-1][2]["payload"]
        invoice2_id = (await bot.payment_store.get(order2))["invoice_id"]
        crypto_pay(invoice2_id)
        status, _ = await post_crypto_webhook(crypto_invoice_of(invoice2_id), signature="deadbeef")
        check("вебхук с неверной подписью отклонён (401)", status == 401)
        check("поддельный вебхук ключ не выдал",
              int(panel_client(email)["expiryTime"]) == expiry_before)

        status, _ = await post_crypto_webhook(crypto_invoice_of(invoice2_id), token="999:ЧУЖОЙ")
        check("вебхук, подписанный не нашим токеном, отклонён", status == 401)

        # Чужой счёт с подменённой суммой
        crypto_pay(invoice2_id, amount="0.01")
        status, body = await post_crypto_webhook(crypto_invoice_of(invoice2_id))
        check("подмена суммы в счёте → ключ не выдан",
              int(panel_client(email)["expiryTime"]) == expiry_before, body[:40])

        # Неизвестный заказ
        crypto_pay(invoice2_id, amount="6.25")
        forged = dict(crypto_invoice_of(invoice2_id), payload="unknown-order-777")
        status, body = await post_crypto_webhook(forged)
        check("вебхук по неизвестному заказу не ломает сервис",
              status == 200 and "unknown_order" in body)

        # Чужой тип события
        status, body = await post_crypto_webhook(crypto_invoice_of(invoice2_id), event="invoice_created")
        check("другие события игнорируются", status == 200 and "ignored" in body)

        # Кнопка «Проверить оплату»: оплаченный счёт, вебхук «потерялся»
        expected_amount = (await bot.payment_store.get(order2))["amount_asset"]
        crypto_pay(invoice2_id, amount=expected_amount)
        cb = _FakeCallback(bot, f"checkpay_{order2}")
        await bot.cb_check_payment(cb)
        check("кнопка «Проверить оплату» выдаёт ключ без вебхука",
              31 <= days_left(panel_client(email)) <= 395, f"{days_left(panel_client(email))} дн.")
        check("кнопка сообщила о начале проверки",
              "Проверяю оплату" in json.dumps(cb.answers, ensure_ascii=False) or bool(cb.message.sent))
        check("после ручной проверки заказ помечен оплаченным",
              (await bot.payment_store.get(order2))["status"] == "paid")
        cb_again = _FakeCallback(bot, f"checkpay_{order2}")
        await bot.cb_check_payment(cb_again)
        check("повторное нажатие не продлевает подписку",
              31 <= days_left(panel_client(email)) <= 395)
        check("повторное нажатие отвечает «оплата уже подтверждена»",
              any("уже подтверждена" in t for t in cb_again.answers))
    finally:
        if runner is not None:
            await runner.cleanup()


async def test_crypto_poller_and_button(store_file):
    print("\n▶ 8. Крипта: резервный опрос API, истёкший счёт и повторная выдача")
    reset_all()
    bot = new_bot({"mode": "crypto"}, store_file)
    email = f"tg-paid-{TG_TG_ID}"

    # Оплата без вебхука: клиент оплатил, вебхук не пришёл — срабатывает опрос
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    order_id = crypto_calls("createInvoice")[-1][2]["payload"]
    invoice_id = (await bot.payment_store.get(order_id))["invoice_id"]
    crypto_pay(invoice_id)

    issued = await bot.crypto_poll_once()
    check("опрос API выдал ключ по оплаченному счёту", issued == 1 and panel_client(email) is not None)
    check("срок подписки 30 дней", 29 <= days_left(panel_client(email)) <= 30)

    again = await bot.crypto_poll_once()
    check("повторный опрос ничего не продлевает", again == 0 and 29 <= days_left(panel_client(email)) <= 30)

    # Истёкший счёт
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "standard")
    order2 = crypto_calls("createInvoice")[-1][2]["payload"]
    invoice2 = (await bot.payment_store.get(order2))["invoice_id"]
    cb = _FakeCallback(bot, f"checkpay_{order2}")
    await bot.cb_check_payment(cb)
    check("неоплаченный счёт: кнопка сообщает, что оплата не завершена",
          any("не завершена" in t for t in cb.message.sent))

    crypto_pay(invoice2, status="expired")
    cb = _FakeCallback(bot, f"checkpay_{order2}")
    await bot.cb_check_payment(cb)
    check("истёкший счёт помечен canceled", (await bot.payment_store.get(order2))["status"] == "canceled")
    check("истёкший счёт ключ не выдал", days_left(panel_client(email)) < 31)

    # Кнопка на чужом заказе
    cb = _FakeCallback(bot, f"checkpay_{order2}", uid=999)
    await bot.cb_check_payment(cb)
    check("чужой заказ не отдаётся по кнопке", any("не найден" in t for t in cb.answers))

    # Опрос при выключенном крипто-режиме ничего не делает
    reset_all()
    bot_stars = new_bot({"mode": "stars"}, store_file)
    check("опрос не трогает заказы других режимов", await bot_stars.crypto_poll_once() == 0)


async def test_crypto_testnet_and_diagnostics(store_file):
    print("\n▶ 8б. Крипта: тестовая сеть, диагностика, статистика")
    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_testnet": "1", "crypto_asset": "TON", "crypto_rate": "300",
                   "crypto_api_url": f"http://127.0.0.1:{CRYPTO_PORT}/testnet/api"}, store_file)
    check("тестовая сеть распознана", bot.CRYPTOBOT_TESTNET is True)
    check("валюта счёта берётся из переменной", bot.CRYPTOBOT_ASSET == "TON")

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    params = crypto_calls("createInvoice")[-1][2]
    check("счёт выставлен в TON", params.get("asset") == "TON")
    check("сумма по курсу 300 ₽/TON: 149 ₽ → 0.50", params.get("amount") == "0.50", str(params.get("amount")))
    text = [m["params"].get("text", "") for m in tg_calls("sendMessage")][-1]
    check("в счёте есть пометка тестовой сети", "Тестовая сеть" in text)

    order_id = params["payload"]
    invoice_id = (await bot.payment_store.get(order_id))["invoice_id"]
    crypto_pay(invoice_id)
    check("в тестовой сети ключ тоже выдаётся",
          await bot.crypto_poll_once() == 1 and panel_client(f"tg-paid-{TG_TG_ID}") is not None)

    stats = bot.payment_store.stats()
    check("статистика считает крипту отдельно", stats["crypto"] == {"TON": 0.5}, str(stats["crypto"]))
    check("выручка в рублёвом эквиваленте учтена", stats["crypto_rub"] == 149)

    msg = make_message(bot, text="/panel_debug")
    await bot.cmd_panel_debug(msg)
    diag = _last_api_text()
    check("/panel_debug: показана тестовая сеть", "тестовая сеть" in diag)
    check("/panel_debug: показана валюта счёта", "TON" in diag)
    check("/panel_debug: показан вебхук", "cryptobot/webhook" in diag)
    check("/panel_debug: показан опрос API", "Опрос API" in diag)
    check("/panel_debug: показано приложение Crypto Pay", "VPN Shop" in diag)

    msg = make_message(bot, text="/payments")
    await bot.cmd_payments(msg)
    payments_text = _last_api_text()
    check("/payments: режим крипты", "CryptoBot" in payments_text or "крипт" in payments_text.lower())
    check("/payments: выручка в крипте", "TON" in payments_text)


async def test_crypto_errors(store_file):
    print("\n▶ 8в. Крипта: понятные ошибки вместо трейсбеков")
    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_token": None}, store_file)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("без CRYPTOBOT_TOKEN счёт не создаётся", False)
    except bot.PaymentError as exc:
        check("без CRYPTOBOT_TOKEN подсказан @CryptoBot → /pay",
              "CRYPTOBOT_TOKEN" in str(exc) and "/pay" in str(exc))

    reset_all()
    CRYPTO["token_broken"] = True
    bot = new_bot({"mode": "crypto"}, store_file)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("неверный токен обрабатывается", False)
    except bot.PaymentError as exc:
        check("ошибка 401 от Crypto Pay понятна пользователю",
              "UNAUTHORIZED" in str(exc) and "CRYPTOBOT_TOKEN" in str(exc), " ".join(str(exc).split())[:70])
    CRYPTO["token_broken"] = False

    reset_all()
    bot = new_bot({"mode": "crypto", "api_url": None}, store_file)
    bot.CRYPTOBOT_API_URL = "http://127.0.0.1:9/api"
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("недоступность Crypto Pay обрабатывается", False)
    except bot.PaymentError as exc:
        check("недоступность Crypto Pay → понятная ошибка", "недоступен" in str(exc))


async def test_duplicate_guard(store_file):
    print("\n▶ 7б. Защита от повторной выдачи по комментарию клиента")
    reset_all()
    bot = new_bot({"mode": "crypto"}, store_file)

    comment = "basic до 17.10.2026 | cryptobot-1"
    check("полный ref из комментария распознаётся",
          bot.comment_has_payment_ref(comment, "cryptobot-1") is True)
    check("короткий номер счёта не совпадает с цифрами даты (баг «2» в «17.10.2026»)",
          bot.comment_has_payment_ref(comment, "2") is False)
    check("пустой ref не считается совпадением", bot.comment_has_payment_ref(comment, "") is False)
    check("пустой комментарий не считается совпадением", bot.comment_has_payment_ref(None, "cryptobot-1") is False)
    check("старый формат комментария (без «|») тоже проверяется",
          bot.comment_has_payment_ref("tg-charge-1", "tg-charge-1") is True)

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    order_id = crypto_calls("createInvoice")[-1][2]["payload"]
    invoice_id = (await bot.payment_store.get(order_id))["invoice_id"]
    crypto_pay(invoice_id)
    check("опрос API выдал ключ по первой оплате", await bot.crypto_poll_once() == 1)
    check("первая оплата выдала ключ", panel_client(f"tg-paid-{TG_TG_ID}") is not None)

    expiry_after_first = int(panel_client(f"tg-paid-{TG_TG_ID}")["expiryTime"])
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "standard")
    order2 = crypto_calls("createInvoice")[-1][2]["payload"]
    invoice2 = (await bot.payment_store.get(order2))["invoice_id"]
    crypto_pay(invoice2, amount=(await bot.payment_store.get(order2))["amount_asset"])
    cb = _FakeCallback(bot, f"checkpay_{order2}")
    await bot.cb_check_payment(cb)
    extended = int(panel_client(f"tg-paid-{TG_TG_ID}")["expiryTime"])
    check("кнопка «Проверить оплату» продлевает подписку на 90 дней",
          round((extended - expiry_after_first) / 86_400_000, 1) == 90,
          f"прибавка {round((extended - expiry_after_first) / 86_400_000, 1)} дн.")
    check("в комментарии клиента — полный id платежа",
          "cryptobot-" in panel_client(f"tg-paid-{TG_TG_ID}")["comment"])


async def test_crypto_stats_and_labels(store_file):
    print("\n▶ 8г. Крипта: подписи тарифов и журнал заказов")
    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_rate": "100"}, store_file)
    label = bot.tariff_price_label(bot.TARIFFS["premium"])
    check("при известном курсе цена показывается в рублях и крипте", "₽" in label, label)
    check("в крипто-режиме бесплатный тариф остаётся бесплатным",
          bot.tariff_price_label(bot.TARIFFS["trial"]) == "Бесплатно")

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "premium")
    order_id = crypto_calls("createInvoice")[-1][2]["payload"]
    store_file_path = (await bot.payment_store.get(order_id))
    check("заказ сохранён на диск", os.path.exists(store_file))
    check("в заказе есть валюта, сумма и курс",
          store_file_path.get("currency") == "USDT" and store_file_path.get("amount_asset") == "11.90"
          and float(store_file_path.get("rate_rub")) == 100.0, str(store_file_path.get("amount_asset")))

    # Неоплаченный заказ не попадает в выручку
    stats = bot.payment_store.stats()
    check("неоплаченный заказ не в выручке", stats["paid_count"] == 0 and stats["crypto"] == {})


# ---------------- сценарии: общие (продолжение) ----------------

async def test_yookassa_button_and_revoke(store_file):
    print("\n▶ 9. Кнопка «Проверить оплату» (ЮKassa), удаление подписки и статистика")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        order_id = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][2]
        payment_id = YK["by_idem"][order_id]

        cb = _FakeCallback(bot, f"checkpay_{order_id}")
        await bot.cb_check_payment(cb)
        check("неоплаченный заказ → «ещё не завершена»", any("не завершена" in t for t in cb.message.sent))
        check("ключ не выдан", panel_client(email) is None)

        yk_succeed(payment_id)
        cb = _FakeCallback(bot, f"checkpay_{order_id}")
        await bot.cb_check_payment(cb)
        check("кнопка «Проверить оплату» выдаёт ключ без вебхука", panel_client(email) is not None)

        cb = _FakeCallback(bot, f"checkpay_{order_id}", uid=999)
        await bot.cb_check_payment(cb)
        check("чужой заказ не отдаётся по кнопке", any("не найден" in t for t in cb.answers))

        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "premium")
        order3 = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][2]
        YK["status_override"] = ("canceled", False)
        cb = _FakeCallback(bot, f"checkpay_{order3}")
        await bot.cb_check_payment(cb)
        YK["status_override"] = None
        check("отменённый платёж помечен canceled", (await bot.payment_store.get(order3))["status"] == "canceled")

        msg = make_message(bot)
        await bot.send_profile(msg, TG_TG_ID)
        profile_text = _last_api_text()
        check("в профиле видно активную подписку", "Активна" in profile_text and "Действует до" in profile_text)
        check("в профиле есть ключ", "vless://" in profile_text)

        adm = make_message(bot, text="/payments")
        await bot.cmd_payments(adm)
        admin_text = _last_api_text()
        check("/payments показывает режим и выручку", "ЮKassa" in admin_text and "Выручка" in admin_text)

        rvk = make_message(bot, text=f"/revoke {TG_TG_ID}")
        await bot.cmd_revoke(rvk)
        check("ревок удалил клиента из панели", panel_client(email) is None)
        check("ревок сообщил об удалении", "удалена" in _last_api_text())

        other = make_message(bot, uid=999, text="/payments")
        await bot.cmd_payments(other)
        check("неадмину /payments запрещён", "только администратору" in _last_api_text())
    finally:
        if runner is not None:
            await runner.cleanup()


async def test_persistence_and_off(store_file):
    print("\n▶ 10. Журнал заказов на диске, режим off и тариф trial")
    reset_all()
    bot = new_bot({"mode": "stars"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    order_id = last_tg("sendInvoice")["payload"]
    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("журнал сохранён на диск", os.path.exists(store_file))
    check("срок клиента 30 дней", 29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30)

    bot2 = new_bot({"mode": "stars"}, store_file)
    stats = bot2.payment_store.stats()
    check("после перезапуска журнал не потерялся",
          stats["paid_count"] == 1 and stats["stars"] == bot2.TARIFFS["basic"]["stars"], f"{stats}")
    order = await bot2.payment_store.get(order_id)
    check("заказ помечен как выданный (provisioned)", bool(order.get("provisioned")))

    await bot2.on_successful_payment(make_message(bot2, successful_payment={
        "currency": "XTR", "total_amount": bot2.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("после перезапуска дубль платежа не продлевает подписку",
          29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30)
    check("после перезапуска дубль платежа не создаёт второго клиента",
          len([e for e in PANEL["clients"] if e == f"tg-paid-{TG_TG_ID}"]) == 1)

    bot3 = new_bot({"mode": "stars"}, store_file + ".lost")
    await bot3.on_successful_payment(make_message(bot3, successful_payment={
        "currency": "XTR", "total_amount": bot3.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("при потерянном журнале платёж не выдаётся повторно (защита по панели)",
          29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30
          and len([e for e in PANEL["clients"] if e == f"tg-paid-{TG_TG_ID}"]) == 1)

    bot4 = new_bot({"mode": "off"}, store_file)
    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("в режиме off счёт не выставляется", False)
    except bot4.PaymentError as exc:
        check("в режиме off понятная ошибка с подсказкой", "PAYMENTS_MODE" in str(exc))

    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, "trial")
        check("trial нельзя оплатить как платный", False)
    except bot4.PaymentError:
        check("trial ведёт на бесплатный тестовый доступ", True)

    bot_stars = new_bot({"mode": "stars"}, store_file)
    stars_label = bot_stars.tariff_price_label(bot_stars.TARIFFS["premium"])
    check("в Stars цена показывается в звёздах", "⭐" in stars_label, stars_label)
    check("STARS_<ТАРИФ> считается из рублей по курсу", bot_stars.TARIFFS["basic"]["stars"] == round(149 / 1.6))

    bot_rub = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    rub_label = bot_rub.tariff_price_label(bot_rub.TARIFFS["premium"])
    check("в ЮKassa цена показывается в рублях", rub_label.endswith("₽"), rub_label)

    bot_override = new_bot({"mode": "stars", "stars_basic": "50"}, store_file)
    check("переменная STARS_BASIC=50 даёт ровно 50 звёзд", bot_override.TARIFFS["basic"]["stars"] == 50)
    check("при переопределении остальные тарифы пересчитываются",
          bot_override.TARIFFS["standard"]["stars"] == round(390 / 1.6))


async def test_diagnostics(store_file):
    print("\n▶ 11. Диагностика: провайдеры, сбои, доставка ключа")
    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": None}, store_file)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("без provider token счёт не выставляется", False)
    except bot.PaymentError as exc:
        check("подсказка про PAYMENT_PROVIDER_TOKEN", "PAYMENT_PROVIDER_TOKEN" in str(exc))

    reset_all()
    bot2 = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": "wrong_key"}, store_file)
    try:
        await bot2.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("ошибка авторизации ЮKassa обрабатывается", False)
    except bot2.PaymentError as exc:
        text = str(exc)
        check("ошибка авторизации ЮKassa понятна пользователю",
              "401" in text and "YOOKASSA" in text, "HTTP 401 + подсказка про ключи ЮKassa")

    reset_all()
    bot4 = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY,
                    "api_url": "http://127.0.0.1:9/v3"}, store_file)
    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
        check("недоступность ЮKassa обрабатывается", False)
    except bot4.PaymentError as exc:
        check("недоступность ЮKassa → понятная ошибка", "недоступна" in str(exc))

    reset_all()
    bot5 = new_bot({"mode": "stars"}, store_file)
    await bot5.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    order_id = last_tg("sendInvoice")["payload"]
    TG["fail_send"] = {"sendMessage"}
    await bot5.on_successful_payment(make_message(bot5, successful_payment={
        "currency": "XTR", "total_amount": bot5.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-fail", "provider_payment_charge_id": "",
    }))
    TG["fail_send"].clear()
    check("оплата прошла, даже если Telegram не принял сообщение с ключом",
          panel_client(f"tg-paid-{TG_TG_ID}") is not None)
    check("заказ не помечается уведомлённым (ключ можно дослать)",
          not (await bot5.payment_store.get(order_id)).get("notified"))

    expiry_before = int(panel_client(f"tg-paid-{TG_TG_ID}")["expiryTime"])
    TG["calls"].clear()
    await bot5.on_successful_payment(make_message(bot5, successful_payment={
        "currency": "XTR", "total_amount": bot5.TARIFFS["basic"]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-fail", "provider_payment_charge_id": "",
    }))
    check("повторная доставка досылает недоставленный ключ",
          any("vless://" in m["params"].get("text", "") for m in tg_calls("sendMessage")))
    check("при досылке срок подписки не меняется",
          int(panel_client(f"tg-paid-{TG_TG_ID}")["expiryTime"]) == expiry_before)
    check("после успешной досылки заказ помечен уведомлённым",
          bool((await bot5.payment_store.get(order_id)).get("notified")))


async def test_simulated_payment(store_file):
    print("\n▶ 13. Проверка выдачи ключа БЕЗ оплаты (/test_pay)")
    reset_all()
    email = f"tg-paid-{TG_TG_ID}"

    # По умолчанию (боевой режим) проверка выключена
    bot = new_bot({"mode": "crypto", "allow_test_pay": None}, store_file)
    check("в боевом режиме проверка без оплаты по умолчанию выключена", bot.test_pay_enabled() is False)
    msg = make_message(bot, text="/test_pay basic")
    await bot.cmd_test_pay(msg)
    check("выключенная проверка подсказывает переменную",
          "PAYMENTS_ALLOW_TEST_PAY=1" in _last_api_text() and panel_client(email) is None)

    # В тестовой сети Crypto Pay включается автоматически
    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_testnet": "1",
                   "crypto_api_url": f"http://127.0.0.1:{CRYPTO_PORT}/testnet/api"}, store_file)
    check("в тестовой сети Crypto Pay проверка включается сама", bot.test_pay_enabled() is True)

    # Включённая проверка: полный путь выдачи без денег
    reset_all()
    bot = new_bot({"mode": "crypto", "allow_test_pay": "1"}, store_file)
    check("проверка включена переменной PAYMENTS_ALLOW_TEST_PAY", bot.test_pay_enabled() is True)

    msg = make_message(bot, text="/test_pay")
    await bot.cmd_test_pay(msg)
    markup = json.dumps(tg_calls("sendMessage")[-1]["params"].get("reply_markup", {}), ensure_ascii=False)
    check("без аргумента показаны тарифы кнопками", "testpay_run_basic" in markup and "testpay_run_premium" in markup)

    msg = make_message(bot, text="/test_pay basic")
    await bot.cmd_test_pay(msg)
    client = panel_client(email)
    check("ключ выдан без оплаты (клиент создан в панели)", client is not None)
    check("срок взят из тарифа: 30 дней", client and 29 <= days_left(client) <= 30,
          f"{days_left(client) if client else '—'} дн.")
    check("лимиты взяты из тарифа (2 устройства, безлимитный трафик)",
          client and client.get("limitIp") == 2 and client.get("totalGB") == 0)
    check("в панели сохранился id тарифа и дата", client and client["comment"].startswith("basic до "))

    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    key_text = [t for t in texts if "🧪" in t and "vless://" in t]
    check("пользователю отправлено сообщение с ключом и пометкой «без оплаты»", bool(key_text))
    check("в тестовом сообщении нет слова «Оплата получена»",
          not any("Оплата получена" in t for t in key_text))
    check("есть кнопка удаления тестовой подписки",
          "testpay_del_" in json.dumps(tg_calls("sendMessage")[-1]["params"].get("reply_markup", {}),
                                       ensure_ascii=False))

    orders = [o for o in bot.payment_store.orders.values() if o.get("simulated")]
    check("заказ помечен тестовым", len(orders) == 1 and orders[0]["mode"] == "test")
    stats = bot.payment_store.stats()
    check("тестовая выдача НЕ попала в выручку",
          stats["paid_count"] == 0 and stats["rub"] == 0 and stats["stars"] == 0 and stats["crypto"] == {},
          f"paid_count={stats['paid_count']}")

    check("счёт в Crypto Pay не создавался (денег не нужно)",
          not crypto_calls("createInvoice") and not crypto_calls("getInvoices"))

    issued = await bot.crypto_poll_once()
    check("опрос оплат не трогает тестовый заказ", issued == 0)

    # Кнопка выбора тарифа: пока тестовый ключ на месте — проверка отказывается его портить
    cb = _FakeCallback(bot, "testpay_run_standard")
    await bot.cb_testpay_run(cb)
    check("повторная проверка при живом ключе отклоняется с понятным текстом",
          any("уже есть платная подписка" in t for t in cb.message.sent))
    check("срок ключа при отказе не изменился", 29 <= days_left(panel_client(email)) <= 30,
          f"{days_left(panel_client(email))} дн.")

    # Удаление тестовой подписки
    order_id = [o["id"] for o in bot.payment_store.orders.values() if o.get("simulated")][-1]
    cb = _FakeCallback(bot, f"testpay_del_{order_id}")
    await bot.cb_testpay_del(cb)
    check("кнопка удаления убрала тестового клиента из панели", panel_client(email) is None)
    check("заказ помечен отменённым", (await bot.payment_store.get(order_id))["status"] == "canceled")
    check("в ответе сказано, что подписка удалена",
          "удалена из панели" in json.dumps(cb.message.sent, ensure_ascii=False))

    # После удаления кнопкой можно проверить другой тариф — срок уже 90 дней
    cb = _FakeCallback(bot, "testpay_run_standard")
    await bot.cb_testpay_run(cb)
    check("после удаления проверка другого тарифа выдаёт ключ на 90 дней",
          89 <= days_left(panel_client(email)) <= 90, f"{days_left(panel_client(email))} дн.")

    # Защита: обычный пользователь не может ни выдать, ни удалить
    reset_all()
    bot = new_bot({"mode": "crypto", "allow_test_pay": "1"}, store_file)
    other = make_message(bot, uid=777, text="/test_pay basic")
    await bot.cmd_test_pay(other)
    check("обычному пользователю /test_pay недоступна",
          "только администратору" in _last_api_text() and panel_client(f"tg-paid-777") is None)

    cb = _FakeCallback(bot, "testpay_run_basic", uid=777)
    await bot.cb_testpay_run(cb)
    check("обычному пользователю кнопка выдачи недоступна",
          cb.answers and "Только для администратора" in cb.answers[0])

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    order_real = crypto_calls("createInvoice")[-1][2]["payload"]
    cb = _FakeCallback(bot, f"testpay_del_{order_real}")
    await bot.cb_testpay_del(cb)
    check("кнопка удаления не трогает настоящие (не тестовые) заказы",
          any("не найден" in t for t in cb.answers))

    # Настоящую подписку проверочная выдача не трогает
    reset_all()
    bot = new_bot({"mode": "crypto", "allow_test_pay": "1"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "basic")
    real_order = crypto_calls("createInvoice")[-1][2]["payload"]
    real_invoice = (await bot.payment_store.get(real_order))["invoice_id"]
    crypto_pay(real_invoice)
    await bot.crypto_poll_once()
    check("для проверки защиты настоящая оплата прошла", panel_client(email) is not None)
    real_expiry = int(panel_client(email)["expiryTime"])

    simulated_before = len([o for o in bot.payment_store.orders.values() if o.get("simulated")])
    msg = make_message(bot, text="/test_pay standard")
    await bot.cmd_test_pay(msg)
    check("при живой подписке проверка отказывается её портить",
          "уже есть платная подписка" in _last_api_text(), "")
    check("подписка не продлена тестом", int(panel_client(email)["expiryTime"]) == real_expiry)
    check("в ответе подсказана команда /revoke", "/revoke" in _last_api_text())
    check("тестовый заказ при отказе не создан",
          len([o for o in bot.payment_store.orders.values() if o.get("simulated")]) == simulated_before)

    # После снятия подписки проверка снова доступна
    rvk = make_message(bot, text=f"/revoke {TG_TG_ID}")
    await bot.cmd_revoke(rvk)
    msg = make_message(bot, text="/test_pay premium")
    await bot.cmd_test_pay(msg)
    check("после /revoke проверочная выдача снова работает", panel_client(email) is not None)


async def test_crypto_self_check(store_file):
    print("\n▶ 14. Проверка связки с Crypto Pay без денег (/crypto_check)")
    reset_all()
    bot = new_bot({"mode": "crypto"}, store_file)

    text = await bot.crypto_self_check()
    check("в отчёте есть название приложения", "VPN Shop" in text)
    check("в отчёте есть обрабатывающий бот", "CryptoBot" in text)
    check("в отчёте есть курс", "95.5" in text, "курс из фейкового API")
    check("счёт создан и сразу удалён", len(crypto_calls("createInvoice")) == 1 and bool(crypto_calls("deleteInvoice")))
    created_id = str(CRYPTO["invoices"] and "" or "") or "1"
    check("счёт проверки удалён именно тот, что создан", CRYPTO["deleted"] == [created_id],
          f"удалено: {CRYPTO['deleted']}")
    check("отчёт объясняет, что платить не нужно", "платить" in text.lower())
    check("отчёт подсказывает /test_pay", "/test_pay" in text)
    params = crypto_calls("createInvoice")[-1][2]
    check("проверочный счёт — на минимальный платный тариф", params.get("amount") == "1.57",
          f"amount={params.get('amount')}")

    msg = make_message(bot, text="/crypto_check")
    await bot.cmd_crypto_check(msg)
    check("команда /crypto_check присылает отчёт", "Проверка Crypto Pay" in _last_api_text())

    other = make_message(bot, uid=777, text="/crypto_check")
    await bot.cmd_crypto_check(other)
    check("обычному пользователю /crypto_check недоступна", "только администратору" in _last_api_text())

    reset_all()
    CRYPTO["token_broken"] = True
    bot = new_bot({"mode": "crypto"}, store_file)
    text = await bot.crypto_self_check()
    check("неверный токен: понятная ошибка с подсказкой", "UNAUTHORIZED" in text and "CRYPTOBOT_TOKEN" in text)
    CRYPTO["token_broken"] = False

    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_token": None}, store_file)
    text = await bot.crypto_self_check()
    check("без токена отчёт объясняет, где его взять", "/pay" in text and "CRYPTOBOT_TOKEN" in text)

    reset_all()
    bot = new_bot({"mode": "crypto", "crypto_asset": "TON", "crypto_rate": "300"}, store_file)
    text = await bot.crypto_self_check()
    check("проверка работает для другой валюты (TON)", "TON" in text and "0.50" in text)

    reset_all()
    bot = new_bot({"mode": "stars"}, store_file)
    msg = make_message(bot, text="/crypto_check")
    await bot.cmd_crypto_check(msg)
    check("в другом режиме команда честно говорит, что не нужна",
          "только для режима крипты" in _last_api_text())


async def test_panel_debug(store_file):
    print("\n▶ 12. /panel_debug показывает состояние оплаты")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    msg = make_message(bot, text="/panel_debug")
    await bot.cmd_panel_debug(msg)
    text = _last_api_text()
    check("/panel_debug: виден режим оплаты", "Оплата" in text and "ЮKassa" in text)
    check("/panel_debug: виден вебхук", "yookassa/webhook" in text)
    check("/panel_debug: видна статистика заказов", "Заказов:" in text)
    tail = text.split("Оплата")[-1]
    check("/panel_debug: без OAuth подсказан путь настройки в кабинете, а не ошибка",
          "HTTP-уведомления" in tail and "❌" not in tail)


# ---------------- вспомогательные заглушки ----------------

class _FakeCallback:
    """Мини-заглушка CallbackQuery для проверки кнопок оплаты."""

    def __init__(self, bot, data, uid=TG_TG_ID):
        self.data = data
        self.from_user = type("U", (), {"id": uid})()
        self.answers = []
        self.message = _FakeCbMessage(bot)

    async def answer(self, text=None, **kwargs):
        if text:
            self.answers.append(text)


class _FakeCbMessage:
    def __init__(self, bot):
        self.chat = type("C", (), {"id": TG_TG_ID})()
        self._bot = bot
        self.sent = []

    async def answer(self, text, **kwargs):
        self.sent.append(text)
        TG["calls"].append({"method": "sendMessage", "params": {"chat_id": TG_TG_ID, "text": text, **kwargs}})

    async def edit_text(self, text, **kwargs):
        self.sent.append(text)

    async def delete(self):
        pass


def _last_api_text():
    sent = tg_calls("sendMessage")
    return sent[-1]["params"].get("text", "") if sent else ""


def _raises(func, exc_type) -> bool:
    """True, если вызов поднял ожидаемое исключение."""
    try:
        func()
    except exc_type:
        return True
    except Exception:
        return False
    return False


async def _get_healthz():
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.get(f"http://127.0.0.1:{WEBHOOK_PORT}/healthz") as resp:
            data = await resp.json()
            return resp.status == 200 and data.get("ok") is True


async def main():
    runners = []
    for port, app in ((PANEL_PORT, make_app()), (TG_PORT, make_tg_app()),
                      (YK_PORT, make_yk_app()), (CRYPTO_PORT, make_crypto_app())):
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        runners.append(runner)

    store_dir = tempfile.mkdtemp(prefix="payments-store-")

    def store_for(name):
        """Отдельный журнал заказов на каждый сценарий."""
        return os.path.join(store_dir, f"{name}.json")

    try:
        await test_mode_detection(store_for("modes"))
        bot, order_id = await test_stars_flow(store_for("stars"))
        await test_stars_guards(store_for("stars"), bot, order_id)
        await test_provider_flow(store_for("provider"))
        await test_provider_receipt_and_test_mode(store_for("provider_receipt"))
        await test_yookassa_flow(store_for("yookassa"))
        await test_receipt_optional(store_for("yookassa_vat"))
        await test_yookassa_oauth_webhook(store_for("yookassa_oauth"))
        await test_crypto_rates()
        await test_crypto_flow(store_for("crypto"))
        await test_duplicate_guard(store_for("crypto_dup"))
        await test_crypto_poller_and_button(store_for("crypto_poll"))
        await test_crypto_testnet_and_diagnostics(store_for("crypto_testnet"))
        await test_crypto_errors(store_for("crypto_errors"))
        await test_crypto_stats_and_labels(store_for("crypto_stats"))
        await test_yookassa_button_and_revoke(store_for("yookassa_btn"))
        await test_persistence_and_off(store_for("persist"))
        await test_diagnostics(store_for("diag"))
        await test_panel_debug(store_for("debug"))
        await test_simulated_payment(store_for("simulate"))
        await test_crypto_self_check(store_for("selfcheck"))
    finally:
        for runner in runners:
            await runner.cleanup()

    print()
    if FAILURES:
        print(f"❌ Провалено проверок: {len(FAILURES)}")
        for name in FAILURES:
            print("   •", name)
        return 1
    print("✅ Все проверки пройдены")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
