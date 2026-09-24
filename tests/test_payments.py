"""
Тесты оплаты подписок: Telegram Stars, карта через BotFather, ЮKassa и FreeKassa.

Каждый сценарий гоняется целиком, без моков внутри логики бота:
  • фейковая панель 3x-ui (panel.py) — куда реально выдаётся ключ;
  • фейковый Telegram Bot API — куда реально уходят счета и сообщения;
  • фейковый API ЮKassa и эмуляция уведомлений FreeKassa;
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
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aiohttp import web
from panel import PANEL, load_bot, make_app, reset

# --- Тарифы нового каталога -------------------------------------------------
# В боте теперь сетка «тип подписки × уровень»: time_<уровень> (ограничение по
# времени) и traffic_<уровень> (только трафик). В сценариях используем понятные
# псевдонимы: цены, лимиты и сроки берём из bot.TARIFFS, чтобы тесты читались.
BASIC = "time_4"       # 450 ₽, 30 дней, безлимитный трафик, 6 устройств
FAMILY = "time_3"      # 250 ₽, 30 дней, 100 ГБ, 5 устройств
SCHOOL = "time_1"      # 70 ₽, 15 дней, 15 ГБ, 1 устройство
PREMIUM = "time_2"     # 130 ₽, 15 дней, 50 ГБ, 3 устройства
TRAFFIC = "traffic_3"  # 300 ₽, без ограничения по времени, 100 ГБ, 5 устройств


from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.types import Message, PreCheckoutQuery

PANEL_PORT = 8744
TG_PORT = 8745
YK_PORT = 8746
WEBHOOK_PORT = 8747
EGRESS_STUB_PORT = 8751
TG_TG_ID = 4242
SHOP_ID = "123456"
SECRET_KEY = "test_secret_key_abc"
FK_MERCHANT_ID = "14248"
FK_SECRET1 = "secret_word_one"
FK_SECRET2 = "secret_word_two"
FK_ALLOWED_IP = "10.0.0.7"

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


# ---------------- FreeKassa: подписи, ссылка и уведомления ----------------
# Повторяем то, что делает сама FreeKassa: считаем подписи независимо от бота
# (своими формулами из документации) и шлём уведомления на вебхук бота.

def fk_amount(value) -> str:
    """Сумма в том виде, в каком её передаёт бот: без лишних нулей."""
    price = float(value)
    return str(int(price)) if price == int(price) else f"{price:.2f}".rstrip("0").rstrip(".")


def fk_sign_form(order_id, amount, *, merchant=FK_MERCHANT_ID, secret=FK_SECRET1,
                 currency="RUB", variant="currency") -> str:
    """Подпись ссылки на оплату — первым секретным словом (формула из документации FK)."""
    parts = [merchant, amount]
    if variant == "plain":
        parts.append(secret)
    else:
        parts += [secret, currency]
    parts.append(order_id)
    return hashlib.md5(":".join(parts).encode()).hexdigest()


def fk_sign_notify(order_id, amount, *, merchant=FK_MERCHANT_ID, secret=FK_SECRET2) -> str:
    """Подпись уведомления — вторым секретным словом: md5(магазин:сумма:секрет2:заказ)."""
    return hashlib.md5(f"{merchant}:{amount}:{secret}:{order_id}".encode()).hexdigest()


def fk_params(order_id, amount, *, merchant=FK_MERCHANT_ID, secret=FK_SECRET2, intid="987654",
              extra=None) -> dict:
    """Параметры уведомления FreeKassa о платеже (как их шлёт сама FK)."""
    amount = fk_amount(amount)
    params = {
        "MERCHANT_ID": merchant,
        "AMOUNT": amount,
        "intid": intid,
        "MERCHANT_ORDER_ID": order_id,
        "P_EMAIL": "buyer@example.com",
        "P_PHONE": "79990001122",
        "CUR_ID": "1",
        "payer_account": "411111xxxxxx1111",
        "commission": "0",
        "us_tg": str(TG_TG_ID),
    }
    params.update(extra or {})
    params["SIGN"] = fk_sign_notify(order_id, amount, merchant=merchant, secret=secret)
    return params


async def post_fk_notification(order_id, amount, *, method="get", merchant=FK_MERCHANT_ID,
                               secret=FK_SECRET2, sign=None, intid="987654", extra=None,
                               headers=None):
    """Отправляет уведомление FreeKassa на вебхук бота и возвращает (статус, ответ)."""
    import aiohttp
    params = fk_params(order_id, amount, merchant=merchant, secret=secret, intid=intid, extra=extra)
    if sign is not None:
        params["SIGN"] = sign
    url = f"http://127.0.0.1:{WEBHOOK_PORT}/freekassa/webhook"
    async with aiohttp.ClientSession() as s:
        if method == "post":
            async with s.post(url, data=params, headers=headers or {}) as resp:
                return resp.status, await resp.text()
        async with s.get(url, params=params, headers=headers or {}) as resp:
            return resp.status, await resp.text()


def fk_link_params(pay_url) -> dict:
    """Разбирает ссылку на оплату, которую бот отдал пользователю."""
    query = urlsplit(pay_url).query
    return {key: values[0] for key, values in parse_qs(query).items()}


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
        "FREEKASSA_MERCHANT_ID": env.get("merchant", FK_MERCHANT_ID),
        "FREEKASSA_SECRET1": env.get("secret1", FK_SECRET1),
        "FREEKASSA_SECRET2": env.get("secret2", FK_SECRET2),
        "FREEKASSA_PAY_URL": env.get("pay_url") or "https://pay.freekassa.ru/",
        "FREEKASSA_CURRENCY": env.get("currency") or "RUB",
        "FREEKASSA_SIGN_VARIANT": env.get("sign_variant"),
        "FREEKASSA_TEST": env.get("fk_test"),
        "FREEKASSA_CHECK_IP": env.get("check_ip"),
        "FREEKASSA_ALLOWED_IPS": env.get("allowed_ips"),
        "PUBLIC_BASE_URL": f"http://127.0.0.1:{WEBHOOK_PORT}",
        "PAYMENTS_ALLOW_TEST_PAY": env.get("allow_test_pay"),
        "PROMO_ENABLED": env.get("promo_enabled"),
        "PROMO_ONCE": env.get("promo_once"),
        "SUPPORT_USERNAME": env.get("support_username"),
        "SUB_URL_BASE": env.get("sub_url_base"),
        "SUB_PORT": env.get("sub_port"),
        "SUB_PATH": env.get("sub_path"),
        "ADMIN_TOOLS": env.get("admin_tools"),
        "TEST_TOOLS": env.get("test_tools"),
        "PAYMENT_STORE_FILE": store_file,
        "PORT": str(WEBHOOK_PORT),
        "STARS_RUB_RATE": "1.6",
        "STARS_TIME_4": env.get("stars_basic"),
    }
    bot = load_bot(PANEL_PORT, admins=env.get("admin_id") if "admin_id" in env else str(admins or TG_TG_ID), env=full_env)
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


# ---------------- сценарии: общие ----------------

async def test_mode_detection(store_file):
    print("\n▶ 1. Определение режима оплаты по переменным окружения")
    bot = new_bot({"mode": None, "provider_token": None, "shop_id": None, "secret_key": None,
                   "merchant": None, "secret1": None, "secret2": None}, store_file)
    check("по умолчанию — Telegram Stars", bot.PAYMENTS_MODE == "stars" and bot.payments_enabled())

    bot = new_bot({"mode": None, "provider_token": "381764678:TEST:12345", "shop_id": None, "secret_key": None}, store_file)
    check("provider token без PAYMENTS_MODE → режим provider", bot.PAYMENTS_MODE == "provider")

    bot = new_bot({"mode": None, "provider_token": None, "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("ключи ЮKassa без PAYMENTS_MODE → режим yookassa", bot.PAYMENTS_MODE == "yookassa")
    check("test_-ключ распознан как тестовый магазин", bot.YOOKASSA_TEST is True)

    bot = new_bot({"mode": None, "provider_token": None, "shop_id": None, "secret_key": None}, store_file)
    check("магазин FreeKassa без PAYMENTS_MODE → режим freekassa", bot.PAYMENTS_MODE == "freekassa")
    check("FreeKassa распознана как настроенная", bot.freekassa_configured() is True)

    bot = new_bot({"mode": "off", "provider_token": "x", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("PAYMENTS_MODE=off выключает оплату", not bot.payments_enabled())

    bot = new_bot({"mode": "stars", "provider_token": None, "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    check("явный PAYMENTS_MODE=stars приоритетнее ключей ЮKassa", bot.PAYMENTS_MODE == "stars")

    bot = new_bot({"mode": "freekassa", "provider_token": None, "shop_id": None, "secret_key": None}, store_file)
    check("явный PAYMENTS_MODE=freekassa выбран", bot.PAYMENTS_MODE == "freekassa")


async def test_stars_flow(store_file):
    print("\n▶ 2. Telegram Stars: счёт → pre-checkout → оплата → выдача ключа")
    reset_all()
    bot = new_bot({"mode": "stars"}, store_file)
    email = f"tg-paid-{TG_TG_ID}"

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    invoice = last_tg("sendInvoice")
    order_id = invoice.get("payload", "")
    stars = bot.TARIFFS[BASIC]["stars"]
    check("счёт выставлен в валюте XTR (звёзды)", invoice.get("currency") == "XTR")
    check("provider_token пустой/не передан — оплата звёздами без платёжного шлюза",
          not invoice.get("provider_token"))
    check(f"цена тарифа — {stars} ⭐️ ({bot.TARIFFS[BASIC]['price']} ₽ / 1.6)",
          invoice["prices"][0]["amount"] == stars,
          f"amount={invoice['prices'][0]['amount']}")
    check("payload счёта = id заказа", order_id.startswith(f"{BASIC}-"))
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
    basic_ips = bot.TARIFFS[BASIC]["ip_limit"]
    check(f"лимит устройств взят из тарифа ({basic_ips})", client and client.get("limitIp") == basic_ips)
    check("трафик безлимитный (totalGB=0) — уровень «Призрак» по времени", client and client.get("totalGB") == 0)
    check("tgId записан в панель", client and client.get("tgId") == TG_TG_ID)
    check("в комментарии — id тарифа и дата", client and client["comment"].startswith(f"{BASIC} до "))
    sent = [m for m in tg_calls("sendMessage") if str(m["params"].get("chat_id")) == str(TG_TG_ID)]
    key_text = sent[-1]["params"].get("text", "") if sent else ""
    check("ссылка-подписка отправлена пользователю",
          "<code>http" in key_text and "/sub/" in key_text, key_text[:80].replace("\n", " "))
    check("вместо ключа клиент получает подписку", "vless://" not in key_text)
    check("в сообщении есть дата окончания подписки", "Действует до" in key_text)

    stats = bot.payment_store.stats()
    check("статистика: 1 оплата, 93 ⭐️", stats["paid_count"] == 1 and stats["stars"] == stars, f"{stats}")
    check("покупателю-админу отдельное уведомление не дублируется",
          not any("Новая оплата" in m["params"].get("text", "") for m in tg_calls("sendMessage")))

    await bot.start_checkout(5555, 5555, FAMILY)
    order2 = last_tg("sendInvoice")["payload"]
    check("счёт для второго пользователя создан", order2.startswith(f"{FAMILY}-5555-"))
    await bot.on_pre_checkout(make_pre_checkout(bot, order2, bot.TARIFFS[FAMILY]["stars"]))
    await bot.on_successful_payment(make_message(bot, uid=5555, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS[FAMILY]["stars"], "invoice_payload": order2,
        "telegram_payment_charge_id": "tg-charge-u5555", "provider_payment_charge_id": "",
    }))
    check("второму пользователю выдан свой ключ", panel_client("tg-paid-5555") is not None)
    check("первый клиент не тронут", panel_client("tg-paid-4242") is not None)
    check("админу ушло уведомление о продаже",
          any("Новая оплата" in m["params"].get("text", "") for m in tg_calls("sendMessage")))
    check("подписка второму пользователю отправлена ему, а не админу",
          any(m["params"].get("chat_id") == 5555 and "/sub/" in m["params"].get("text", "")
              for m in tg_calls("sendMessage")))
    return bot, order_id


async def test_stars_guards(store_file, bot, order_id):
    print("\n▶ 3. Защита от подделок и дублей (Stars)")
    email = f"tg-paid-{TG_TG_ID}"

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, bot.TARIFFS[BASIC]["stars"]))
    answer = last_tg("answerPreCheckoutQuery")
    check("pre-checkout по оплаченному счёту отклонён",
          answer.get("ok") is False and "оплачен" in answer.get("error_message", ""))
    check("отказ не создал нового клиента", len([e for e in PANEL["clients"] if e == email]) == 1)

    await bot.on_pre_checkout(make_pre_checkout(bot, "unknown-order-123", 10))
    check("pre-checkout по неизвестному счёту отклонён", last_tg("answerPreCheckoutQuery").get("ok") is False)

    order = await bot.payment_store.create(bot.new_order(TG_TG_ID, FAMILY))
    await bot.on_pre_checkout(make_pre_checkout(bot, order["id"], 1))
    answer = last_tg("answerPreCheckoutQuery")
    check("подмена суммы отклонена", answer.get("ok") is False and "Сумма" in answer.get("error_message", ""))

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-1", "provider_payment_charge_id": "",
    }))
    check("повторная оплата тем же платежом не создала второго клиента",
          len([e for e in PANEL["clients"] if e == email]) == 1)
    check("повтор не продлил срок", 29 <= days_left(panel_client(email)) <= 30,
          f"{days_left(panel_client(email))} дн.")

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS[BASIC]["stars"], "invoice_payload": "nope-123",
        "telegram_payment_charge_id": "tg-charge-2", "provider_payment_charge_id": "",
    }))
    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    check("оплата по неизвестному счёту обрабатывается без выдачи",
          len([e for e in PANEL["clients"] if e == email]) == 1 and any("не найден" in t for t in texts))

    order2 = await bot.payment_store.create(bot.new_order(TG_TG_ID, FAMILY))
    saved_url = bot.XUI_URL
    bot.XUI_URL = "http://127.0.0.1:9"  # заведомо закрытый порт
    try:
        await bot.on_successful_payment(make_message(bot, successful_payment={
            "currency": "XTR", "total_amount": bot.TARIFFS[FAMILY]["stars"], "invoice_payload": order2["id"],
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
        "currency": "XTR", "total_amount": bot.TARIFFS[FAMILY]["stars"], "invoice_payload": order2["id"],
        "telegram_payment_charge_id": "tg-charge-3", "provider_payment_charge_id": "",
    }))
    order2_final = await bot.payment_store.get(order2["id"])
    client2 = panel_client(email)
    check("повторная доставка платежа завершает выдачу (без повторного списания)",
          order2_final.get("provisioned") and client2 is not None)
    expected_total = bot.TARIFFS[BASIC]["days"] + bot.TARIFFS[FAMILY]["days"]
    check(f"срок продлён: {bot.TARIFFS[BASIC]['days']} дн. + "
          f"{bot.TARIFFS[FAMILY]['days']} дн. ≈ {expected_total}",
          expected_total - 2 <= days_left(client2) <= expected_total, f"{days_left(client2)} дн.")
    check("на каждого покупателя — ровно одна запись в панели",
          sorted(PANEL["clients"]) == [f"tg-paid-{TG_TG_ID}", "tg-paid-5555"])


async def test_provider_flow(store_file):
    print("\n▶ 4. Оплата картой через платёжный токен BotFather (provider)")
    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": "381764678:TEST:98765"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, FAMILY)
    invoice = last_tg("sendInvoice")
    order_id = invoice.get("payload", "")
    family = bot.TARIFFS[FAMILY]
    family_total = family["price"] * 100
    check("валюта счёта — RUB", invoice.get("currency") == "RUB")
    check("provider_token подставлен из PAYMENT_PROVIDER_TOKEN",
          invoice.get("provider_token") == "381764678:TEST:98765")
    check(f"сумма в копейках ({family['price']} ₽ = {family_total})",
          invoice["prices"][0]["amount"] == family_total,
          f"amount={invoice['prices'][0]['amount']}")

    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, family_total, currency="RUB"))
    check("pre-checkout подтверждён", last_tg("answerPreCheckoutQuery").get("ok") is True)

    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "RUB", "total_amount": family_total, "invoice_payload": order_id,
        "telegram_payment_charge_id": "card-charge-1", "provider_payment_charge_id": "yk-charge-1",
    }))
    client = panel_client(f"tg-paid-{TG_TG_ID}")
    check("после оплаты картой клиент создан", client is not None)
    check(f"срок {family['days']} дней",
          client and family["days"] - 1 <= days_left(client) <= family["days"],
          f"{days_left(client) if client else '—'} дн.")
    check("в панель записан provider charge id",
          client and "yk-charge-1" in str(bot.payment_store.orders[order_id].get("provider_charge_id")))
    check(f"выручка рублёвая: {family['price']} ₽", bot.payment_store.stats()["rub"] == family["price"])


async def test_provider_receipt_and_test_mode(store_file):
    print("\n▶ 4б. BotFather-режим: тестовый токен, подсказка карты, чек 54-ФЗ")
    reset_all()
    test_token = "381764678:TEST:100037"

    bot = new_bot({"mode": "provider", "provider_token": "x:LIVE:12345"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
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
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    check("перед счётом отправлена подсказка с тестовой картой",
          any("5555 5555 5555 4477" in t and "Тестовый" in t for t in texts))
    check("подсказка не раскрывает токен", not any(test_token in t for t in texts))
    invoice = last_tg("sendInvoice")
    check("счёт всё равно выставлен тестовым токеном", invoice.get("provider_token") == test_token)
    order_id = invoice["payload"]

    basic_total = bot.TARIFFS[BASIC]["price"] * 100
    await bot.on_pre_checkout(make_pre_checkout(bot, order_id, basic_total, currency="RUB"))
    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "RUB", "total_amount": basic_total, "invoice_payload": order_id,
        "telegram_payment_charge_id": "card-charge-test", "provider_payment_charge_id": "",
    }))
    check("тестовая оплата выдала ключ", panel_client(f"tg-paid-{TG_TG_ID}") is not None)

    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": "x:LIVE:12345", "send_receipt": "1"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, FAMILY)
    family = bot.TARIFFS[FAMILY]
    invoice = last_tg("sendInvoice")
    raw_receipt = invoice["provider_data"]
    receipt = (raw_receipt if isinstance(raw_receipt, dict) else json.loads(raw_receipt))["receipt"]
    item = receipt["items"][0]
    check("чек передан в provider_data", bool(invoice.get("provider_data")))
    check(f"сумма чека совпадает с тарифом ({family['price']}.00 RUB)",
          item["amount"] == {"value": f"{family['price']}.00", "currency": "RUB"}, item["amount"])
    check("в чеке ставка НДС и признак услуги",
          item["vat_code"] == 1 and item["payment_subject"] == "service")
    check("в чеке описание тарифа и срок",
          family["name"] in item["description"] and f"{family['days']} дн." in item["description"],
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
    check("/panel_debug показывает исходящий IP сервиса (для whitelist у платёжек)",
          "Исходящий IP:" in text, [line for line in text.split("\n") if "Исходящий" in line][:1])


async def test_yookassa_flow(store_file):
    print("\n▶ 5. ЮKassa: создание платежа, вебхук, выдача ключа")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    basic = bot.TARIFFS[BASIC]

    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        _, auth, idem, body = [c for c in YK["calls"] if c[0] == "POST /payments"][-1]
        check("в ЮKassa ушёл POST /v3/payments с Basic auth магазина",
              auth == "Basic " + base64.b64encode(f"{SHOP_ID}:{SECRET_KEY}".encode()).decode())
        check(f"сумма платежа {basic['price']}.00 RUB",
              body["amount"] == {"value": f"{basic['price']}.00", "currency": "RUB"})
        check("передан чек по 54-ФЗ (vat_code=1)",
              body.get("receipt", {}).get("items", [{}])[0].get("vat_code") == 1)
        check("Idempotence-Key = id заказа", idem.startswith(f"{BASIC}-") and idem in bot.payment_store.orders)
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
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, FAMILY)
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
                                    "amount": {"value": f"{basic['price']}.00", "currency": "RUB"},
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
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    body_with = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][3]
    check("с YOOKASSA_VAT_CODE=1 чек уходит в платёж", "receipt" in body_with)
    check("в чеке указан vat_code и сумма", body_with["receipt"]["items"][0]["vat_code"] == 1
          and body_with["receipt"]["items"][0]["amount"]["value"] == f"{bot.TARIFFS[BASIC]['price']}.00")

    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY, "vat": "0"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    body_without = [c for c in YK["calls"] if c[0] == "POST /payments"][-1][3]
    check("без фискализации (vat=0) чек не передаётся — платёж не сломается", "receipt" not in body_without)
    check("платёж всё равно создан корректно",
          body_without["amount"]["value"] == f"{bot.TARIFFS[BASIC]['price']}.00")


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


# ---------------- сценарии: FreeKassa ----------------

async def test_freekassa_signatures():
    print("\n▶ 6. FreeKassa: подписи, ссылка на оплату и сверка суммы")
    store_file = os.path.join(tempfile.mkdtemp(prefix="fk-sign-"), "payments.json")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)

    check("режим FreeKassa и магазин из переменных",
          bot.PAYMENTS_MODE == "freekassa" and bot.freekassa_configured() is True)

    order = bot.new_order(TG_TG_ID, BASIC)
    price = bot.TARIFFS[BASIC]["price"]
    link = bot.freekassa_payment_url(order)
    params = fk_link_params(link)
    check("ссылка ведёт на платёжную страницу FreeKassa", link.startswith(bot.FREEKASSA_PAY_URL + "/?"))
    check("в ссылке есть магазин, номер заказа, сумма и валюта",
          params.get("m") == FK_MERCHANT_ID and params.get("o") == order["id"]
          and params.get("oa") == str(price) and params.get("currency") == "RUB", str(params))
    check("подпись ссылки совпадает с формулой FreeKassa (md5(m:oa:секрет1:валюта:o))",
          params.get("s") == fk_sign_form(order["id"], str(price)))
    check("в ссылке передан telegram_id (вернётся в уведомлении)",
          params.get("us_tg") == str(TG_TG_ID))
    check("язык страницы оплаты — русский", params.get("lang") == "ru")

    reset_all()
    bot_plain = new_bot({"mode": "freekassa", "sign_variant": "plain"}, store_file)
    order_plain = bot_plain.new_order(TG_TG_ID, BASIC)
    plain_params = fk_link_params(bot_plain.freekassa_payment_url(order_plain))
    check("старая формула (без валюты) тоже поддерживается",
          plain_params.get("s") == fk_sign_form(order_plain["id"], str(price), variant="plain"))

    probe_order = f"{BASIC}-1-2-ab12cd"
    probe = {"MERCHANT_ID": FK_MERCHANT_ID, "AMOUNT": str(price), "MERCHANT_ORDER_ID": probe_order}
    check("подпись уведомления = md5(магазин:сумма:секрет2:заказ)",
          bot.freekassa_sign_notify(probe) == fk_sign_notify(probe_order, price))
    check("подпись уведомления не совпадает с чужой подписью",
          bot.freekassa_sign_notify(probe) != fk_sign_notify(probe_order, price, secret="чужой"))
    check("подписи ссылки и уведомления считаются разными словами",
          bot.freekassa_sign_form(order) != bot.freekassa_sign_notify(
              {"MERCHANT_ID": FK_MERCHANT_ID, "AMOUNT": str(price), "MERCHANT_ORDER_ID": order["id"]}))

    check("целая сумма передаётся без лишних нулей", bot.freekassa_amount({"amount_rub": 249}) == "249")
    check("дробная сумма передаётся без хвостовых нулей",
          bot.freekassa_amount({"amount_rub": 150.50}) == "150.5")
    check("сумма из уведомления сверяется в копейках",
          bot.freekassa_amount_matches(order, f"{price}.00") is True)
    check("другая сумма не проходит", bot.freekassa_amount_matches(order, "1") is False)
    check("мусор вместо суммы не проходит", bot.freekassa_amount_matches(order, "abc") is False)


async def test_freekassa_flow(store_file):
    print("\n▶ 7. FreeKassa: ссылка на оплату → уведомление → выдача ключа")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"

    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        basic_price = bot.TARIFFS[BASIC]["price"]
        message = [m for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]["params"]
        markup = json.dumps(message["reply_markup"], ensure_ascii=False)
        check("кнопка «Оплатить» ведёт на страницу FreeKassa", "pay.freekassa.ru" in markup)
        check("в ссылке нет двойного слэша перед параметрами",
              "pay.freekassa.ru//?" not in markup and "ru/?m=" in markup,
              markup[markup.find("pay.freekassa.ru"):][:48])
        check("есть кнопка «Проверить оплату»", "checkpay_" in markup)
        check("есть кнопка «Отменить заказ»", "cancelorder_" in markup)
        check(f"в сообщении видна сумма ({basic_price} ₽)", f"{basic_price} ₽" in message.get("text", ""))

        order = [o for o in bot.payment_store.orders.values()][-1]
        order_id = order["id"]
        check("заказ сохранён со ссылкой на оплату и валютой RUB",
              order["payment_url"].startswith(bot.FREEKASSA_PAY_URL) and order["currency"] == "RUB")
        check("ключ до оплаты не выдан", panel_client(email) is None)

        # Уведомление с поддельной подписью
        status, body = await post_fk_notification(order_id, basic_price, sign="deadbeef")
        check("уведомление с неверной подписью не подтверждается",
              status == 200 and body.strip() == "no", body[:40])
        check("поддельное уведомление ключ не выдало", panel_client(email) is None)

        # Уведомление по неизвестному заказу
        status, body = await post_fk_notification("unknown-order-777", basic_price)
        check("уведомление по неизвестному заказу отклонено", body.strip() == "no")

        # Настоящая оплата (метод GET, как по умолчанию в кабинете FK)
        status, body = await post_fk_notification(order_id, basic_price, intid="555111")
        check("уведомление FreeKassa принято и подтверждено «YES»",
              status == 200 and body.strip() == "YES", body[:40])
        client = panel_client(email)
        check("ключ выдан после подтверждённой оплаты", client is not None)
        check("срок 30 дней", client and 29 <= days_left(client) <= 30,
              f"{days_left(client) if client else '—'} дн.")
        check("в комментарии клиента — номер операции FreeKassa",
              client and "fk-555111" in str(client.get("comment")), str((client or {}).get("comment")))
        saved = await bot.payment_store.get(order_id)
        check("заказ помечен оплаченным, сохранён intid",
              saved["status"] == "paid" and saved.get("intid") == "555111")
        check("номер операции записан как платёж заказа",
              bot.order_charge_id(saved) == "fk-555111", bot.order_charge_id(saved))

        # Дубль уведомления (FK повторяет, пока не получит YES)
        status, body = await post_fk_notification(order_id, basic_price, intid="555111")
        check("повтор уведомления снова подтверждается «YES»", body.strip() == "YES")
        check("повтор не продлевает подписку", 29 <= days_left(panel_client(email)) <= 30)
        check("повтор не создаёт второго клиента",
              len([e for e in PANEL["clients"] if e == email]) == 1)

        # Вторая оплата — методом POST (в кабинете FK переключается одной галочкой)
        expiry_first = int(panel_client(email)["expiryTime"])
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, FAMILY)
        order2 = [o for o in bot.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(
            order2["id"], bot.TARIFFS[FAMILY]["price"], method="post", intid="555222")
        check("уведомление методом POST обрабатывается так же", body.strip() == "YES")
        family_days = bot.TARIFFS[FAMILY]["days"]
        added = round((int(panel_client(email)["expiryTime"]) - expiry_first) / 86_400_000, 1)
        check(f"вторая оплата продлила подписку на {family_days} дней", added == family_days, f"+{added} дн.")

        # Подмена суммы и чужой магазин
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, PREMIUM)
        order3 = [o for o in bot.payment_store.orders.values()][-1]
        expiry_before = int(panel_client(email)["expiryTime"])
        status, body = await post_fk_notification(order3["id"], 1)
        check("подмена суммы → ключ не выдан и «no»",
              body.strip() == "no" and int(panel_client(email)["expiryTime"]) == expiry_before)
        status, body = await post_fk_notification(order3["id"], bot.TARIFFS[PREMIUM]["price"],
                                                 merchant="999999")
        check("уведомление другого магазина отклонено", body.strip() == "no")
        status, body = await post_fk_notification(order3["id"], bot.TARIFFS[PREMIUM]["price"],
                                                 secret="чужое_секретное_слово")
        check("подпись чужим секретным словом отклонена", body.strip() == "no")
        check("подписка после подделок не изменилась",
              int(panel_client(email)["expiryTime"]) == expiry_before)

        # Кнопка «Проверить оплату»: у FreeKassa нет запроса статуса — ждём уведомление
        cb = _FakeCallback(bot, f"checkpay_{order3['id']}")
        await bot.cb_check_payment(cb)
        check("кнопка объясняет, что статус приходит уведомлением",
              any("FreeKassa" in t and "уведомлени" in t.lower() for t in cb.message.sent),
              json.dumps(cb.message.sent, ensure_ascii=False)[:80])
        check("кнопка не выдала ключ вместо оплаты",
              int(panel_client(email)["expiryTime"]) == expiry_before)

        # Оплата третьего заказа всё же проходит и продлевает подписку
        status, body = await post_fk_notification(order3["id"], bot.TARIFFS[PREMIUM]["price"],
                                                 intid="555333")
        check("оплата третьего заказа подтверждена", body.strip() == "YES")
        premium_days = bot.TARIFFS[PREMIUM]["days"]
        added = round((int(panel_client(email)["expiryTime"]) - expiry_before) / 86_400_000, 1)
        check(f"третья оплата продлила подписку на {premium_days} дней", added == premium_days, f"+{added} дн.")
    finally:
        if runner is not None:
            await runner.cleanup()


async def test_freekassa_ip_check_and_errors(store_file):
    print("\n▶ 8. FreeKassa: проверка IP уведомлений и понятные ошибки")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"

    try:
        check("по умолчанию проверка IP выключена (Railway прячет IP за прокси)",
              bot.FREEKASSA_CHECK_IP is False)
        check("белый список IP FreeKassa задан",
              "168.119.157.136" in bot.FREEKASSA_ALLOWED_IPS and "136.243.38.147" in bot.FREEKASSA_ALLOWED_IPS)

        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        order = [o for o in bot.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(
            order["id"], bot.TARIFFS[BASIC]["price"], headers={"X-Real-IP": "8.8.8.8"})
        check("без проверки IP уведомление принимается с любого адреса", body.strip() == "YES")
        check("ключ выдан", panel_client(email) is not None)
    finally:
        await runner.cleanup()

    # Проверка IP включена: доверяем только белым адресам
    reset_all()
    ip_store = os.path.join(tempfile.mkdtemp(prefix="fk-ip-"), "payments.json")
    bot2 = new_bot({"mode": "freekassa", "check_ip": "1",
                    "allowed_ips": f"{FK_ALLOWED_IP},168.119.157.136"}, ip_store)
    runner2 = await bot2.run_webhook_server()
    try:
        check("проверка IP включается переменной", bot2.FREEKASSA_CHECK_IP is True)
        await bot2.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        order2 = [o for o in bot2.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(
            order2["id"], bot2.TARIFFS[BASIC]["price"], headers={"X-Real-IP": "8.8.8.8"})
        check("уведомление с чужого IP отклонено (403)", status == 403 and body.startswith("no"), body[:30])
        check("с чужого IP ключ не выдан", panel_client(email) is None)
        status, body = await post_fk_notification(
            order2["id"], bot2.TARIFFS[BASIC]["price"],
            headers={"X-Forwarded-For": f"{FK_ALLOWED_IP}, 172.16.0.1"}, intid="556677")
        check("уведомление с разрешённого IP принято (берём X-Forwarded-For)",
              body.strip() == "YES", body[:30])
        check("ключ выдан после уведомления с белого IP", panel_client(email) is not None)
    finally:
        await runner2.cleanup()

    # Без магазина и секретных слов ссылка не формируется — вместо трейсбека понятный текст
    reset_all()
    bot3 = new_bot({"mode": "freekassa", "merchant": None, "secret1": None, "secret2": None}, store_file)
    try:
        await bot3.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        check("без ключей магазина ссылка не выдаётся", False)
    except bot3.PaymentError as exc:
        text = str(exc)
        check("подсказано, какие переменные задать",
              all(name in text for name in ("FREEKASSA_MERCHANT_ID", "FREEKASSA_SECRET1", "FREEKASSA_SECRET2")),
              " ".join(text.split())[:80])
        check("подсказана команда проверки настроек", "/freekassa_check" in text)

    reset_all()
    bot4 = new_bot({"mode": "freekassa", "secret2": None}, store_file)
    answer, note = await bot4.process_freekassa_notification(
        {"MERCHANT_ID": FK_MERCHANT_ID, "AMOUNT": "249", "MERCHANT_ORDER_ID": "basic-1-2-ab12cd",
         "SIGN": fk_sign_notify("basic-1-2-ab12cd", 249)})
    check("без второго секретного слова уведомление честно не подтверждается",
          answer == "no" and "FREEKASSA_SECRET2" in note, note)


async def test_freekassa_test_mode_and_diagnostics(store_file):
    print("\n▶ 8б. FreeKassa: тестовый режим и диагностика")
    reset_all()
    bot = new_bot({"mode": "freekassa", "fk_test": "1", "admin_tools": "1"}, store_file)
    check("тестовый режим распознан", bot.FREEKASSA_TEST is True)
    check("в тестовом режиме проверочные команды включаются сами", bot.test_pay_enabled() is True)

    runner = await bot.run_webhook_server()
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        text = [m["params"].get("text", "") for m in tg_calls("sendMessage")][-1]
        check("в счёте есть пометка тестового режима", "Тестовый режим FreeKassa" in text, text[-90:])

        order = [o for o in bot.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(order["id"], order["amount_rub"], intid="700001")
        check("в тестовом режиме ключ тоже выдаётся",
              body.strip() == "YES" and panel_client(f"tg-paid-{TG_TG_ID}") is not None)

        stats = bot.payment_store.stats()
        check("оплата FreeKassa попала в рублёвую выручку",
              stats["paid_count"] == 1 and stats["rub"] == order["amount_rub"], str(stats))

        msg = make_message(bot, text="/panel_debug")
        await bot.cmd_panel_debug(msg)
        diag = _last_api_text()
        check("/panel_debug: показан магазин FK", FK_MERCHANT_ID in diag)
        check("/panel_debug: показан тестовый режим", "тестовый режим" in diag)
        check("/panel_debug: показан адрес уведомлений", "/freekassa/webhook" in diag)
        check("/panel_debug: показана валюта и формула подписи", "RUB" in diag and "currency" in diag)
        check("/panel_debug: подсказана проверка без оплаты", "/freekassa_check" in diag)

        msg = make_message(bot, text="/payments")
        await bot.cmd_payments(msg)
        payments_text = _last_api_text()
        check("/payments: показан режим FreeKassa", "FreeKassa" in payments_text)
        check("/payments: показан магазин", FK_MERCHANT_ID in payments_text)
        check("/payments: показана выручка в рублях", "Выручка" in payments_text)
    finally:
        await runner.cleanup()


async def test_duplicate_guard(store_file):
    print("\n▶ 7б. Защита от повторной выдачи по комментарию клиента")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)

    comment = "basic до 17.10.2026 | fk-123456"
    check("полный ref из комментария распознаётся",
          bot.comment_has_payment_ref(comment, "fk-123456") is True)
    check("короткий номер операции не совпадает с цифрами даты (баг «2» в «17.10.2026»)",
          bot.comment_has_payment_ref(comment, "2") is False)
    check("пустой ref не считается совпадением", bot.comment_has_payment_ref(comment, "") is False)
    check("пустой комментарий не считается совпадением", bot.comment_has_payment_ref(None, "fk-123456") is False)
    check("старый формат комментария (без «|») тоже проверяется",
          bot.comment_has_payment_ref("tg-charge-1", "tg-charge-1") is True)

    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        order = [o for o in bot.payment_store.orders.values()][-1]
        await post_fk_notification(order["id"], order["amount_rub"], intid="123456")
        check("первая оплата выдала ключ", panel_client(email) is not None)

        expiry_after_first = int(panel_client(email)["expiryTime"])
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, FAMILY)
        order2 = [o for o in bot.payment_store.orders.values()][-1]

        cb = _FakeCallback(bot, f"checkpay_{order2['id']}")
        await bot.cb_check_payment(cb)
        check("без уведомления оплата не подтверждается",
              int(panel_client(email)["expiryTime"]) == expiry_after_first)

        await post_fk_notification(order2["id"], order2["amount_rub"], intid="123457")
        extended = int(panel_client(email)["expiryTime"])
        family_days = bot.TARIFFS[FAMILY]["days"]
        check(f"уведомление продлевает подписку на {family_days} дней",
              round((extended - expiry_after_first) / 86_400_000, 1) == family_days,
              f"прибавка {round((extended - expiry_after_first) / 86_400_000, 1)} дн.")
        check("в комментарии клиента — номер последней операции FreeKassa",
              "fk-123457" in str(panel_client(email)["comment"]), str(panel_client(email)["comment"]))
    finally:
        await runner.cleanup()


async def test_freekassa_stats_and_labels(store_file):
    print("\n▶ 8г. FreeKassa: подписи тарифов и журнал заказов")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    premium_price = bot.TARIFFS[PREMIUM]["price"]
    check("цена тарифа показывается в рублях",
          bot.tariff_price_label(bot.TARIFFS[PREMIUM]) == f"{premium_price} ₽",
          bot.tariff_price_label(bot.TARIFFS[PREMIUM]))
    check("бесплатный тариф остаётся бесплатным",
          bot.tariff_price_label(bot.TARIFFS["trial"]) == "Бесплатно")

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, PREMIUM)
    order = [o for o in bot.payment_store.orders.values()][-1]
    check("заказ сохранён на диск", os.path.exists(store_file))
    check("в заказе рублёвая валюта, режим freekassa и ссылка на оплату",
          order["currency"] == "RUB" and order["mode"] == "freekassa"
          and order["payment_url"].startswith(bot.FREEKASSA_PAY_URL))

    stats = bot.payment_store.stats()
    check("неоплаченный заказ не попадает в выручку",
          stats["paid_count"] == 0 and stats["rub"] == 0, str(stats))

    answer, _ = await bot.process_freekassa_notification(
        fk_params(order["id"], premium_price, intid="321321"))
    stats = bot.payment_store.stats()
    check("оплаченный заказ попадает в рублёвую выручку",
          answer == "YES" and stats["rub"] == premium_price and stats["paid_count"] == 1, str(stats))
    check(f"в разбивке по тарифам учтён {PREMIUM}", stats["by_tariff"].get(PREMIUM) == 1, str(stats["by_tariff"]))


# ---------------- сценарии: общие (продолжение) ----------------

async def test_yookassa_button_and_revoke(store_file):
    print("\n▶ 9. Кнопка «Проверить оплату» (ЮKassa), удаление подписки и статистика")
    reset_all()
    bot = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
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

        await bot.start_checkout(TG_TG_ID, TG_TG_ID, PREMIUM)
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
        check("в профиле есть ссылка-подписка", "/sub/" in profile_text,
              profile_text[-120:].replace("\n", " "))

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
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    order_id = last_tg("sendInvoice")["payload"]
    await bot.on_successful_payment(make_message(bot, successful_payment={
        "currency": "XTR", "total_amount": bot.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("журнал сохранён на диск", os.path.exists(store_file))
    check("срок клиента 30 дней", 29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30)

    bot2 = new_bot({"mode": "stars"}, store_file)
    stats = bot2.payment_store.stats()
    check("после перезапуска журнал не потерялся",
          stats["paid_count"] == 1 and stats["stars"] == bot2.TARIFFS[BASIC]["stars"], f"{stats}")
    order = await bot2.payment_store.get(order_id)
    check("заказ помечен как выданный (provisioned)", bool(order.get("provisioned")))

    await bot2.on_successful_payment(make_message(bot2, successful_payment={
        "currency": "XTR", "total_amount": bot2.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("после перезапуска дубль платежа не продлевает подписку",
          29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30)
    check("после перезапуска дубль платежа не создаёт второго клиента",
          len([e for e in PANEL["clients"] if e == f"tg-paid-{TG_TG_ID}"]) == 1)

    bot3 = new_bot({"mode": "stars"}, store_file + ".lost")
    await bot3.on_successful_payment(make_message(bot3, successful_payment={
        "currency": "XTR", "total_amount": bot3.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-persist", "provider_payment_charge_id": "",
    }))
    check("при потерянном журнале платёж не выдаётся повторно (защита по панели)",
          29 <= days_left(panel_client(f"tg-paid-{TG_TG_ID}")) <= 30
          and len([e for e in PANEL["clients"] if e == f"tg-paid-{TG_TG_ID}"]) == 1)

    bot4 = new_bot({"mode": "off"}, store_file)
    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        check("в режиме off счёт не выставляется", False)
    except bot4.PaymentError as exc:
        check("в режиме off понятная ошибка с подсказкой", "PAYMENTS_MODE" in str(exc))

    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, "trial")
        check("trial нельзя оплатить как платный", False)
    except bot4.PaymentError:
        check("trial ведёт на бесплатный тестовый доступ", True)

    bot_stars = new_bot({"mode": "stars"}, store_file)
    stars_label = bot_stars.tariff_price_label(bot_stars.TARIFFS[PREMIUM])
    check("в Stars цена показывается в звёздах", "⭐" in stars_label, stars_label)
    check("STARS_<ТАРИФ> считается из рублей по курсу",
          bot_stars.TARIFFS[BASIC]["stars"] == round(bot_stars.TARIFFS[BASIC]["price"] / 1.6))

    bot_rub = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY}, store_file)
    rub_label = bot_rub.tariff_price_label(bot_rub.TARIFFS[PREMIUM])
    check("в ЮKassa цена показывается в рублях", rub_label.endswith("₽"), rub_label)

    bot_override = new_bot({"mode": "stars", "stars_basic": "50"}, store_file)
    check("переменная STARS_TIME_4=50 даёт ровно 50 звёзд", bot_override.TARIFFS[BASIC]["stars"] == 50)
    check("при переопределении остальные тарифы пересчитываются",
          bot_override.TARIFFS[FAMILY]["stars"] == round(bot_override.TARIFFS[FAMILY]["price"] / 1.6))


async def test_egress_ip(store_file):
    print("\n▶ 12а. Исходящий IP сервиса: определение и отказ без сети")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)

    ip = await bot.fetch_egress_ip(timeout=6)
    check("исходящий IP определяется (внешний сервис отвечает) либо честно пусто",
          ip == "" or ("." in ip or ":" in ip), repr(ip))
    if ip:
        check("в адресе нет лишних пробелов и разметки",
              ip == ip.strip() and " " not in ip and "<" not in ip, repr(ip))

    unreachable = await bot.fetch_egress_ip(timeout=1, urls=("http://127.0.0.1:9/ip",))
    check("недоступный сервис не ломает диагностику — просто пустая строка", unreachable == "", repr(unreachable))

    # Локальный сервис-заглушка: успешный путь одинаков и с любым внешним сервисом
    async def ip_page(request):
        return web.Response(text="203.0.113.7\n")

    stub = web.Application()
    stub.router.add_get("/ip", ip_page)
    stub_runner = web.AppRunner(stub)
    await stub_runner.setup()
    stub_port = EGRESS_STUB_PORT
    await web.TCPSite(stub_runner, "127.0.0.1", stub_port).start()
    try:
        got = await bot.fetch_egress_ip(timeout=3, urls=(f"http://127.0.0.1:{stub_port}/ip",))
    finally:
        await stub_runner.cleanup()
    check("адрес от сервиса читается и очищается от пробелов и перевода строки",
          got == "203.0.113.7", repr(got))
    check("строка диагностики подставляет найденный адрес",
          "<code>203.0.113.7</code>" in bot.egress_ip_line("203.0.113.7"))
    check("строка для бота объясняет, что адрес меняется при деплое",
          "меняется при каждом деплое" in bot.egress_ip_line("1.2.3.4"))
    check("без адреса строка сообщает, что определить не удалось",
          "не удалось" in bot.egress_ip_line(""))


async def test_diagnostics(store_file):
    print("\n▶ 11. Диагностика: провайдеры, сбои, доставка ключа")
    reset_all()
    bot = new_bot({"mode": "provider", "provider_token": None}, store_file)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        check("без provider token счёт не выставляется", False)
    except bot.PaymentError as exc:
        check("подсказка про PAYMENT_PROVIDER_TOKEN", "PAYMENT_PROVIDER_TOKEN" in str(exc))

    reset_all()
    bot2 = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": "wrong_key"}, store_file)
    try:
        await bot2.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        check("ошибка авторизации ЮKassa обрабатывается", False)
    except bot2.PaymentError as exc:
        text = str(exc)
        check("ошибка авторизации ЮKassa понятна пользователю",
              "401" in text and "YOOKASSA" in text, "HTTP 401 + подсказка про ключи ЮKassa")

    reset_all()
    bot4 = new_bot({"mode": "yookassa", "shop_id": SHOP_ID, "secret_key": SECRET_KEY,
                    "api_url": "http://127.0.0.1:9/v3"}, store_file)
    try:
        await bot4.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        check("недоступность ЮKassa обрабатывается", False)
    except bot4.PaymentError as exc:
        check("недоступность ЮKassa → понятная ошибка", "недоступна" in str(exc))

    reset_all()
    bot5 = new_bot({"mode": "stars"}, store_file)
    await bot5.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    order_id = last_tg("sendInvoice")["payload"]
    TG["fail_send"] = {"sendMessage"}
    await bot5.on_successful_payment(make_message(bot5, successful_payment={
        "currency": "XTR", "total_amount": bot5.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
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
        "currency": "XTR", "total_amount": bot5.TARIFFS[BASIC]["stars"], "invoice_payload": order_id,
        "telegram_payment_charge_id": "tg-charge-fail", "provider_payment_charge_id": "",
    }))
    check("повторная доставка досылает недоставленную подписку",
          any("/sub/" in m["params"].get("text", "") for m in tg_calls("sendMessage")))
    check("при досылке срок подписки не меняется",
          int(panel_client(f"tg-paid-{TG_TG_ID}")["expiryTime"]) == expiry_before)
    check("после успешной досылки заказ помечен уведомлённым",
          bool((await bot5.payment_store.get(order_id)).get("notified")))


async def test_simulated_payment(store_file):
    print("\n▶ 13. Проверка выдачи ключа БЕЗ оплаты (/test_pay)")
    reset_all()
    email = f"tg-paid-{TG_TG_ID}"

    # По умолчанию (боевой режим) проверка выключена
    bot = new_bot({"mode": "freekassa", "allow_test_pay": None}, store_file)
    check("в боевом режиме проверка без оплаты по умолчанию выключена", bot.test_pay_enabled() is False)
    msg = make_message(bot, text=f"/test_pay {BASIC}")
    await bot.cmd_test_pay(msg)
    check("выключенная проверка подсказывает переменную",
          "PAYMENTS_ALLOW_TEST_PAY=1" in _last_api_text() and panel_client(email) is None)

    # В тестовом режиме FreeKassa включается автоматически
    reset_all()
    bot = new_bot({"mode": "freekassa", "fk_test": "1"}, store_file)
    check("в тестовом режиме FreeKassa проверка включается сама", bot.test_pay_enabled() is True)

    # Включённая проверка: полный путь выдачи без денег
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1"}, store_file)
    check("проверка включена переменной PAYMENTS_ALLOW_TEST_PAY", bot.test_pay_enabled() is True)

    msg = make_message(bot, text="/test_pay")
    await bot.cmd_test_pay(msg)
    markup = json.dumps(tg_calls("sendMessage")[-1]["params"].get("reply_markup", {}), ensure_ascii=False)
    check("без аргумента показаны тарифы кнопками", f"testpay_run_{BASIC}" in markup and f"testpay_run_{PREMIUM}" in markup)

    msg = make_message(bot, text=f"/test_pay {BASIC}")
    await bot.cmd_test_pay(msg)
    client = panel_client(email)
    check("ключ выдан без оплаты (клиент создан в панели)", client is not None)
    check("срок взят из тарифа: 30 дней", client and 29 <= days_left(client) <= 30,
          f"{days_left(client) if client else '—'} дн.")
    basic_ips = bot.TARIFFS[BASIC]["ip_limit"]
    check(f"лимиты взяты из тарифа ({basic_ips} устройств, безлимитный трафик)",
          client and client.get("limitIp") == basic_ips and client.get("totalGB") == 0)
    check("в панели сохранился id тарифа и дата", client and client["comment"].startswith(f"{BASIC} до "))

    texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
    key_text = [t for t in texts if "🧪" in t and "/sub/" in t]
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
          stats["paid_count"] == 0 and stats["rub"] == 0 and stats["stars"] == 0,
          f"paid_count={stats['paid_count']}")

    check("ссылка на оплату в FreeKassa не создавалась (денег не нужно)",
          not [o for o in bot.payment_store.orders.values() if o.get("payment_url")])

    # Кнопка выбора тарифа: пока тестовый ключ на месте — проверка отказывается его портить
    cb = _FakeCallback(bot, f"testpay_run_{FAMILY}")
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

    # После удаления кнопкой можно проверить другой тариф
    cb = _FakeCallback(bot, f"testpay_run_{FAMILY}")
    await bot.cb_testpay_run(cb)
    family_days = bot.TARIFFS[FAMILY]["days"]
    check(f"после удаления проверка другого тарифа выдаёт ключ на {family_days} дней",
          family_days - 1 <= days_left(panel_client(email)) <= family_days,
          f"{days_left(panel_client(email))} дн.")

    # Защита: обычный пользователь не может ни выдать, ни удалить
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1"}, store_file)
    other = make_message(bot, uid=777, text=f"/test_pay {BASIC}")
    await bot.cmd_test_pay(other)
    check("обычному пользователю /test_pay недоступна",
          "только администратору" in _last_api_text() and panel_client(f"tg-paid-777") is None)

    cb = _FakeCallback(bot, f"testpay_run_{BASIC}", uid=777)
    await bot.cb_testpay_run(cb)
    check("обычному пользователю кнопка выдачи недоступна",
          cb.answers and "Только для администратора" in cb.answers[0])

    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    order_real = [o for o in bot.payment_store.orders.values()][-1]["id"]
    cb = _FakeCallback(bot, f"testpay_del_{order_real}")
    await bot.cb_testpay_del(cb)
    check("кнопка удаления не трогает настоящие (не тестовые) заказы",
          any("не найден" in t for t in cb.answers))

    # Настоящую подписку проверочная выдача не трогает
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1"}, store_file)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
    real_order = [o for o in bot.payment_store.orders.values()][-1]
    answer, _ = await bot.process_freekassa_notification(
        fk_params(real_order["id"], real_order["amount_rub"], intid="909090"))
    check("для проверки защиты настоящая оплата прошла",
          answer == "YES" and panel_client(email) is not None)
    real_expiry = int(panel_client(email)["expiryTime"])

    simulated_before = len([o for o in bot.payment_store.orders.values() if o.get("simulated")])
    msg = make_message(bot, text=f"/test_pay {FAMILY}")
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
    msg = make_message(bot, text=f"/test_pay {PREMIUM}")
    await bot.cmd_test_pay(msg)
    check("после /revoke проверочная выдача снова работает", panel_client(email) is not None)


async def test_admin_access(store_file):
    print("\n▶ 15. Доступ администратора (ADMIN_ID: один, список, мусор, пусто)")
    reset_all()

    # Один админ
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": str(TG_TG_ID)}, store_file)
    check("один ID: владелец — админ", bot.is_admin(TG_TG_ID) is True)
    check("один ID: чужой — не админ", bot.is_admin(777) is False)

    # Несколько админов через запятую
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": f"{TG_TG_ID}, 777"}, store_file)
    check("список ID: первый админ", bot.is_admin(TG_TG_ID) is True)
    check("список ID: второй админ", bot.is_admin(777) is True)
    check("список ID: посторонний не админ", bot.is_admin(999) is False)
    check("список разобран во все ID", bot.ADMIN_IDS == [TG_TG_ID, 777], str(bot.ADMIN_IDS))

    # Странности формата
    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_id": f" +{TG_TG_ID} ; 777 ", "allow_test_pay": "1"}, store_file)
    check("плюс, точка с запятой и пробелы не мешают", bot.ADMIN_IDS == [TG_TG_ID, 777], str(bot.ADMIN_IDS))

    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_id": "@username", "allow_test_pay": "1"}, store_file)
    check("мусорный ADMIN_ID: не блокирует владельца (команды открыты), как и у старых команд",
          bot.is_admin(TG_TG_ID) is True and bot.ADMIN_IDS == [])

    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_id": "", "allow_test_pay": "1"}, store_file)
    check("пустой ADMIN_ID: команды открыты всем (бот предупредит при старте)", bot.is_admin(777) is True)

    # Второй админ из списка может работать с командой
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": f"{TG_TG_ID},777"}, store_file)
    msg = make_message(bot, uid=777, text=f"/test_pay {BASIC}")
    await bot.cmd_test_pay(msg)
    check("второй админ из списка получил ключ через /test_pay", panel_client("tg-paid-777") is not None)

    # Отказ содержит диагностику
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": str(TG_TG_ID)}, store_file)
    msg = make_message(bot, uid=555, text="/test_pay basic")
    await bot.cmd_test_pay(msg)
    text = _last_api_text()
    check("отказ показывает ID пользователя", "555" in text)
    check("отказ показывает, какой ADMIN_ID сейчас задан", str(TG_TG_ID) in text)
    check("отказ подсказывает про запятую для нескольких админов", "запятую" in text)
    check("отказ не выдал ключ", panel_client("tg-paid-555") is None)

    # Некорректный ADMIN_ID (@username вместо ID): владельца не блокируем,
    # но честно говорим об этом в /myid — иначе легко решить, что «бот меня не признал»
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": "@username"}, store_file)
    check("мусорный ADMIN_ID не блокирует админ-команды (нельзя запереть себя вне бота)",
          bot.is_admin(555) is True)
    msg = make_message(bot, uid=555, text="/myid")
    await bot.cmd_myid(msg)
    text = _last_api_text()
    check("/myid предупреждает, что ADMIN_ID заполнен нечисловым значением",
          "@username" in text and "некорректно" in text)
    check("/myid подсказывает формат списка админов", "111,222" in text)

    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_id": ""}, store_file)
    msg = make_message(bot, uid=555, text="/myid")
    await bot.cmd_myid(msg)
    check("/myid отдельно сообщает, что ADMIN_ID не задана", "не задана" in _last_api_text())

    # /myid отвечает всем и объясняет статус
    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_id": str(TG_TG_ID)}, store_file)
    msg = make_message(bot, uid=555, text="/myid")
    await bot.cmd_myid(msg)
    text = _last_api_text()
    check("/myid для не-админа показывает список админов и что делать",
          str(TG_TG_ID) in text and "ADMIN_ID" in text and "не в списке" in text)

    msg = make_message(bot, uid=TG_TG_ID, text="/myid")
    await bot.cmd_myid(msg)
    check("/myid для админа подтверждает статус", "Ты администратор" in _last_api_text())

    # /panel_debug показывает админов
    msg = make_message(bot, text="/panel_debug")
    await bot.cmd_panel_debug(msg)
    check("/panel_debug показывает список админов и свой ID",
          "ADMIN_ID" in _last_api_text() and str(TG_TG_ID) in _last_api_text())


async def test_freekassa_self_check(store_file):
    print("\n▶ 14. Проверка настроек FreeKassa без денег (/freekassa_check)")
    reset_all()
    bot = new_bot({"mode": "freekassa", "merchant": None, "secret1": None, "secret2": None}, store_file)
    text = await bot.freekassa_self_check()
    check("без ключей отчёт объясняет, где их взять",
          "FREEKASSA_MERCHANT_ID" in text and "Настройки магазина" in text)

    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    runner = await bot.run_webhook_server()
    try:
        text = await bot.freekassa_self_check()
        check("отчёт показывает магазин", FK_MERCHANT_ID in text)
        check("отчёт подтверждает обе подписи", text.count("✅") >= 2, f"✅ ×{text.count('✅')}")
        check("отчёт показывает URL оповещения для кабинета FK",
              f"http://127.0.0.1:{WEBHOOK_PORT}/freekassa/webhook" in text)
        check("отчёт показывает адрес возврата на бота", "t.me/" in text)
        check("отчёт напоминает про галочку «Подтверждение платежа»",
              "Подтверждение платежа" in text)
        check("отчёт подсказывает кнопку «Проверить статус»", "Проверить статус" in text)
        check("отчёт проверяет доступность страницы оплаты",
              "Доступность страницы оплаты" in text)
        check("отчёт показывает исходящий IP бота (нужен, если платёжка просит whitelist)",
              "Исходящий IP бота:" in text, [line for line in text.split("\n") if "Исходящий" in line][:1])
        check("если домен не отвечает — подсказано зеркало pay.kassa.shop",
              "Доступность страницы оплаты: отвечает ✅" in text
              or "pay.kassa.shop" in text, text[-260:])
        # Домен из переменной может быть с хвостовым слэшем или без — ссылка одинаково верная
        reset_all()
        mirror = new_bot({"mode": "freekassa", "pay_url": "https://pay.kassa.shop"}, store_file)
        probe = {"id": "probe-1", "tg_id": 0, "amount_rub": 99, "currency": "RUB"}
        url_no_slash = mirror.freekassa_payment_url(probe)
        check("домен без хвостового слэша даёт ссылку вида /?m=",
              url_no_slash.startswith("https://pay.kassa.shop/?m="), url_no_slash[:60])
        reset_all()
        mirror_slash = new_bot({"mode": "freekassa", "pay_url": "https://pay.kassa.shop/"}, store_file)
        check("домен с хвостовым слэшем не даёт «//»",
              mirror_slash.freekassa_payment_url(probe).startswith("https://pay.kassa.shop/?m="))

        check("отчёт ведёт к первой настоящей оплате",
              "первая настоящая оплата" in text and "PAYMENTS_ALLOW_TEST_PAY=1" in text)
        check("самопроверка сервера прошла (healthz отвечает)", "Самопроверка сервера: ✅" in text, text[-200:])

        msg = make_message(bot, text="/freekassa_check")
        await bot.cmd_freekassa_check(msg)
        check("команда /freekassa_check присылает отчёт", "Проверка FreeKassa" in _last_api_text())

        other = make_message(bot, uid=777, text="/freekassa_check")
        await bot.cmd_freekassa_check(other)
        check("обычному пользователю /freekassa_check недоступна",
              "только администратору" in _last_api_text())
    finally:
        await runner.cleanup()

    reset_all()
    bot_stars = new_bot({"mode": "stars"}, store_file)
    msg = make_message(bot_stars, text="/freekassa_check")
    await bot_stars.cmd_freekassa_check(msg)
    check("в другом режиме команда честно говорит, что не нужна",
          "режим оплаты" in _last_api_text())


async def test_myid_payments_diag(store_file):
    print("\n▶ 14б. /myid показывает состояние оплаты и почему проверки скрыты")
    reset_all()
    bot = new_bot({"mode": "freekassa", "fk_test": "1", "admin_tools": "1"}, store_file)

    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: видно режим оплаты", "FreeKassa" in text, text[-120:].replace("\n", " | "))
    check("/myid: видно ID магазина", FK_MERCHANT_ID in text)
    check("/myid: видно, что секретные слова заданы", "заданы ✅" in text)
    check("/myid: видно, что включён тестовый режим FK", "Тестовый режим FK" in text)
    check("/myid: показан адрес для «URL оповещения»", "/freekassa/webhook" in text)
    check("/myid: видно, что диагностика /freekassa_check доступна",
          "/freekassa_check" in text and "доступна" in text)
    check("/myid: сказано, что выдача без оплаты включена",
          "/test_pay" in text and "включена" in text)

    # ADMIN_TOOLS=0 — команда проверки не отвечает, и /myid объясняет почему
    reset_all()
    bot = new_bot({"mode": "freekassa", "fk_test": "1", "admin_tools": "0"}, store_file)
    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: сказано, что выдача без оплаты скрыта", "скрыта" in text)
    check("/myid: подсказана переменная ADMIN_TOOLS=1", "ADMIN_TOOLS=1" in text)
    check("/myid: видно, что служебные команды скрыты", "ADMIN_TOOLS=0" in text)

    # Проверки разрешены, но TEST_TOOLS=0 их прячет
    reset_all()
    bot = new_bot({"mode": "freekassa", "allow_test_pay": "1", "admin_tools": "1", "test_tools": "0"}, store_file)
    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: TEST_TOOLS=0 назван причиной", "TEST_TOOLS=0" in text and "скрыта" in text)

    # Проверки скрыты, потому что не включён тестовый режим
    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_tools": "1"}, store_file)
    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: подсказано, как включить выдачу без оплаты",
          "PAYMENTS_ALLOW_TEST_PAY=1" in text and "скрыта" in text)
    check("/myid: диагностика /freekassa_check в бою доступна",
          "/freekassa_check" in text and "доступна" in text)

    # Магазин не задан — видно прямо в подсказке
    reset_all()
    bot = new_bot({"mode": "freekassa", "merchant": None, "secret1": None, "secret2": None,
                   "admin_tools": "1"}, store_file)
    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: видно, что магазин не задан", "не задан ❌" in text)

    # Контакт поддержки из переменной перекрывает стандартный — видно в /myid и в разделе
    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_tools": "1",
                   "support_username": "@Support_Test"}, store_file)
    await bot.cmd_myid(make_message(bot, text="/myid"))
    text = _last_api_text()
    check("/myid: показан контакт из переменной SUPPORT_USERNAME",
          "@Support_Test" in text and "из переменной" in text,
          text[-140:].replace("\n", " | "))
    check("собака в SUPPORT_USERNAME не мешает (лишний @ срезается)",
          bot.SUPPORT_USERNAME == "Support_Test"
          and bot.support_link() == "https://t.me/Support_Test", bot.support_link())

    # Обычному пользователю диагностика оплаты не показывается
    reset_all()
    bot = new_bot({"mode": "freekassa", "admin_tools": "1", "admin_id": str(TG_TG_ID)}, store_file)
    await bot.cmd_myid(make_message(bot, uid=555, text="/myid"))
    text = _last_api_text()
    check("обычный пользователь не видит диагностику оплаты",
          "/freekassa_check" not in text and FK_MERCHANT_ID not in text)


async def test_production_handlers(store_file):
    print("\n▶ 14в. Боевой режим: /freekassa_check есть у админа, /test_pay — нет")
    reset_all()
    prod = new_bot({"mode": "freekassa", "admin_tools": "1"}, store_file)
    handlers = {h.callback.__name__ for h in prod.dp.message.handlers}
    check("боевой режим: диагностика FreeKassa зарегистрирована",
          "cmd_freekassa_check" in handlers, str(sorted(handlers)))
    check("боевой режим: выдача ключа без оплаты не зарегистрирована",
          "cmd_test_pay" not in handlers)
    check("боевой режим: кнопки проверок скрыты", not prod.test_tools_enabled())
    check("боевой режим: /freekassa_check указана в /myid", prod.admin_tools_enabled())

    # администратору диагностика отвечает и без тестовых флагов
    msg = make_message(prod, text="/freekassa_check")
    await prod.cmd_freekassa_check(msg)
    check("боевой режим: /freekassa_check отвечает", "Проверка FreeKassa" in _last_api_text())
    check("боевой режим: в отчёте сказано «боевой режим»",
          "боевой режим" in _last_api_text())
    check("боевой режим: напоминание выключить тест в кабинете",
          "выключена" in _last_api_text() and "FREEKASSA_TEST" in _last_api_text())

    # в тестовом режиме — отдельная памятка и команда выдачи без оплаты
    reset_all()
    test_bot = new_bot({"mode": "freekassa", "fk_test": "1", "admin_tools": "1"}, store_file)
    check("тестовый режим: выдача без оплаты зарегистрирована",
          "cmd_test_pay" in {h.callback.__name__ for h in test_bot.dp.message.handlers})
    await test_bot.cmd_freekassa_check(make_message(test_bot, text="/freekassa_check"))
    check("тестовый режим: в отчёте сказано «тестовый режим»",
          "тестовый режим" in _last_api_text())


async def test_subscription_link(store_file):
    print("\n▶ 14е. Ссылка-подписка: адрес сервиса подписок, проверка и запасной ключ")
    reset_all()
    reset(sub={"enable": True, "port": None, "path": "/sub/", "domain": "", "uri": ""})
    bot = new_bot({"mode": "freekassa"}, store_file + ".base")
    runner = await bot.run_webhook_server()
    tg_id = 551001

    def text_for(chat_id: int) -> str:
        """Последнее сообщение бота этому чату (админу уходит отдельное уведомление)."""
        msgs = [m for m in tg_calls("sendMessage")
                if str(m["params"].get("chat_id")) == str(chat_id)
                and m["params"].get("text")]
        return msgs[-1]["params"]["text"] if msgs else ""

    try:
        # 1. Обычный случай: сервис подписок на порту панели, ссылка проверена
        await bot.start_checkout(tg_id, tg_id, BASIC)
        order = [o for o in bot.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(order["id"], bot.TARIFFS[BASIC]["price"])
        client = panel_client(f"tg-paid-{tg_id}")
        check("оплата прошла, клиент создан", body == "YES" and client is not None, body)

        sub_id = str(client.get("subId") or "")
        check("у клиента есть Sub ID (нужен для подписки)", bool(sub_id), sub_id)
        text = text_for(tg_id)
        check("в сообщении именно ссылка-подписка",
              f"http://127.0.0.1:{PANEL_PORT}/sub/{sub_id}" in text,
              text[:90].replace("\n", " "))
        check("ключ vless клиенту не показывается", "vless://" not in text)
        check("бот проверил ссылку запросом к сервису подписок",
              ("sub/get", sub_id) in PANEL["calls"], str(PANEL["calls"][-4:]))
        check("бот спросил у панели настройки подписок", ("setting/all",) in PANEL["calls"])

        # Проверяем, что ссылка действительно рабочая: сервис отдаёт конфигурацию
        ok, detail = await bot._check_sub_link(f"http://127.0.0.1:{PANEL_PORT}/sub/{sub_id}")
        check("ссылка из сообщения отдаёт конфигурацию", ok, detail)

        # 2. Адрес проверяется один раз и кэшируется (не дёргаем панель на каждой выдаче)
        PANEL["calls"].clear()
        await bot.start_checkout(tg_id + 1, tg_id + 1, BASIC)
        order2 = [o for o in bot.payment_store.orders.values()][-1]
        # intid у каждого уведомления свой: по нему бот отсекает повторные доставки
        await post_fk_notification(order2["id"], bot.TARIFFS[BASIC]["price"], intid="987655")
        check("второй заказ тоже выдан",
              panel_client(f"tg-paid-{tg_id + 1}") is not None)
        check("повторная выдача обошлась без новых запросов настроек",
              ("setting/all",) not in PANEL["calls"], str(PANEL["calls"]))
        text2 = text_for(tg_id + 1)
        check("второй клиент получил свою ссылку-подписку",
              f"/sub/" in text2 and f"http://127.0.0.1:{PANEL_PORT}/sub/" in text2,
              text2[:90].replace("\n", " "))

        # 3. Запасной вариант: сервис подписок выключен в панели —
        #    клиент получает ключ, админ предупреждение
        reset_all()
        reset(sub={"enable": False, "port": None, "path": "/sub/", "domain": "", "uri": ""})
        off = new_bot({"mode": "freekassa"}, store_file + ".off")
        await off.start_checkout(tg_id, tg_id, BASIC)
        order3 = [o for o in off.payment_store.orders.values()][-1]
        info3 = await off.fulfill_order(order3, charge_id="test-sub-off")
        check("при выключенном сервисе подписок ссылки нет", info3["info"]["sub_link"] is None)
        check("ключ при этом выдан (клиент без доступа не остаётся)",
              bool(info3["info"].get("link")))
        text3 = text_for(tg_id)
        check("клиент получил ключ вместо ссылки",
              "vless://" in text3 and "/sub/" not in text3, text3[:90].replace("\n", " "))
        admin_texts = [m["params"].get("text", "") for m in tg_calls("sendMessage")]
        check("админ предупреждён, что подписки нет",
              any("Ссылки-подписки нет" in t for t in admin_texts),
              str(admin_texts)[-160:])

        # 4. Переопределения: SUB_URL_BASE, Sub URI и Sub Domain из панели
        cases = [
            ("SUB_URL_BASE", {"sub_url_base": f"http://127.0.0.1:{PANEL_PORT}/sub"},
             {"enable": True, "port": None, "path": "/sub/", "domain": "", "uri": ""},
             f"http://127.0.0.1:{PANEL_PORT}/sub/"),
            ("Sub URI из панели", {"sub_url_base": None},
             {"enable": True, "port": 2096, "path": "/sub/",
              "domain": "", "uri": "https://sub.example.com:2096/sub/"},
             "https://sub.example.com:2096/sub/"),
            ("Sub Domain из панели", {"sub_url_base": None},
             {"enable": True, "port": 2096, "path": "/sub/",
              "domain": "vpn.example.com", "uri": ""},
             "https://vpn.example.com:2096/sub/"),
        ]
        for index, (label, env, sub_settings, expected) in enumerate(cases):
            reset_all()
            reset(sub=sub_settings)
            # Адрес берём из настоящих настроек панели (через фейковый API 3x-ui):
            # панель может быть за прокси, поэтому проверку доступности тут не ждём.
            variant = new_bot({**{"mode": "freekassa"}, **env}, f"{store_file}.case{index}")
            async with variant.XUIClient() as client:
                panel_settings = await variant.fetch_panel_settings(client)
            base, note = await variant.get_subscription_base(refresh=True)
            candidates = [b for b, _ in variant.subscription_candidates(panel_settings)]
            check(f"адрес подписки: {label}", candidates[0] == expected.rstrip("/"),
                  f"{candidates[:2]} (ожидался {expected})")
            check(f"пояснение к адресу ({label}) непустое", bool(note), note)

        # 5. Приоритет адресов: переменная важнее настроек панели
        variant = new_bot({"mode": "freekassa", "sub_url_base": "https://my-sub.example.com",
                           "sub_port": None, "sub_path": None}, f"{store_file}.prio")
        order_candidates = variant.subscription_candidates({
            "subURI": "https://sub.panel.example.com/sub/", "subDomain": "vpn.example.com",
            "subPort": 2096, "subPath": "/sub/",
        })
        check("SUB_URL_BASE идёт первым, затем Sub URI, затем домен панели",
              [b for b, _ in order_candidates][:3] == [
                  "https://my-sub.example.com/sub",
                  "https://sub.panel.example.com/sub",
                  "https://vpn.example.com:2096/sub",
              ], str(order_candidates))
        check("в кандидатах нет мусорных адресов",
              all(b.startswith("http") and "None" not in b for b, _ in order_candidates),
              str(order_candidates))
    finally:
        await runner.cleanup()


async def test_promo_tariff(store_file):
    print("\n▶ 14д. Промо-тариф: 15 дней, 10 ГБ, бесплатно и один раз на аккаунт")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    email = f"tg-paid-{TG_TG_ID}"

    check("промо включён по умолчанию", bot.promo_enabled() is True)
    check("тариф промо: 15 дней, 10 ГБ, 1 устройство",
          bot.TARIFFS["promo"]["days"] == bot.PROMO_DAYS == 15
          and bot.TARIFFS["promo"]["traffic_gb"] == 10
          and bot.TARIFFS["promo"]["ip_limit"] == 1)
    check("промо указан как бесплатный", bot.tariff_price_label(bot.TARIFFS["promo"]) == "Бесплатно")
    check("промо видно в списке тарифов", bot.promo_visible(TG_TG_ID) is True)

    kb = bot.tariffs_kb(TG_TG_ID)
    callbacks = [button.callback_data for row in kb.inline_keyboard for button in row]
    labels = " | ".join(button.text for row in kb.inline_keyboard for button in row)
    check("в кнопках тарифов есть промо", "buy_promo" in callbacks, str(callbacks))
    check("промо подписан как бесплатный пункт", "бесплатно" in labels.lower(), labels[:160])
    screen = _FakeCallback(bot, "tariffs")
    await bot.cb_tariffs(screen)
    tariffs_text = screen.message.sent[-1] if screen.message.sent else ""
    check("на экране тарифов промо с трафиком 10 ГБ",
          "Промо" in tariffs_text and "10 ГБ" in tariffs_text and "Бесплатно" in tariffs_text,
          tariffs_text[:120].replace("\n", " "))
    await bot.grant_promo(TG_TG_ID, TG_TG_ID)
    client = panel_client(email)
    check("промо создало подписку в панели", client is not None)
    check("срок промо — 15 дней", round(days_left(client)) == 15, str(days_left(client)))
    check("лимит трафика — 10 ГБ",
          round(client["totalGB"] / (1024 ** 3)) == 10, str(client["totalGB"]))
    check("заказ помечен промо и не попал в выручку",
          any(o.get("promo") for o in bot.payment_store.orders.values())
          and bot.payment_store.stats()["rub"] == 0
          and bot.payment_store.stats()["promo_count"] == 1)

    diag = bot.payments_diag_text()
    check("в /myid видно состояние промо", "Промо-доступ: включён" in diag, diag[-160:].replace("\n", " "))
    text = _last_api_text()
    check("ключ отправлен с пометкой промо", "Промо-доступ активирован" in text, text[:80])
    check("в сообщении про промо нет слова «оплата»", "оплата" not in text.lower())

    await bot.cmd_payments(make_message(bot, text="/payments"))
    panel_text = _last_api_text()
    check("в /payments есть счётчик промо", "Промо-доступов выдано" in panel_text,
          panel_text[-160:].replace("\n", " "))

    # Повторно — нельзя
    check("после активации промо скрыт из тарифов", bot.promo_visible(TG_TG_ID) is False)
    repeat_refused = False
    try:
        await bot.grant_promo(TG_TG_ID, TG_TG_ID)
    except Exception as exc:
        repeat_refused = "уже активирован" in str(exc)
    check("повторная выдача промо отклонена", repeat_refused)
    check("повторная попытка не создала второй заказ",
          bot.payment_store.stats()["promo_count"] == 1)

    # Кнопка в тарифах доводит клиента до готового ключа (как это делает пользователь)
    reset_all()
    click = new_bot({"mode": "freekassa"}, store_file + ".click")
    user_id = 999001
    cb = _FakeCallback(click, "buy_promo", uid=user_id)
    await click.cb_buy(cb)
    click_client = panel_client(f"tg-paid-{user_id}")
    check("нажатие «Промо» выдаёт ключ", click_client is not None)
    check("подписка после нажатия кнопки активна на 15 дней",
          round(days_left(click_client)) == 15, str(days_left(click_client)))
    check("клиент увидел уведомление о выдаче", "Активирую промо-доступ" in " ".join(cb.answers),
          str(cb.answers))
    second = _FakeCallback(click, "buy_promo", uid=user_id)
    await click.cb_buy(second)
    check("повторное нажатие объясняет, что промо уже активирован",
          any("уже активирован" in t for t in second.message.sent), str(second.message.sent)[:120])

    # PROMO_ENABLED=0 — пункта нет и выдача отклоняется
    reset_all()
    off = new_bot({"mode": "freekassa", "promo_enabled": "0"}, store_file)
    check("PROMO_ENABLED=0 выключает промо", off.promo_enabled() is False)
    check("выключенный промо не виден", off.promo_visible(TG_TG_ID) is False)
    try:
        await off.grant_promo(TG_TG_ID, TG_TG_ID)
        off_marker = False
    except Exception as exc:
        off_marker = "закрыт" in str(exc)
    check("выключенный промо не выдаётся", off_marker)

    # PROMO_ONCE=0 — промо не считается использованным (для проверок на своём аккаунте):
    # после /revoke выданный ранее промо можно активировать заново.
    reset_all()
    many = new_bot({"mode": "freekassa", "promo_once": "0"}, store_file + ".once")
    await many.grant_promo(TG_TG_ID, TG_TG_ID)
    check("PROMO_ONCE=0 не помечает промо использованным",
          many.promo_used(TG_TG_ID) is False and many.promo_visible(TG_TG_ID) is True)
    rvk = make_message(many, text=f"/revoke {TG_TG_ID}")
    await many.cmd_revoke(rvk)
    await many.grant_promo(TG_TG_ID, TG_TG_ID)
    check("после /revoke промо выдаётся повторно",
          many.payment_store.stats()["promo_count"] == 2,
          str(many.payment_store.stats()["promo_count"]))

    # Тем, у кого уже есть платная подписка, промо не выдаётся —
    # иначе промо переписало бы лимиты оплаченного тарифа на 10 ГБ.
    reset_all()
    paid = new_bot({"mode": "freekassa"}, store_file + ".paid")
    runner = await paid.run_webhook_server()
    try:
        await paid.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        order = [o for o in paid.payment_store.orders.values()][-1]
        status, body = await post_fk_notification(order["id"], paid.TARIFFS[BASIC]["price"])
        check("платная подписка активирована", body == "YES" and panel_client(email) is not None, body)
        total_before = panel_client(email)["totalGB"]
        paid_refused = False
        try:
            await paid.grant_promo(TG_TG_ID, TG_TG_ID)
        except Exception as exc:
            paid_refused = "уже есть действующая подписка" in str(exc)
        check("промо не выдаётся при активной подписке", paid_refused)
        check("лимиты оплаченного тарифа не тронуты",
              panel_client(email)["totalGB"] == total_before,
              f"{total_before} -> {panel_client(email)['totalGB']}")

        # Просроченная подписка: промо тоже не выдаём (аккаунт с историей оплат),
        # но и не говорим «у тебя активная подписка».
        async def expired_sub(_tg_id):
            return {"client": {}, "inbound": {}, "used_bytes": 0, "total_bytes": 0,
                    "expiry_ms": int(time.time() * 1000) - 86_400_000, "enable": True}

        paid.get_paid_subscription = expired_sub
        expired_refused = False
        try:
            await paid.grant_promo(TG_TG_ID, TG_TG_ID)
        except Exception as exc:
            expired_refused = ("только новым пользователям" in str(exc)
                               and "действующая подписка" not in str(exc))
        check("промо не выдаётся тем, у кого подписка была и закончилась", expired_refused)
    finally:
        await runner.cleanup()


async def test_cancel_order(store_file):
    print("\n▶ 14г. Отмена заказа: статус, проверка оплаты и позднее поступление денег")
    reset_all()
    bot = new_bot({"mode": "freekassa"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"

    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, BASIC)
        order = [o for o in bot.payment_store.orders.values()][-1]
        order_id = order["id"]
        check("свежий заказ ждёт оплаты", order["status"] == "pending")

        # Чужой пользователь отменить заказ не может
        stranger = _FakeCallback(bot, f"cancelorder_{order_id}", uid=777)
        await bot.cb_cancel_order(stranger)
        check("чужой пользователь заказ не отменяет",
              (await bot.payment_store.get(order_id))["status"] == "pending")
        check("чужому пользователю сказано, что заказ не найден",
              any("не найден" in a.lower() for a in stranger.answers))

        cb = _FakeCallback(bot, f"cancelorder_{order_id}")
        await bot.cb_cancel_order(cb)
        check("заказ переведён в статус «отменён»",
              (await bot.payment_store.get(order_id))["status"] == "canceled")
        check("клиент увидел подтверждение отмены", "отменён" in " ".join(cb.answers).lower()
              or any("отменён" in t.lower() for t in cb.message.sent))
        check("в сообщении об отмене убрана ссылка на оплату",
              "Оплатить" not in " ".join(cb.message.sent))

        # Повторная отмена — без изменений
        cb2 = _FakeCallback(bot, f"cancelorder_{order_id}")
        await bot.cb_cancel_order(cb2)
        check("повторная отмена сообщает, что заказ уже отменён",
              any("уже отменён" in a.lower() for a in cb2.answers))

        # «Проверить оплату» по отменённому заказу
        cb3 = _FakeCallback(bot, f"checkpay_{order_id}")
        await bot.cb_check_payment(cb3)
        check("по отменённому заказу оплату не ищем",
              any("отменён" in a.lower() for a in cb3.answers))

        # Клиент всё-таки оплатил по старой ссылке — деньги не должны пропасть
        status, body = await post_fk_notification(order_id, order["amount_rub"])
        check("уведомление по отменённому заказу принято (YES)", body == "YES", body)
        paid = await bot.payment_store.get(order_id)
        check("заказ снова стал оплаченным", paid["status"] == "paid")
        check("ключ выдан, несмотря на отмену", panel_client(email) is not None)
        check("в заказе отмечено, что оплата пришла после отмены", paid.get("canceled_then_paid") is True)
        notice = [c for c in tg_calls("sendMessage")
                  if "отменён" in c["params"].get("text", "").lower()
                  and "Оплата пришла" in c["params"].get("text", "")]
        check("клиент предупреждён об оплате отменённого заказа", bool(notice))
    finally:
        await runner.cleanup()


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
    # Блок про подписки смотрит на сервис подписок, а не на кассу: у него свои пометки
    tail = text.split("Оплата")[-1].split("Сервис подписок")[0]
    check("/panel_debug: без OAuth подсказан путь настройки в кабинете, а не ошибка",
          "HTTP-уведомления" in tail and "❌" not in tail)
    check("/panel_debug: виден блок про сервис подписок",
          "Сервис подписок" in text and "Sub ID" in text)


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
                      (YK_PORT, make_yk_app())):
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
        await test_freekassa_signatures()
        await test_freekassa_flow(store_for("freekassa"))
        await test_duplicate_guard(store_for("freekassa_dup"))
        await test_freekassa_ip_check_and_errors(store_for("freekassa_ip"))
        await test_freekassa_test_mode_and_diagnostics(store_for("freekassa_test"))
        await test_freekassa_stats_and_labels(store_for("freekassa_stats"))
        await test_yookassa_button_and_revoke(store_for("yookassa_btn"))
        await test_persistence_and_off(store_for("persist"))
        await test_egress_ip(store_for("egress"))
        await test_diagnostics(store_for("diag"))
        await test_panel_debug(store_for("debug"))
        await test_simulated_payment(store_for("simulate"))
        await test_freekassa_self_check(store_for("selfcheck"))
        await test_myid_payments_diag(store_for("myid"))
        await test_production_handlers(store_for("prodhandlers"))
        await test_cancel_order(store_for("cancelorder"))
        await test_promo_tariff(store_for("promo"))
        await test_subscription_link(store_for("sub_link"))
        await test_admin_access(store_for("admin"))
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
