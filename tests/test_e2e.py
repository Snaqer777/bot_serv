"""
Сквозной прогон ВСЕХ функций бота — так, как их видит живой Telegram.

В отличие от специализированных наборов (test_payments, test_help, test_referral,
test_production), здесь один длинный путь: первый запуск и принятие соглашения →
инструкция → тарифы → оплата → ключ → профиль → рефералка → админ-функции →
тестовый ключ. Каждый шаг идёт через
настоящий слой aiogram: сообщения уходят на фейковый Bot API, ключи создаются в
фейковой панели 3x-ui, оплата проходит через фейковый API Platega и её callback.

Запуск: python tests/test_e2e.py
"""
import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aiohttp import web
from panel import PANEL, client_of, clients_named, load_bot, make_app, reset

from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.types import CallbackQuery, Message

import test_payments as fp   # фейковые Bot API / Platega / помощники

ADMIN = 4242          # владелец бота
FRIEND = 7777         # друг, пришедший по реферальной ссылке
STRANGER = 555        # обычный пользователь
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


# ---------------- чтение ответов бота (как их видит клиент) ----------------

def api(method, chat_id=None):
    items = [c["params"] for c in fp.tg_calls(method)]
    if chat_id is not None:
        items = [p for p in items if str(p.get("chat_id")) == str(chat_id)]
    return items


def last_sent(chat_id):
    items = api("sendMessage", chat_id)
    return items[-1] if items else {}


def last_edit(chat_id):
    items = api("editMessageText", chat_id)
    return items[-1] if items else {}


def last_text(chat_id, method="sendMessage"):
    params = last_sent(chat_id) if method == "sendMessage" else last_edit(chat_id)
    return params.get("text", "") or ""


def buttons(params):
    markup = params.get("reply_markup") or {}
    return [
        b.get("callback_data") or b.get("url") or ""
        for row in markup.get("inline_keyboard", [])
        for b in row
    ]


def texts_to(chat_id):
    return [p.get("text", "") for p in api("sendMessage", chat_id)] + \
           [p.get("text", "") for p in api("editMessageText", chat_id)]


def got_terms(chat_id):
    """Пришёл ли пользователю текст соглашения (отдельным сообщением)."""
    return any("ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" in text for text in texts_to(chat_id))


# ---------------- инфраструктура ----------------

def e2e_bot(store_file, ref_file, admins=None, secret=TOTP_SECRET, **overrides):
    """Бот на фейковых Telegram + 3x-ui + Platega со всеми функциями включёнными."""
    full_env = {
        "PAYMENTS_MODE": "platega",
        "PLATEGA_MERCHANT_ID": fp.PLAT_MERCHANT_ID,
        "PLATEGA_SECRET": fp.PLAT_SECRET,
        "PLATEGA_API_URL": f"http://127.0.0.1:{fp.PLAT_PORT}",
        "PLATEGA_CURRENCY": "RUB",
        "PUBLIC_BASE_URL": f"http://127.0.0.1:{fp.WEBHOOK_PORT}",
        "PORT": str(fp.WEBHOOK_PORT),
        "PAYMENT_STORE_FILE": store_file,
        "REFERRAL_STORE_FILE": ref_file,
        "BOT_USERNAME": "myvpnbot",
        "SERVICE_NAME": "TestVPN",
        "SUPPORT_USERNAME": "test_support",
        "ADMIN_TOOLS": "1",          # в e2e проверяем и служебные команды
        "TRIAL_PUBLIC": "0",         # бесплатный тест — только админу
        "PAYMENTS_ALLOW_TEST_PAY": "1",
        "REFERRAL_BONUS_DAYS": "7",
        "REFERRAL_INVITED_BONUS_DAYS": "3",
        "STARS_RUB_RATE": "1.6",
        "XUI_2FA_SECRET": secret,
        "TERMS_ACCEPT": "1",          # экран соглашения при первом запуске — как в бою
        "TRIAL_BUTTON": "0",          # кнопки теста скрыты: бот выглядит боевым
        "TERMS_STORE_FILE": os.path.join(os.path.dirname(store_file),
                                          "terms-" + os.path.basename(store_file)),
    }
    full_env.update(overrides)
    bot = load_bot(fp.PANEL_PORT, admins=str(admins or ADMIN), secret=secret, env=full_env)
    session = AiohttpSession()
    session.api = TelegramAPIServer.from_base(f"http://127.0.0.1:{fp.TG_PORT}")
    bot.bot.session = session
    return bot


def make_message(bot, uid, text="/start"):
    return Message.model_validate({
        "message_id": 1,
        "date": int(time.time()),
        "chat": {"id": uid, "type": "private"},
        "from": {"id": uid, "is_bot": False, "first_name": "Tester", "language_code": "ru"},
        "text": text,
    }, context={"bot": bot.bot})


def make_cb(bot, data, uid=ADMIN, message_id=10):
    """CallbackQuery как от живого клиента: с настоящим aiogram Message внутри."""
    return CallbackQuery.model_validate({
        "id": f"cb-{data}-{uid}",
        "from": {"id": uid, "is_bot": False, "first_name": "Tester", "language_code": "ru"},
        "chat_instance": "ci-1",
        "data": data,
        "message": {
            "message_id": message_id,
            "date": int(time.time()),
            "chat": {"id": uid, "type": "private"},
            "from": {"id": 999, "is_bot": True, "first_name": "Bot"},
            "text": "предыдущий экран",
        },
    }, context={"bot": bot.bot})


def click(bot, data, uid=ADMIN):
    """Нажатие кнопки: возвращает саму CallbackQuery, чтобы читать ответы."""
    return make_cb(bot, data, uid=uid)


def panel_client(tg_id):
    """Платная подписка пользователя в первой локации (обычно Стокгольм)."""
    return client_of(f"tg-paid-{tg_id}")


def panel_client_in(inbound_id, tg_id):
    """Подписка в конкретной локации (1 — Стокгольм, 2 — Варшава)."""
    return client_of(f"tg-paid-{tg_id}", inbound_id)


def panel_subscriptions(tg_id):
    """Все записи подписки пользователя — по одной на локацию."""
    return clients_named(f"tg-paid-{tg_id}")


def trial_client(tg_id):
    return client_of(f"tg-test-{tg_id}")


def days_left(client):
    if not client:
        return None
    return round((int(client["expiryTime"]) - int(time.time() * 1000)) / 86_400_000, 1)


async def pay_via_platega(bot, uid, tariff, *, confirmed=True, location=None):
    """
    Полный путь оплаты: ссылка на оплату → callback Platega → выдача ключа.

    location — выбранный сервер для тарифов с одним туннелем (как в кнопке
    «💳 Оплатить» после трёх шагов выбора).
    """
    cb = click(bot, "tariffs", uid=uid)
    await bot.cb_tariffs(cb)
    if location:
        cb = click(bot, f"buyat_{tariff}_{location}", uid=uid)
        await bot.cb_buy_at(cb)
    else:
        cb = click(bot, f"buy_{tariff}", uid=uid)
        await bot.cb_buy(cb)
    order = [o for o in bot.payment_store.orders.values() if o["tg_id"] == uid][-1]
    status, body = await fp.post_platega_callback(
        order["id"], order["amount_rub"],
        status="CONFIRMED" if confirmed else "PENDING",
        transaction_id=str(order.get("payment_id") or f"77{len(bot.payment_store.orders):04d}"))
    assert status == 200, (status, body)
    return order["id"]


# ---------------- сценарии ----------------

async def step_start(bot):
    print("\n▶ 1. Первый запуск: соглашение → «✅ Согласен» → приветствие и меню")
    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, ADMIN, "/start"))
    gate_kb = buttons(last_sent(ADMIN))
    check("первый /start присылает пользовательское соглашение",
          got_terms(ADMIN) and "1. Общие положения" in " ".join(texts_to(ADMIN)))
    check("текст соглашения умещается в лимит Telegram",
          max(len(t) for t in texts_to(ADMIN)) < 4096,
          f"{max(len(t) for t in texts_to(ADMIN))} символов")
    check("соглашение приходит свёрнутой цитатой (тап — «Показать полностью»)",
          any("<blockquote expandable>" in t for t in texts_to(ADMIN)))
    check("под соглашением кнопка «Согласен — продолжить»",
          "accept_terms" in gate_kb, str(gate_kb))
    check("меню до подтверждения не показывается", "tariffs" not in gate_kb)

    await bot.cb_accept_terms(click(bot, "accept_terms", uid=ADMIN))
    check("кнопка «Согласен» открывает приветствие и главное меню",
          "Добро пожаловать" in last_text(ADMIN, method="editMessageText")
          and {"tariffs", "profile", "help_menu"} <= set(buttons(last_edit(ADMIN))))
    check("принятие сохранено (файл отметок)", bot.terms_store.is_accepted(ADMIN))

    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, ADMIN, "/start"))
    text = last_text(ADMIN)
    menu = buttons(last_sent(ADMIN))

    check("второй /start — сразу приветствие, без соглашения",
          "ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" not in text and "Добро пожаловать" in text)
    check("приветствие показывает протокол и тарифы",
          "VLESS Reality" in text and "Тарифы" in text)
    check("кнопки тестового VPN нет даже у админа (TRIAL_BUTTON=0)",
          "get_test_key_btn" not in menu, str(menu))
    check("меню: тарифы, профиль, инструкция, приглашения, поддержка, соглашение",
          {"tariffs", "profile", "help_menu", "invite", "support", "terms"} <= set(menu), str(menu))
    check("в приветствии нет строки про кнопку теста",
          "Бесплатный тестовый доступ" not in text)

    check("обычному пользователю тестовый ключ не предлагают",
          "get_test_key_btn" not in buttons_from(bot.main_menu_kb(STRANGER)))
    check("и /test_vpn не заявлен в меню команд Telegram",
          "test_vpn" not in [c.command for c in bot.bot_commands()],
          str([c.command for c in bot.bot_commands()]))

    # Обычный пользователь проходит тот же путь
    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, STRANGER, "/start"))
    check("новичок тоже сначала видит соглашение",
          got_terms(STRANGER) and "accept_terms" in buttons(last_sent(STRANGER)))

    fp.TG["calls"].clear()
    await bot.cmd_help(make_message(bot, STRANGER, "/help"))
    check("до подтверждения инструкция не открывается — только соглашение",
          got_terms(STRANGER) and not any("Подключение VPN: пошагово" in t for t in texts_to(STRANGER)))

    await bot.cb_accept_terms(click(bot, "accept_terms", uid=STRANGER))
    check("после «Согласен» новичок видит меню", bot.terms_store.is_accepted(STRANGER))

    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, STRANGER, "/start"))
    check("/start обычного пользователя без обещаний бесплатного теста",
          "Бесплатный тестовый доступ" not in last_text(STRANGER)
          and "test_vpn" not in last_text(STRANGER)
          and "Добро пожаловать" in last_text(STRANGER))


def buttons_from(markup):
    return [b.callback_data or b.url or "" for row in markup.inline_keyboard for b in row]


async def step_help(bot):
    print("\n▶ 2. Инструкция: /help → устройство → шаги → проверка → «не работает»")
    fp.TG["calls"].clear()
    await bot.cmd_help(make_message(bot, STRANGER, "/help"))
    intro = last_sent(STRANGER)
    check("/help открывает меню устройств",
          "Подключение VPN: пошагово" in intro.get("text", ""))
    check("в меню есть все платформы и чек-листы",
          {"help_ios", "help_android", "help_windows", "help_macos", "help_tv",
           "help_check", "help_trouble"} <= set(buttons(intro)), str(buttons(intro)))

    fp.TG["calls"].clear()
    await bot.cb_help_platform(click(bot, "help_android", uid=STRANGER))
    android = last_text(STRANGER, method="editMessageText")
    check("инструкция Android: шаги, приложения и главное меню",
          "Android — пошагово" in android and "v2rayNG" in android
          and "Шаг 5. Проверь" in android
          and {"help_check", "help_trouble", "profile", "help_menu"} <= set(buttons(last_edit(STRANGER))))

    fp.TG["calls"].clear()
    await bot.cb_help_platform(click(bot, "help_check", uid=STRANGER))
    check("проверка подключения с 2ip.ru и whoer.net",
          "2ip.ru" in last_text(STRANGER, method="editMessageText")
          and "whoer.net" in last_text(STRANGER, method="editMessageText"))

    fp.TG["calls"].clear()
    await bot.cb_help_platform(click(bot, "help_trouble", uid=STRANGER))
    trouble = last_text(STRANGER, method="editMessageText")
    check("чек-лист «не работает»: 7 шагов и подсказка про /myid",
          "Не работает? Идём по порядку" in trouble
          and all(f"{n}️⃣" in trouble for n in range(1, 8))
          and "/myid" in trouble)


async def step_payment(bot):
    print("\n▶ 3. Тарифы → счёт → оплата → ключ → /profile")
    fp.TG["calls"].clear()
    await bot.cb_tariffs(click(bot, "tariffs", uid=ADMIN))
    tariffs = last_edit(ADMIN)
    tariffs_text = tariffs.get("text", "")
    check("на первом экране — два типа подписки (по времени и по трафику), тестового пункта нет",
          "По времени" in tariffs_text and "По трафику" in tariffs_text
          and "Тестовый период" not in tariffs_text)
    check("в кнопках тарифов нет buy_trial",
          "buy_trial" not in buttons(last_edit(ADMIN)), str(buttons(last_edit(ADMIN))))
    check("есть напоминание про условия сервиса", "/terms" in tariffs_text)
    check("сказано, что оплата на защищённой странице и ключ придёт сразу",
          "Platega" in tariffs_text and "после оплаты" in tariffs_text)

    # Шаг 2: уровни выбранного типа подписки
    fp.TG["calls"].clear()
    await bot.cb_tariff_kind(click(bot, "tkind_time", uid=ADMIN))
    levels_text = last_edit(ADMIN).get("text", "")
    check("шаг 2: показаны четыре уровня с ценами",
          all(level in levels_text for level in ("Новичок", "Нетраннер", "Кибер-самурай", "Призрак")),
          levels_text[:120].replace("\n", " "))
    check("в уровнях видны трафик, срок, устройства и туннели",
          "15 ГБ" in levels_text and "30 дней" in levels_text
          and "устройств" in levels_text and "туннел" in levels_text)
    check("кнопка возврата ведёт назад к типам", "tariffs" in buttons(last_edit(ADMIN)))

    # Шаг 3 для многотуннельного тарифа: сервер не выбирается, сразу подтверждение
    fp.TG["calls"].clear()
    cb = click(bot, "tlvl_time_3", uid=ADMIN)
    await bot.cb_tariff_level(cb)
    confirm_text = last_edit(ADMIN).get("text", "")
    check("шаг 3 (тариф на несколько туннелей): подтверждение без выбора сервера",
          "Кибер-самурай" in confirm_text and "все серверы" in confirm_text
          and not any(b.startswith("tlocs_") for b in buttons(last_edit(ADMIN))),
          confirm_text[:120].replace("\n", " "))
    check("в подтверждении есть цена, туннели и кнопка оплаты",
          "Цена" in confirm_text and "Туннелей" in confirm_text
          and f"buyat_time_3" in buttons(last_edit(ADMIN)))

    order_id = await pay_via_platega(bot, ADMIN, "time_3")
    client = panel_client(ADMIN)
    check("после оплаты клиент создан в панели", client is not None)
    check("срок подписки 30 дней", 29 <= (days_left(client) or 0) <= 30,
          f"{days_left(client)} дн.")
    check("тариф на несколько туннелей выдан во всех локациях сразу",
          len(panel_subscriptions(ADMIN)) == 2
          and panel_client_in(2, ADMIN) is not None,
          f"записей: {len(panel_subscriptions(ADMIN))}")
    check("клиенты в разных локациях — разные подключения панели",
          {c["limitIp"] for c in panel_subscriptions(ADMIN)} == {5})
    key_msg = last_text(ADMIN)
    check("доступ отправлен сообщением (ссылки-подписки по локациям)",
          "/sub/" in key_msg and "ссылки-подписки" in key_msg,
          key_msg[:80].replace("\n", " "))
    check("отдельный ключ vless в сообщении не показывается", "vless://" not in key_msg)
    check("в сообщении нет внутреннего адреса панели",
          "XUI_URL" not in key_msg, key_msg[:70].replace("\n", " "))
    check("в сообщении есть тариф, срок и дата",
          "Кибер-самурай" in key_msg and "Действует до" in key_msg)
    check("в сообщении перечислены оба сервера со своими ссылками",
          "Стокгольм" in key_msg and "Варшава" in key_msg
          and key_msg.count("/sub/") >= 2,
          key_msg[:160].replace("\n", " "))
    check("кнопки после оплаты: инструкция, ключ, главное меню",
          {"help_menu", "profile", "main_menu"} <= set(buttons(last_sent(ADMIN))))

    fp.TG["calls"].clear()
    await bot.cmd_profile(make_message(bot, ADMIN, "/profile"))
    profile = last_text(ADMIN)
    check("/profile показывает активную подписку", "Активна" in profile)
    check("/profile показывает срок и ссылку-подписку",
          "Действует до" in profile and "/sub/" in profile)
    check("/profile перечисляет серверы тарифа",
          "Серверы" in profile and "Stockholm" in profile and "Warsaw" in profile,
          [line for line in profile.split("\n") if "Сервер" in line])
    check("в профиле остались тарифы, а кнопки теста нет",
          {"tariffs", "main_menu"} <= set(buttons(last_sent(ADMIN)))
          and "get_test_key_btn" not in buttons(last_sent(ADMIN)),
          str(buttons(last_sent(ADMIN))))

    check("заказ записан как оплаченный",
          (bot.payment_store.orders[order_id]["status"] == "paid"))


async def step_trial_key(bot):
    print("\n▶ 4. Тестовый ключ: кнопок нет, команда работает")
    fp.TG["calls"].clear()
    await bot.cmd_test_vpn(make_message(bot, ADMIN, "/test_vpn"))
    trial = trial_client(ADMIN)
    check("тестовый клиент создан в панели (tg-test-*)", trial is not None)
    check("тестовый доступ отправлен (ссылка-подписка)", "/sub/" in last_text(ADMIN),
          last_text(ADMIN)[:80].replace("\n", " "))
    check("в тестовом доступе ключ vless не показывается", "vless://" not in last_text(ADMIN))
    check("в сообщении срок 24 часа и трафик 1 ГиБ",
          "24 часа" in last_text(ADMIN) and "1 ГиБ" in last_text(ADMIN))
    check("кнопки под тестовым ключом",
          {"help_menu", "profile", "main_menu"} <= set(buttons(last_sent(ADMIN))))

    await bot.cmd_test_vpn(make_message(bot, ADMIN, "/test_vpn"))
    check("повторный запрос отдаёт тот же доступ, а не создаёт новый",
          "действующий тестовый доступ" in last_text(ADMIN).lower(),
          last_text(ADMIN)[:80].replace("\n", " "))

    check("тестовый ключ не тронул платную подписку",
          panel_client(ADMIN) is not None and trial_client(ADMIN) is not None)

    await bot.cmd_reset_vpn(make_message(bot, ADMIN, "/reset_vpn"))
    check("сброс удалил только тестового клиента, платный на месте",
          trial_client(ADMIN) is None and panel_client(ADMIN) is not None)
    check("бот подтвердил удаление", "удалён" in last_text(ADMIN).lower())

    await bot.cmd_test_vpn(make_message(bot, STRANGER, "/test_vpn"))
    check("обычному пользователю тестовый ключ не выдаётся",
          "недоступен" in last_text(STRANGER) and trial_client(STRANGER) is None)


async def step_referral(bot):
    print("\n▶ 5. Рефералка: ссылка → друг → его оплата → бонусы обоим")
    fp.TG["calls"].clear()
    await bot.cmd_invite(make_message(bot, ADMIN, "/invite"))
    page = last_text(ADMIN)
    check("/invite даёт личную ссылку", f"start=ref_{ADMIN}" in page)
    check("на странице есть правила и статистика",
          "Как это работает" in page and "Пришло по ссылке" in page)

    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, FRIEND, f"/start ref_{ADMIN}"))
    check("друг по ссылке сначала видит соглашение",
          got_terms(FRIEND) and "Тебя пригласили" not in " ".join(texts_to(FRIEND)))
    check("приглашение уже засчитано: админу ушло уведомление о новом друге",
          any("пришёл друг" in t for t in texts_to(ADMIN)))
    check("а приветствие с бонусом ждёт кнопки «Согласен»",
          not any("Тебя пригласили" in t for t in texts_to(FRIEND)))

    await bot.cb_accept_terms(click(bot, "accept_terms", uid=FRIEND))
    check("после «Согласен» друг видит приветствие с бонусом +3 дня",
          any("Тебя пригласили" in t for t in texts_to(FRIEND)))

    expiry_before = int(panel_client(ADMIN)["expiryTime"])
    await pay_via_platega(bot, FRIEND, "time_4")
    friend_client = panel_client(FRIEND)
    check("друг получил ключ через callback Platega", friend_client is not None)
    check("другу добавили +3 дня к тарифу (33)",
          32 <= (days_left(friend_client) or 0) <= 33, f"{days_left(friend_client)} дн.")
    check("друг получил уведомление про бонус",
          any("Бонус за друзей" in t for t in texts_to(FRIEND)))

    expiry_after = int(panel_client(ADMIN)["expiryTime"])
    check("пригласившему начислено ровно 7 дней",
          expiry_after - expiry_before == 7 * 86400 * 1000,
          f"{(expiry_after - expiry_before) / 86_400_000} дн.")
    check("админу сообщили, что дни уже в подписке",
          any("уже в твоей подписке" in t for t in texts_to(ADMIN)))

    await bot.cmd_invite(make_message(bot, ADMIN, "/invite"))
    check("статистика обновилась: 1 пришёл, 1 оплатил",
          "Пришло по ссылке: <b>1</b>" in last_text(ADMIN)
          and "Из них оплатили: <b>1</b>" in last_text(ADMIN))


async def step_admin_tools(bot):
    print("\n▶ 6. Служебные команды (ADMIN_TOOLS=1)")
    fp.TG["calls"].clear()
    await bot.cmd_payments(make_message(bot, ADMIN, "/payments"))
    payments_text = last_text(ADMIN)
    check("/payments показывает режим и выручку",
          "Оплата подписок" in payments_text and "Выручка" in payments_text)
    check("/payments показывает кнопки проверок",
          {"testpay_menu", "platega_check"} <= set(buttons(last_sent(ADMIN))))

    fp.TG["calls"].clear()
    await bot.cmd_panel_debug(make_message(bot, ADMIN, "/panel_debug"))
    debug = last_text(ADMIN)
    check("/panel_debug отвечает диагностикой панели",
          "3x-ui" in debug or "панел" in debug.lower())
    check("/panel_debug показывает админов", "ADMIN_ID" in debug)

    fp.TG["calls"].clear()
    await bot.cmd_totp(make_message(bot, ADMIN, "/totp"))
    totp = last_text(ADMIN)
    code = "".join(ch for ch in totp if ch.isdigit())[:6]
    check("/totp выдаёт 6-значный код", len(code) == 6 and "осталось" in totp)

    fp.TG["calls"].clear()
    await bot.cmd_groups(make_message(bot, ADMIN, "/groups"))
    check("/groups отвечает по группам панели", "групп" in last_text(ADMIN).lower())

    fp.TG["calls"].clear()
    await bot.cmd_inbounds(make_message(bot, ADMIN, "/inbounds"))
    inbounds_text = last_text(ADMIN)
    check("/inbounds показывает подключения панели (обе локации)",
          "Stockholm" in inbounds_text and "Warsaw" in inbounds_text,
          inbounds_text[:120].replace("\n", " "))

    fp.TG["calls"].clear()
    revenue_before = bot.payment_store.stats()["rub"]
    expiry_before = int(panel_client(ADMIN)["expiryTime"])
    await bot.cmd_test_pay(make_message(bot, ADMIN, "/test_pay time_3"))
    check("при живой подписке /test_pay отказывается её портить",
          "уже есть платная подписка" in last_text(ADMIN)
          and int(panel_client(ADMIN)["expiryTime"]) == expiry_before)

    # Освобождаем аккаунт админа и проверяем саму выдачу
    await bot.cmd_revoke(make_message(bot, ADMIN, f"/revoke {ADMIN}"))
    check("/revoke по своему ID тоже работает", panel_client(ADMIN) is None)

    fp.TG["calls"].clear()
    await bot.cmd_test_pay(make_message(bot, ADMIN, "/test_pay time_3"))
    # /test_pay присылает два сообщения: сначала ключ, потом отчёт с кнопкой удаления
    check("/test_pay выдаёт доступ без оплаты (админ)",
          panel_client(ADMIN) is not None
          and any("/sub/" in t for t in texts_to(ADMIN)[-3:]),
          last_text(ADMIN)[:80].replace("\n", " "))
    check("выдан именно тариф time_3 (30 дней, 100 ГБ)",
          29 <= (days_left(panel_client(ADMIN)) or 0) <= 30, f"{days_left(panel_client(ADMIN))} дн.")
    check("тестовая выдача не попала в выручку",
          bot.payment_store.stats()["rub"] == revenue_before)
    check("в сообщении видно, что это проверка",
          "Проверка выдачи" in last_text(ADMIN) or "🧪" in last_text(ADMIN))
    check("есть кнопка удаления тестовой подписки",
          any(b.startswith("testpay_del_") for b in buttons(last_sent(ADMIN))))

    order_id = [o["id"] for o in bot.payment_store.orders.values() if o.get("simulated")][-1]
    fp.TG["calls"].clear()
    await bot.cb_testpay_del(click(bot, f"testpay_del_{order_id}", uid=ADMIN))
    check("кнопка удаления убрала тестовую подписку", panel_client(ADMIN) is None)
    check("заказ помечен отменённым",
          (await bot.payment_store.get(order_id))["status"] == "canceled")

    fp.TG["calls"].clear()
    await bot.cmd_platega_check(make_message(bot, ADMIN, "/platega_check"))
    self_check = last_text(ADMIN)
    check("/platega_check проверяет настройки без денег",
          "Проверка Platega" in self_check and "ключи приняты" in self_check)
    check("в отчёте есть Callback URL для кабинета Platega",
          fp.PLAT_WEBHOOK_PATH in self_check)

    fp.TG["calls"].clear()
    await bot.cmd_revoke(make_message(bot, ADMIN, f"/revoke {FRIEND}"))
    check("/revoke удаляет подписку из панели", panel_client(FRIEND) is None)

    fp.TG["calls"].clear()
    await bot.cmd_myid(make_message(bot, ADMIN, "/myid"))
    check("/myid показывает ID и статус админа",
          str(ADMIN) in last_text(ADMIN) and "администратор" in last_text(ADMIN).lower())

    fp.TG["calls"].clear()
    await bot.cb_support(click(bot, "support", uid=STRANGER))
    support_text = last_text(STRANGER, method="editMessageText")
    check("поддержка отвечает ссылкой из переменной",
          "@test_support" in support_text, support_text[:90].replace("\n", " "))

    await bot.cmd_terms(make_message(bot, STRANGER, "/terms"))
    check("/terms отдаёт соглашение", "ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" in last_text(STRANGER)
          and "10. Контактная информация" in last_text(STRANGER)
          and "<blockquote expandable>" in last_text(STRANGER))

    fp.TG["calls"].clear()
    await bot.cmd_privacy(make_message(bot, STRANGER, "/privacy"))
    privacy_text = last_text(STRANGER)
    check("/privacy отдаёт политику конфиденциальности",
          "ПОЛИТИКА КОНФИДЕНЦИАЛЬНОСТИ" in privacy_text
          and "7. Изменения в Политике" in privacy_text
          and "<blockquote expandable>" in privacy_text
          and len(privacy_text) < 4096)
    fp.TG["calls"].clear()
    await bot.cmd_terms(make_message(bot, STRANGER, "/terms"))
    check("в соглашении есть ссылка на политику конфиденциальности",
          "/privacy" in last_text(STRANGER))


async def step_production_bot(store_file, ref_file):
    print("\n▶ 7. Боевой вид: без ADMIN_TOOLS служебных команд нет")
    bot = e2e_bot(store_file, ref_file, ADMIN_TOOLS=None, TRIAL_PUBLIC=None,
                  PAYMENTS_ALLOW_TEST_PAY=None, TRIAL_BUTTON="1")
    handlers = {getattr(h.callback, "__name__", "") for h in bot.dp.message.handlers}
    check("служебные команды не зарегистрированы",
          not ({"cmd_payments", "cmd_panel_debug", "cmd_totp", "cmd_groups",
                "cmd_inbounds", "cmd_reset_vpn", "cmd_revoke", "cmd_test_pay",
                "cmd_platega_check"} & handlers),
          str(sorted(handlers)))
    check("/myid остаётся всегда", "cmd_myid" in handlers)

    fp.TG["calls"].clear()
    await bot.cmd_start(make_message(bot, ADMIN, "/start"))
    check("боевой бот тоже просит подтвердить соглашение при первом запуске",
          got_terms(ADMIN))
    await bot.cb_accept_terms(click(bot, "accept_terms", uid=ADMIN))

    fp.TG["calls"].clear()
    await bot.cmd_myid(make_message(bot, ADMIN, "/myid"))
    check("админу /myid подсказывает, как вернуть команды", "ADMIN_TOOLS=1" in last_text(ADMIN))

    await bot.cb_accept_terms(click(bot, "accept_terms", uid=STRANGER))
    check("с TRIAL_BUTTON=1 кнопка теста возвращается админу (и только ему)",
          "get_test_key_btn" in buttons_from(bot.main_menu_kb(ADMIN))
          and "get_test_key_btn" not in buttons_from(bot.main_menu_kb(STRANGER)))
    await bot.cmd_profile(make_message(bot, STRANGER, "/profile"))
    check("в профиле пользователя нет кнопки тестового ключа",
          "get_test_key_btn" not in buttons(last_sent(STRANGER)),
          str(buttons(last_sent(STRANGER))))

    await bot.cb_get_test_key(click(bot, "get_test_key_btn", uid=STRANGER))
    check("устаревшая кнопка теста не выдаёт ключ",
          trial_client(STRANGER) is None)


async def main():
    runners = []
    fp.reset_all()
    reset()
    for port, app in ((fp.PANEL_PORT, make_app()), (fp.TG_PORT, fp.make_tg_app()),
                      (fp.PLAT_PORT, fp.make_platega_app())):
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        runners.append(runner)

    store_dir = tempfile.mkdtemp(prefix="e2e-")
    bot = e2e_bot(os.path.join(store_dir, "orders.json"), os.path.join(store_dir, "referrals.json"))
    webhook_runner = await bot.run_webhook_server()

    try:
        await step_start(bot)
        await step_help(bot)
        await step_payment(bot)
        await step_trial_key(bot)
        await step_referral(bot)
        await step_admin_tools(bot)
        await step_production_bot(os.path.join(store_dir, "orders2.json"),
                                  os.path.join(store_dir, "referrals2.json"))
    finally:
        if webhook_runner is not None:
            await webhook_runner.cleanup()
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
