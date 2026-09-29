"""
Тесты тарифной сетки и четырёх шагов выбора тарифа.

Проверяем ровно то, что видит клиент:
  1. каталог совпадает с утверждённой таблицей (тип × уровень: цена, трафик, срок,
     устройства, серверы, протоколы), старых тарифов и промо в боте нет;
  2. путь покупки: «Купить VPN» → тип подписки → уровень → (сервер) → протоколы →
     подтверждение → оплата;
  3. тарифы на один сервер выдаются в выбранной локации, на два — сразу в обеих,
     а клиент заводится в подключение каждого выбранного протокола;
  4. «по трафику» не истекает по времени (expiryTime = 0), лимит трафика — из тарифа;
  5. протоколы показываются только те, что есть на уровне и в панели; подключение
     ищется по переменной XUI_INBOUND_<ЛОКАЦИЯ>_<ПРОТОКОЛ> или по названию (remark).

Инфраструктура (фейковая панель 3x-ui, фейковый Telegram, вебхук) переиспользуется
из test_payments.py — чтобы не дублировать стенд.
"""
import asyncio
import json
import os
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web
from panel import ALL_INBOUNDS, PANEL, client_of, clients_named, load_bot, make_app, reset
import test_payments as tp
from test_payments import (TG, TG_TG_ID, check, make_message, new_bot, reset_all,
                           tg_calls, _FakeCallback, post_platega_callback)

# --- Таблица владельца: тип × уровень ---------------------------------------
# (цена, трафик ГБ, дней, устройств, серверов); traffic_gb = 0/ips = 0 — без ограничения.
TIME_GRID = {
    1: (70, 10, 15, 1, 1),
    2: (130, 50, 15, 3, 2),
    3: (250, 100, 30, 5, 2),
    4: (450, 200, 30, 0, 2),
}
TRAFFIC_GRID = {
    1: (70, 10, 0, 1, 1),
    2: (150, 50, 0, 3, 2),
    3: (300, 100, 0, 5, 2),
    4: (500, 200, 0, 0, 2),
}
LEVEL_NAMES = {1: "Новичок", 2: "Нетраннер", 3: "Кибер-самурай", 4: "Призрак"}
LEVEL_PROTOCOLS = {1: 1, 2: 2, 3: 3, 4: 6}      # сколько протоколов открыто на уровне
PROTOCOL_TITLES = ("VLESS Reality", "AmneziaWG", "WireGuard",
                   "Hysteria2", "Shadowsocks-2022", "TUIC")
OLD_KEYS = ("basic", "family", "school", "premium")


def buttons(target):
    """callback_data кнопок из последнего ответа FakeCallback/_FakeCallback."""
    markup = getattr(target, "reply_markup", None)
    if markup is None:
        msg = getattr(target, "message", target)
        sent = getattr(msg, "kwargs", None)
        if sent:
            markup = sent[-1].get("reply_markup")
    return [b.callback_data for row in (markup.inline_keyboard if markup else []) for b in row]


def kb_buttons(keyboard):
    """callback_data кнопок готовой клавиатуры бота."""
    return [b.callback_data for row in (keyboard.inline_keyboard if keyboard else []) for b in row]


def last_buttons():
    """callback_data кнопок последнего сообщения бота (sendMessage или editMessageText)."""
    for call in reversed(TG["calls"]):
        markup = call["params"].get("reply_markup")
        if markup is not None:
            return kb_buttons(markup)
    return []


def plain(text):
    """Текст без HTML-разметки — для проверки подписей с жирным/курсивом."""
    return text.replace("<b>", "").replace("</b>", "").replace("<i>", "").replace("</i>", "")


def days_left(client):
    if not client:
        return None
    return round((int(client["expiryTime"]) - int(time.time() * 1000)) / 86_400_000, 1)


# ---------------- 1. Каталог ----------------

async def test_catalog(store_file):
    print("\n▶ 1. Каталог тарифов совпадает с утверждённой таблицей")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)

    check("в каталоге ровно 8 платных тарифов — 4 уровня × 2 типа",
          bot.paid_tariff_keys() == [f"time_{n}" for n in range(1, 5)]
          + [f"traffic_{n}" for n in range(1, 5)],
          str(bot.paid_tariff_keys()))
    check("старых тарифов (Школьник/Базовый/Семейный/Премиум) больше нет",
          not any(key in bot.TARIFFS for key in OLD_KEYS),
          str([key for key in OLD_KEYS if key in bot.TARIFFS]))
    check("промо-доступа в боте больше нет: бесплатно — только тест 10 ГБ / 15 дней",
          "promo" not in bot.TARIFFS and bot.TARIFFS["trial"]["price"] == 0
          and bot.TARIFFS["trial"]["traffic_gb"] == 10 and bot.TARIFFS["trial"]["days"] == 15,
          str({key: bot.TARIFFS[key].get("traffic_gb") for key in bot.TARIFFS}))

    for kind, grid in (("time", TIME_GRID), ("traffic", TRAFFIC_GRID)):
        for level, (price, gb, days, ips, servers) in grid.items():
            tariff = bot.TARIFFS[f"{kind}_{level}"]
            check(f"{kind}_{level}: {LEVEL_NAMES[level]} — {price} ₽, {gb} ГБ, "
                  f"{days or 'без срока'} дн., {ips or 'безлимит'} устр., {servers} серв., "
                  f"{LEVEL_PROTOCOLS[level]} проток.",
                  tariff["price"] == price and tariff["traffic_gb"] == gb
                  and tariff["days"] == days and tariff["ips"] == ips
                  and tariff["tunnels"] == servers
                  and len(tariff["protocols"]) == LEVEL_PROTOCOLS[level],
                  f"price={tariff['price']} гб={tariff['traffic_gb']} дней={tariff['days']} "
                  f"устр={tariff['ips']} серверов={tariff['tunnels']} "
                  f"протоколов={len(tariff['protocols'])}")
            check(f"{kind}_{level}: название «{LEVEL_NAMES[level]}» + подпись типа",
                  tariff["name"].startswith(LEVEL_NAMES[level])
                  and bot.TARIFF_KINDS[kind]["short"] in tariff["name"],
                  tariff["name"])

    check("протоколы идут по порядку: у Новичка VLESS, у Призрака — все и с TUIC",
          bot.TARIFFS["time_1"]["protocols"] == ["vless"]
          and len(bot.TARIFFS["time_4"]["protocols"]) == 6
          and bot.TARIFFS["time_4"]["protocols"][-1] == "tuic"
          and bot.protocols_label(bot.TARIFFS["time_4"]) == "все протоколы + TUIC",
          str(bot.TARIFFS["time_4"]["protocols"]))

    check("цены Стокгольма и Варшавы одинаковы (одна панель, обе локации в тарифах)",
          bot.tariff_locations(bot.TARIFFS["time_1"])[0]["key"] == "stockholm"
          and [spot["key"] for spot in bot.tariff_locations(bot.TARIFFS["time_3"])]
          == ["stockholm", "warsaw"])
    check("у односерверного тарифа локация одна на выбор, у остальных — все",
          bot.TARIFFS["time_1"]["locations"] == "1 локация на выбор"
          and bot.TARIFFS["traffic_4"]["locations"] == "Все локации",
          f"{bot.TARIFFS['time_1']['locations']} / {bot.TARIFFS['traffic_4']['locations']}")
    check("у тарифа «по времени» есть срок, у «по трафику» — нет",
          bot.TARIFFS["time_1"]["days"] > 0 and bot.TARIFFS["traffic_1"]["days"] == 0)
    check("все платные тарифы посчитаны в звёздах (курс STARS_RUB_RATE)",
          all(bot.TARIFFS[key].get("stars") for key in bot.paid_tariff_keys()),
          str({key: bot.TARIFFS[key].get("stars") for key in bot.paid_tariff_keys()}))
    check("тарифы видны в /myid с ценами обеих сеток",
          all(name in bot.payments_diag_text() for name in ("Новичок", "Призрак", "по трафику")))


# ---------------- 2. Четыре шага выбора ----------------

async def test_four_steps(store_file):
    print("\n▶ 2. Четыре шага: тип → уровень → сервер → протоколы → подтверждение")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)

    # Шаг 1
    await bot.cb_tariffs(_FakeCallback(bot, "tariffs"))
    step1_buttons = kb_buttons(bot.tariffs_kb(TG_TG_ID))
    step1_labels = [b.text for row in bot.tariffs_kb(TG_TG_ID).inline_keyboard for b in row]
    check("шаг 1: выбор типа подписки (по трафику / по времени)",
          "tkind_time" in step1_buttons and "tkind_traffic" in step1_buttons
          and "buy_promo" not in step1_buttons,
          str(step1_buttons))
    check("шаг 1: подписи типов — как в дереве",
          any("По трафику (без ограничения по времени)" in text for text in step1_labels)
          and any("По времени (с лимитом трафика)" in text for text in step1_labels),
          str(step1_labels))
    check("шаг 1: в кнопках нет старых тарифов",
          not any(f"buy_{key}" in step1_buttons for key in OLD_KEYS), str(step1_buttons))

    # Шаг 2: «по времени»
    kind_cb = _FakeCallback(bot, "tkind_time")
    await bot.cb_tariff_kind(kind_cb)
    levels_text = kind_cb.message.sent[-1]
    check("шаг 2: заголовок «Шаг 2. Выберите тариф (уровень)»",
          "Шаг 2. Выберите тариф (уровень)" in levels_text, levels_text[:80].replace("\n", " "))
    check("шаг 2: показаны четыре уровня с ценами",
          all(name in levels_text for name in LEVEL_NAMES.values())
          and all(f"{price} ₽" in levels_text for price, *_ in TIME_GRID.values()),
          levels_text[:100].replace("\n", " "))
    check("шаг 2: у каждого уровня протоколы, устройства, трафик и срок",
          all(part in levels_text for part in ("протокол", "устройств", "10 ГБ", "30 дней")),
          levels_text[:160].replace("\n", " "))
    level_buttons = kb_buttons(bot.kind_levels_kb("time"))
    check("шаг 2: кнопки ведут на конкретный уровень",
          level_buttons[:4] == [f"tlvl_time_{n}" for n in range(1, 5)], str(level_buttons))
    check("шаг 2: есть возврат к типам", "tariffs" in level_buttons, str(level_buttons))

    # Шаг 2: «по трафику» — без срока
    kind2 = _FakeCallback(bot, "tkind_traffic")
    await bot.cb_tariff_kind(kind2)
    traffic_text = kind2.message.sent[-1]
    check("шаг 2: у типа «по трафику» сказано, что время не ограничено",
          "Без ограничения по времени" in traffic_text)
    check("шаг 2: у «по трафику» нет срока в днях",
          "дней" not in traffic_text.lower() and "дня" not in traffic_text.lower(),
          traffic_text[-120:].replace("\n", " "))

    # Шаг 3, тариф на 1 сервер: выбор сервера
    one = _FakeCallback(bot, "tlvl_time_1")
    await bot.cb_tariff_level(one)
    server_text = one.message.sent[-1]
    server_buttons = kb_buttons(bot.server_pick_kb("time", 1))
    check("шаг 3 (1 сервер): предложено выбрать сервер",
          "Шаг 3. Выберите сервер" in server_text, server_text[:90].replace("\n", " "))
    check("шаг 3 (1 сервер): кнопки — Варшава и Стокгольм",
          sorted(server_buttons[:2]) == ["tlocs_time_1_stockholm", "tlocs_time_1_warsaw"],
          str(server_buttons))
    check("шаг 3 (1 сервер): кнопок оплаты ещё нет",
          not any(b.startswith("buyat_") for b in server_buttons), str(server_buttons))
    check("шаг 3 (1 сервер): есть возврат к уровням", "tkind_time" in server_buttons)

    # Шаг 4: выбор протоколов для уровня 1 (доступен один — VLESS)
    stockholm = _FakeCallback(bot, "tlocs_time_1_stockholm")
    await bot.cb_tariff_location(stockholm)
    step4_text = plain(stockholm.message.sent[-1])
    step4_buttons = last_buttons()
    check("шаг 4: заголовок «Шаг 4. Выберите протокол(ы)»",
          "Шаг 4. Выберите протокол(ы)" in step4_text, step4_text[:80].replace("\n", " "))
    check("шаг 4: у Новичка только VLESS Reality (1 протокол на уровне)",
          "VLESS Reality" in step4_text and "AmneziaWG" not in step4_text,
          step4_text[:160].replace("\n", " "))
    check("шаг 4: протокол сразу отмечен, есть «Продолжить»",
          "✅ VLESS Reality" in step4_text and "tcont" in step4_buttons, str(step4_buttons))
    check("шаг 4: есть возврат к серверу", "tsrv_time_1" in step4_buttons, str(step4_buttons))

    # Подтверждение
    done = _FakeCallback(bot, "tcont")
    await bot.cb_tariff_protocol_done(done)
    confirm = done.message.sent[-1]
    check("подтверждение: тип, тариф, сервер, протоколы и цена",
          all(part in confirm for part in ("По времени", "Новичок", "Стокгольм",
                                           "VLESS Reality", "70 ₽")),
          confirm[:160].replace("\n", " "))
    confirm_kb = kb_buttons(bot.tariff_confirm_kb("time_1", "stockholm"))
    check("подтверждение: кнопка оплаты знает тариф и сервер",
          "buyat_time_1_stockholm" in confirm_kb, str(confirm_kb))

    # Шаг 3–4, тариф на 2 сервера: сервер не выбираем, протоколы уровня 3 (три)
    many = _FakeCallback(bot, "tlvl_traffic_3")
    await bot.cb_tariff_level(many)
    many_text = plain(many.message.sent[-1])
    many_buttons = last_buttons()
    check("шаг 3 (2+ сервера): выбора сервера нет, сразу протоколы",
          "Шаг 3" not in many_text and "Шаг 4. Выберите протокол(ы)" in many_text
          and not any(b.startswith("tlocs_") for b in many_buttons), str(many_buttons))
    check("шаг 4: у Кибер-самурая три протокола — VLESS, AmneziaWG, WireGuard",
          all(name in many_text for name in PROTOCOL_TITLES[:3])
          and "Hysteria2" not in many_text,
          many_text[-260:].replace("\n", " | "))
    check("шаг 4: у многотуннельного тарифа возврат к уровням",
          any(b.startswith("tkind_") for b in many_buttons), str(many_buttons))

    # Переключение протокола: убираем WireGuard и возвращаем
    off = _FakeCallback(bot, "tpro_wireguard")
    await bot.cb_tariff_protocol(off)
    off_text = plain(off.message.sent[-1])
    check("протокол можно выключить (◻️ вместо ✅)",
          "◻️ WireGuard" in off_text and "✅ VLESS Reality" in off_text,
          [line for line in off_text.split("\n") if "WireGuard" in line][:1])
    on = _FakeCallback(bot, "tpro_wireguard")
    await bot.cb_tariff_protocol(on)
    check("и включить обратно", "✅ WireGuard" in plain(on.message.sent[-1]))

    # Последний протокол убрать нельзя
    bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"] = ["vless"]
    last = _FakeCallback(bot, "tpro_vless")
    await bot.cb_tariff_protocol(last)
    check("нельзя убрать последний протокол — подсказка в ответе",
          any("хотя бы один протокол" in answer for answer in last.answers), str(last.answers))

    # Подтверждение многотуннельного тарифа: цена и протоколы на месте
    done_many = _FakeCallback(bot, "tcont")
    await bot.cb_tariff_protocol_done(done_many)
    many_confirm = done_many.message.sent[-1]
    check("подтверждение (2+ сервера): все серверы и выбранные протоколы",
          "все серверы" in many_confirm and "VLESS Reality" in many_confirm
          and "300 ₽" in many_confirm, many_confirm[:200].replace("\n", " "))

    # Защита от старых кнопок
    legacy = _FakeCallback(bot, "buyat_time_1")
    await bot.cb_buy_at(legacy)
    check("односерверный тариф без сервера не оплачивается — просим выбрать заново",
          any("Выбери сервер" in answer for answer in legacy.answers), str(legacy.answers))
    check("заказ при этом не создан", not bot.payment_store.orders)

    bad_kind = _FakeCallback(bot, "tkind_unknown")
    await bot.cb_tariff_kind(bad_kind)
    check("неизвестный тип подписки отклонён с подсказкой",
          any("нет" in answer.lower() for answer in bad_kind.answers), str(bad_kind.answers))


# ---------------- 3. Выдача по серверам и протоколам ----------------

async def test_delivery_by_location(store_file):
    print("\n▶ 3. Выдача: сервер по выбору, клиент — в подключение каждого протокола")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await _delivery_body(bot, email)
    finally:
        await runner.cleanup()


async def _delivery_body(bot, email):
    # Односерверный тариф в Варшаве, протокол по умолчанию (VLESS)
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_1", "warsaw")
    order = [o for o in bot.payment_store.orders.values()][-1]
    check("заказ запомнил выбранный сервер", order.get("location") == "warsaw", str(order.get("location")))
    check("заказ запомнил протоколы уровня", order.get("protocols") == ["vless"],
          str(order.get("protocols")))
    pay_msg = [m for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]["params"]
    check("в счёте указан выбранный сервер", "Варшава" in pay_msg.get("text", ""),
          pay_msg.get("text", "")[:120].replace("\n", " "))

    status, body = await post_platega_callback(order["id"], order["amount_rub"], transaction_id="700001")
    check("оплата подтверждена", status == 200 and body.strip() == "ok")
    check("подписка создана только в выбранной локации (Варшава)",
          client_of(email, 2) is not None and client_of(email, 1) is None,
          f"Стокгольм={client_of(email, 1)}, Варшава={client_of(email, 2)}")
    check("клиент заведён в подключение VLESS (Warsaw-Reality)", client_of(email, 2) is not None)
    check("срок из тарифа time_1 (15 дней)", 14 <= days_left(client_of(email, 2)) <= 15,
          f"{days_left(client_of(email, 2))} дн.")
    check("лимит устройств и трафика — из тарифа",
          client_of(email, 2)["limitIp"] == 1
          and round(client_of(email, 2)["totalGB"] / (1024 ** 3)) == 10,
          f"ip={client_of(email, 2)['limitIp']} гб={client_of(email, 2)['totalGB']}")
    key_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "/sub/" in m["params"].get("text", "")][-1]
    check("клиенту ушла одна ссылка-подписка", key_text.count("/sub/") == 1
          and "Варшава" in key_text, key_text[:110].replace("\n", " "))

    # Тариф на 2 сервера и 3 протокола: 6 подключений, одна ссылка-подписка
    reset_all()
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_3")
    order2 = [o for o in bot.payment_store.orders.values()][-1]
    check("у многотуннельного тарифа локация в заказе не указана",
          not order2.get("location"), str(order2.get("location")))
    check("в заказе три протокола уровня",
          order2.get("protocols") == ["vless", "amneziawg", "wireguard"],
          str(order2.get("protocols")))
    status, body = await post_platega_callback(order2["id"], order2["amount_rub"], transaction_id="700002")
    check("вторая оплата подтверждена", status == 200 and body.strip() == "ok")
    subs = clients_named(email)
    check("клиент создан в 6 подключениях: 2 сервера × 3 протокола", len(subs) == 6,
          f"записей: {len(subs)} — {[c['id'] for c in subs]}")
    check("клиенты в подключениях не пересекаются по id панели", len({c["id"] for c in subs}) == 6)
    check("у всех подключений один subId — одна ссылка-подписка",
          len({c["subId"] for c in subs}) == 1, str({c["subId"] for c in subs}))
    key_text2 = [m["params"]["text"] for m in tg_calls("sendMessage") if "/sub/" in m["params"].get("text", "")][-1]
    check("в сообщении одна ссылка-подписка на все протоколы и серверы",
          key_text2.count("/sub/") == 1, key_text2[:150].replace("\n", " "))
    check("в сообщении перечислены все три протокола",
          all(name in key_text2 for name in PROTOCOL_TITLES[:3]), key_text2[:200].replace("\n", " "))
    check("цена в заказе — 250 ₽ по таблице", order2["amount_rub"] == 250, str(order2["amount_rub"]))

    # /profile показывает обе локации
    profile = _FakeCallback(bot, "profile")
    await bot.cb_profile(profile)
    profile_text = profile.message.sent[-1]
    check("/profile перечисляет серверы и протоколы подписки",
          "Стокгольм" in profile_text and "Варшава" in profile_text
          and "VLESS Reality" in profile_text,
          [line for line in profile_text.split("\n") if "Сервер" in line or "Протокол" in line])


# ---------------- 4. Тариф «по трафику» ----------------

async def test_traffic_tariff(store_file):
    print("\n▶ 4. Тариф «по трафику»: без срока, лимит трафика из тарифа")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await _traffic_body(bot, email)
    finally:
        await runner.cleanup()


async def _traffic_body(bot, email):
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "traffic_2", "stockholm")
    order = [o for o in bot.payment_store.orders.values()][-1]
    pay_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]
    check("в счёте «по трафику» срок подписан как «без ограничения по времени»",
          "без ограничения по времени" in pay_text, pay_text[:140].replace("\n", " "))
    check("в счёте видны трафик и выбранный сервер",
          "50 ГБ" in pay_text and "Стокгольм" in pay_text)

    status, body = await post_platega_callback(order["id"], order["amount_rub"],
                                               transaction_id="700003")
    check("оплата подтверждена", status == 200 and body.strip() == "ok")
    client = client_of(email, 1)
    check("подписка создана в выбранной локации", client is not None)
    check("срок не ограничен (expiryTime = 0), пока не израсходован трафик",
          int(client["expiryTime"]) == 0, str(client["expiryTime"]))
    check("лимит трафика — 50 ГБ из тарифа",
          round(client["totalGB"] / (1024 ** 3)) == 50, str(client["totalGB"]))
    check("устройств — 3 из тарифа", client["limitIp"] == 3, str(client["limitIp"]))
    check("в комментарии клиента — тариф, «без ограничения по времени» и платёж",
          client["comment"].startswith("traffic_2 без ограничения по времени | platega-"),
          client["comment"])
    key_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "/sub/" in m["params"].get("text", "")][-1]
    check("клиенту сказано, что срок не ограничен",
          "без ограничения по времени" in key_text, key_text[:140].replace("\n", " "))
    check("в выручке учтена цена по таблице (150 ₽)",
          bot.payment_store.stats()["rub"] == 150, str(bot.payment_store.stats()["rub"]))


# ---------------- 5. Тестовая выдача и /test_pay ----------------

async def test_test_pay_locations(store_file):
    print("\n▶ 5. /test_pay: тариф, сервер и протоколы")
    reset_all()
    bot = new_bot({"mode": "platega", "allow_test_pay": "1"}, store_file)
    email = f"tg-paid-{TG_TG_ID}"

    await bot.cmd_test_pay(make_message(bot, text="/test_pay"))
    kb = bot.test_pay_kb()
    kb_buttons = [b.callback_data for row in kb.inline_keyboard for b in row]
    check("односерверные тарифы — кнопка на каждую локацию",
          "testpay_run_time_1_stockholm" in kb_buttons and "testpay_run_time_1_warsaw" in kb_buttons,
          str(kb_buttons))
    check("многосерверный тариф — одна кнопка без локации",
          "testpay_run_time_3" in kb_buttons
          and "testpay_run_time_3_stockholm" not in kb_buttons)
    check("в подписи кнопки видно сервер",
          any("Стокгольм" in b.text for row in kb.inline_keyboard for b in row)
          and any("Варшава" in b.text for row in kb.inline_keyboard for b in row))

    await bot.cmd_test_pay(make_message(bot, text="/test_pay traffic_1 warsaw"))
    check("тестовый ключ выдан в Варшаве",
          client_of(email, 2) is not None and client_of(email, 1) is None)
    check("тестовый ключ соответствует тарифу (10 ГБ, без срока)",
          round(client_of(email, 2)["totalGB"] / (1024 ** 3)) == 10
          and int(client_of(email, 2)["expiryTime"]) == 0)

    await bot.cmd_revoke(make_message(bot, text=f"/revoke {TG_TG_ID}"))
    check("/revoke убрал тестовую подписку из локации", client_of(email, 2) is None)

    await bot.cmd_test_pay(make_message(bot, text="/test_pay time_2"))
    check("многосерверный тариф по /test_pay: 2 сервера × 2 протокола = 4 записи",
          len(clients_named(email)) == 4, str(len(clients_named(email))))

    await bot.cmd_test_pay(make_message(bot, text="/test_pay traffic_1 atlantis"))
    check("неизвестный сервер отклонён с подсказкой",
          "Неизвестный сервер" in tp._last_api_text(), tp._last_api_text()[:80])


# ---------------- 6. Серверы, протоколы и подключения в диагностике ----------------

async def test_locations_diag(store_file):
    print("\n▶ 6. Серверы и протоколы в /myid и /panel_debug, привязка по переменным и названию")
    reset_all()
    bot = new_bot({"mode": "platega", "admin_tools": "1", "allow_test_pay": "1"}, store_file)

    await bot.cmd_myid(make_message(bot, text="/myid"))
    myid_text = tp._last_api_text()
    check("/myid перечисляет локации с их переменными",
          "Локации" in myid_text and "XUI_INBOUND_STOCKHOLM" in myid_text
          and "XUI_INBOUND_WARSAW" in myid_text, myid_text[:160].replace("\n", " "))
    check("/myid перечисляет переменные протоколов",
          "XUI_INBOUND_STOCKHOLM_AMNEZIAWG" in myid_text
          and "XUI_INBOUND_WARSAW_TUIC" in myid_text, myid_text[:400].replace("\n", " "))

    await bot.cmd_panel_debug(make_message(bot, text="/panel_debug"))
    debug_text = "".join(m["params"].get("text", "") for m in tg_calls("sendMessage"))
    check("/panel_debug показывает раздел локаций с источником привязки",
          "Локации (серверы)" in debug_text and "Stockholm" in debug_text
          and "Warsaw" in debug_text,
          [line for line in debug_text.split("\n") if "Локац" in line or "Stockholm" in line][:3])
    check("/panel_debug видит подключения протоколов",
          "Stockholm-Reality" in debug_text and "Warsaw-Hysteria2" in debug_text)
    check("/panel_debug показывает, какие протоколы доступны",
          "Протоколы" in debug_text and "Hysteria2" in debug_text,
          [line for line in debug_text.split("\n") if "Протокол" in line][:2])

    # Доступность протоколов: панель отвечает, у Призрака — все шесть
    bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})
    availability = await bot.protocol_availability(bot.TARIFFS["time_4"], None)
    check("для «Призрака» доступны все шесть протоколов на обеих локациях",
          len(availability) == 6
          and all(len(locations) == 2 for locations in availability.values()),
          str({key: len(value) for key, value in availability.items()}))

    # Протокол, которого нет в панели, в выборе не показывается
    removed = next(item for item in ALL_INBOUNDS if item["remark"] == "Stockholm-TUIC")
    ALL_INBOUNDS.remove(removed)
    bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})
    try:
        # Тариф на один сервер: выбор ограничен выбранной локацией (Стокгольм).
        one_server = dict(bot.TARIFFS["time_4"], tunnels=1)
        availability = await bot.protocol_availability(one_server, "stockholm")
        check("протокол без подключения на сервере в выборе не показывается",
              "tuic" not in availability and "hysteria2" in availability,
              str({key: locations for key, locations in availability.items()}))
    finally:
        ALL_INBOUNDS.append(removed)
        bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})

    # Явные переменные: ID подключений локаций
    probe = load_bot(tp.PANEL_PORT, env={"XUI_INBOUND_STOCKHOLM": "2",
                                         "XUI_INBOUND_WARSAW": "1"})
    async with probe.XUIClient() as client:
        inbounds = await client.get_inbounds()
    check("в панели есть подключения всех протоколов", len(inbounds) == 12, str(len(inbounds)))

    explicit = load_bot(tp.PANEL_PORT, env={"XUI_INBOUND_ID": "1",
                                            "XUI_INBOUND_STOCKHOLM": "2",
                                            "XUI_INBOUND_WARSAW": "1"})
    spots = {spot["key"]: spot for spot in explicit.configured_locations()}
    check("переменные XUI_INBOUND_<ЛОКАЦИЯ> перекрывают привязку по названию",
          spots["stockholm"]["inbound_id"] == 2 and spots["warsaw"]["inbound_id"] == 1,
          f"{spots['stockholm']['inbound_id']} / {spots['warsaw']['inbound_id']}")
    async with explicit.XUIClient() as client:
        inbound, auto, source = await explicit.resolve_location_inbound(client, spots["stockholm"])
    check("подключение локации берётся по переменной",
          int(inbound["id"]) == 2 and source == "XUI_INBOUND_STOCKHOLM=2", f"{source} (#{inbound['id']})")

    # Без переменных: поиск по названию подключения
    auto_bot = load_bot(tp.PANEL_PORT, env={"XUI_INBOUND_ID": "1",
                                            "XUI_INBOUND_STOCKHOLM": None,
                                            "XUI_INBOUND_WARSAW": None})
    auto_spots = {spot["key"]: spot for spot in auto_bot.configured_locations()}
    async with auto_bot.XUIClient() as client:
        w_inbound, _, w_source = await auto_bot.resolve_location_inbound(client, auto_spots["warsaw"])
        s_inbound, _, s_source = await auto_bot.resolve_location_inbound(client, auto_spots["stockholm"])
    check("Варшава находится по названию подключения в панели",
          "Warsaw-Reality" in str(w_inbound.get("remark")) and "название" in w_source, w_source)
    check("Стокгольм находится по названию подключения в панели",
          "Stockholm-Reality" in str(s_inbound.get("remark")) and "название" in s_source, s_source)
    check("поиск по названию не путает локации", w_inbound["id"] != s_inbound["id"])

    # Протокол можно привязать переменной XUI_INBOUND_<ЛОКАЦИЯ>_<ПРОТОКОЛ>
    proto_bot = load_bot(tp.PANEL_PORT, env={"XUI_INBOUND_WARSAW_HYSTERIA2": "10"})
    proto_spots = {spot["key"]: spot for spot in proto_bot.configured_locations()}
    async with proto_bot.XUIClient() as client:
        inbounds = await client.get_inbounds()
    matched = proto_bot.match_protocol_inbound(inbounds, proto_spots["warsaw"], "hysteria2")
    check("переменная XUI_INBOUND_<ЛОКАЦИЯ>_<ПРОТОКОЛ> задаёт подключение протокола",
          matched is not None and int(matched["id"]) == 10,
          str(matched.get("id") if matched else None))
    other = proto_bot.match_protocol_inbound(inbounds, proto_spots["stockholm"], "hysteria2")
    check("для другой локации подставляется своё подключение (по названию)",
          other is not None and "Stockholm-Hysteria2" in str(other.get("remark")),
          str(other.get("remark") if other else None))


async def main():
    runners = []
    for port, app in ((tp.PANEL_PORT, make_app()), (tp.TG_PORT, tp.make_tg_app()),
                      (tp.PLAT_PORT, tp.make_platega_app())):
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        runners.append(runner)

    store_dir = tempfile.mkdtemp(prefix="tariffs-store-")

    def store_for(name):
        return os.path.join(store_dir, f"{name}.json")

    try:
        await test_catalog(store_for("catalog"))
        await test_four_steps(store_for("steps"))
        await test_delivery_by_location(store_for("delivery"))
        await test_traffic_tariff(store_for("traffic"))
        await test_test_pay_locations(store_for("testpay"))
        await test_locations_diag(store_for("diag"))
    finally:
        for runner in runners:
            await runner.cleanup()

    print()
    if tp.FAILURES:
        print(f"❌ Провалено проверок: {len(tp.FAILURES)}")
        for name in tp.FAILURES:
            print("   •", name)
        return 1
    print("✅ Все проверки пройдены")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
