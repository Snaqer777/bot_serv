"""
Тесты тарифной сетки DarkTier: 4 уровня, туннели (сервер × вариант протокола) и 4 шага покупки.

Проверяем ровно то, что видит клиент:
  1. каталог: 8 платных тарифов (4 уровня × 2 типа), цены/трафик/сроки/устройства,
     серверы по уровням (1 / 2 / 2 / 2) и туннели (1–3 / 2–6 / 6–14 / 18);
  2. протоколы: пять базовых, у VLESS и Shadowsocks-2022 по три варианта (Reality/XHTTP/gRPC
     и три шифра), у AmneziaWG / WireGuard / Hysteria2 — по одному;
  3. путь покупки: тип → уровень → сервер → протоколы → подтверждение → оплата;
     уровень 1 выбирает сервер и один протокол, уровень 3 — три протокола из пяти,
     уровень 4 — все протоколы без выбора;
  4. выдача: клиент создаётся в подключении каждого варианта каждого выбранного протокола
     на каждом сервере (18 записей у «Призрака»), subId у всех один — одна ссылка-подписка;
  5. «Мои подписки» показывают протоколы, варианты и серверы.

Инфраструктура (фейковая панель 3x-ui с 18 подключениями, фейковый Telegram, вебхук)
переиспользуется из test_payments.py.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web
from panel import ALL_INBOUNDS, client_of, clients_named, load_bot, make_app, reset
import test_payments as tp
from test_payments import (TG, TG_TG_ID, check, make_message, new_bot, reset_all,
                           tg_calls, _FakeCallback, post_platega_callback)

# --- Таблица владельца: тип × уровень ---------------------------------------
# (цена, трафик ГБ, дней, устройств, серверов, туннели (мин, макс))
TIME_GRID = {
    1: (70, 10, 15, 1, 1, (1, 3)),
    2: (130, 50, 15, 3, 2, (2, 6)),
    3: (250, 100, 30, 5, 2, (6, 14)),
    4: (450, 200, 30, 0, 2, (18, 18)),
}
TRAFFIC_GRID = {
    1: (70, 10, 0, 1, 1, (1, 3)),
    2: (150, 50, 0, 3, 2, (2, 6)),
    3: (300, 100, 0, 5, 2, (6, 14)),
    4: (500, 200, 0, 0, 2, (18, 18)),
}
LEVEL_NAMES = {1: "Новичок", 2: "Нетраннер", 3: "Кибер-самурай", 4: "Призрак"}
LEVEL_CHOICES = {1: 1, 2: 1, 3: 3, 4: 0}          # сколько протоколов выбирает клиент
PROTOCOL_BASE = ("VLESS", "Shadowsocks-2022", "AmneziaWG", "WireGuard", "Hysteria2")
VLESS_VARIANTS = ("VLESS Reality", "VLESS Reality + XHTTP", "VLESS Reality + gRPC")
SS_VARIANTS = ("Shadowsocks-2022 · AES-128-GCM", "Shadowsocks-2022 · AES-256-GCM",
               "Shadowsocks-2022 · ChaCha20-Poly1305")
OLD_KEYS = ("basic", "family", "school", "premium")


def kb_buttons(keyboard):
    """callback_data кнопок готовой клавиатуры бота."""
    return [b.callback_data for row in (keyboard.inline_keyboard if keyboard else []) for b in row]


def last_edit() -> dict:
    """Последний экран бота (editMessageText или sendMessage) из журнала Telegram."""
    for call in reversed(TG["calls"]):
        if call["method"] in ("editMessageText", "sendMessage") and call["params"].get("text"):
            return call["params"]
    return {}


def last_buttons() -> list:
    for call in reversed(TG["calls"]):
        markup = call["params"].get("reply_markup")
        if markup is not None:
            return kb_buttons(markup)
    return []


def plain(text: str) -> str:
    """Текст без HTML-разметки — для проверки подписей с жирным/курсивом."""
    return (text.replace("<b>", "").replace("</b>", "")
            .replace("<i>", "").replace("</i>", ""))


def days_left(client):
    if not client:
        return None
    return round((int(client["expiryTime"]) - int(time.time() * 1000)) / 86_400_000, 1)


# ---------------- 1. Каталог и туннели ----------------

async def test_catalog(store_file):
    print("\n▶ 1. Каталог: уровни, цены, серверы и туннели")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)

    check("в каталоге ровно 8 платных тарифов — 4 уровня × 2 типа",
          bot.paid_tariff_keys() == [f"time_{n}" for n in range(1, 5)]
          + [f"traffic_{n}" for n in range(1, 5)],
          str(bot.paid_tariff_keys()))
    check("старых тарифов (Школьник/Базовый/Семейный/Премиум) больше нет",
          not any(key in bot.TARIFFS for key in OLD_KEYS),
          str([key for key in OLD_KEYS if key in bot.TARIFFS]))
    check("промо-доступа нет: бесплатно только тест 10 ГБ / 15 дней",
          "promo" not in bot.TARIFFS and bot.TARIFFS["trial"]["price"] == 0
          and bot.TARIFFS["trial"]["traffic_gb"] == 10 and bot.TARIFFS["trial"]["days"] == 15)

    check("пять базовых протоколов, у VLESS и Shadowsocks — по три варианта",
          list(bot.PROTOCOL_ORDER) == ["vless", "shadowsocks", "amneziawg", "wireguard", "hysteria2"]
          and bot.protocol_variant_count("vless") == 3
          and bot.protocol_variant_count("shadowsocks") == 3
          and all(bot.protocol_variant_count(key) == 1
                  for key in ("amneziawg", "wireguard", "hysteria2")),
          str({key: bot.protocol_variant_count(key) for key in bot.PROTOCOL_ORDER}))
    check("названия вариантов VLESS — Reality, XHTTP, gRPC",
          tuple(bot.protocol_tunnel_titles("vless")) == VLESS_VARIANTS,
          str(bot.protocol_tunnel_titles("vless")))
    check("названия вариантов Shadowsocks-2022 — три шифра",
          tuple(bot.protocol_tunnel_titles("shadowsocks")) == SS_VARIANTS,
          str(bot.protocol_tunnel_titles("shadowsocks")))

    for kind, grid in (("time", TIME_GRID), ("traffic", TRAFFIC_GRID)):
        for level, (price, gb, days, ips, servers, tunnels) in grid.items():
            tariff = bot.TARIFFS[f"{kind}_{level}"]
            check(f"{kind}_{level}: {LEVEL_NAMES[level]} — {price} ₽, {gb} ГБ, "
                  f"{days or 'без срока'} дн., {ips or 'безлимит'} устр., {servers} серв., "
                  f"туннели {tunnels[0]}–{tunnels[1]}",
                  tariff["price"] == price and tariff["traffic_gb"] == gb
                  and tariff["days"] == days and tariff["ips"] == ips
                  and tariff["servers"] == servers
                  and (tariff["tunnels_min"], tariff["tunnels_max"]) == tunnels,
                  f"price={tariff['price']} гб={tariff['traffic_gb']} дней={tariff['days']} "
                  f"устр={tariff['ips']} серверов={tariff['servers']} "
                  f"туннелей={tariff['tunnels_min']}–{tariff['tunnels_max']}")
            check(f"{kind}_{level}: название «{LEVEL_NAMES[level]}» + подпись типа",
                  tariff["name"].startswith(LEVEL_NAMES[level])
                  and bot.TARIFF_KINDS[kind]["short"] in tariff["name"],
                  tariff["name"])
            check(f"{kind}_{level}: на уровне {LEVEL_NAMES[level]} "
                  f"{'все протоколы' if not LEVEL_CHOICES[level] else str(LEVEL_CHOICES[level]) + ' на выбор'}",
                  bot.tariff_protocol_choices(tariff) == LEVEL_CHOICES[level])
            check(f"{kind}_{level}: подпись туннелей «{tariff['tunnels_min']}–{tariff['tunnels_max']}»",
                  bot.tunnels_range(level) == tunnels
                  and (str(tunnels[1]) in bot.tariff_tunnels_label(tariff)),
                  bot.tariff_tunnels_label(tariff))

    check("цены Стокгольма и Варшавы одинаковы (одна панель, обе локации в тарифах)",
          bot.tariff_locations(bot.TARIFFS["time_1"])[0]["key"] == "stockholm"
          and [spot["key"] for spot in bot.tariff_locations(bot.TARIFFS["time_3"])]
          == ["stockholm", "warsaw"])
    check("у тарифа «по времени» есть срок, у «по трафику» — нет",
          bot.TARIFFS["time_1"]["days"] > 0 and bot.TARIFFS["traffic_1"]["days"] == 0)
    check("все платные тарифы посчитаны в звёздах (курс STARS_RUB_RATE)",
          all(bot.TARIFFS[key].get("stars") for key in bot.paid_tariff_keys()))
    check("тарифы и протоколы видны в /myid",
          all(name in bot.payments_diag_text() for name in ("Новичок", "Призрак", "туннел"))
          and "VLESS" in bot.payments_diag_text())
    check("/myid подсказывает переменные подключений вариантов",
          "VLESS_XHTTP" in bot.payments_diag_text()
          and "SHADOWSOCKS_AES256" in bot.payments_diag_text(),
          [line for line in bot.payments_diag_text().split("\n") if "переменные" in line][:1])


# ---------------- 2. Четыре шага покупки ----------------

async def test_four_steps(store_file):
    print("\n▶ 2. Четыре шага: тип → уровень → сервер → протоколы → подтверждение")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)

    await bot.cb_tariffs(_FakeCallback(bot, "tariffs"))
    step1_buttons = kb_buttons(bot.tariffs_kb(TG_TG_ID))
    step1_labels = [b.text for row in bot.tariffs_kb(TG_TG_ID).inline_keyboard for b in row]
    check("шаг 1: выбор типа подписки",
          "tkind_time" in step1_buttons and "tkind_traffic" in step1_buttons
          and "buy_promo" not in step1_buttons, str(step1_buttons))
    check("шаг 1: подписи типов — как в дереве",
          any("По трафику (без ограничения по времени)" in text for text in step1_labels)
          and any("По времени (с лимитом трафика)" in text for text in step1_labels))

    # Шаг 2: уровни
    TG["calls"].clear()
    await bot.cb_tariff_kind(_FakeCallback(bot, "tkind_time"))
    levels_text = plain(last_edit().get("text", ""))
    check("шаг 2: заголовок «Шаг 2. Выберите тариф (уровень)»",
          "Шаг 2. Выберите тариф (уровень)" in levels_text)
    check("шаг 2: четыре уровня с ценами",
          all(name in levels_text for name in LEVEL_NAMES.values())
          and all(f"{price} ₽" in levels_text for price, *_ in TIME_GRID.values()))
    check("шаг 2: у уровней видны серверы, протоколы, трафик и число туннелей",
          all(part in levels_text for part in ("1 сервер на выбор", "2 сервера (оба)",
                                               "1 протокол на выбор", "все протоколы",
                                               "10 ГБ", "200 ГБ", "18 туннелей", "до 14 туннелей")),
          levels_text[:300].replace("\n", " | "))
    check("шаг 2: кнопки ведут на конкретный уровень",
          kb_buttons(bot.kind_levels_kb("time"))[:4] == [f"tlvl_time_{n}" for n in range(1, 5)])

    # Шаг 3, уровень 1: выбор сервера
    TG["calls"].clear()
    await bot.cb_tariff_level(_FakeCallback(bot, "tlvl_time_1"))
    server_text = plain(last_edit().get("text", ""))
    check("шаг 3 (Новичок): предложено выбрать сервер",
          "Шаг 3. Выберите сервер" in server_text and "один сервер" in server_text)
    check("шаг 3 (Новичок): кнопки — Варшава и Стокгольм",
          sorted(kb_buttons(bot.server_pick_kb("time", 1))[:2])
          == ["tlocs_time_1_stockholm", "tlocs_time_1_warsaw"])

    # Шаг 4, уровень 1: один протокол из пяти, по умолчанию VLESS (рекомендуемый)
    TG["calls"].clear()
    await bot.cb_tariff_location(_FakeCallback(bot, "tlocs_time_1_warsaw"))
    step4_text = plain(last_edit().get("text", ""))
    check("шаг 4: заголовок и все пять протоколов с подсказками",
          "Шаг 4. Выберите протокол(ы)" in step4_text
          and all(name in step4_text for name in PROTOCOL_BASE)
          and "Максимальная скрытность" in step4_text
          and "Скорость на нестабильных сетях" in step4_text,
          step4_text[:200].replace("\n", " | "))
    check("шаг 4: у протоколов видны варианты и число туннелей",
          all(name in step4_text for name in VLESS_VARIANTS + SS_VARIANTS)
          and "3 туннеля: VLESS Reality" in step4_text,
          step4_text[200:500].replace("\n", " | "))
    check("шаг 4: VLESS — рекомендуемый и уже отмечен (⭐ ✅)",
          "✅ VLESS ⭐" in step4_text)
    check("шаг 4: подписано, что выбирается один протокол",
          "Выбери один протокол" in step4_text and "на выбранном сервере" in step4_text)

    # Протоколы уровня 1 — переключатель-радио
    TG["calls"].clear()
    switch = _FakeCallback(bot, "tpro_shadowsocks")
    await bot.cb_tariff_protocol(switch)
    check("выбор одного протокола заменяет предыдущий (радио-кнопка)",
          bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"] == ["shadowsocks"]
          and "✅ Shadowsocks-2022" in plain(last_edit().get("text", "")))
    TG["calls"].clear()
    await bot.cb_tariff_protocol(_FakeCallback(bot, "tpro_vless"))
    check("и возвращается обратно", bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"] == ["vless"])

    # Подтверждение: 3 туннеля VLESS на одном сервере
    TG["calls"].clear()
    await bot.cb_tariff_protocol_done(_FakeCallback(bot, "tcont"))
    confirm = plain(last_edit().get("text", ""))
    check("подтверждение: тип, тариф, сервер, протоколы, туннели и цена",
          all(part in confirm for part in ("По времени", "Новичок", "Варшава", "VLESS",
                                           "70 ₽", "Вы получаете"))
          and "3 туннеля на 1 сервере" in confirm,
          [line for line in confirm.split("\n") if "получаете" in line])
    check("подтверждение: перечислены все три варианта VLESS",
          all(name in confirm for name in VLESS_VARIANTS),
          [line for line in confirm.split("\n") if "получаете" in line])
    check("кнопка оплаты знает тариф и сервер",
          "buyat_time_1_warsaw" in kb_buttons(bot.tariff_confirm_kb("time_1", "warsaw")))
    check("с подтверждения можно вернуться к протоколам",
          "tback_time_1" in kb_buttons(bot.tariff_confirm_kb("time_1", "warsaw")))
    TG["calls"].clear()
    await bot.cb_tariff_back_to_protocols(_FakeCallback(bot, "tback_time_1"))
    check("кнопка «Назад» возвращает на шаг 4",
          "Шаг 4. Выберите протокол(ы)" in plain(last_edit().get("text", "")))

    # Шаг 3, уровень 3: оба сервера входят сразу
    TG["calls"].clear()
    await bot.cb_tariff_level(_FakeCallback(bot, "tlvl_time_3"))
    step3_text = plain(last_edit().get("text", ""))
    check("шаг 3 (Кибер-самурай): оба сервера входят сразу, выбора нет",
          "Шаг 3. Серверы" in step3_text and "оба сервера" in step3_text
          and "Стокгольм" in step3_text and "Варшава" in step3_text
          and not any(b.startswith("tlocs_") for b in last_buttons()),
          step3_text[:150].replace("\n", " "))
    TG["calls"].clear()
    await bot.cb_tariff_servers_all(_FakeCallback(bot, "tsall_time_3"))
    many_text = plain(last_edit().get("text", ""))
    many_buttons = last_buttons()
    check("шаг 4 (Кибер-самурай): пять протоколов, по умолчанию отмечены три",
          "Шаг 4. Выберите протокол(ы)" in many_text and many_text.count("✅") == 3
          and "Выбери 3 протокола" in many_text,
          many_text[:200].replace("\n", " | "))
    check("шаг 4: у каждого протокола общее число туннелей с учётом двух серверов",
          "6 туннелей: VLESS Reality" in many_text.replace("\n", " ")
          and "(на 2 серверах)" in many_text,
          many_text[200:520].replace("\n", " | "))
    check("шаг 4: можно выбрать другой протокол, но не больше трёх",
          "tpro_shadowsocks" in many_buttons and "tpro_wireguard" in many_buttons)

    # Пробуем выбрать четвёртый — бот просит снять галочку
    extra = _FakeCallback(bot, "tpro_wireguard")
    await bot.cb_tariff_protocol(extra)
    check("четвёртый протокол не выбирается: подсказка снять галочку",
          any("сними галочку" in answer for answer in extra.answers), str(extra.answers))
    # Снимаем один и добавляем другой
    TG["calls"].clear()
    await bot.cb_tariff_protocol(_FakeCallback(bot, "tpro_amneziawg"))
    TG["calls"].clear()
    await bot.cb_tariff_protocol(_FakeCallback(bot, "tpro_wireguard"))
    chosen = bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"]
    check("можно заменить протокол в наборе (три из пяти)",
          len(chosen) == 3 and "wireguard" in chosen and "amneziawg" not in chosen, str(chosen))
    # Убираем всё до одного — последний убрать нельзя
    for key in ("wireguard", "shadowsocks"):
        TG["calls"].clear()
        await bot.cb_tariff_protocol(_FakeCallback(bot, f"tpro_{key}"))
    last = _FakeCallback(bot, "tpro_vless")
    await bot.cb_tariff_protocol(last)
    check("последний протокол убрать нельзя",
          any("хотя бы один протокол" in answer for answer in last.answers), str(last.answers))

    # «Продолжить» с одним протоколом вместо трёх — предупреждение, заказа нет
    TG["calls"].clear()
    early = _FakeCallback(bot, "tcont")
    await bot.cb_tariff_protocol_done(early)
    check("с одним протоколом вместо трёх оплата не начинается",
          any("Нужно выбрать 3" in answer for answer in early.answers), str(early.answers))
    check("заказ при этом не создан", not bot.payment_store.orders)

    # Уровень 4: все протоколы, выбор не нужен
    TG["calls"].clear()
    await bot.cb_tariff_level(_FakeCallback(bot, "tlvl_traffic_4"))
    TG["calls"].clear()
    await bot.cb_tariff_servers_all(_FakeCallback(bot, "tsall_traffic_4"))
    all_text = plain(last_edit().get("text", ""))
    check("шаг 4 (Призрак): все протоколы отмечены, выбор не нужен",
          "входят все протоколы" in all_text and all_text.count("✅") == 5,
          all_text[:200].replace("\n", " | "))
    TG["calls"].clear()
    skip = _FakeCallback(bot, "tpro_hysteria2")
    await bot.cb_tariff_protocol(skip)
    check("у «Призрака» протоколы не переключаются — подсказка",
          any("все протоколы" in answer for answer in skip.answers), str(skip.answers))
    TG["calls"].clear()
    await bot.cb_tariff_protocol_done(_FakeCallback(bot, "tcont"))
    ghost = plain(last_edit().get("text", ""))
    check("подтверждение «Призрака»: 18 туннелей на обоих серверах",
          "18 туннелей на 2 серверах" in ghost
          and "9 туннелей на каждом сервере" in ghost
          and all(name in ghost for name in VLESS_VARIANTS + SS_VARIANTS),
          [line for line in ghost.split("\n") if "получаете" in line])

    # Защита от старых кнопок
    legacy = _FakeCallback(bot, "buyat_time_1")
    await bot.cb_buy_at(legacy)
    check("односерверный тариф без сервера не оплачивается — просим выбрать заново",
          any("Выбери сервер" in answer for answer in legacy.answers), str(legacy.answers))
    bad_kind = _FakeCallback(bot, "tkind_unknown")
    await bot.cb_tariff_kind(bad_kind)
    check("неизвестный тип подписки отклонён с подсказкой",
          any("нет" in answer.lower() for answer in bad_kind.answers), str(bad_kind.answers))


# ---------------- 3. Выдача туннелей ----------------

async def test_delivery_tunnels(store_file):
    print("\n▶ 3. Выдача: туннель = сервер × вариант протокола")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await _delivery_level1(bot, email)
        reset_all()
        await _delivery_level4(bot, email)
    finally:
        await runner.cleanup()


async def _delivery_level1(bot, email):
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_1", "warsaw", ["vless"])
    order = [o for o in bot.payment_store.orders.values()][-1]
    check("заказ запомнил сервер и протокол", order.get("location") == "warsaw"
          and order.get("protocols") == ["vless"], str(order.get("protocols")))

    status, body = await post_platega_callback(order["id"], order["amount_rub"], transaction_id="701001")
    check("оплата подтверждена", status == 200 and body.strip() == "ok")
    subs = clients_named(email)
    check("VLESS выдаётся всеми тремя вариантами: Reality, XHTTP, gRPC", len(subs) == 3,
          f"записей: {len(subs)} — {[c['id'] for c in subs]}")
    check("все туннели — в Варшаве (Стокгольма нет)",
          client_of(email, 1) is None and all(client_of(email, i) for i in (2, 11, 12)),
          f"Стокгольм={client_of(email, 1)}")
    check("subId у всех один — одна ссылка-подписка",
          len({c["subId"] for c in subs}) == 1)
    check("срок и лимиты — из тарифа Новичок",
          14 <= days_left(subs[0]) <= 15 and subs[0]["limitIp"] == 1
          and round(subs[0]["totalGB"] / (1024 ** 3)) == 10)
    key_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "/sub/" in m["params"].get("text", "")][-1]
    check("клиенту ушла одна ссылка-подписка",
          key_text.count("/sub/") == 1 and "Варшава" in key_text, key_text[:120].replace("\n", " "))
    check("в сообщении перечислены три варианта VLESS и число туннелей",
          all(name in key_text for name in VLESS_VARIANTS) and "3 туннеля" in key_text,
          key_text[:300].replace("\n", " | "))


async def _delivery_level4(bot, email):
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "traffic_4")
    order = [o for o in bot.payment_store.orders.values()][-1]
    check("«Призрак» берёт все пять протоколов без выбора",
          order.get("protocols") == ["vless", "shadowsocks", "amneziawg", "wireguard", "hysteria2"],
          str(order.get("protocols")))
    status, body = await post_platega_callback(order["id"], order["amount_rub"], transaction_id="701002")
    check("оплата подтверждена", status == 200 and body.strip() == "ok")
    subs = clients_named(email)
    check("выданы все 18 туннелей: 9 вариантов × 2 сервера", len(subs) == 18,
          f"записей: {len(subs)}")
    check("клиенты в подключениях не пересекаются по id панели", len({c["id"] for c in subs}) == 18)
    check("subId у всех 18 подключений один", len({c["subId"] for c in subs}) == 1)
    from panel import PANEL
    used_inbounds = {inbound_id for inbound_id, row in PANEL["inbound_clients"].items() if email in row}
    check("задействованы все 18 подключений панели",
          used_inbounds == {i["id"] for i in ALL_INBOUNDS}, str(sorted(used_inbounds)))
    check("срок «по трафику» не ограничен (expiryTime = 0)",
          all(int(c["expiryTime"]) == 0 for c in subs))
    check("устройства — безлимит из тарифа «Призрак»",
          all(c["limitIp"] == 0 for c in subs), str({c["limitIp"] for c in subs}))
    key_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "/sub/" in m["params"].get("text", "")][-1]
    check("одна ссылка-подписка на все протоколы и серверы", key_text.count("/sub/") == 1)
    check("в сообщении все девять вариантов и 18 туннелей",
          all(name in key_text for name in VLESS_VARIANTS + SS_VARIANTS)
          and "AmneziaWG" in key_text and "WireGuard" in key_text and "Hysteria2" in key_text
          and "18 туннелей" in key_text, key_text[:340].replace("\n", " | "))

    # Уровень 3: три протокола на двух серверах
    reset_all()
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_3", None, ["vless", "shadowsocks", "wireguard"])
    order3 = [o for o in bot.payment_store.orders.values()][-1]
    status, body = await post_platega_callback(order3["id"], order3["amount_rub"], transaction_id="701003")
    check("оплата уровня 3 подтверждена", status == 200 and body.strip() == "ok")
    subs3 = clients_named(email)
    check("7 вариантов трёх протоколов × 2 сервера = 14 туннелей", len(subs3) == 14,
          f"записей: {len(subs3)}")
    check("в туннелях нет невыбранных протоколов (AmneziaWG и Hysteria2 отсутствуют)",
          "Stockholm-AmneziaWG" not in {c.get("comment") and "" or "" for c in subs3}
          and len([c for c in subs3 if c["id"] in {8, 9, 16, 17, 10, 18}]) == 0,
          str(sorted(c["id"] for c in subs3)))

    # «Мои подписки»: протоколы, варианты и серверы
    profile = _FakeCallback(bot, "profile")
    await bot.cb_profile(profile)
    profile_text = plain(profile.message.sent[-1])
    check("/profile перечисляет протоколы, варианты и серверы",
          "Туннелей: 14" in profile_text
          and all(name in profile_text for name in VLESS_VARIANTS + SS_VARIANTS)
          and "WireGuard" in profile_text
          and "Стокгольм" in profile_text and "Варшава" in profile_text,
          [line for line in profile_text.split("\n") if "Туннелей" in line or "получает" in line])


# ---------------- 4. Тариф «по трафику» ----------------

async def test_traffic_tariff(store_file):
    print("\n▶ 4. Тариф «по трафику»: без срока, лимит трафика из тарифа")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file)
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "traffic_2", "stockholm", ["hysteria2"])
        order = [o for o in bot.payment_store.orders.values()][-1]
        pay_text = [m["params"]["text"] for m in tg_calls("sendMessage") if "Оплата тарифа" in m["params"].get("text", "")][-1]
        check("в счёте «по трафику» срок подписан как «без ограничения по времени»",
              "без ограничения по времени" in pay_text, pay_text[:140].replace("\n", " "))
        check("в счёте видны трафик и выбранный сервер",
              "50 ГБ" in pay_text and "Стокгольм" in pay_text)

        status, body = await post_platega_callback(order["id"], order["amount_rub"], transaction_id="701004")
        check("оплата подтверждена", status == 200 and body.strip() == "ok")
        subs = clients_named(email)
        check("«Нетраннер» с Hysteria2: по одному туннелю на каждом сервере", len(subs) == 2,
              f"записей: {len(subs)}")
        check("срок не ограничен (expiryTime = 0)", all(int(c["expiryTime"]) == 0 for c in subs))
        check("лимиты из тарифа: 50 ГБ, 3 устройства",
              all(round(c["totalGB"] / (1024 ** 3)) == 50 and c["limitIp"] == 3 for c in subs))
        check("в комментарии клиента — тариф и «без ограничения по времени»",
              all(c["comment"].startswith("traffic_2 без ограничения по времени | platega-")
                  for c in subs), subs[0]["comment"])
        check("в выручке учтена цена по таблице (150 ₽)",
              bot.payment_store.stats()["rub"] == 150, str(bot.payment_store.stats()["rub"]))
    finally:
        await runner.cleanup()


# ---------------- 5. Тестовая выдача и /test_pay ----------------

async def test_test_pay(store_file):
    print("\n▶ 5. /test_pay: тариф, сервер и варианты протокола")
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
          "testpay_run_traffic_4" in kb_buttons
          and "testpay_run_traffic_4_stockholm" not in kb_buttons)

    await bot.cmd_test_pay(make_message(bot, text="/test_pay time_1 warsaw"))
    subs = clients_named(email)
    check("тестовая выдача уровня 1 — три варианта VLESS", len(subs) == 3,
          f"записей: {len(subs)}")
    check("тестовый доступ не истёк по времени и совпадает с тарифом",
          14 <= (days_left(subs[0]) or 0) <= 15 and subs[0]["limitIp"] == 1)

    await bot.cmd_revoke(make_message(bot, text=f"/revoke {TG_TG_ID}"))
    check("/revoke убрал все туннели подписки", not clients_named(email))

    await bot.cmd_test_pay(make_message(bot, text="/test_pay traffic_4"))
    check("«Призрак» по /test_pay выдаёт 18 туннелей", len(clients_named(email)) == 18,
          str(len(clients_named(email))))

    await bot.cmd_test_pay(make_message(bot, text="/test_pay traffic_1 atlantis"))
    check("неизвестный сервер отклонён с подсказкой",
          "Неизвестный сервер" in tp._last_api_text(), tp._last_api_text()[:80])


# ---------------- 6. Подключения и диагностика ----------------

async def test_inbounds_diag(store_file):
    print("\n▶ 6. Подключения панели: привязка туннелей и диагностика")
    reset_all()
    bot = new_bot({"mode": "platega", "admin_tools": "1", "allow_test_pay": "1"}, store_file)

    probe = load_bot(tp.PANEL_PORT)
    async with probe.XUIClient() as client:
        inbounds = await client.get_inbounds()
    check("в панели 18 подключений — 9 туннелей на две локации", len(inbounds) == 18,
          str(len(inbounds)))
    spots = {spot["key"]: spot for spot in probe.configured_locations()}
    matched = probe.match_tunnel_inbound(inbounds, spots["warsaw"], "vless", "xhttp")
    check("XHTTP находится по названию подключения",
          matched is not None and "Warsaw-VLESS-XHTTP" in str(matched.get("remark")),
          str(matched.get("remark") if matched else None))
    matched = probe.match_tunnel_inbound(inbounds, spots["stockholm"], "shadowsocks", "aes256")
    check("Shadowsocks AES-256 находится по методу шифрования",
          matched is not None and "AES-256" in str(matched.get("remark")),
          str(matched.get("remark") if matched else None))
    matched = probe.match_tunnel_inbound(inbounds, spots["warsaw"], "hysteria2", "default")
    check("Hysteria2 находится по названию", matched is not None
          and "Warsaw-Hysteria2" in str(matched.get("remark")))
    check("AmneziaWG не путается с WireGuard",
          probe.inbound_protocol_key(
              next(i for i in inbounds if i["remark"] == "Stockholm-AmneziaWG")) == "amneziawg"
          and probe.inbound_protocol_key(
              next(i for i in inbounds if i["remark"] == "Stockholm-WireGuard")) == "wireguard")

    # Переменная XUI_INBOUND_<ЛОКАЦИЯ>_<ВАРИАНТ> важнее названия
    explicit = load_bot(tp.PANEL_PORT, env={"XUI_INBOUND_WARSAW_VLESS_XHTTP": "3"})
    async with explicit.XUIClient() as client:
        inbounds2 = await client.get_inbounds()
    spots2 = {spot["key"]: spot for spot in explicit.configured_locations()}
    forced = explicit.match_tunnel_inbound(inbounds2, spots2["warsaw"], "vless", "xhttp")
    check("переменная XUI_INBOUND_<ЛОКАЦИЯ>_<ВАРИАНТ> задаёт подключение туннеля",
          forced is not None and int(forced["id"]) == 3, str(forced.get("id") if forced else None))
    check("имя переменной собирается из варианта",
          explicit.tunnel_env_name("warsaw", "shadowsocks", "aes256")
          == "XUI_INBOUND_WARSAW_SHADOWSOCKS_AES256"
          and explicit.tunnel_env_name("stockholm", "vless", "xhttp")
          == "XUI_INBOUND_STOCKHOLM_VLESS_XHTTP")

    # Вариант, которого нет в панели, не показывается в выборе
    # (берём последний загруженный модуль: у него все 18 подключений)
    removed = next(item for item in ALL_INBOUNDS if item["remark"] == "Stockholm-Hysteria2")
    ALL_INBOUNDS.remove(removed)
    explicit._INBOUNDS_CACHE.update({"at": 0.0, "items": []})
    try:
        one_server = dict(explicit.TARIFFS["time_4"], servers=1)
        availability = await explicit.tunnel_availability(one_server, "stockholm")
        check("вариант без подключения на сервере в выборе не показывается",
              "hysteria2" not in availability and "vless" in availability,
              str({key: list(value) for key, value in availability.items()}))
        check("остальные варианты VLESS на месте",
              len(availability["vless"]) == 3
              and set(availability["vless"]) == {"reality", "xhttp", "grpc"},
              str(list(availability["vless"])))
    finally:
        ALL_INBOUNDS.append(removed)

    # Диагностика — на свежем модуле (после reload'ов выше)
    bot = new_bot({"mode": "platega", "admin_tools": "1", "allow_test_pay": "1"},
                  store_file + ".diag")
    await bot.cmd_myid(make_message(bot, text="/myid"))
    myid_text = tp._last_api_text()
    check("/myid перечисляет локации и протоколы",
          "Локации" in myid_text and "XUI_INBOUND_STOCKHOLM" in myid_text
          and "Shadowsocks-2022" in myid_text and "Туннели уровня" in myid_text,
          myid_text[:200].replace("\n", " "))

    await bot.cmd_panel_debug(make_message(bot, text="/panel_debug"))
    debug_text = "".join(m["params"].get("text", "") for m in tg_calls("sendMessage"))
    check("/panel_debug показывает туннели по локациям",
          "Туннели (локация × вариант протокола)" in debug_text
          and "Варшава · VLESS: VLESS Reality: #2, VLESS Reality + XHTTP: #11" in debug_text
          and "Shadowsocks-2022 · AES-256-GCM: #14" in debug_text
          and "Варшава · Hysteria2: Hysteria2: #18" in debug_text,
          [line for line in debug_text.split("\n") if "Варшава · VLESS" in line][:1])
    check("/panel_debug перечисляет все подключения панели",
          "Warsaw-Shadowsocks-ChaCha20" in debug_text and "Warsaw-Hysteria2" in debug_text)
    check("/panel_debug считает найденные подключения",
          "Найдено подключений" in debug_text and "VLESS: 6/6" in debug_text,
          [line for line in debug_text.split("\n") if "Найдено" in line][:1])


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
        await test_delivery_tunnels(store_for("delivery"))
        await test_traffic_tariff(store_for("traffic"))
        await test_test_pay(store_for("testpay"))
        await test_inbounds_diag(store_for("diag"))
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
