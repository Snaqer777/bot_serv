"""
Тесты тарифной сетки DarkTier: 4 уровня, туннели (сервер × вариант протокола) и 4 шага покупки.

Проверяем ровно то, что видит клиент:
  1. каталог: 8 платных тарифов (4 уровня × 2 типа), цены/трафик/сроки/устройства,
     серверы по уровням (1 / 2 / 2 / 2) и туннели (1–3 / 2–6 / 6–14 / 18);
  2. протоколы: пять базовых, у VLESS и Shadowsocks-2022 по три варианта (Reality/XHTTP/gRPC
     и три шифра), у Hysteria2 / AmneziaWG / WireGuard — по одному;
     порядок протоколов в меню: VLESS → Hysteria2 → AmneziaWG → WireGuard → Shadowsocks-2022;
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
from panel import (ALL_INBOUNDS, _tunnel_inbound, client_of, clients_named, load_bot,
                   make_app, reset)
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
PROTOCOL_BASE = ("VLESS", "Hysteria2", "AmneziaWG", "WireGuard", "Shadowsocks-2022")
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


def sent_buttons() -> list:
    """Кнопки последнего экрана: и sendMessage (markup — словарь), и editMessageText."""
    for call in reversed(TG["calls"]):
        markup = call["params"].get("reply_markup")
        if markup is None:
            continue
        if isinstance(markup, dict):
            return [b.get("callback_data") or b.get("url") or ""
                    for row in markup.get("inline_keyboard", []) for b in row]
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
          list(bot.PROTOCOL_ORDER) == ["vless", "hysteria2", "amneziawg", "wireguard", "shadowsocks"]
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
          and "3 туннеля: VLESS Reality" in step4_text
          and "3 туннеля: Shadowsocks-2022 · AES-128-GCM" in step4_text.replace("\n", " "),
          step4_text[200:520].replace("\n", " | "))
    check("шаг 4: Shadowsocks-2022 — три туннеля на сервер, как и VLESS",
          bot.protocol_variant_count("shadowsocks") == 3
          and len(bot.protocol_tunnel_titles("shadowsocks")) == 3)
    check("шаг 4: протоколы идут в порядке VLESS → Hysteria2 → AmneziaWG → WireGuard → Shadowsocks",
          [line.split(" ")[1] for line in step4_text.split("\n") if line.startswith(("✅ ", "◻️ "))]
          == list(PROTOCOL_BASE),
          str([line.split(" ")[1] for line in step4_text.split("\n") if line.startswith(("✅ ", "◻️ "))]))
    check("по умолчанию у Новичка отмечен VLESS — рекомендуемый",
          bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"] == ["vless"])
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

    # «Назад» на шаге 4 ведёт на шаг 3, а не перерисовывает шаг 4 (был такой баг)
    check("шаг 4 (Новичок): «Назад» — отдельная кнопка, а не «Дальше»",
          "tsback_time_1" in last_buttons() and "tsall_time_1" not in last_buttons(),
          str(last_buttons()))
    TG["calls"].clear()
    await bot.cb_tariff_step3_back(_FakeCallback(bot, "tsback_time_1"))
    back_text = plain(last_edit().get("text", ""))
    check("возврат с шага 4 у Новичка — снова выбор сервера",
          "Шаг 3. Выберите сервер" in back_text
          and {"tlocs_time_1_warsaw", "tlocs_time_1_stockholm"} <= set(last_buttons()),
          back_text[:120].replace("\n", " ") + " | " + str(last_buttons()))
    # Старые сообщения с tsrv_ тоже должны вести на шаг 3, а не на шаг 4
    TG["calls"].clear()
    await bot.cb_tariff_server_screen(_FakeCallback(bot, "tsrv_time_1"))
    check("старая кнопка tsrv_ ведёт на шаг 3",
          "Шаг 3. Выберите сервер" in plain(last_edit().get("text", "")))

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
    check("шаг 4: у каждого протокола подписано число туннелей на сервер и всего",
          "3 туннеля на сервер (2 сервера — 6): VLESS Reality" in many_text.replace("\n", " ")
          and "1 туннель на сервер (2 сервера — 2): Hysteria2" in many_text.replace("\n", " ")
          and "3 туннеля на сервер (2 сервера — 6): Shadowsocks-2022" in many_text.replace("\n", " "),
          many_text[200:520].replace("\n", " | "))
    check("шаг 4: можно выбрать другой протокол, но не больше трёх",
          "tpro_shadowsocks" in many_buttons and "tpro_wireguard" in many_buttons)
    check("шаг 4 (Кибер-самурай): «Назад» ведёт на шаг 3, а не на себя же",
          "tsback_time_3" in many_buttons and "tsall_time_3" not in many_buttons,
          str(many_buttons))
    TG["calls"].clear()
    await bot.cb_tariff_step3_back(_FakeCallback(bot, "tsback_time_3"))
    back3_text = plain(last_edit().get("text", ""))
    check("возврат с шага 4 — снова экран серверов, с кнопкой «Дальше»",
          "Шаг 3. Серверы" in back3_text and "Стокгольм" in back3_text
          and "tsall_time_3" in last_buttons(), back3_text[:120].replace("\n", " "))
    check("на шаге 3 снова доступен возврат к уровням",
          "tkind_time" in last_buttons(), str(last_buttons()))
    TG["calls"].clear()
    await bot.cb_tariff_servers_all(_FakeCallback(bot, "tsall_time_3"))
    check("после возврата и «Дальше» выбор протоколов сохранился",
          len(bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"]) == 3
          and "Шаг 4. Выберите протокол(ы)" in plain(last_edit().get("text", "")),
          str(bot.PROTOCOL_SELECTION[TG_TG_ID]["selected"]))

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
    for key in ("wireguard", "hysteria2"):
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
    TG["calls"].clear()
    await bot.cb_tariff_level(_FakeCallback(bot, "tlvl_traffic_4"))
    await bot.cb_tariff_servers_all(_FakeCallback(bot, "tsall_traffic_4"))
    ghost_back = last_buttons()
    check("шаг 4 (Призрак): «Назад» тоже ведёт на шаг 3",
          "tsback_traffic_4" in ghost_back and "tsall_traffic_4" not in ghost_back,
          str(ghost_back))
    TG["calls"].clear()
    await bot.cb_tariff_step3_back(_FakeCallback(bot, "tsback_traffic_4"))
    check("возврат с шага 4 у «Призрака» — экран серверов",
          "Шаг 3. Серверы" in plain(last_edit().get("text", ""))
          and "tsall_traffic_4" in last_buttons())
    TG["calls"].clear()
    await bot.cb_tariff_servers_all(_FakeCallback(bot, "tsall_traffic_4"))
    TG["calls"].clear()
    await bot.cb_tariff_protocol_done(_FakeCallback(bot, "tcont"))
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
          order.get("protocols") == ["vless", "hysteria2", "amneziawg", "wireguard", "shadowsocks"],
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
    await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_3", None, ["vless", "shadowsocks", "hysteria2"])
    order3 = [o for o in bot.payment_store.orders.values()][-1]
    status, body = await post_platega_callback(order3["id"], order3["amount_rub"], transaction_id="701003")
    check("оплата уровня 3 подтверждена", status == 200 and body.strip() == "ok")
    subs3 = clients_named(email)
    check("7 вариантов трёх протоколов × 2 сервера = 14 туннелей", len(subs3) == 14,
          f"записей: {len(subs3)}")
    check("в туннелях нет невыбранных протоколов (AmneziaWG и WireGuard отсутствуют)",
          len([c for c in subs3 if c["id"] in {8, 9, 16, 17}]) == 0,
          str(sorted(c["id"] for c in subs3)))

    # «Мои подписки»: протоколы, варианты и серверы
    profile = _FakeCallback(bot, "profile")
    await bot.cb_profile(profile)
    profile_text = plain(profile.message.sent[-1])
    check("/profile перечисляет протоколы, варианты и серверы",
          "Туннелей: 14" in profile_text
          and all(name in profile_text for name in VLESS_VARIANTS + SS_VARIANTS)
          and "Hysteria2" in profile_text
          and "Стокгольм" in profile_text and "Варшава" in profile_text,
          [line for line in profile_text.split("\n") if "Туннелей" in line or "получает" in line])


# ---------------- 3б. Чего нет в панели: отчёт, а не тишина ----------------

async def test_missing_tunnels(store_file):
    print("\n▶ 3б. Нет подключений в панели: покупателю выдаём что есть, админу — отчёт")
    reset_all()
    # Покупатель — 4242, админ — тоже он и 777: уведомление уйдёт в чат 777,
    # поэтому его можно прочитать отдельно от сообщений покупателя.
    bot = new_bot({"mode": "platega", "admin_id": f"{TG_TG_ID}, 777"}, store_file + ".missing")
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    # Убираем из панели всю Варшаву и один вариант Стокгольма.
    removed = [item for item in list(ALL_INBOUNDS)
               if item["remark"].startswith("Warsaw") or item["remark"] == "Stockholm-Hysteria2"]
    for item in removed:
        ALL_INBOUNDS.remove(item)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_4")
        order = [o for o in bot.payment_store.orders.values()][-1]
        status, body = await post_platega_callback(order["id"], order["amount_rub"], transaction_id="701010")
        check("оплата подтверждена, несмотря на неполную панель",
              status == 200 and body.strip() == "ok")
        subs = clients_named(email)
        check("выданы туннели, которые есть: 8 из Стокгольма (9 туннелей минус Hysteria2)",
              len(subs) == 8, f"записей: {len(subs)}")
        check("в подписке нет ни одного клиента Варшавы",
              not any(c["id"] in {i["id"] for i in removed} for c in subs))

        admin_text = "".join(m["params"].get("text", "") for m in tg_calls("sendMessage")
                             if str(m["params"].get("chat_id")) == "777")
        check("админу пришёл отчёт о ненайденных подключениях",
              "Не найдены подключения в панели" in admin_text
              and "Варшава · VLESS Reality + XHTTP" in admin_text,
              [line for line in admin_text.split("\n") if "Варшава ·" in line][:2])
        check("в отчёте админу указаны переменные для подключений",
              "XUI_INBOUND_WARSAW_VLESS_XHTTP" in admin_text
              and "XUI_INBOUND_WARSAW_SHADOWSOCKS_AES128" in admin_text)
        check("админ видит, что туннелей выдано меньше оплаченного, и подсказку про /panel_debug",
              "8 из 18" in admin_text and "/panel_debug" in admin_text,
              [line for line in admin_text.split("\n") if "Туннелей" in line])

        buyer_text = [m["params"]["text"] for m in tg_calls("sendMessage")
                      if str(m["params"].get("chat_id")) == str(TG_TG_ID)
                      and "Оплата получена" in m["params"].get("text", "")][-1]
        check("покупатель видит, что выдали не все туннели, и куда писать",
              "выдано 8 из 18" in buyer_text and "поддерж" in buyer_text.lower(),
              [line for line in buyer_text.split("\n") if "выдано" in line][:1])

        await bot.cmd_panel_debug(make_message(bot, text="/panel_debug"))
        debug_text = "".join(m["params"].get("text", "") for m in tg_calls("sendMessage"))
        check("/panel_debug показывает «ни одного подключения» для выпавшей локации",
              "Варшава: найдено 0 из 9" in debug_text
              and "ни одного подключения этой локации" in debug_text,
              [line for line in debug_text.split("\n") if "Варшава: найдено" in line][:1])
        check("/panel_debug перечисляет ненайденное с переменными",
              "Не хватает подключений" in debug_text
              and "Варшава · AmneziaWG — <code>XUI_INBOUND_WARSAW_AMNEZIAWG</code>" in debug_text,
              [line for line in debug_text.split("\n") if "AmneziaWG —" in line][:1])
        check("/panel_debug считает итог по туннелям",
              "Итого туннелей: 8 из 18" in debug_text,
              [line for line in debug_text.split("\n") if "Итого" in line][:1])
        # Покупатель на шаге 3 видит, что Варшава ещё настраивается
        reset_all()
        bot2 = new_bot({"mode": "platega"}, store_file + ".note")
        await bot2.cb_tariff_level(_FakeCallback(bot2, "tlvl_time_3"))
        step3 = tp.tg_calls("editMessageText")[-1]["params"]["text"]
        check("шаг 3 предупреждает, что сервер ещё настраивается",
              "Пока настраивается" in step3 and "Варшава" in step3,
              [line for line in step3.split("\n") if "настраивается" in line][:1])
        check("шаг 3 при этом продолжает работать: оба сервера и кнопка «Дальше» на месте",
              "Стокгольм" in step3 and any(
                  b.callback_data == "tsall_time_3"
                  for row in tp.tg_calls("editMessageText")[-1]["params"]["reply_markup"].inline_keyboard
                  for b in row))
    finally:
        ALL_INBOUNDS.extend(removed)
        await runner.cleanup()


async def test_duplicate_inbound(store_file):
    print("\n▶ 3в. Один inbound на два варианта: второй не выдаём и предупреждаем")
    reset_all()
    bot = new_bot({"mode": "platega"}, store_file + ".dup")
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    # Варшавский XHTTP подключён тем же ID, что и Reality (частая ошибка настройки)
    duplicate = next(item for item in ALL_INBOUNDS if item["remark"] == "Warsaw-VLESS-XHTTP")
    original_id = duplicate["id"]
    duplicate["id"] = int(next(i["id"] for i in ALL_INBOUNDS if i["remark"] == "Warsaw-Reality"))
    try:
        info = await bot.activate_paid_subscription(
            TG_TG_ID, "time_4", order_id="dup-1", payment_ref="dup-ref",
            protocols=["vless"],
        )
        check("дубликат не заводят дважды: выданы Reality, gRPC и оба Стокгольма",
              len(info["entries"]) == 5, f"записей: {len(info['entries'])}")
        check("в отчёте помечено, что XHTTP указывает на то же подключение",
              any("то же подключение" in item.get("reason", "") for item in info["missing"]),
              str([item.get("reason") for item in info["missing"]]))
        check("подсказка называет переменную для XHTTP",
              any(item.get("env") == "XUI_INBOUND_WARSAW_VLESS_XHTTP" for item in info["missing"]))
    finally:
        duplicate["id"] = original_id
        await runner.cleanup()


# ---------------- 3г. /reissue: дособрать туннели оплаченной подписке ----------

async def test_reissue_command(store_file):
    print("\n▶ 3г. /reissue: недостающие туннели доезжают до покупателя")
    reset_all()
    bot = new_bot({"mode": "platega", "admin_id": f"{TG_TG_ID}, 777", "admin_tools": "1",
                   "allow_test_pay": "1"}, store_file + ".reissue")
    runner = await bot.run_webhook_server()
    email = f"tg-paid-{TG_TG_ID}"
    # 1. Панель неполная: Варшавы нет вовсе, Стокгольм без Hysteria2.
    removed = [item for item in list(ALL_INBOUNDS)
               if item["remark"].startswith("Warsaw") or item["remark"] == "Stockholm-Hysteria2"]
    for item in removed:
        ALL_INBOUNDS.remove(item)
    try:
        await bot.start_checkout(TG_TG_ID, TG_TG_ID, "time_4")
        order = [o for o in bot.payment_store.orders.values()][-1]
        await post_platega_callback(order["id"], order["amount_rub"], transaction_id="701020")
        check("сначала выдан неполный набор (8 туннелей)", len(clients_named(email)) == 8,
              f"записей: {len(clients_named(email))}")
        before = {c["id"] for c in clients_named(email)}

        # 2. Админ доложил подключения в панель и дособрал туннели
        ALL_INBOUNDS.extend(removed)
        bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})
        await bot.cmd_reissue(make_message(bot, text="/reissue"))
        hint = tp._last_api_text()
        check("без аргументов /reissue объясняет, как пользоваться",
              "Использование" in hint and "tg_id" in hint)

        tg_calls("sendMessage").clear()
        await bot.cmd_reissue(make_message(bot, text=f"/reissue {TG_TG_ID}"))
        subs = clients_named(email)
        check("досборка довела подписку до 18 туннелей", len(subs) == 18,
              f"записей: {len(subs)}")
        check("ранее выданные туннели не пересоздавались",
              before <= {c["id"] for c in subs},
              f"было {len(before)}, стало {len({c['id'] for c in subs})}")
        check("новые туннели получили тот же срок, что и остальная подписка",
              len({int(c["expiryTime"]) for c in subs}) == 1,
              str(sorted({int(c["expiryTime"]) for c in subs})))
        check("subId по-прежнему один — ссылка у клиента не менялась",
              len({c["subId"] for c in subs}) == 1)
        note = tp._last_api_text()
        check("админу отчёт: сколько добавили и что клиент уведомлён",
              "Добавлено туннелей: <b>10</b>" in note and "Всего туннелей в подписке: <b>18</b>" in note,
              note[:160].replace("\n", " "))
        buyer_msgs = [m["params"]["text"] for m in tg_calls("sendMessage")
                      if str(m["params"].get("chat_id")) == str(TG_TG_ID)]
        check("покупателю пришло сообщение про новые туннели и ту же ссылку",
              any("добавлены новые туннели" in text for text in buyer_msgs)
              and any("/sub/" in text for text in buyer_msgs),
              buyer_msgs[-1][:100].replace("\n", " ") if buyer_msgs else "нет сообщений")

        # повторный вызов ничего не дублирует
        tg_calls("sendMessage").clear()
        await bot.cmd_reissue(make_message(bot, text=f"/reissue {TG_TG_ID}"))
        check("повторный /reissue не плодит дубли",
              len(clients_named(email)) == 18 and "Добавлено туннелей: <b>0</b>" in tp._last_api_text(),
              tp._last_api_text()[:120].replace("\n", " "))
    finally:
        for item in removed:
            if item not in ALL_INBOUNDS:
                ALL_INBOUNDS.append(item)
        await runner.cleanup()


# ---------------- 6б. /panel_map: привязка подключений без переменных ----------------

async def test_panel_map_command(store_file):
    print("\n▶ 6б. /panel_map: привязка подключений кнопками и текстом")
    reset_all()
    # Сценарии выше могли оставить переменные XUI_INBOUND_* в окружении процесса
    # (например, XUI_INBOUND_WARSAW_VLESS_XHTTP из диагностики). Здесь нужна
    # «панель без понятных названий», поэтому переменные убираем.
    for name in [key for key in os.environ if key.startswith("XUI_INBOUND")]:
        os.environ.pop(name, None)
    map_file = store_file + ".inbound_map.json"
    bot = new_bot({"mode": "platega", "admin_tools": "1"}, store_file + ".map",
                  extra_env={"INBOUND_MAP_FILE": map_file})

    # Панель с нестандартными названиями: у Варшавы вместо «Warsaw-…» — «Node-…»,
    # локацию по названию не определить. Такую панель и лечит /panel_map.
    renamed = [(item, item["remark"]) for item in ALL_INBOUNDS
               if str(item["remark"]).startswith("Warsaw")]
    try:
        for item, _remark in renamed:
            item["remark"] = f"Node-{item['id']}"
        bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})

        await bot.cmd_panel_map(make_message(bot, text="/panel_map"))
        text = plain(tp._last_api_text())
        check("/panel_map сообщает, сколько туннелей нашлось",
              "Найдено туннелей: 9 из 18" in text, text[:160].replace("\n", " "))
        check("/panel_map перечисляет ненайденные туннели Варшавы",
              "🇵🇱 Варшава · Hysteria2" in text and "🇵🇱 Варшава · AmneziaWG" in text
              and "🇵🇱 Варшава · VLESS Reality + XHTTP" in text,
              [line for line in text.split("\n") if "Варшава" in line][:2])
        check("на каждый ненайденный туннель есть кнопка привязки",
              "pmap_o_warsaw|hysteria2|default" in sent_buttons()
              and "pmap_o_warsaw|vless|xhttp" in sent_buttons(),
              str(sent_buttons()))
        check("подсказана и текстовая форма",
              "/panel_map Warsaw_Hysteria2=18" in text.replace("\u00a0", " "), text[-200:])

        # Кнопками: туннель → подключение
        TG["calls"].clear()
        await bot.cb_panel_map_open(_FakeCallback(bot, "pmap_o_warsaw|hysteria2|default"))
        candidates = sent_buttons()
        check("показаны подключения того же протокола (Hysteria2 в обеих локациях)",
              set(candidates) == {"pmap_c_18_warsaw|hysteria2|default",
                                  "pmap_c_10_warsaw|hysteria2|default", "pmap"},
              str(candidates))
        TG["calls"].clear()
        await bot.cb_panel_map_bind(_FakeCallback(bot, "pmap_c_18_warsaw|hysteria2|default"))
        check("привязка сохранена в боте",
              bot.inbound_map.get("warsaw", "hysteria2", "default") == 18,
              str(bot.inbound_map.items()))
        check("после привязки счётчик стал 10 из 18",
              "Найдено туннелей: 10 из 18" in plain(last_edit().get("text", "")),
              plain(last_edit().get("text", ""))[:120].replace("\n", " "))
        matched = bot.match_tunnel_inbound([dict(item) for item in ALL_INBOUNDS],
                                           bot.location_by_key("warsaw"), "hysteria2", "default")
        check("привязка сразу работает в подборе туннелей",
              (matched or {}).get("id") == 18, str((matched or {}).get("id")))
        check("файл привязок записан рядом с журналом оплат",
              json.load(open(map_file, encoding="utf-8"))["map"]["warsaw|hysteria2|default"] == 18,
              map_file)

        # Текстом: 8 оставшихся туннелей Варшавы, одним сообщением
        TG["calls"].clear()
        await bot.cmd_panel_map(make_message(
            bot, text="/panel_map Warsaw_VLESS_Reality=2 Warsaw_VLESS_XHTTP=11 "
                      "Warsaw_VLESS_gRPC=12 Warsaw_Shadowsocks_AES128=13 "
                      "Warsaw_Shadowsocks_AES256=14 Warsaw_Shadowsocks_ChaCha20=15 "
                      "Warsaw_AmneziaWG=16 Warsaw_WireGuard=17"))
        text = plain(tp._last_api_text())
        check("текстовая форма привязала все оставшиеся туннели",
              "Сохранено привязок: 8 из 8" in text, text[:200].replace("\n", " "))
        check("теперь найдены все 18 туннелей",
              "Найдено туннелей: 18 из 18" in text and "✅ Все подключения найдены" in text,
              text[-160:].replace("\n", " "))
        check("без «Не найдены подключения» на экране не осталось",
              "не нашёл подключения" not in text)
        check("AmneziaWG привязан к wireguard-подключению с предупреждением",
              bot.inbound_map.get("warsaw", "amneziawg", "default") == 16
              and "проверь обфускацию" in text, text[:160].replace("\n", " "))

        # Ошибки видно сразу: чужой протокол и опечатка в названии
        TG["calls"].clear()
        await bot.cmd_panel_map(make_message(bot, text="/panel_map Warsaw_Hysteria2=17"))
        text = plain(tp._last_api_text())
        check("подключение другого протокола не принимается",
              "это WireGuard, а нужен Hysteria2" in text and "Сохранено привязок: 0 из 1" in text,
              text[:220].replace("\n", " "))
        check("неверная привязка не перезаписала рабочую",
              bot.inbound_map.get("warsaw", "hysteria2", "default") == 18)
        TG["calls"].clear()
        await bot.cmd_panel_map(make_message(bot, text="/panel_map Warsaw_Hysteria=18"))
        check("опечатка в названии туннеля объясняется",
              "не знаю туннель" in plain(tp._last_api_text()),
              plain(tp._last_api_text())[:160].replace("\n", " "))

        # Привязки переживают перезапуск бота: читаются из того же файла
        again = new_bot({"mode": "platega", "admin_tools": "1"}, store_file + ".map2",
                        extra_env={"INBOUND_MAP_FILE": map_file})
        check("привязки читаются после перезапуска",
              again.inbound_map.get("warsaw", "shadowsocks", "chacha20") == 15
              and again.inbound_map.get("stockholm", "hysteria2", "default") == 0,
              str(again.inbound_map.items()[:3]))

        # Снятие привязок возвращает подбор по названию
        saved_before = len(again.inbound_map.items())
        await again.cmd_panel_map(make_message(again, text="/panel_map clear"))
        check("«/panel_map clear» снимает привязки",
              again.inbound_map.get("warsaw", "hysteria2", "default") == 0
              and f"Привязки сняты: {saved_before}" in plain(tp._last_api_text()),
              plain(tp._last_api_text())[:120].replace("\n", " "))
        check("после снятия снова находится 9 из 18",
              "Найдено туннелей: 9 из 18" in plain(tp._last_api_text()))
    finally:
        for item, remark in renamed:
            item["remark"] = remark
        bot._INBOUNDS_CACHE.update({"at": 0.0, "items": []})



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

    # Варианты, как их называет сама панель: методы формата 2022-blake3-*,
    # транспорт splithttp и grpcSettings — бот должен узнавать и их
    panel_style = [
        _tunnel_inbound(101, "Stockholm-SS-A", 8501, protocol="shadowsocks",
                        network="tcp", security="none", method="2022-blake3-aes-128-gcm"),
        _tunnel_inbound(102, "Stockholm-SS-B", 8502, protocol="shadowsocks",
                        network="tcp", security="none", method="2022-blake3-aes-256-gcm"),
        _tunnel_inbound(103, "Stockholm-SS-C", 8503, protocol="shadowsocks",
                        network="tcp", security="none", method="2022-blake3-chacha20-poly1305"),
        _tunnel_inbound(104, "Stockholm-X", 8504, network="splithttp"),
        _tunnel_inbound(105, "Stockholm-G", 8505, network="tcp",
                        security="reality"),
    ]
    variant_map = {int(item["id"]): bot.inbound_variant_key(item, "shadowsocks")
                   for item in panel_style[:3]}
    check("методы панели 2022-blake3-* раскладываются по вариантам Shadowsocks",
          variant_map == {101: "aes128", 102: "aes256", 103: "chacha20"}, str(variant_map))
    check("транспорт splithttp считается вариантом XHTTP",
          bot.inbound_protocol_key(panel_style[3]) == "vless"
          and bot.inbound_variant_key(panel_style[3], "vless") == "xhttp",
          f"{bot.inbound_protocol_key(panel_style[3])}/{bot.inbound_variant_key(panel_style[3], 'vless')}")

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
        await test_missing_tunnels(store_for("missing"))
        await test_duplicate_inbound(store_for("duplicate"))
        await test_reissue_command(store_for("reissue"))
        await test_traffic_tariff(store_for("traffic"))
        await test_test_pay(store_for("testpay"))
        await test_inbounds_diag(store_for("diag"))
        await test_panel_map_command(store_for("panelmap"))
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
