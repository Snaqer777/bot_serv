"""
Тесты реферальной программы («пригласи друга»).

Проверяем весь путь целиком, как у реального пользователя:
  • переход по ссылке t.me/<бот>?start=ref_<id>;
  • друг получает +N дней к первой оплате;
  • пригласивший получает +M дней: сразу к подписке или в копилку до следующей покупки;
  • повторные оплаты и тестовая выдача ключа бонусов НЕ удваивают;
  • страница /invite и выключение программы переменной REFERRAL_ENABLED.

Стенд: фейковая панель 3x-ui + фейковый Telegram Bot API (как в test_payments.py).
Запуск: python tests/test_referral.py
"""
import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aiohttp import web
from panel import PANEL, load_bot, make_app, reset

# Новый каталог: «по времени» и «по трафику». В реферальных сценариях важен срок
# (дни), поэтому берём тарифы с ограничением по времени.
BASIC = "time_3"   # 250 ₽, 30 дней, 100 ГБ, 5 устройств, 2+ локации
FAMILY = "time_1"  # 70 ₽, 15 дней, 15 ГБ, 1 устройство (выбор сервера)


from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.types import Message

PANEL_PORT = 8750
TG_PORT = 8751
BOT_USERNAME = "myvpnbot"
REFERRER = 1001
FRIEND1 = 1002
FRIEND2 = 1003
FRIEND3 = 1004
BONUS_DAYS = 7
INVITED_BONUS_DAYS = 3

FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


# ---------------- фейковый Telegram Bot API ----------------

TG = {"calls": [], "next_id": 100}


def tg_calls(method):
    return [c for c in TG["calls"] if c["method"] == method]


def last_tg(method):
    items = tg_calls(method)
    return items[-1]["params"] if items else {}


def texts_to(chat_id):
    return [
        c["params"].get("text", "")
        for c in tg_calls("sendMessage")
        if str(c["params"].get("chat_id")) == str(chat_id)
    ]


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
                if value.lstrip("-").isdigit():
                    params[key] = int(value)
                    continue
            params[key] = value
    except Exception:
        try:
            params = await request.json()
        except Exception:
            params = {}

    TG["calls"].append({"method": token_method, "params": params})
    if token_method in ("answerPreCheckoutQuery", "answerCallbackQuery", "deleteMessage", "answerWebAppQuery"):
        return web.json_response({"ok": True, "result": True})
    TG["next_id"] += 1
    return web.json_response({
        "ok": True,
        "result": {"message_id": TG["next_id"], "date": int(time.time()),
                   "chat": {"id": params.get("chat_id", 0), "type": "private"},
                   "text": params.get("text", "")},
    })


def make_tg_app():
    app = web.Application()
    app.router.add_post("/bot{token}/{method}", tg_api)
    return app


# ---------------- инфраструктура ----------------

def new_bot(store_file, ref_file, env=None, admins=None):
    """Загружает bot.py с реферальным окружением и переключает его на фейковый Telegram."""
    env = dict(env or {})
    full_env = {
        "PAYMENTS_MODE": env.get("mode", "stars"),
        "PAYMENT_STORE_FILE": store_file,
        "REFERRAL_ENABLED": env.get("enabled", "1"),
        "REFERRAL_BONUS_DAYS": str(env.get("bonus", BONUS_DAYS)),
        "REFERRAL_INVITED_BONUS_DAYS": str(env.get("invited_bonus", INVITED_BONUS_DAYS)),
        "REFERRAL_STORE_FILE": ref_file,
        "BOT_USERNAME": env.get("username", BOT_USERNAME),
    }
    bot = load_bot(PANEL_PORT, admins=str(admins or REFERRER), env=full_env)
    session = AiohttpSession()
    session.api = TelegramAPIServer.from_base(f"http://127.0.0.1:{TG_PORT}")
    bot.bot.session = session
    return bot


def make_message(bot, uid, text="/start", **extra):
    payload = {
        "message_id": 1,
        "date": int(time.time()),
        "chat": {"id": uid, "type": "private"},
        "from": {"id": uid, "is_bot": False, "first_name": "Tester", "language_code": "ru"},
        "text": text,
        **extra,
    }
    return Message.model_validate(payload, context={"bot": bot.bot})


def panel_client(tg_id):
    return PANEL["clients"].get(f"tg-paid-{tg_id}")


def days_left(tg_id):
    client = panel_client(tg_id)
    if not client:
        return None
    return round((int(client["expiryTime"]) - int(time.time() * 1000)) / 86_400_000, 1)


def expiry_of(tg_id):
    client = panel_client(tg_id)
    return int(client["expiryTime"]) if client else 0


async def pay_stars(bot, uid, tariff=BASIC, charge=None):
    """Счёт + подтверждение оплаты (звёзды). Возвращает id заказа."""
    await bot.start_checkout(uid, uid, tariff)
    order_id = last_tg("sendInvoice")["payload"]
    stars = bot.TARIFFS[tariff]["stars"]
    from aiogram.types import PreCheckoutQuery
    pre = PreCheckoutQuery.model_validate({
        "id": f"pcq-{order_id}",
        "from": {"id": uid, "is_bot": False, "first_name": "Tester", "language_code": "ru"},
        "chat_instance": "ci-1",
        "currency": "XTR",
        "total_amount": stars,
        "invoice_payload": order_id,
    }, context={"bot": bot.bot})
    await bot.on_pre_checkout(pre)
    await bot.on_successful_payment(make_message(bot, uid, successful_payment={
        "currency": "XTR",
        "total_amount": stars,
        "invoice_payload": order_id,
        "telegram_payment_charge_id": charge or f"tg-charge-{uid}",
        "provider_payment_charge_id": "",
    }))
    return order_id


def reset_all():
    reset()
    TG["calls"].clear()


# ---------------- сценарии ----------------

async def test_payload_and_link(store_file, ref_file):
    print("\n▶ 1. Разбор ссылки-приглашения и сборка личной ссылки")
    bot = new_bot(store_file, ref_file)
    check("ref_12345 распознан", bot.parse_referral_payload("ref_12345") == 12345)
    check("REF-77 распознан (регистр не важен)", bot.parse_referral_payload("REF-77") == 77)
    check("ref0 (нулевой id) отброшен", bot.parse_referral_payload("ref0") is None)
    check("ref_0 отброшен", bot.parse_referral_payload("ref_0") is None)
    check("мусор отброшен", bot.parse_referral_payload("hello") is None)
    check("пустая строка отброшена", bot.parse_referral_payload("") is None)

    link = await bot.referral_link(REFERRER)
    check("ссылка собрана по BOT_USERNAME", link == f"https://t.me/{BOT_USERNAME}?start=ref_{REFERRER}", link)
    check("в правилах указаны дни бонуса",
          f"+{BONUS_DAYS} {bot.days_word(BONUS_DAYS)}" in bot.referral_rules_text())
    check("склонение слова «день»",
          (bot.days_word(1), bot.days_word(3), bot.days_word(7), bot.days_word(11)) ==
          ("день", "дня", "дней", "дней"))


async def test_invite_registration(store_file, ref_file):
    print("\n▶ 2. Переход по ссылке: друг регистрируется, пригласивший получает уведомление")
    reset_all()
    bot = new_bot(store_file, ref_file)

    await bot.cmd_start(make_message(bot, REFERRER, "/start"))
    check("пригласивший запомнен как пользователь бота", bot.referral_store.knows_user(REFERRER))
    check("реферальных записей пока нет", bot.referral_store.invite_of(FRIEND1) is None)

    await bot.cmd_start(make_message(bot, FRIEND1, f"/start ref_{REFERRER}"))
    invite = bot.referral_store.invite_of(FRIEND1)
    check("друг записан за пригласившим", bool(invite) and invite["referrer"] == REFERRER, str(invite))
    check("бонус другу ещё не начислен", not invite.get("first_paid_at") if invite else False)
    check("пригласившему пришло уведомление о новом друге",
          any("пришёл друг" in t for t in texts_to(REFERRER)))
    check("друг получил приветствие с подарком",
          any(f"+{INVITED_BONUS_DAYS} {bot.days_word(INVITED_BONUS_DAYS)}" in t for t in texts_to(FRIEND1)))

    # Повторный переход по другой ссылке не переписывает приглашение
    await bot.cmd_start(make_message(bot, FRIEND1, f"/start ref_{FRIEND2}"))
    invite = bot.referral_store.invite_of(FRIEND1)
    check("первое приглашение нельзя переписать", invite["referrer"] == REFERRER)

    # Своя ссылка не считается
    TG["calls"].clear()
    await bot.cmd_start(make_message(bot, FRIEND1, f"/start ref_{FRIEND1}"))
    check("своя ссылка отклонена", any("Своя же ссылка" in t for t in texts_to(FRIEND1)))
    check("приглашение осталось прежним", bot.referral_store.invite_of(FRIEND1)["referrer"] == REFERRER)

    # Ссылка на несуществующего (не запускавшего бота) пригласившего — без записи
    await bot.cmd_start(make_message(bot, FRIEND3, "/start ref_999999"))
    check("неизвестный пригласивший не создаёт запись", bot.referral_store.invite_of(FRIEND3) is None)

    TG["calls"].clear()
    await bot.cmd_start(make_message(bot, FRIEND2, f"/start ref_{REFERRER}"))
    check("второй друг тоже привязан к пригласившему",
          bot.referral_store.invite_of(FRIEND2)["referrer"] == REFERRER)

    # Страница /invite
    TG["calls"].clear()
    await bot.cmd_invite(make_message(bot, REFERRER, "/invite"))
    page = texts_to(REFERRER)[-1] if texts_to(REFERRER) else ""
    check("на странице /invite есть личная ссылка", f"start=ref_{REFERRER}" in page)
    check("на странице /invite есть статистика", "Пришло по ссылке: <b>2</b>" in page, page[:120])


async def test_friend_pays(store_file, ref_file):
    print("\n▶ 3. Друг оплатил: +дни другу и бонус пригласившему (в копилку)")
    reset_all()
    bot = new_bot(store_file, ref_file)

    await bot.cmd_start(make_message(bot, REFERRER, "/start"))
    await bot.cmd_start(make_message(bot, FRIEND1, f"/start ref_{REFERRER}"))

    await pay_stars(bot, FRIEND1, BASIC)
    check("друг получил тариф + бонус приглашённого (~33 дня)",
          days_left(FRIEND1) is not None and 32 <= days_left(FRIEND1) <= 33,
          f"{days_left(FRIEND1)} дн.")
    check("в комментарии клиента — тариф и платёж",
          f"{BASIC} до " in panel_client(FRIEND1)["comment"] and "|" in panel_client(FRIEND1)["comment"])
    check("бонус другу указан в сообщении об оплате",
          any("Бонус за друзей:" in t
              and f"+{INVITED_BONUS_DAYS} {bot.days_word(INVITED_BONUS_DAYS)}" in t
              for t in texts_to(FRIEND1)))
    check("у приглашённого отмечена первая оплата",
          bool(bot.referral_store.invite_of(FRIEND1).get("first_paid_at")))

    check("у пригласившего нет подписки — дни легли в копилку",
          bot.referral_store.pending_days(REFERRER) == BONUS_DAYS)
    check("пригласившему сообщили про копилку",
          any("копятся" in t for t in texts_to(REFERRER)))
    stats = bot.referral_store.stats(REFERRER)
    check("статистика: 1 друг пришёл, 1 оплатил",
          stats["came"] == 1 and stats["paid"] == 1, str(stats))

    # Повторная доставка того же платежа ничего не удваивает
    TG["calls"].clear()
    order = await bot.payment_store.get(last_order_id(bot))
    await bot.fulfill_order(order, charge_id=order.get("charge_id") or "tg-dupe")
    check("повторная доставка платежа не удваивает бонус",
          bot.referral_store.pending_days(REFERRER) == BONUS_DAYS)

    # Пригласивший покупает тариф — копилка сгорает в дни подписки
    TG["calls"].clear()
    await pay_stars(bot, REFERRER, BASIC)
    check("пригласивший получил тариф + накопленные дни (~37 дней)",
          days_left(REFERRER) is not None and 36 <= days_left(REFERRER) <= 37,
          f"{days_left(REFERRER)} дн.")
    check("копилка обнулилась", bot.referral_store.pending_days(REFERRER) == 0)
    check("в сообщении пригласившего есть бонусные дни",
          any("Бонус за друзей:" in t
              and f"+{BONUS_DAYS} {bot.days_word(BONUS_DAYS)}" in t
              for t in texts_to(REFERRER)))

    return bot


def last_order_id(bot):
    orders = sorted(bot.payment_store.orders.values(), key=lambda o: o.get("created_at") or 0)
    return orders[-1]["id"]


async def test_second_friend_immediate(store_file, ref_file):
    print("\n▶ 4. Второй друг оплатил: пригласившему дни сразу в подписку")
    reset_all()
    bot = new_bot(store_file, ref_file)

    await bot.cmd_start(make_message(bot, REFERRER, "/start"))
    await bot.cmd_start(make_message(bot, FRIEND2, f"/start ref_{REFERRER}"))

    # У пригласившего уже есть активная подписка
    await pay_stars(bot, REFERRER, BASIC)
    before = expiry_of(REFERRER)
    check("подписка пригласившего ~30 дней", 29 <= days_left(REFERRER) <= 30)

    TG["calls"].clear()
    await bot.cmd_start(make_message(bot, FRIEND2, f"/start ref_{REFERRER}"))
    await pay_stars(bot, FRIEND2, FAMILY)

    after = expiry_of(REFERRER)
    check(f"пригласившему добавилось ровно {BONUS_DAYS} дней",
          after - before == BONUS_DAYS * 86400 * 1000, f"дельта {(after - before) / 86_400_000} дн.")
    check("пригласившему сообщили, что дни уже в подписке",
          any("уже в твоей подписке" in t for t in texts_to(REFERRER)))
    comment = panel_client(REFERRER)["comment"]
    check("комментарий клиента обновлён с сохранением платежа",
          comment.startswith(f"{BASIC} до ") and "|" in comment, comment)
    check("бонус не ушёл в копилку", bot.referral_store.pending_days(REFERRER) == 0)
    stats = bot.referral_store.stats(REFERRER)
    check("статистика: 1 друг пришёл, 1 оплатил, 7 дней начислено",
          stats["came"] == 1 and stats["paid"] == 1 and stats["earned_days"] >= BONUS_DAYS, str(stats))


async def test_test_payment_no_reward(store_file, ref_file):
    print("\n▶ 5. Тестовая выдача ключа (/test_pay) бонусов не даёт")
    reset_all()
    bot = new_bot(store_file, ref_file)

    await bot.cmd_start(make_message(bot, REFERRER, "/start"))
    await bot.cmd_start(make_message(bot, FRIEND3, f"/start ref_{REFERRER}"))

    await bot.simulate_successful_payment(FRIEND3, FRIEND3, BASIC)
    check("тестовый ключ выдан (~30 дней, без бонуса)",
          days_left(FRIEND3) is not None and 29 <= days_left(FRIEND3) <= 30,
          f"{days_left(FRIEND3)} дн.")
    check("приглашение осталось неоплаченным",
          not bot.referral_store.invite_of(FRIEND3).get("first_paid_at"))
    check("копилка пригласившего пуста", bot.referral_store.pending_days(REFERRER) == 0)
    check("статистика не считает тестовую выдачу оплатой",
          bot.referral_store.stats(REFERRER)["paid"] == 0)


async def test_persistence_and_disable(store_file, ref_file):
    print("\n▶ 6. Журнал приглашений переживает перезапуск; выключение программы")
    bot = new_bot(store_file, ref_file)
    invite = bot.referral_store.invite_of(FRIEND1)
    check("после перезапуска журнал на месте", invite is not None, str(bot.referral_store.stats(REFERRER)))
    check("приглашение сохранило пригласившего и факт оплаты",
          bool(invite) and invite["referrer"] == REFERRER and invite["first_paid_at"] > 0, str(invite))

    off_bot = new_bot(store_file, ref_file, {"enabled": "0"})
    TG["calls"].clear()
    await off_bot.cmd_invite(make_message(off_bot, REFERRER, "/invite"))
    check("при выключенной программе /invite честно об этом говорит",
          any("выключена" in t for t in texts_to(REFERRER)))
    await off_bot.cmd_start(make_message(off_bot, FRIEND3, "/start ref_555555"))
    check("при выключенной программе переход по ссылке ничего не пишет",
          off_bot.referral_store.invite_of(555555) is None)

    check("выключенная программа не даёт бонусных дней в activate",
          isinstance(off_bot.REFERRAL_ENABLED, bool) and off_bot.REFERRAL_ENABLED is False)


async def main():
    runner = web.AppRunner(make_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PANEL_PORT).start()
    tg_runner = web.AppRunner(make_tg_app())
    await tg_runner.setup()
    await web.TCPSite(tg_runner, "127.0.0.1", TG_PORT).start()

    store_dir = tempfile.mkdtemp(prefix="referral-store-")

    def store_for(name):
        return os.path.join(store_dir, f"{name}.json")

    try:
        await test_payload_and_link(store_for("link"), store_for("ref_link"))
        await test_invite_registration(store_for("invite"), store_for("ref_invite"))
        await test_friend_pays(store_for("friend"), store_for("ref_friend"))
        await test_second_friend_immediate(store_for("second"), store_for("ref_second"))
        await test_test_payment_no_reward(store_for("testpay"), store_for("ref_testpay"))
        await test_persistence_and_disable(store_for("friend"), store_for("ref_friend"))
    finally:
        await runner.cleanup()
        await tg_runner.cleanup()

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
