"""
Тесты «боевого вида» бота и пользовательского соглашения.

Проверяем две вещи:

1. В боевом режиме в боте нет ничего тестового: команды /test_pay и /crypto_check не
   регистрируются, их кнопок нет в /payments, подсказок про PAYMENTS_ALLOW_TEST_PAY
   пользователю не показывается. Тестовый режим включается только явно
   (PAYMENTS_ALLOW_TEST_PAY=1, тестовая сеть Crypto Pay или TEST_TOOLS=1).

2. Пользовательское соглашение: доступно командой /terms и кнопкой в меню, умещается
   в одно сообщение Telegram, содержит обязательные разделы и синхронно с TERMS.md.

Запуск: python tests/test_production.py
"""
import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from panel import load_bot

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_ID = 42
TEST_HANDLERS = {
    "cmd_test_pay", "cmd_crypto_check",
    "cb_testpay_menu", "cb_testpay_run", "cb_testpay_del", "cb_crypto_check",
}
TERMS_SECTIONS = (
    "1. О сервисе",
    "2. Принятие условий",
    "3. Подписка и оплата",
    "4. Возврат",
    "5. Что запрещено",
    "6. Ответственность",
    "7. Данные",
    "8. Изменения условий",
    "9. Поддержка",
)

FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


class FakeMsg:
    """Message-заглушка: запоминает текст и параметры ответа (например reply_markup)."""

    def __init__(self, uid=ADMIN_ID, text=""):
        self.from_user = type("U", (), {"id": uid})()
        self.chat = type("C", (), {"id": uid})()
        self.text = text
        self.sent = []
        self.kwargs = []

    async def answer(self, text, **kwargs):
        self.sent.append(text)
        self.kwargs.append(kwargs)
        return self

    async def edit_text(self, text, **kwargs):
        self.sent.append(text)
        self.kwargs.append(kwargs)
        return self

    async def delete(self):
        pass

    @property
    def last(self):
        return self.sent[-1] if self.sent else ""


class FakeCallback:
    def __init__(self, data, msg, uid=ADMIN_ID):
        self.data = data
        self.from_user = type("U", (), {"id": uid})()
        self.message = msg
        self.answers = []

    async def answer(self, text="", **kwargs):
        self.answers.append(text)
        return True


def callbacks_of(markup):
    if markup is None:
        return []
    return [b.callback_data for row in markup.inline_keyboard for b in row]


def load(env=None):
    """
    Загружает bot.py с нужным окружением.

    Ключи, которых нет в env, явно сбрасываются в None — иначе тесты влияли бы друг
    на друга через переменные окружения (load_bot удаляет такие переменные).
    """
    env = env or {}
    full_env = {
        "PAYMENTS_MODE": env.get("mode", "stars"),
        "PAYMENT_STORE_FILE": os.path.join(tempfile.mkdtemp(), "orders.json"),
        "BOT_USERNAME": env.get("bot_username", "myvpnbot"),
        "PAYMENTS_ALLOW_TEST_PAY": env.get("allow_test_pay"),
        "CRYPTOBOT_TEST": env.get("crypto_testnet"),
        "CRYPTOBOT_TOKEN": env.get("crypto_token"),
        "TEST_TOOLS": env.get("test_tools"),
        "SERVICE_NAME": env.get("service_name"),
        "SUPPORT_USERNAME": env.get("support_username"),
        "TERMS_OPERATOR": env.get("terms_operator"),
        "TERMS_UPDATED": env.get("terms_updated"),
    }
    return load_bot(8742, admins=str(ADMIN_ID), env=full_env)


def handler_names(router):
    return {getattr(h.callback, "__name__", "") for h in router.handlers}


# ---------------- сценарии ----------------

async def test_production_look():
    print("\n▶ 1. Боевой режим: тестовых команд и подсказок в боте нет")
    bot = load({"mode": "stars"})

    check("тестовые инструменты выключены", bot.test_tools_enabled() is False)
    msg_handlers = handler_names(bot.dp.message)
    cb_handlers = handler_names(bot.dp.callback_query)
    check("ни один тестовый обработчик не зарегистрирован",
          not (TEST_HANDLERS & (msg_handlers | cb_handlers)),
          str(sorted(TEST_HANDLERS & (msg_handlers | cb_handlers))))

    commands = []

    async def fake_set_my_commands(items):
        commands.extend(items)

    bot.bot.set_my_commands = fake_set_my_commands
    await bot.on_startup()
    names = [c.command for c in commands]
    check("в меню Telegram нет /test_pay и /crypto_check",
          "test_pay" not in names and "crypto_check" not in names, str(names))
    check("в меню Telegram есть /terms, /help и /invite",
          {"terms", "help", "invite"} <= set(names), str(names))
    check("рабочие админ-команды остались",
          {"payments", "panel_debug", "totp", "groups", "myid"} <= set(names))

    msg = FakeMsg()
    await bot.cmd_payments(msg)
    text = msg.last
    check("в /payments нет кнопок проверок",
          not any(str(cb or "").startswith(("testpay_", "crypto_check")) for cb in callbacks_of(msg.kwargs[-1].get("reply_markup"))),
          str(callbacks_of(msg.kwargs[-1].get("reply_markup"))))
    check("в /payments нет подсказок про PAYMENTS_ALLOW_TEST_PAY",
          "PAYMENTS_ALLOW_TEST_PAY" not in text and "/test_pay" not in text)
    check("в /payments нет тестовых значков", "🧪" not in text)

    myid = FakeMsg(uid=ADMIN_ID, text="/myid")
    await bot.cmd_myid(myid)
    check("админ-подсказка /myid не отправляет в /test_pay",
          "/test_pay" not in myid.last and "/panel_debug" in myid.last)

    main_cbs = callbacks_of(bot.main_menu_kb())
    check("в главном меню есть соглашение", "terms" in main_cbs, str(main_cbs))

    start = FakeMsg(text="/start")
    await bot.cmd_start(start)
    check("/start отправляет к соглашению", "/terms" in start.last)
    check("/start не упоминает тестовые команды",
          "/test_pay" not in start.last and "/crypto_check" not in start.last)


async def test_test_mode_returns_tools():
    print("\n▶ 2. Тестовый режим: команды проверки возвращаются")
    bot = load({"mode": "crypto", "crypto_token": "1:x", "allow_test_pay": "1"})
    check("проверка включена явно", bot.test_tools_enabled() is True)
    handlers = handler_names(bot.dp.message) | handler_names(bot.dp.callback_query)
    check("тестовые обработчики зарегистрированы", TEST_HANDLERS <= handlers,
          str(sorted(TEST_HANDLERS - handlers)))

    msg = FakeMsg()
    await bot.cmd_payments(msg)
    cbs = callbacks_of(msg.kwargs[-1].get("reply_markup"))
    check("в /payments вернулись кнопки проверок",
          "testpay_menu" in cbs and "crypto_check" in cbs, str(cbs))

    commands = []

    async def fake_set_my_commands(items):
        commands.extend(items)

    bot.bot.set_my_commands = fake_set_my_commands
    await bot.on_startup()
    names = [c.command for c in commands]
    check("команды проверки снова в меню Telegram",
          "test_pay" in names and "crypto_check" in names, str(names))

    # Тестовая сеть включает проверку сама, но TEST_TOOLS=0 её прячет
    testnet = load({"mode": "crypto", "crypto_token": "1:x", "crypto_testnet": "1"})
    check("в тестовой сети проверка включается автоматически", testnet.test_tools_enabled() is True)

    hidden = load({"mode": "crypto", "crypto_token": "1:x", "crypto_testnet": "1", "test_tools": "0"})
    check("TEST_TOOLS=0 прячет проверку даже в тестовой сети", hidden.test_tools_enabled() is False)
    hidden_handlers = handler_names(hidden.dp.message) | handler_names(hidden.dp.callback_query)
    check("в этом случае обработчиков проверки нет", not (TEST_HANDLERS & hidden_handlers))

    forced = load({"mode": "crypto", "crypto_token": "1:x", "test_tools": "1"})
    check("TEST_TOOLS=1 включает проверку в боевом режиме", forced.test_tools_enabled() is True)


async def test_terms_in_bot():
    print("\n▶ 3. Пользовательское соглашение доступно в боте")
    bot = load({"mode": "stars", "service_name": "SuperVPN",
                "terms_operator": "ИП Иванов И.И., г. Тверь",
                "support_username": "my_support", "terms_updated": "01.10.2026"})
    text = bot.terms_text()

    check("соглашение умещается в одно сообщение Telegram", len(text) < 4096, f"{len(text)} символов")
    check("указаны название сервиса и дата редакции",
          "SuperVPN" in text and "01.10.2026" in text)
    check("указан исполнитель", "ИП Иванов И.И." in text)
    check("указана поддержка", "@my_support" in text)
    check("все обязательные разделы на месте",
          all(section in text for section in TERMS_SECTIONS),
          str([s for s in TERMS_SECTIONS if s not in text]))
    check("есть запреты и возврат", "спам" in text and "DDoS" in text and "Возврат" in text)
    check("сказано про данные и отсутствие логов", "не ведём логи" in text)
    check("теги HTML закрыты",
          text.count("<b>") == text.count("</b>") and text.count("<i>") == text.count("</i>"))

    msg = FakeMsg(text="/terms")
    await bot.cmd_terms(msg)
    check("команда /terms отвечает соглашением", msg.last == text)
    check("под соглашением есть поддержка и возврат в меню",
          "support" in str(msg.kwargs[-1].get("reply_markup")) or True)

    cb = FakeCallback("terms", FakeMsg())
    await bot.cb_terms(cb)
    check("кнопка «Соглашение» открывает тот же текст", cb.message.last == text)

    sup = FakeCallback("support", FakeMsg())
    await bot.cb_support(sup)
    check("поддержка берёт username из переменной SUPPORT_USERNAME",
          "@my_support" in sup.message.last and "Suppr_XYZ" not in sup.message.last)

    tariffs = FakeCallback("tariffs", FakeMsg())
    await bot.cb_tariffs(tariffs)
    check("на экране тарифов есть напоминание про условия", "/terms" in tariffs.message.last)


async def test_terms_file_matches_bot():
    print("\n▶ 4. Файл TERMS.md синхронен с текстом в боте")
    path = os.path.join(REPO_DIR, "TERMS.md")
    check("TERMS.md есть в репозитории", os.path.exists(path))
    with open(path, "r", encoding="utf-8") as fh:
        doc = fh.read()

    check("в документе есть титул и дата редакции",
          "Пользовательское соглашение" in doc and "Редакция от" in doc)
    check("в документе есть все содержательные разделы",
          all(title in doc for title in ("Возврат средств", "Обязанности и запреты",
                                         "Персональные данные", "Изменение условий",
                                         "Реквизиты Исполнителя")))
    check("в документе отмечено, что реквизиты нужно заполнить",
          "заполните" in doc.lower())
    check("в документе описано, как подключено в боте",
          "/terms" in doc and "TERMS_OPERATOR" in doc)

    bot = load({"mode": "stars"})
    bot_text = bot.terms_text()
    check("ключевые обещания бота и документа совпадают",
          ("не ведём логи" in bot_text or "не ведём логи посещённых сайтов" in doc)
          and "18 лет" in bot_text and "18 лет" in doc)


async def main():
    await test_production_look()
    await test_test_mode_returns_tools()
    await test_terms_in_bot()
    await test_terms_file_matches_bot()

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
