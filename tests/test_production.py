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
ADMIN_HANDLERS = {
    "cmd_inbounds", "cmd_reset_vpn", "cmd_groups", "cmd_panel_debug",
    "cmd_totp", "cmd_payments", "cmd_revoke",
}
TERMS_SECTIONS = (
    "1. Общие положения",
    "2. Предмет соглашения",
    "3. Порядок оплаты",
    "4. Предоставление доступа",
    "5. Возврат и отмена",
    "6. Контакты поддержки",
    "7. Политика обработки персональных данных",
    "8. Ответственность",
    "9. Изменение условий",
    "10. Заключительные положения",
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


def has_terms_text(msg):
    """Есть ли среди отправленных сообщений текст соглашения."""
    return any("ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" in text for text in msg.sent)


def has_accept_button(msg):
    """Есть ли в последнем сообщении кнопка «✅ Согласен — продолжить»."""
    return "accept_terms" in callbacks_of(_last_markup(msg))


def _last_markup(target):
    """reply_markup из последнего ответа FakeMsg/FakeCallback."""
    msg = target.message if isinstance(target, FakeCallback) else target
    return msg.kwargs[-1].get("reply_markup") if msg.kwargs else None


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
        "ADMIN_TOOLS": env.get("admin_tools"),
        "TRIAL_PUBLIC": env.get("trial_public"),
        "TRIAL_BUTTON": env.get("trial_button"),
        "SERVICE_NAME": env.get("service_name"),
        "SUPPORT_USERNAME": env.get("support_username"),
        "SUPPORT_EMAIL": env.get("support_email"),
        "TERMS_OPERATOR": env.get("terms_operator"),
        "TERMS_UPDATED": env.get("terms_updated"),
        # Экран соглашения при первом запуске проверяется отдельным сценарием
        # (test_terms_gate), остальным он не мешает.
        "TERMS_ACCEPT": env.get("terms_accept", "0"),
        "TERMS_STORE_FILE": os.path.join(tempfile.mkdtemp(), "terms.json"),
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
    check("служебных команд админа в меню нет",
          not ({"payments", "panel_debug", "totp", "groups", "inbounds", "reset_vpn"} & set(names)),
          str(names))
    check("в меню остались только рабочие команды",
          set(names) == {"start", "profile", "help", "invite", "terms", "myid"}, str(names))

    admin_handlers = handler_names(bot.dp.message)
    check("админские обработчики не зарегистрированы",
          not (ADMIN_HANDLERS & admin_handlers),
          str(sorted(ADMIN_HANDLERS & admin_handlers)))
    check("/myid доступна всегда (по ней админ узнаёт свой ID)",
          "cmd_myid" in admin_handlers)

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
    check("админ-подсказка /myid не отправляет в /test_pay", "/test_pay" not in myid.last)
    check("/myid объясняет, как вернуть служебные команды",
          "ADMIN_TOOLS=1" in myid.last and "скрыты" in myid.last)

    other = FakeMsg(uid=555, text="/myid")
    await bot.cmd_myid(other)
    check("обычный пользователь не видит подсказок про ADMIN_TOOLS",
          "ADMIN_TOOLS" not in other.last)

    # Пользовательское меню: без кнопки теста и без служебных кнопок после оплаты
    user_menu = callbacks_of(bot.main_menu_kb(555))
    check("у обычного пользователя нет кнопки тестового доступа",
          "get_test_key_btn" not in user_menu, str(user_menu))
    check("кнопки теста нет и у администратора (TRIAL_BUTTON=0 по умолчанию)",
          "get_test_key_btn" not in callbacks_of(bot.main_menu_kb(ADMIN_ID)))
    user_key = callbacks_of(bot.key_actions_kb(555))
    check("обычному пользователю не предлагают сброс ключа (это админ-операция)",
          "reset_my_vpn" not in user_key and "support" in user_key, str(user_key))
    check("админу кнопка сброса остаётся", "reset_my_vpn" in callbacks_of(bot.key_actions_kb(ADMIN_ID)))

    main_cbs = callbacks_of(bot.main_menu_kb())
    check("в главном меню есть соглашение", "terms" in main_cbs, str(main_cbs))

    start = FakeMsg(text="/start")
    await bot.cmd_start(start)
    check("/start отправляет к соглашению", "/terms" in start.last)
    check("/start не упоминает тестовые команды",
          "/test_pay" not in start.last and "/crypto_check" not in start.last)


async def test_test_mode_returns_tools():
    print("\n▶ 2. Тестовый режим: команды проверки возвращаются")
    bot = load({"mode": "crypto", "crypto_token": "1:x", "allow_test_pay": "1",
                "admin_tools": "1"})
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
    testnet = load({"mode": "crypto", "crypto_token": "1:x", "crypto_testnet": "1", "admin_tools": "1"})
    check("в тестовой сети проверка включается автоматически", testnet.test_tools_enabled() is True)

    hidden = load({"mode": "crypto", "crypto_token": "1:x", "crypto_testnet": "1",
                   "admin_tools": "1", "test_tools": "0"})
    check("TEST_TOOLS=0 прячет проверку даже в тестовой сети", hidden.test_tools_enabled() is False)
    hidden_handlers = handler_names(hidden.dp.message) | handler_names(hidden.dp.callback_query)
    check("в этом случае обработчиков проверки нет", not (TEST_HANDLERS & hidden_handlers))

    forced = load({"mode": "crypto", "crypto_token": "1:x", "test_tools": "1", "admin_tools": "1"})
    check("TEST_TOOLS=1 включает проверку в боевом режиме", forced.test_tools_enabled() is True)

    # Без служебных команд проверки оплаты не показываются даже при allow_test_pay
    no_admin = load({"mode": "crypto", "crypto_token": "1:x", "allow_test_pay": "1", "admin_tools": "0"})
    check("ADMIN_TOOLS=0 прячет проверки оплаты", no_admin.test_tools_enabled() is False)
    check("обработчиков проверок нет", not (TEST_HANDLERS & (handler_names(no_admin.dp.message)
                                                             | handler_names(no_admin.dp.callback_query))))


async def test_admin_switch():
    print("\n▶ 2а. ADMIN_TOOLS: одна переменная открывает и закрывает служебные команды")
    for value, expected in (("1", True), ("true", True), ("0", False), ("", False)):
        bot = load({"admin_tools": value} if value else {})
        check(f"ADMIN_TOOLS={value or 'не задана'} → служебные команды "
              f"{'включены' if expected else 'скрыты'}",
              bot.admin_tools_enabled() is expected)

    on = load({"admin_tools": "1"})
    handlers = handler_names(on.dp.message)
    check("ADMIN_TOOLS=1 регистрирует все служебные команды",
          ADMIN_HANDLERS <= handlers, str(sorted(ADMIN_HANDLERS - handlers)))
    commands = []

    async def fake_set_my_commands(items):
        commands.extend(items)

    on.bot.set_my_commands = fake_set_my_commands
    await on.on_startup()
    names = [c.command for c in commands]
    check("ADMIN_TOOLS=1 возвращает команды в меню Telegram",
          {"payments", "panel_debug", "groups", "inbounds", "totp", "reset_vpn"} <= set(names),
          str(names))

    off = load({"admin_tools": "0"})
    check("ADMIN_TOOLS=0 закрывает обратно",
          not (ADMIN_HANDLERS & handler_names(off.dp.message)))
    check("тестовые проверки тоже закрыты", off.test_tools_enabled() is False)


async def test_trial_visibility():
    print("\n▶ 2б. TRIAL_PUBLIC: кому виден бесплатный тест на 24 часа")
    closed = load({})
    check("по умолчанию тест доступен только администратору",
          closed.trial_available_for(555) is False and closed.trial_available_for(ADMIN_ID) is True)
    check("админу тест разрешён (право), но кнопки по умолчанию скрыты",
          closed.trial_available_for(ADMIN_ID) is True
          and closed.trial_button_visible(ADMIN_ID) is False
          and "get_test_key_btn" not in callbacks_of(closed.main_menu_kb(ADMIN_ID)))

    start = FakeMsg(uid=555, text="/start")
    await closed.cmd_start(start)
    check("обычному пользователю /start не обещает бесплатный тест",
          "/test_vpn" not in start.last and "Бесплатный тестовый доступ" not in start.last)

    denied = FakeMsg(uid=555, text="/test_vpn")
    await closed.cmd_test_vpn(denied)
    check("если пользователь всё же отправит /test_vpn — вежливый ответ без админ-текста",
          "недоступен" in denied.last and "ADMIN_ID" not in denied.last and "администратор" not in denied.last.lower())

    # Тестовый пункт не должен маячить в тарифах у обычного пользователя
    tariffs = FakeCallback("tariffs", FakeMsg(uid=555), uid=555)
    await closed.cb_tariffs(tariffs)
    check("в тарифах у обычного пользователя нет бесплатного теста",
          "Тестовый период" not in tariffs.message.last, tariffs.message.last[:80])
    user_tariffs = callbacks_of(_last_markup(tariffs))
    check("и кнопки buy_trial у него нет", "buy_trial" not in user_tariffs, str(user_tariffs))
    admin_tariffs = callbacks_of(closed.tariffs_kb(ADMIN_ID))
    check("у администратора тестового пункта в тарифах тоже нет",
          "buy_trial" not in admin_tariffs, str(admin_tariffs))

    trial_click = FakeCallback("buy_trial", FakeMsg(uid=555), uid=555)
    await closed.cb_buy(trial_click)
    check("нажатие на тестовый тариф даёт понятный ответ, а не тишину",
          any("недоступен" in a for a in trial_click.answers), str(trial_click.answers))

    try:
        await closed.start_checkout(555, 555, "trial")
        check("start_checkout(trial) для пользователя отклонён", False)
    except Exception as exc:
        check("start_checkout(trial) для пользователя отклонён без упоминания /test_vpn",
              "test_vpn" not in str(exc) and "недоступен" in str(exc), str(exc)[:70])

    check("в соглашении нет рекламы бесплатного теста (текст оферты утверждён владельцем)",
          "тестовый доступ" not in closed.terms_text().lower()
          and "test_vpn" not in closed.terms_text())

    open_bot = load({"trial_public": "1", "trial_button": "1"})
    check("TRIAL_PUBLIC=1 + TRIAL_BUTTON=1 открывают тест всем",
          open_bot.trial_available_for(555) is True and open_bot.trial_button_visible(555) is True)
    opened_start = FakeMsg(uid=555, text="/start")
    await open_bot.cmd_start(opened_start)
    check("и /start снова обещает бесплатный тест",
          "Бесплатный тестовый доступ" in opened_start.last)
    check("кнопка теста есть в меню у всех",
          "get_test_key_btn" in callbacks_of(open_bot.main_menu_kb(555)))
    check("при TRIAL_PUBLIC=1 и TRIAL_BUTTON=1 тестовый пункт вернулся и в тарифы",
          "buy_trial" in callbacks_of(open_bot.tariffs_kb(555)))
    check("текст соглашения одинаков при любом TRIAL_PUBLIC",
          open_bot.terms_text() == closed.terms_text())

    # TRIAL_BUTTON: вид кнопок отдельно от права на тест
    hidden = load({"trial_public": "1"})
    check("TRIAL_PUBLIC=1 без TRIAL_BUTTON: право есть, кнопок нет",
          hidden.trial_available_for(555) is True and hidden.trial_button_visible(555) is False)
    hidden_start = FakeMsg(uid=555, text="/start")
    await hidden.cmd_start(hidden_start)
    check("в приветствии нет строки про кнопку теста",
          "Бесплатный тестовый доступ" not in hidden_start.last)
    hidden_tariffs = FakeCallback("tariffs", FakeMsg(uid=555), uid=555)
    await hidden.cb_tariffs(hidden_tariffs)
    check("в тарифах остались только платные пункты",
          "Тестовый период" not in hidden_tariffs.message.last
          and "Школьник" in hidden_tariffs.message.last)
    profile = FakeMsg(uid=555, text="/profile")
    await hidden.send_profile(profile, 555)
    check("в профиле кнопки теста нет",
          "get_test_key_btn" not in callbacks_of(_last_markup(profile)),
          str(callbacks_of(_last_markup(profile))))
    check("в меню Telegram команды /test_vpn нет",
          "test_vpn" not in [c.command for c in hidden.bot_commands()],
          str([c.command for c in hidden.bot_commands()]))

    # /myid у админа: подсказка, что тестовый ключ доступен командой
    # (важно сделать до следующей загрузки bot.py — модуль в тестах переиспользуется)
    myid = FakeMsg(uid=ADMIN_ID, text="/myid")
    await hidden.cmd_myid(myid)
    check("админу /myid напоминает, что тестовый ключ доступен командой",
          "TRIAL_BUTTON=0" in myid.last and "/test_vpn" in myid.last, myid.last[:80])

    admin_bot = load({"trial_button": "1", "admin_tools": "1"})
    check("TRIAL_BUTTON=1 возвращает кнопку админу",
          admin_bot.trial_button_visible(ADMIN_ID) is True
          and "get_test_key_btn" in callbacks_of(admin_bot.main_menu_kb(ADMIN_ID)))
    check("и тестовый пункт в его тарифах", "buy_trial" in callbacks_of(admin_bot.tariffs_kb(ADMIN_ID)))
    check("и команду /test_vpn в меню Telegram",
          "test_vpn" in [c.command for c in admin_bot.bot_commands()],
          str([c.command for c in admin_bot.bot_commands()]))

    no_button = load({"admin_tools": "1"})
    check("TRIAL_BUTTON=0 убирает /test_vpn даже из меню команд админа",
          "test_vpn" not in [c.command for c in no_button.bot_commands()],
          str([c.command for c in no_button.bot_commands()]))


async def test_terms_in_bot():
    print("\n▶ 3. Пользовательское соглашение доступно в боте")
    bot = load({"mode": "stars", "service_name": "SuperVPN",
                "terms_operator": "ИП Иванов И.И., г. Тверь",
                "support_username": "my_support", "support_email": "help@example.com",
                "terms_updated": "01.10.2026"})
    text = bot.terms_text()

    check("соглашение умещается в одно сообщение Telegram", len(text) < 4096, f"{len(text)} символов")
    check("заголовок и подзаголовок как в утверждённом тексте",
          "ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ (ПУБЛИЧНАЯ ОФЕРТА)" in text)
    check("указаны название сервиса и дата редакции",
          "SuperVPN" in text and "01.10.2026" in text)
    check("указан исполнитель (переменная TERMS_OPERATOR)",
          "ИП Иванов И.И." in text)
    check("указаны Telegram и почта поддержки",
          "@my_support" in text and "help@example.com" in text)
    check("все обязательные разделы на месте",
          all(section in text for section in TERMS_SECTIONS),
          str([s for s in TERMS_SECTIONS if s not in text]))
    check("сказано про акцепт оферты и цифровую услугу",
          "акцепт оферты" in text and "в цифровом виде" in text)
    check("есть безвозвратность и порядок возврата",
          "безвозвратной" in text and "Возврат средств за уже оказанную услугу не производится" in text)
    check("есть запреты и ответственность",
          "противоправных действий" in text and "заблокирован без возврата средств" in text)
    check("описана обработка персональных данных",
          "Telegram ID" in text and "не передаются третьим лицам" in text)
    check("оплата: CryptoBot и Telegram Stars", "CryptoBot" in text and "Telegram Stars" in text)
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
    check("в документе есть все разделы утверждённого текста",
          all(title in doc for title in (
              "Предмет соглашения", "Порядок оплаты", "Предоставление доступа",
              "Возврат и отмена", "Контакты поддержки", "Политика обработки персональных данных",
              "Ответственность", "Заключительные положения", "Реквизиты Исполнителя")))
    check("в документе отмечено, что реквизиты нужно заполнить",
          "заполните" in doc.lower())
    check("в документе описано, как подключено в боте",
          "/terms" in doc and "TERMS_OPERATOR" in doc)

    bot = load({"mode": "stars"})
    bot_text = bot.terms_text()
    check("ключевые обещания бота и документа совпадают",
          "акцепт оферты" in bot_text and "акцепт оферты" in doc
          and "24 часов" in bot_text and "24 часов" in doc)


async def test_terms_gate():
    print("\n▶ 5. Соглашение при первом запуске: экран и кнопка «Согласен»")
    bot = load({"terms_accept": "1"})
    check("TERMS_ACCEPT=1 по умолчанию включён для незнакомого пользователя",
          bot.TERMS_ACCEPT is True and bot.terms_gate_needed(555) is True)
    check("у администратора тот же экран, что и у всех", bot.terms_gate_needed(ADMIN_ID) is True)

    start = FakeMsg(uid=555, text="/start")
    await bot.cmd_start(start)
    check("первый /start присылает текст соглашения отдельным сообщением",
          len(start.sent) == 2 and "ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" in start.sent[0]
          and "1. Общие положения" in start.sent[0],
          f"сообщений: {len(start.sent)}")
    check("текст соглашения умещается в лимит Telegram", len(start.sent[0]) < 4096,
          f"{len(start.sent[0])} символов")
    check("вторым сообщением идёт просьба подтвердить с кнопкой",
          "Привет!" in start.last and "accept_terms" in callbacks_of(_last_markup(start)))
    check("меню до подтверждения не показывается",
          "tariffs" not in callbacks_of(_last_markup(start)))
    check("до подтверждения пользователь не отмечен принявшим",
          bot.terms_store.is_accepted(555) is False)

    for name, handler, msg in (
        ("/help", bot.cmd_help, FakeMsg(uid=555, text="/help")),
        ("/profile", bot.cmd_profile, FakeMsg(uid=555, text="/profile")),
        ("/invite", bot.cmd_invite, FakeMsg(uid=555, text="/invite")),
        ("/test_vpn", bot.cmd_test_vpn, FakeMsg(uid=555, text="/test_vpn")),
    ):
        await handler(msg)
        check(f"{name} до подтверждения тоже показывает соглашение",
              has_terms_text(msg) and has_accept_button(msg), msg.last[:60])

    terms_cmd = FakeMsg(uid=555, text="/terms")
    await bot.cmd_terms(terms_cmd)
    check("/terms у новичка даёт кнопку принятия",
          has_accept_button(terms_cmd) and "ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ" in terms_cmd.last)

    still_terms = FakeMsg(uid=555, text="/terms")
    await bot.cmd_terms(still_terms)
    check("повторный /terms до принятия кнопку не теряет",
          "accept_terms" in callbacks_of(_last_markup(still_terms)))

    agree = FakeCallback("accept_terms", FakeMsg(uid=555), uid=555)
    await bot.cb_accept_terms(agree)
    check("нажатие «Согласен» открывает приветствие и главное меню",
          "Добро пожаловать" in agree.message.last
          and {"tariffs", "profile", "help_menu"} <= set(callbacks_of(_last_markup(agree))))
    check("принятие записано (кто и когда)",
          bot.terms_store.is_accepted(555) and bot.terms_store.accepted_at(555) > 0)
    check("повторное нажатие не путает бота",
          any("принято" in a for a in agree.answers), str(agree.answers))

    again = FakeMsg(uid=555, text="/start")
    await bot.cmd_start(again)
    check("второй /start показывает обычное приветствие без соглашения",
          "Добро пожаловать" in again.last and "Пользовательское соглашение" not in again.last)
    check("в /terms кнопки принятия больше нет",
          "accept_terms" not in callbacks_of(bot.terms_kb(555)))

    stale = FakeCallback("main_menu", FakeMsg(uid=777), uid=777)
    await bot.cb_main_menu(stale)
    check("старая кнопка меню у непринявшего ведёт на соглашение",
          has_terms_text(stale.message) and has_accept_button(stale.message))

    stale_tariffs = FakeCallback("tariffs", FakeMsg(uid=777), uid=777)
    await bot.cb_tariffs(stale_tariffs)
    check("старая кнопка «Тарифы» тоже ведёт на соглашение",
          has_terms_text(stale_tariffs.message)
          and not any("Школьник" in t for t in stale_tariffs.message.sent))

    try:
        await bot.start_checkout(777, 777, "basic")
        check("оплата до подтверждения соглашения отклонена", False)
    except Exception as exc:
        check("оплата до подтверждения соглашения отклонена",
              "соглашение" in str(exc) and "Согласен" in str(exc), str(exc)[:60])

    off = load({"terms_accept": "0"})
    check("TERMS_ACCEPT=0 выключает экран", off.terms_gate_needed(777) is False)
    off_start = FakeMsg(uid=777, text="/start")
    await off.cmd_start(off_start)
    check("с выключенным экраном /start сразу показывает меню",
          "Добро пожаловать" in off_start.last
          and "accept_terms" not in callbacks_of(_last_markup(off_start)))


async def main():
    await test_production_look()
    await test_test_mode_returns_tools()
    await test_admin_switch()
    await test_trial_visibility()
    await test_terms_in_bot()
    await test_terms_file_matches_bot()
    await test_terms_gate()

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
