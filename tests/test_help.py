"""
Тесты пошаговой инструкции по подключению (/help, кнопки «Как подключиться»).

Проверяем то, что видит пользователь: ссылки на официальные приложения, шаги
до рабочего подключения, проверку IP и чек-лист «не работает». Отдельно
следим, чтобы в инструкции не было сайтов-клонов и старых советов.

Запуск: python tests/test_help.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from panel import Msg, load_bot

FAILURES = []

SEO_CLONES = ("happ.press", "myhapp.works", "vpnhaapp.ru", "happvpn.su", "happvpn")
PLATFORMS = ("ios", "android", "windows", "macos", "tv")


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


def load(**env):
    full_env = {"PAYMENTS_MODE": "stars", "BOT_USERNAME": "myvpnbot"}
    full_env.update(env)
    return load_bot(8742, admins="42", env=full_env)


def callbacks_of(kb):
    return [b.callback_data for row in kb.inline_keyboard for b in row]


def button_texts(kb):
    return [b.text for row in kb.inline_keyboard for b in row]


def all_texts(*items):
    return "\n".join(items)


async def test_menu_and_command():
    print("\n▶ 1. Меню инструкции и команда /help")
    bot = load()
    kb = bot.install_menu_kb()
    cbs = callbacks_of(kb)
    check("в меню есть все устройства",
          all(f"help_{p}" in cbs for p in PLATFORMS), str(cbs))
    check("в меню есть проверка подключения и чек-лист",
          "help_check" in cbs and "help_trouble" in cbs)
    check("есть кнопки «мой ключ» и возврат в меню", "profile" in cbs and "main_menu" in cbs)
    check("текст входа объясняет, где взять ключ", "Мой профиль" in bot.INSTALL_INTRO)

    msg = Msg(42)
    await bot.cmd_help(msg)
    check("команда /help отвечает инструкцией", bot.INSTALL_INTRO[:20] in msg.last)

    # Псевдоним /install
    msg2 = Msg(42)
    await bot.cmd_install(msg2)
    check("команда /install — тот же экран", bot.INSTALL_INTRO[:20] in msg2.last)


async def test_platform_steps():
    print("\n▶ 2. Для каждого устройства: шаги, официальные ссылки, проверка IP")
    bot = load()
    links = bot.APP_LINKS
    for platform in PLATFORMS:
        text = bot.install_text(platform)
        steps = range(1, 5) if platform == "tv" else range(1, 6)
        check(f"{platform}: шаги {'1–4' if platform == 'tv' else '1–5'} на месте",
              all(f"Шаг {n}" in text for n in steps), "")
        check(f"{platform}: есть ссылка на скачивание клиента",
              "href=\"https://" in text)
        check(f"{platform}: ключ берётся из «Мой профиль»", "Мой профиль" in text)
        check(f"{platform}: есть проверка IP (2ip.ru)", "2ip.ru" in text)
        check(f"{platform}: нет старых советов через /test_vpn", "/test_vpn" not in text)
        check(f"{platform}: нет сайтов-клонов Happ",
              not any(clone in text for clone in SEO_CLONES))

    ios = bot.install_text("ios")
    check("iOS: предлагается клиент из российского App Store",
          "Streisand" in ios and "apps.apple.com" in ios)
    check("iOS: предупреждение про зарубежный Apple ID для Happ",
          "Apple ID" in ios)
    check("iOS: есть INCY из российского App Store",
          "INCY" in ios and "apps.apple.com/ru/app/incy/id6756943388" in ios)
    check("iOS: FoXray больше не предлагается", "FoXray" not in ios)
    android = bot.install_text("android")
    check("Android: v2rayNG и из Google Play, и APK", "Google Play" in android and "GitHub" in android)
    check("Android: Hiddify убран из списка", "Hiddify" not in android)
    check("Android: v2rayNG и Happ остались", "v2rayNG" in android and "Happ" in android)
    windows = bot.install_text("windows")
    check("Windows: v2rayN и системный прокси/TUN", "v2rayN" in windows and "прокси" in windows)
    tv = bot.install_text("tv")
    check("TV: подсказка про пульт/мышь", "мыш" in tv)

    # Ссылки в APP_LINKS — только официальные домены
    domains = " ".join(links.values())
    check("в ссылках есть официальные домены",
          "happ.su" in domains and "github.com/2dust/v2rayNG" in domains and "hiddify.com" in domains)
    check("в ссылках нет сайтов-клонов", not any(clone in domains for clone in SEO_CLONES))


async def test_check_and_trouble():
    print("\n▶ 3. Проверка подключения и чек-лист «не работает»")
    bot = load()
    check_text = bot.install_check_text()
    check("проверка: 2ip.ru и whoer.net", "2ip.ru" in check_text and "whoer.net" in check_text)
    check("проверка: что считается нормой", "Нормальные признаки" in check_text)
    check("проверка: понятный вывод, куда вернуться", "инструкцию" in check_text)

    trouble = bot.install_trouble_text()
    check("чек-лист: 7 пунктов", all(f"{n}️⃣" in trouble for n in range(1, 8)))
    check("чек-лист: разрешение VPN и режим полёта",
          "разреши создание VPN" in trouble and "полёта" in trouble)
    check("чек-лист: Always-on VPN для Android", "Always-on" in trouble)
    check("чек-лист: продление подписки", "Тарифы" in trouble)
    check("чек-лист: поддержка и /myid", "поддержку" in trouble and "/myid" in trouble)
    check("чек-лист: перевыпуск ключа", "Сбросить и получить заново" in trouble)


class FakeCallback:
    """Мини-заглушка CallbackQuery: хендлерам нужны data, from_user, message и answer()."""

    def __init__(self, data, msg, uid=42):
        self.data = data
        self.from_user = type("U", (), {"id": uid})()
        self.message = msg
        self.answered = False

    async def answer(self, *args, **kwargs):
        self.answered = True
        return True


def make_cb(bot, data, uid=42):
    msg = Msg(uid)
    return FakeCallback(data, msg, uid), msg


async def test_handlers():
    print("\n▶ 4. Кнопки работают: открывают нужный экран")
    bot = load()
    for platform in PLATFORMS:
        cb, msg = make_cb(bot, f"help_{platform}")
        await bot.cb_help_platform(cb)
        check(f"кнопка help_{platform} открывает свою инструкцию",
              msg.last == bot.install_text(platform))

    cb, msg = make_cb(bot, "help_check")
    await bot.cb_help_platform(cb)
    check("кнопка «Проверить подключение» открывает проверку", msg.last == bot.install_check_text())

    cb, msg = make_cb(bot, "help_trouble")
    await bot.cb_help_platform(cb)
    check("кнопка «Не работает» открывает чек-лист", msg.last == bot.install_trouble_text())

    cb, msg = make_cb(bot, "help_unknown")
    await bot.cb_help_platform(cb)
    check("неизвестная кнопка возвращает в меню устройств", msg.last == bot.INSTALL_INTRO)

    cb, msg = make_cb(bot, "help_menu")
    await bot.cb_help_menu(cb)
    check("«Другое устройство» возвращает меню устройств", msg.last == bot.INSTALL_INTRO)

    cb, msg = make_cb(bot, "activation")
    await bot.cb_activation(cb)
    check("старая кнопка «Инструкция по настройке» ведёт в новое меню",
          msg.last == bot.INSTALL_INTRO)


async def test_wiring():
    print("\n▶ 5. Кнопки в меню, после оплаты и в списке команд")
    bot = load()
    main_cbs = callbacks_of(bot.main_menu_kb())
    check("в главном меню — «Как подключиться»", "help_menu" in main_cbs, str(main_cbs))
    key_cbs = callbacks_of(bot.key_actions_kb())
    check("после выдачи ключа — кнопка инструкции", "help_menu" in key_cbs)
    check("после выдачи ключа — кнопка профиля с подпиской", "profile" in key_cbs)
    check("в главном меню — «Пригласить друга»", "invite" in main_cbs)

    info = {"tariff": bot.TARIFFS["time_3"], "expiry_ms": 4102444800000, "link": "vless://demo",
            "sub_link": "https://sub.example.com:2096/sub/demo", "status": "created"}
    paid_text = bot.order_paid_message({"id": "o-1", "simulated": False}, info)
    check("после оплаты зовём в пошаговую инструкцию", "Как подключиться" in paid_text)
    check("после оплаты нет старых советов", "/test_vpn" not in paid_text)
    check("после оплаты выдаётся ссылка-подписка",
          "ссылка-подписка" in paid_text and "/sub/demo" in paid_text)
    check("ключ vless в сообщении не показывается", "vless://" not in paid_text)

    # Команды видны в меню Telegram (on_startup дергает set_my_commands)
    commands_seen = []

    async def fake_set_my_commands(commands):
        commands_seen.extend(commands)

    bot.bot.set_my_commands = fake_set_my_commands
    await bot.on_startup()
    names = [c.command for c in commands_seen]
    check("в меню команд есть /help", "help" in names, str(names))
    check("в меню команд есть /invite", "invite" in names)


async def main():
    await test_menu_and_command()
    await test_platform_steps()
    await test_check_and_trouble()
    await test_handlers()
    await test_wiring()

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
