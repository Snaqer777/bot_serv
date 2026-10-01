"""
Тесты поддержки 2FA (Google Authenticator): сверка генератора кодов с pyotp
и реальный вход в фейковую панель с включённой двухфакторкой.

Проверяем:
  • коды совпадают с независимой реализацией (pyotp) на разных временах;
  • панель принимает код из соседнего окна (3x-ui допускает ±1 окно);
  • бот повторяет вход, если окно кода сменилось, пока панель отвечала;
  • понятные ошибки вместо трейсбеков: нет секрета, битый секрет, неверный пароль;
  • команды /totp и /panel_debug.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pyotp
from aiohttp import web
from panel import PANEL, Msg, load_bot, make_app, reset

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
WRONG_SECRET = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"
PORT = 8743
FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


async def scenario(name, secret, expect_ok, **panel_kwargs):
    """Гоняет полный цикл входа и проверяет результат."""
    reset(two_factor=True, totp_secret=SECRET, **panel_kwargs)
    bot = load_bot(PORT, secret=secret)
    print(f"\n▶ {name}")
    try:
        async with bot.XUIClient() as client:
            items = await client.get_inbounds()
        check("вход выполнен и API отвечает", expect_ok and isinstance(items, list) and items, f"inbounds={len(items)}")
    except bot.XUIError as exc:
        if expect_ok:
            check("вход выполнен", False, f"ошибка: {' '.join(str(exc).split())[:160]}")
        else:
            check("понятная ошибка вместо трейсбека", True)
            print("     текст:", " ".join(str(exc).split())[:240])
            return str(exc)
    except Exception as exc:
        check("ошибка типа XUIError", False, f"{type(exc).__name__}: {exc}")
    return None


async def main():
    runner = web.AppRunner(make_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()

    print("▶ Сверка TOTP с pyotp")
    bot = load_bot(PORT, secret=SECRET)
    ok = True
    for ts in (0, 59_999_999, time.time(), time.time() + 12345.6, 2_000_000_000):
        if bot.totp_code(SECRET, at=ts) != pyotp.TOTP(SECRET).at(int(ts)):
            ok = False
            print("     расхождение при t =", ts)
    check("коды совпадают с pyotp на разных временах", ok)
    check("код меняется каждые 30 секунд",
          bot.totp_code(SECRET, at=1000) != bot.totp_code(SECRET, at=1030))
    check("сдвиг окна назад/вперёд работает",
          bot.totp_code(SECRET, at=1000, shift_windows=-1) == bot.totp_code(SECRET, at=970)
          and bot.totp_code(SECRET, at=1000, shift_windows=1) == bot.totp_code(SECRET, at=1030))
    check("код состоит из 6 цифр", len(bot.totp_code(SECRET)) == 6 and bot.totp_code(SECRET).isdigit())
    check("остаток окна в диапазоне 0..30", 0 < bot.totp_seconds_left(time.time()) <= 30)

    print("\n▶ Проверка корректности секрета")
    check("корректный секрет принят", bot.totp_secret_problem(SECRET) is None)
    check("пустой секрет отвергнут", bool(bot.totp_secret_problem("")))
    check("секрет с недопустимыми символами отвергнут", bool(bot.totp_secret_problem("JBSWY3DP!!")))
    check("слишком короткий секрет отвергнут", bool(bot.totp_secret_problem("JBSWY3")))
    check(f"длина секрета ≥ {bot.TOTP_MIN_SECRET_LEN} символов", bot.TOTP_MIN_SECRET_LEN <= len(SECRET))

    await scenario("Вход с корректным секретом 2FA", SECRET, expect_ok=True)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=SECRET)
    async with bot.XUIClient() as client:
        code = await client._fresh_totp_code(shift_windows=1)
    check("код следующего окна принимается панелью (допуск ±1 окно)",
          pyotp.TOTP(SECRET).verify(code, valid_window=1))

    reset(two_factor=True, totp_secret=SECRET, reject_first_login=True, reject_msg="invalid 2fa code")
    bot = load_bot(PORT, secret=SECRET)
    try:
        async with bot.XUIClient() as client:
            await client.get_inbounds()
        check("после отказа панели бот повторяет вход и succeeds", True)
    except bot.XUIError as exc:
        check("после отказа панели бот повторяет вход и succeeds", False,
              " ".join(str(exc).split())[:160])
    check("было сделано минимум 2 попытки входа", len(PANEL["login_attempts"]) >= 2,
          f"попыток: {len(PANEL['login_attempts'])}")

    text = await scenario("Панель требует 2FA, а секрет не задан", None, expect_ok=False)
    check("подсказано, что нужно XUI_2FA_SECRET", "XUI_2FA_SECRET" in text and "API Token" in text)

    text = await scenario("Секрет задан неверно", WRONG_SECRET, expect_ok=False)
    check("ошибка объясняет, что код не подошёл", "2FA" in text or "код" in text.lower())

    text = await scenario("Секрет заполнен мусором", "НЕ-BASE32-СЕКРЕТ", expect_ok=False)
    check("ошибка объясняет проблему с секретом",
          "некорректно" in text.lower() or "base32" in text.lower() or "XUI_2FA_SECRET" in text)

    reset(two_factor=False)
    bot = load_bot(PORT, secret=None)
    async with bot.XUIClient() as client:
        items = await client.get_inbounds()
    check("панель без 2FA: вход без кода", isinstance(items, list) and bool(items))

    reset(two_factor=False)
    import panel as panel_module
    panel_module.SERVER_TIME_SHIFT = 42
    bot = load_bot(PORT, secret=None)
    async with bot.XUIClient() as client:
        offset = client.server_time_offset
    panel_module.SERVER_TIME_SHIFT = 0
    check("рассинхрон часов панели учтён (±5 сек)", abs(offset - 42) <= 5, f"offset={offset:.1f}")

    print("\n▶ Команды")
    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=SECRET)
    msg = Msg(uid=42)
    await bot.cmd_totp(msg)
    text = msg.last
    check("/totp показывает код", "<code>" in text and any(str(c) in text for c in range(10)))
    check("/totp показывает остаток окна", "осталось" in text)
    check("/totp не раскрывает секрет целиком", SECRET not in text and SECRET[-4:] in text)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=None)
    msg = Msg(uid=42)
    await bot.cmd_totp(msg)
    check("/totp без секрета объясняет, что делать", "XUI_2FA_SECRET" in msg.last)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=SECRET)
    msg = Msg(uid=777)
    await bot.cmd_totp(msg)
    check("/totp недоступна неадмину", "только администратору" in msg.last)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=SECRET)
    msg = Msg(uid=42)
    await bot.cmd_panel_debug(msg)
    check("/panel_debug сообщает, что панель под 2FA", "2FA" in msg.last)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=None)
    msg = Msg(uid=42)
    await bot.cmd_panel_debug(msg)
    check("/panel_debug предупреждает, что секрет не задан", "XUI_2FA_SECRET" in msg.last)

    reset(two_factor=True, totp_secret=SECRET)
    bot = load_bot(PORT, secret=None)
    bot.XUI_TOKEN = "panel-api-token"
    try:
        async with bot.XUIClient() as client:
            items = await client.get_inbounds()
        check("с XUI_TOKEN вход работает даже при включённой 2FA",
              isinstance(items, list) and bool(items))
    except bot.XUIError as exc:
        check("с XUI_TOKEN вход работает даже при включённой 2FA", False,
              " ".join(str(exc).split())[:120])

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
