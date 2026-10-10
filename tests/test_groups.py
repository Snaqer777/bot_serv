"""
Тесты работы бота с группами клиентов 3x-ui (панель 3.2+).

Проверяем, что клиенты бота попадают именно в УЖЕ СОЗДАННУЮ группу панели:
  • поиск группы панели без учёта регистра и с подсказкой похожих названий;
  • четыре состояния (exists / new / unsupported / disabled);
  • статусы привязки (assigned / assigned_new / not_assigned / unsupported / skipped);
  • тексты сообщений пользователю и команду /groups.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aiohttp import web
from panel import PANEL, Msg, load_bot, make_app, reset

PORT = 8742
FAILURES = []


def check(name, cond, extra=""):
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILURES.append(name)


async def test_group_matching():
    print("\n▶ 1. Поиск группы панели (регистр, отсутствие, похожие названия)")
    bot = load_bot(PORT, group="bot-test")

    check("точное совпадение", bot.XUIClient.group_exists([{"name": "bot-test"}]) == "bot-test")
    check("регистр не важен: «Bot-Test» найдена по «bot-test»",
          bot.XUIClient.group_exists([{"name": "Bot-Test"}]) == "Bot-Test")
    check("лишние пробелы в названии не мешают",
          bot.XUIClient.group_exists([{"name": " bot-test "}]) == "bot-test")
    check("группы нет — None", bot.XUIClient.group_exists([{"name": "other"}]) is None)
    check("пустой список групп — None", bot.XUIClient.group_exists([]) is None)

    similar = bot.XUIClient.similar_groups([{"name": "bot-tests"}, {"name": "production"}])
    check("подсказка похожих названий работает", similar == ["bot-tests"], f"{similar}")
    check("случайное название не считается похожим",
          bot.XUIClient.similar_groups([{"name": "production"}]) == [])

    names = bot.XUIClient.group_names([{"name": "a"}, {}, {"name": "b"}])
    check("пустые записи групп отбрасываются", names == ["a", "b"])


async def test_resolve_states():
    print("\n▶ 2. Состояния группы: exists / new / unsupported / disabled")
    reset(groups={"Bot-Test"})
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        name, state = await client.resolve_client_group()
    check("группа есть в панели → exists и название из панели", (name, state) == ("Bot-Test", "exists"), f"{name}/{state}")

    reset(groups={"production"})
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        name, state = await client.resolve_client_group()
    check("группы нет → new (панель создаст при выдаче ключа)", (name, state) == ("bot-test", "new"))

    reset(supports_groups=False)
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        name, state = await client.resolve_client_group()
    check("панель старее 3.2 → unsupported", (name, state) == (None, "unsupported"))

    reset()
    bot = load_bot(PORT, group=None)
    async with bot.XUIClient() as client:
        name, state = await client.resolve_client_group()
    check("XUI_CLIENT_GROUP не задана → disabled", (name, state) == (None, "disabled"))


async def test_group_statuses():
    print("\n▶ 3. Статусы привязки клиента к группе")
    reset()
    bot = load_bot(PORT, group=None)
    async with bot.XUIClient() as client:
        check("без XUI_CLIENT_GROUP → skipped",
              await client.add_clients_to_group(["tg-test-42"], "bot-test") == "skipped")
        check("без email → skipped",
              await client.add_clients_to_group([], "bot-test") == "skipped")

    reset(groups={"bot-test"}, clients={"tg-test-42": {"id": "u1", "email": "tg-test-42", "expiryTime": 0, "enable": True}})
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        status = await client.add_clients_to_group(["tg-test-42"], "bot-test", existed=True)
    check("существующая группа + клиент в панели → assigned", status == "assigned", status)
    check("клиент реально попал в группу", PANEL["clients"]["tg-test-42"].get("group_name") == "bot-test")

    reset(clients={"tg-test-42": {"id": "u1", "email": "tg-test-42", "expiryTime": 0, "enable": True}})
    bot = load_bot(PORT, group="bot-new")
    async with bot.XUIClient() as client:
        status = await client.add_clients_to_group(["tg-test-42"], "bot-new", existed=False)
    check("новой группы не было → assigned_new", status == "assigned_new", status)
    check("панель завела группу", "bot-new" in PANEL["groups"])

    reset(supports_groups=False, clients={"tg-test-42": {"id": "u1", "email": "tg-test-42", "expiryTime": 0, "enable": True}})
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        status = await client.add_clients_to_group(["tg-test-42"], "bot-test", existed=False)
    check("панель без поддержки групп → unsupported", status == "unsupported", status)

    reset(groups=set())
    bot = load_bot(PORT, group="bot-test")
    async with bot.XUIClient() as client:
        status = await client.add_clients_to_group(["tg-test-42"], "bot-test", existed=False)
    check("панель не подтвердила группу → not_assigned", status == "not_assigned", status)


async def test_end_to_end():
    print("\n▶ 4. Сквозная выдача: /test_vpn кладёт клиента в существующую группу")
    reset(groups={"bot-test"})
    bot = load_bot(PORT, group="bot-test")
    msg = Msg()
    await bot.cmd_test_vpn(msg)
    text = msg.last
    check("доступ выдан", "/sub/" in text or "vless://" in text)
    check("клиент попал в существующую группу панели",
          PANEL["clients"]["tg-test-42"].get("group_name") == "bot-test")
    check("сообщение говорит про существующую группу",
          "добавлен в существующую группу" in text and "bot-test" in text)
    check("нет предупреждения о новой группе", "раньше не было" not in text)

    print("\n▶ 5. Регистр: переменная не совпадает с панелью — берём написание панели")
    reset(groups={"Bot-Test"})
    bot = load_bot(PORT, group="BOT-TEST")
    msg = Msg()
    await bot.cmd_test_vpn(msg)
    check("клиент в группе с написанием панели",
          PANEL["clients"]["tg-test-42"].get("group_name") == "Bot-Test")
    check("в сообщении название из панели", "Bot-Test" in msg.last)

    print("\n▶ 6. Группы в панели нет: предупреждаем и создаём")
    reset(groups={"other"})
    bot = load_bot(PORT, group="bot-test")
    msg = Msg()
    await bot.cmd_test_vpn(msg)
    check("клиент создан", PANEL["clients"].get("tg-test-42") is not None)
    check("предупреждение о новой группе есть", "раньше не было" in msg.last)
    check("подсказана команда /groups", "/groups" in msg.last)

    print("\n▶ 7. Панель без поддержки групп: ключ всё равно выдаём")
    reset(supports_groups=False)
    bot = load_bot(PORT, group="bot-test")
    msg = Msg()
    await bot.cmd_test_vpn(msg)
    check("доступ выдан", "/sub/" in msg.last or "vless://" in msg.last)
    check("объяснили, что панель не умеет группы", "Группы недоступны" in msg.last and "3.2" in msg.last)

    print("\n▶ 8. Без XUI_CLIENT_GROUP поведение прежнее")
    reset()
    bot = load_bot(PORT, group=None)
    msg = Msg()
    await bot.cmd_test_vpn(msg)
    check("доступ выдан", "/sub/" in msg.last or "vless://" in msg.last)
    check("ничего про группы не пишем", "Группа" not in msg.last)
    check("группа у клиента не проставлена", not PANEL["clients"]["tg-test-42"].get("group_name"))


async def test_groups_command():
    print("\n▶ 9. Команда /groups")
    reset(groups={"bot-test", "production"}, clients={
        "tg-test-42": {"id": "u1", "email": "tg-test-42", "expiryTime": 0, "enable": True, "group_name": "bot-test"},
    })
    bot = load_bot(PORT, group="bot-test")
    msg = Msg(uid=42)
    await bot.cmd_groups(msg)
    text = msg.last
    check("список групп показан", "bot-test" in text and "production" in text)
    check("группа бота помечена", "использует бот" in text)
    check("сказано, что клиенты идут в существующую группу", "существующую группу" in text)

    reset(groups={"bot-test"})
    bot = load_bot(PORT, group="bot-tets")
    msg = Msg(uid=42)
    await bot.cmd_groups(msg)
    text = msg.last
    check("опечатка: панель предупредит о создании новой группы", "панель создаст её" in text)
    check("опечатка: подсказаны похожие названия", "Похожие названия" in text and "bot-test" in text)

    reset()
    bot = load_bot(PORT, group="bot-test")
    msg = Msg(uid=42)
    await bot.cmd_groups(msg)
    check("пустая панель: честно сообщаем", "пока нет ни одной группы" in msg.last)

    reset(supports_groups=False)
    bot = load_bot(PORT, group="bot-test")
    msg = Msg(uid=42)
    await bot.cmd_groups(msg)
    check("старая панель: объясняем про 3.2", "не поддерживает группы" in msg.last and "3.2" in msg.last)

    reset(groups={"bot-test"})
    bot = load_bot(PORT, group=None)
    msg = Msg(uid=42)
    await bot.cmd_groups(msg)
    check("без переменной подсказываем её задать", "XUI_CLIENT_GROUP" in msg.last)

    reset(groups={"bot-test"})
    bot = load_bot(PORT, group="bot-test", admins="42")
    msg = Msg(uid=777)
    await bot.cmd_groups(msg)
    check("неадмину команда недоступна", "только администратору" in msg.last)


async def test_panel_debug():
    print("\n▶ 10. /panel_debug показывает состояние группы")
    reset(groups={"bot-test"})
    bot = load_bot(PORT, group="bot-test")
    msg = Msg(uid=42)
    await bot.cmd_panel_debug(msg)
    check("в диагностике видно группу бота", "Группа бота" in msg.last and "bot-test" in msg.last)

    reset(supports_groups=False)
    bot = load_bot(PORT, group="bot-test")
    msg = Msg(uid=42)
    await bot.cmd_panel_debug(msg)
    check("в диагностике видно, что панель без групп", "не поддерживает группы" in msg.last)


async def main():
    runner = web.AppRunner(make_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    try:
        await test_group_matching()
        await test_resolve_states()
        await test_group_statuses()
        await test_end_to_end()
        await test_groups_command()
        await test_panel_debug()
    finally:
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
