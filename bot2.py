import asyncio
import os
from dotenv import load_dotenv
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN = "8810047635:AAEhdlU0s_fDDtsLINvAkJzNAISnWWgS2hk"
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

TARIFFS = {
    "school": {"name": "Школьник", "price": 99, "traffic": "50 ГБ", "ips": 1, "locations": "1 (Стокгольм)"},
    "basic": {"name": "Базовый", "price": 249, "traffic": "Безлимит", "ips": 3, "locations": "2 (Стокгольм...)"},
    "family": {"name": "Семейный", "price": 399, "traffic": "Безлимит", "ips": 5, "locations": "3 локации"},
    "premium": {"name": "Премиум", "price": 599, "traffic": "Безлимит", "ips": 10, "locations": "Все локации"},
}

def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔐 Подключить VPN", callback_data="connect_vpn")],
        [InlineKeyboardButton(text="👤 Мой профиль", callback_data="profile"),
         InlineKeyboardButton(text="💰 Тарифы", callback_data="tariffs")],
        [InlineKeyboardButton(text="📋 Инструкция по активации", callback_data="activation")],
        [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")]
    ])

def tariffs_kb():
    keyboard = []
    for key, data in TARIFFS.items():
        keyboard.append([InlineKeyboardButton(text=f"{data['name']} — {data['price']} ₽", callback_data=f"buy_{key}")])
    keyboard.append([InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)

def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад в меню", callback_data="main_menu")]])

@dp.message(Command("start"))
async def cmd_start(message: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Я принимаю условия", callback_data="accept_license")]
    ])
    await message.answer(
        "📄 <b>Лицензионное соглашение</b>\n\n"
        "1. Использование только для легальной деятельности.\n"
        "2. Запрещена передача ключей третьим лицам.\n"
        "3. Администрация не несет ответственности за действия пользователей.\n\n"
        "<i>Нажмите кнопку ниже для продолжения.</i>",
        reply_markup=kb, parse_mode="HTML"
    )

@dp.callback_query(F.data == "accept_license")
async def accept_license(callback: CallbackQuery):
    await callback.message.edit_text("✅ Условия приняты. Выберите действие:", reply_markup=main_menu_kb())

@dp.callback_query(F.data == "main_menu")
async def main_menu(cb: CallbackQuery):
    await cb.message.edit_text("🏠 Главное меню:", reply_markup=main_menu_kb())

@dp.callback_query(F.data == "tariffs")
async def tariffs(cb: CallbackQuery):
    text = "<b>Выберите тариф:</b>\n\n"
    for k, d in TARIFFS.items():
        text += f"• {d['name']} — {d['price']}₽ | {d['traffic']} | {d['ips']} устр. | {d['locations']}\n"
    await cb.message.edit_text(text, reply_markup=tariffs_kb(), parse_mode="HTML")

@dp.callback_query(F.data.startswith("buy_"))
async def buy(cb: CallbackQuery):
    t = TARIFFS[cb.data.split("_")[1]]
    await cb.message.edit_text(
        f"💳 <b>{t['name']}</b> — {t['price']}₽\n\n<i>Кнопка оплаты будет подключена позже.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="💳 Оплатить (заглушка)", callback_data="fake_pay")],
            [InlineKeyboardButton(text="◀️ Назад", callback_data="tariffs")]
        ]), parse_mode="HTML"
    )

@dp.callback_query(F.data == "fake_pay")
async def fake_pay(cb: CallbackQuery):
    await cb.answer("Оплата успешна (демо)!", show_alert=True)
    await cb.message.edit_text("✅ Оплата прошла (заглушка). Перейди в профиль или активируй по инструкции.", reply_markup=back_kb())

@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.message.edit_text("👤 Профиль:\n\nСтатус: нет активной подписки.\n(Данные появятся после подключения 3x-ui и БД)", reply_markup=back_kb())

@dp.callback_query(F.data == "connect_vpn")
async def connect(cb: CallbackQuery):
    await cb.message.edit_text("🔐 Для подключения выбери тариф 👇", reply_markup=tariffs_kb())

# --- ИНСТРУКЦИЯ ПО АКТИВАЦИИ (ЗА РУЧКУ) ---
@dp.callback_query(F.data == "activation")
async def activation(cb: CallbackQuery):
    await cb.message.edit_text(
        "📋 <b>Инструкция по активации от А до Я</b>\n\n"
        "<b>🍎 iOS (iPhone / iPad)</b>\n"
        "1. Скачай одно из приложений:\n"
        "   • <a href='https://apps.apple.com/app/happ'>Happ</a>\n"
        "   • <a href='https://apps.apple.com/app/incy'>INCY</a>\n"
        "   • <a href='https://apps.apple.com/app/wispy'>Wispy</a>\n"
        "2. Открой приложение → нажми <b>«+</b> (добавить)\n"
        "3. Выбери <b>«Импорт из буфера»</b> или вставь ссылку вручную\n"
        "4. Нажми <b>«Подключить»</b> (значок Play)\n"
        "5. Разреши добавление VPN в настройках iOS\n\n"

        "<b>🤖 Android</b>\n"
        "1. Скачай: <a href='https://play.google.com/store/apps/details?id=com.v2box.v2box'>v2box</a>\n"
        "2. Открой → нажми <b>«+»</b> внизу справа\n"
        "3. Жми <b>«Импорт из буфера обмена»</b>\n"
        "4. Вставь свой ключ из профиля → жми <b>«Сохранить»</b>\n"
        "5. Нажми на профиль → кнопка <b>«Старт»</b>\n\n"

        "<b>💻 PC (Windows / Mac)</b>\n"
        "1. Скачай: <a href='https://github.com/v2raytun/v2raytun'>v2raytun</a> или <a href='https://gethapp.app'>Happ</a>\n"
        "2. Установи и запусти программу\n"
        "3. Нажми <b>«Add» / «Добавить»</b> → выбери <b>«Import URL»</b>\n"
        "4. Вставь ссылку VLESS из профиля → <b>«Сохранить»</b>\n"
        "5. Жми <b>«Connect»</b> и разреши VPN в системе\n\n"
        "<i>Не работает? Пиши в поддержку 👇</i>",
        reply_markup=back_kb(), parse_mode="HTML", disable_web_page_preview=True
    )

@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    await cb.message.edit_text(
        "💬 <b>Поддержка</b>\n\n"
        "По всем вопросам пиши сюда:\n"
        "👉 <a href='https://t.me/твой_юзер'>@твой_юзер</a>\n\n"
        "Отвечаем обычно в течение часа.",
        reply_markup=back_kb(), parse_mode="HTML"
    )

async def main():
    print("Бот запущен...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())