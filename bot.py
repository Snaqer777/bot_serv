import asyncio
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

# --- КЛАВИАТУРЫ ---
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

# --- СТАРТ + ЛИЦЕНЗИЯ ---
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

# --- ТАРИФЫ ---
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
    await cb.message.edit_text("✅ Оплата прошла (заглушка). Перейди в профиль.", reply_markup=back_kb())

# --- ПРОФИЛЬ ---
@dp.callback_query(F.data == "profile")
async def profile(cb: CallbackQuery):
    await cb.message.edit_text("👤 Профиль:\n\nСтатус: нет активной подписки.\n(Данные появятся после подключения 3x-ui и БД)", reply_markup=back_kb())

# --- ПОДКЛЮЧИТЬ VPN ---
@dp.callback_query(F.data == "connect_vpn")
async def connect(cb: CallbackQuery):
    await cb.message.edit_text("🔐 Для подключения выбери тариф 👇", reply_markup=tariffs_kb())

# --- ИНСТРУКЦИЯ ПО АКТИВАЦИИ ---
@dp.callback_query(F.data == "activation")
async def activation(cb: CallbackQuery):
    await cb.message.edit_text(
        "📋 <b>Инструкция по активации</b>\n\n"
        "• Android → <b>V2Box</b>\n"
        "• iOS → <b>Wispy, INCY, Happ, V2RayTun</b> / Shadowrocket\n"
        "• PC → <b>Happ, V2RayTun</b>\n\n"
        "1. Установи приложение.\n"
        "2. Скопируй ключ из профиля или после оплаты.\n"
        "3. Добавь ключ в приложение и подключись.",
        reply_markup=back_kb(), parse_mode="HTML"
    )

# --- ПОДДЕРЖКА ---
@dp.callback_query(F.data == "support")
async def support(cb: CallbackQuery):
    # Замени ссылку на своего юзера или аккаунт поддержки
    await cb.message.edit_text(
        "💬 <b>Поддержка</b>\n\n"
        "По всем вопросам пиши сюда:\n"
        "👉 @Suppr_XYZ\n"
        "Отвечаем обычно в течение часа.",
        reply_markup=back_kb(), parse_mode="HTML"
    )

async def main():
    print("Бот запущен...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())