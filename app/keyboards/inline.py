# app/keyboards/inline.py
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from app.keyboards.callback_data import PeriodCallback

PERIODS = {
    "hour": (1, "Hour"),
    "day": (24, "Day"),
    "week": (7 * 24, "Week"),
    "month": (30 * 24, "Month"),
    "quarter": (90 * 24, "Quarter"),
    "year": (365 * 24, "Year"),
}


def get_period_selection_keyboard(back_button: bool = False) -> InlineKeyboardMarkup:
    """Returns a keyboard for selecting a time period."""
    builder = InlineKeyboardBuilder()
    for key, (_, label) in PERIODS.items():
        builder.button(
            text=label,
            callback_data=PeriodCallback(action="show", period_key=key),
        )
    builder.adjust(2)  # 2 buttons per row
    if back_button:
        builder.row(
            InlineKeyboardButton(text="« Back to Periods", callback_data="stats_menu")
        )
    return builder.as_markup()


def get_stats_keyboard(period_key: str) -> InlineKeyboardMarkup:
    """Returns a keyboard with actions for a selected period."""
    builder = InlineKeyboardBuilder()
    label = PERIODS[period_key][1].lower()

    builder.button(
        text=f"📈 Compare with previous {label}",
        callback_data=PeriodCallback(action="compare", period_key=period_key),
    )
    builder.button(
        text=f"🌏 Geo Stats for this {label}",
        callback_data=PeriodCallback(action="geo", period_key=period_key),
    )
    builder.button(text="📅 Select another period", callback_data="stats_menu")
    builder.adjust(1)  # 1 button per row
    return builder.as_markup()
