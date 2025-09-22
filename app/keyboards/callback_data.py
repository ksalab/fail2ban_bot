# app/keyboards/callback_data.py
from aiogram.filters.callback_data import CallbackData


class PeriodCallback(CallbackData, prefix="period"):
    """
    Callback data for period-related actions.
    - action: 'show', 'compare', 'geo'
    - period_key: 'hour', 'day', 'week', etc.
    """

    action: str
    period_key: str
