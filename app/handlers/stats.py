# app/handlers/stats.py
import logging
from pathlib import Path

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, FSInputFile, Message

from app.config import Settings
from app.db_manager import DBManager
from app.keyboards.callback_data import PeriodCallback
from app.keyboards.inline import (
    PERIODS,
    get_period_selection_keyboard,
    get_stats_keyboard,
)
from app.services.fail2ban import count_bans_in_period, extract_banned_ips
from app.utils.plotting import (
    generate_comparison_plot,
    generate_single_period_plot,
    generate_world_map_plot,
)

logger = logging.getLogger(__name__)
router = Router()


async def safe_delete_message(query: CallbackQuery):
    """Safely deletes the message from a callback query."""
    try:
        if query.message:
            await query.message.delete()
    except Exception as e:
        logger.debug("Failed to delete message %d: %s", query.message.message_id, e)


@router.message(Command("stats"))
async def handle_stats_command(message: Message):
    """Handler for the /stats command, shows period selection."""
    logger.info("User %d opened stats menu with /stats command.", message.from_user.id)
    await message.answer(
        "📊 Select period:", reply_markup=get_period_selection_keyboard()
    )


@router.callback_query(F.data == "stats_menu")
async def handle_stats_menu_callback(query: CallbackQuery):
    """Handler for 'stats_menu' callback, returns to period selection."""
    logger.info("User %d returned to stats menu.", query.from_user.id)
    await query.message.edit_text(
        "📊 Select period:", reply_markup=get_period_selection_keyboard()
    )
    await query.answer()


@router.message(Command("geo"))
async def handle_geo_command(message: Message, db_manager: DBManager, config: Settings):
    """Handler for /geo command, shows global map of all-time bans."""
    logger.info("User %d requested global geo stats.", message.from_user.id)
    await message.answer("🗺️ Generating global map, this may take a moment...")

    ips = extract_banned_ips(db_manager, config)
    if not ips:
        await message.answer("No banned IPs found to generate a map.")
        return

    title = "Global Distribution of Banned IPs — All Time"
    plot_path = generate_world_map_plot(ips, title, config)

    if plot_path and Path(plot_path).exists():
        await message.answer_photo(
            photo=FSInputFile(plot_path),
            caption=f"🌍 {title}",
        )
    else:
        await message.answer("❌ Failed to generate the world map.")


@router.callback_query(PeriodCallback.filter(F.action == "show"))
async def handle_period_stats(
    query: CallbackQuery,
    callback_data: PeriodCallback,
    db_manager: DBManager,
    config: Settings,
):
    """Handler to show stats for a selected period."""
    period_key = callback_data.period_key
    hours, label = PERIODS[period_key]
    logger.info("User %d requested stats for period: %s", query.from_user.id, label)

    await query.answer(f"Generating stats for {label}...")

    current_bans = count_bans_in_period(db_manager, config, hours)
    plot_path = generate_single_period_plot(db_manager, config, hours, label)

    caption = f"Bans in the last {label.lower()}:\n\nTotal: {current_bans}"

    if plot_path and Path(plot_path).exists():
        await query.message.answer_photo(
            photo=FSInputFile(plot_path),
            caption=caption,
            reply_markup=get_stats_keyboard(period_key),
        )
        await safe_delete_message(query)
    else:
        await query.message.edit_text(
            f"{caption}\n\n(Could not generate plot)",
            reply_markup=get_stats_keyboard(period_key),
        )


@router.callback_query(PeriodCallback.filter(F.action == "compare"))
async def handle_comparison_stats(
    query: CallbackQuery,
    callback_data: PeriodCallback,
    db_manager: DBManager,
    config: Settings,
):
    """Handler to compare current period with the previous one."""
    period_key = callback_data.period_key
    hours, label = PERIODS[period_key]
    logger.info(
        "User %d requested comparison for period: %s", query.from_user.id, label
    )

    await query.answer(f"Generating comparison for {label}...")

    current_bans = count_bans_in_period(db_manager, config, hours)
    previous_bans = count_bans_in_period(db_manager, config, 2 * hours) - current_bans

    diff = current_bans - previous_bans
    trend = "↗️" if diff > 0 else "↘️" if diff < 0 else "➡️"
    change = abs(diff)
    percent_change = (
        (change / previous_bans * 100)
        if previous_bans > 0
        else (100.0 if current_bans > 0 else 0.0)
    )

    caption = (
        f"📊 Comparison: {label} vs Previous {label}\n\n"
        f"📌 Current: {current_bans}\n"
        f"📌 Previous: {previous_bans}\n"
        f"📈 Change: {trend} {change} ({percent_change:.1f}%)"
    )

    plot_path = generate_comparison_plot(current_bans, previous_bans, label, config)

    if plot_path and Path(plot_path).exists():
        await query.message.answer_photo(
            photo=FSInputFile(plot_path),
            caption=caption,
            reply_markup=get_period_selection_keyboard(back_button=True),
        )
        await safe_delete_message(query)
    else:
        await query.message.edit_text(
            caption,
            reply_markup=get_period_selection_keyboard(back_button=True),
        )


@router.callback_query(PeriodCallback.filter(F.action == "geo"))
async def handle_period_geo_stats(
    query: CallbackQuery,
    callback_data: PeriodCallback,
    db_manager: DBManager,
    config: Settings,
):
    """Handler for showing geo map for a specific period."""
    period_key = callback_data.period_key
    hours, label = PERIODS[period_key]
    logger.info("User %d requested geo stats for period: %s", query.from_user.id, label)

    await query.answer(f"Generating map for {label}...")

    ips = extract_banned_ips(db_manager, config, since_hours=hours)
    if not ips:
        await query.message.answer(f"No banned IPs found in the last {label.lower()}.")
        return

    title = f"Global Distribution of Banned IPs — Last {label}"
    plot_path = generate_world_map_plot(ips, title, config)

    if plot_path and Path(plot_path).exists():
        await query.message.answer_photo(
            photo=FSInputFile(plot_path),
            caption=f"🌍 {title}",
            reply_markup=get_period_selection_keyboard(back_button=True),
        )
        await safe_delete_message(query)
    else:
        await query.message.edit_text(
            "❌ Failed to generate the world map for this period.",
            reply_markup=get_period_selection_keyboard(back_button=True),
        )
