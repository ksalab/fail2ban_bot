# app/handlers/common.py
import logging

from aiogram import F, Router
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import Message
from aiogram.utils.markdown import hbold

from app.config import Settings
from app.services.fail2ban import get_service_status

logger = logging.getLogger(__name__)
router = Router()


@router.message(CommandStart())
async def handle_start(message: Message, config: Settings):
    """Handler for the /start command."""
    logger.info("User %d initiated /start command.", message.from_user.id)
    text = (
        "📊 Welcome to Fail2Ban Monitor Bot!\n\n"
        "Available commands:\n"
        "• /stats — View ban statistics\n"
        "• /status — Check service state\n"
        "• /geo — View global geo stats"
    )
    await message.answer(text)


@router.message(Command("status"))
async def handle_status(message: Message, config: Settings):
    """Handler for the /status command."""
    logger.info("User %d requested service status.", message.from_user.id)
    status = get_service_status(jail_names=config.F2B_JAIL_NAMES)

    running_emoji = "🟢" if status["running"] else "🔴"
    enabled_emoji = "✅" if status["enabled"] else "❌"

    text_parts = [
        f"🛡️ {hbold('Fail2Ban Service Status')}\n\n"
        f"Service Running: {running_emoji}\n"
        f"Service Enabled: {enabled_emoji}\n"
        f"Version: {status['version']}\n"
        f"Started at: {status['start_time']}\n\n"
    ]

    if status["jail_statuses"]:
        for jail_name, jail_status in status["jail_statuses"].items():
            text_parts.append(f"{hbold(f'Status for jail [{jail_name}]')}:")
            text_parts.append(f"<code>\n{jail_status}\n</code>")
    else:
        text_parts.append("No jails configured to monitor.")

    await message.answer("\n".join(text_parts), parse_mode=ParseMode.HTML)
