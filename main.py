# main.py
import asyncio
import logging
import os
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from app.config import Settings, load_config
from app.db_manager import DBManager
from app.handlers import common, stats
from app.middlewares.admin import AdminMiddleware
from app.services.fail2ban import periodic_log_sync
from app.services.geoip import update_geoip_db
from app.utils.logging_setup import setup_logging

logger = logging.getLogger(__name__)


async def on_startup(bot: Bot, db_manager: DBManager, config: Settings):
    """
    Actions to perform on bot startup.
    - Clean up old charts.
    - Update GeoIP database.
    - Start periodic background tasks.
    """
    logger.info("Bot is starting up...")

    # Clean old charts in temp directory
    tmp_dir = Path(config.TMP_DIR)
    for plot_file in tmp_dir.glob("fail2ban_*.png"):
        try:
            os.unlink(plot_file)
            logger.debug("Removed old plot: %s", plot_file)
        except Exception as e:
            logger.warning("Failed to remove old plot %s: %s", plot_file, e)

    # Initial GeoIP update
    await update_geoip_db(bot, config)

    # Start periodic background log synchronization
    asyncio.create_task(periodic_log_sync(db_manager, config))
    logger.info("Background tasks have been scheduled.")


async def on_shutdown(db_manager: DBManager):
    """
    Function to perform actions on bot shutdown, such as closing database connection.
    """
    logger.info("Closing database connection...")
    await db_manager.close()
    logger.info("Database connection closed.")


async def main():
    """Main function to configure and run the bot."""
    # Setup logging
    setup_logging()

    # Load configuration
    config = load_config()
    logger.info("Configuration loaded.")

    # Initialize bot and dispatcher
    bot = Bot(
        token=config.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN),
    )
    dp = Dispatcher()

    # Initialize DB Manager
    db_manager = DBManager()

    # Pass db_manager and config to handlers and middlewares
    dp["db_manager"] = db_manager
    dp["config"] = config

    # Register admin check middleware for all messages and callbacks
    dp.message.middleware(AdminMiddleware(config.ADMINS))
    dp.callback_query.middleware(AdminMiddleware(config.ADMINS))

    # Register routers
    dp.include_routers(common.router, stats.router)
    logger.info("Routers included.")

    # Register startup hook
    dp.startup.register(on_startup)

    try:
        logger.info("Starting polling...")
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped by user.")
    finally:
        await bot.session.close()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.critical("Bot failed to start: %s", e, exc_info=True)
