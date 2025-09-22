# app/utils/logging_setup.py
import logging
import re
from logging.handlers import RotatingFileHandler

from app.config import load_config

config = load_config()


class ColoredFormatter(logging.Formatter):
    """Formatter for colored console output."""

    CYAN = "\x1b[36m"
    MAGENTA = "\x1b[35m"
    GREY = "\x1b[38;5;242m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    ICONS = {
        logging.DEBUG: "🔧",
        logging.INFO: "🟢",
        logging.WARNING: "⚠️",
        logging.ERROR: "🔴",
        logging.CRITICAL: "💥",
    }

    COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        icon = self.ICONS.get(record.levelno, "❓")

        asctime = f"{self.CYAN}{self.formatTime(record, self.datefmt)}{self.RESET}"
        levelname = f"{color}{icon} {record.levelname:<8}{self.RESET}"
        name = f"{self.GREY}{record.name}{self.RESET}"

        message = record.getMessage()
        # Sanitize potential bot tokens from logs
        message = re.sub(r"bot\d+:[\w-]+", "botXXX:XXX", message)

        formatted_message = f"{asctime} | {levelname} | {name}: {message}"
        if record.exc_info:
            if not message.endswith("\n"):
                formatted_message += "\n"
            formatted_message += self.formatException(record.exc_info)
        return formatted_message


def setup_logging():
    """Configures logging for the application."""
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Console Handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter(datefmt=config.DATE_FORMAT))
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # File Handler
    try:
        file_handler = RotatingFileHandler(
            "bot.log", maxBytes=5 * 1024 * 1024, backupCount=2
        )
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
            datefmt=config.DATE_FORMAT,
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        logging.error("Failed to set up file logging: %s", e)

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
