# app/config.py
import tempfile
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory of the project
BASE_DIR = Path(__file__).parent.parent


class Settings(BaseSettings):
    """Bot configuration settings."""

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    # === Telegram Bot (Required) ===
    BOT_TOKEN: str
    ADMINS: List[int] = Field(..., min_length=1)
    CHAT_ID: int
    MESSAGE_THREAD_ID: int | None = None

    # === Fail2Ban and System (Required paths/settings) ===
    LOG_FILE: Path = Path("/var/log/fail2ban.log")
    F2B_JAIL_NAMES: List[str] = ["sshd"]

    # === Logging ===
    LOG_LEVEL: str = "INFO"

    # === Database ===
    DB_NAME: str = "fail2ban.db"

    # === GeoIP Database (Optional key, Recommended settings) ===
    GEOIP_DB_PATH: Path = BASE_DIR / "geoip" / "GeoLite2-City.mmdb"
    GEOIP_UPDATE_DAYS: int = 28
    GEOIP_CACHE_SIZE: int = 1000
    GEOIP_DOWNLOAD_TIMEOUT_SECONDS: int = 60
    MAXMIND_ACCOUNT_ID: int | None = None
    MAXMIND_LICENSE_KEY: str | None = None

    # === Bot Behavior ===
    BOT_SYNC_INTERVAL_SECONDS: int = 300

    # === Plotting (Optional tuning) ===
    PLOT_DPI: int = 120
    MAP_LEGEND_ITEMS: int = 20

    # === Internal settings ===
    TMP_DIR: Path = Path(tempfile.gettempdir())
    DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


def load_config() -> Settings:
    """Load configuration from .env file."""
    return Settings()
