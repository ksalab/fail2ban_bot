# ==========================================================================
# fail2ban_bot_aiogram.py
# Telegram bot (aiogram v3.22) for fail2ban monitoring: stats, plots, status, logs
# ==========================================================================

import asyncio
import aiohttp
import cartopy.crs as ccrs
import cartopy.io.shapereader as shpreader
import geoip2.database
import hashlib
import logging
import os
import pandas as pd
import re
import subprocess
import tarfile
import tempfile

from collections import OrderedDict
from datetime import datetime, timedelta
from dateutil import parser
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# === aiogram v3.22 ===
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.types import (
    Message,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    FSInputFile,
)

# === Load config ===
load_dotenv()

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
TMP_DIR = Path(tempfile.gettempdir())

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMINS = (
    list(map(int, os.getenv("ADMINS", "").split(","))) if os.getenv("ADMINS") else []
)
CHAT_ID = int(os.getenv("CHAT_ID")) if os.getenv("CHAT_ID") else None
MESSAGE_THREAD_ID = os.getenv("MESSAGE_THREAD_ID")
LOG_FILE_PATH = os.getenv("LOG_FILE", "/var/log/fail2ban.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./geoip/GeoLite2-City.mmdb")

THREAD_ID = int(MESSAGE_THREAD_ID) if MESSAGE_THREAD_ID else None

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required in .env")
if CHAT_ID is None:
    raise RuntimeError("CHAT_ID is required in .env")

# === Periods ===
PERIODS = {
    "hour": (1, "Hour"),
    "day": (24, "Day"),
    "week": (7 * 24, "Week"),
    "month": (30 * 24, "Month"),
    "quarter": (90 * 24, "Quarter"),
    "year": (365 * 24, "Year"),
}


# === Logging with per-field coloring ===
class ColoredFormatter(logging.Formatter):
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
        message = re.sub(r"bot\d+:[\w-]+", "botXXX:XXX", message)

        formatted = f"{asctime} | {levelname} | {name}: {message}"

        if record.exc_info:
            if not message.endswith("\n"):
                formatted += "\n"
            formatted += self.formatException(record.exc_info)
        return formatted


def setup_logging(log_level: str) -> None:
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    level = log_levels.get(log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s: %(message)s",
        datefmt=DATE_FORMAT,
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter("", datefmt=DATE_FORMAT))
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# === Helpers / cache ===
MAX_CACHE_SIZE = 1000
geo_cache = OrderedDict()


def is_user_admin(user_id: int) -> bool:
    return user_id in ADMINS


async def safe_delete_message(query: CallbackQuery):
    logger = logging.getLogger(__name__)
    try:
        if query.message:
            await query.message.delete()
    except Exception as e:
        logger.debug(f"Failed to delete message: {e}")


def get_geo_info(ip: str) -> Dict[str, str]:
    logger = logging.getLogger(__name__)
    if ip in geo_cache:
        geo_cache.move_to_end(ip)
        return geo_cache[ip]

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            country = response.country.name or "Unknown"
            city = response.city.name or "Unknown"
            result = {"country": country, "city": city, "ip": ip}
    except Exception as e:
        result = {"country": "Unknown", "city": "Unknown", "ip": ip}
        logger.debug(f"Geo lookup failed for {ip}: {e}")

    geo_cache[ip] = result
    if len(geo_cache) > MAX_CACHE_SIZE:
        geo_cache.popitem(last=False)
    return result


def stable_color(country_name: str) -> str:
    h = hashlib.sha1(country_name.encode("utf-8")).hexdigest()
    return "#" + h[:6]


def parse_log_timestamp(log_line: str) -> Optional[datetime]:
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?", log_line)
    if iso_match:
        ts_str = iso_match.group(1)
        try:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            logging.getLogger(__name__).debug("Failed to parse timestamp (ISO basic)")

    iso8601_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?", log_line)
    if iso8601_match:
        ts_str = iso8601_match.group(1)
        try:
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        except Exception:
            logging.getLogger(__name__).debug("Failed to parse timestamp (ISO8601)")
    return None


def extract_banned_ips(since_hours: int = None) -> List[str]:
    """
    Extract unique banned IP addresses from fail2ban log.

    Args:
        since_hours (int, optional): If set, only include bans within the last N hours.

    Returns:
        List[str]: List of unique banned IP addresses.
    """
    logger = logging.getLogger(__name__)
    ips = []
    now = datetime.now()
    if since_hours:
        cutoff = now - timedelta(hours=since_hours)
    try:
        with open(LOG_FILE_PATH, "r") as f:
            for line in f:
                if "Ban " not in line:
                    continue
                m = re.search(
                    r"Ban ([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)", line
                )
                if not m:
                    continue
                ip = m.group(1)
                ts = parse_log_timestamp(line)
                if since_hours and ts and ts < cutoff:
                    continue
                ips.append(ip)
    except Exception as e:
        logger.error(f"Error reading banned IPs: {e}")
    return list(set(ips))


def count_bans_in_period(hours: int) -> int:
    """
    Count the number of bans in the last given hours.

    Args:
        hours (int): Number of hours to look back.

    Returns:
        int: Number of bans in the period.
    """
    logger = logging.getLogger(__name__)
    now = datetime.now()
    cutoff = now - timedelta(hours=hours)
    count = 0
    try:
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
        for line in reversed(lines):
            if "Ban" not in line:
                continue
            ts = parse_log_timestamp(line)
            if ts is None:
                continue
            if ts and ts >= cutoff:
                count += 1
            elif ts and ts < cutoff:
                break
    except Exception as e:
        logger.error(f"Error reading log file {LOG_FILE_PATH}: {e}")
    logger.info(f"Counted {count} bans in last {hours} hours")
    return count


def get_service_status() -> Dict[str, str]:
    """
    Retrieve fail2ban service information.

    Returns:
        Dict[str, str]: Dictionary containing:
            - running (bool): Whether the service is active.
            - enabled (bool): Whether the service starts on boot.
            - version (str): fail2ban version.
            - start_time (str): Timestamp of last service start.
            - sshd_status (str): Status of sshd jail.

    Notes:
        Multiple subprocess calls are wrapped in try/except to ensure
        that failure in one part doesn't break the entire function.
    """
    logger = logging.getLogger(__name__)
    try:
        active = (
            subprocess.run(
                ["systemctl", "is-active", "fail2ban"], capture_output=True, text=True
            ).stdout.strip()
            == "active"
        )
    except Exception as e:
        logger.error(f"Failed to check active state: {e}")
        active = False

    try:
        enabled = (
            subprocess.run(
                ["systemctl", "is-enabled", "fail2ban"], capture_output=True, text=True
            ).stdout.strip()
            == "enabled"
        )
    except Exception as e:
        logger.error(f"Failed to check enabled state: {e}")
        enabled = False

    try:
        result = subprocess.run(
            ["fail2ban-client", "status", "sshd"], capture_output=True, text=True
        )
        sshd_status = (
            result.stdout if result.returncode == 0 else "Could not get sshd status"
        )
    except Exception as e:
        logger.error(f"Failed to run fail2ban-client status sshd: {e}")
        sshd_status = "Error retrieving status"

    try:
        version = (
            subprocess.run(
                ["fail2ban-client", "--version"], capture_output=True, text=True
            ).stdout.strip()
            or "unknown"
        )
    except Exception as e:
        logger.error(f"Failed to get version: {e}")
        version = "unknown"

    try:
        result = subprocess.run(
            ["systemctl", "show", "fail2ban", "--property=ActiveEnterTimestamp"],
            capture_output=True,
            text=True,
        )
        line = result.stdout.strip()
        if "ActiveEnterTimestamp=" in line:
            ts_str = line.split("=", 1)[1]
            try:
                start_time = parser.parse(ts_str)
                start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                start_str = "Unknown"
    except Exception as e:
        logger.error(f"Failed to get start time: {e}")
        start_str = "Unknown"

    logger.info(
        f"Retrieved fail2ban service status: running={active}, enabled={enabled}, version={version}"
    )
    return {
        "running": active,
        "enabled": enabled,
        "version": version,
        "start_time": start_str,
        "sshd_status": sshd_status,
    }


def generate_single_period_plot(hours: int, period_name: str) -> str:
    """
    Generate a bar plot showing number of bans per interval within a period.

    Args:
        hours (int): Total number of hours to include.
        period_name (str): Label for the period (used in file name and title).

    Returns:
        str: Path to the saved PNG plot.
    """
    logger = logging.getLogger(__name__)
    now = datetime.now()
    buckets = min(20, hours) if hours <= 24 else 15
    interval = timedelta(seconds=(hours * 3600) // buckets)
    current = now - timedelta(hours=hours)
    times, counts = [], []

    while current < now:
        next_t = current + interval
        cnt = 0
        try:
            with open(LOG_FILE_PATH, "r") as f:
                for line in f:
                    if "Ban" not in line:
                        continue
                    ts = parse_log_timestamp(line)
                    if ts and current <= ts < next_t:
                        cnt += 1
        except:
            pass
        times.append(
            current.strftime("%H:%M") if hours <= 24 else current.strftime("%m-%d")
        )
        counts.append(cnt)
        current = next_t

    plt.figure(figsize=(10, 4))
    plt.bar(
        range(len(times)),
        counts,
        tick_label=times,
        width=0.8,
        color="steelblue",
        alpha=0.7,
    )
    plt.title(
        f"Bans per {'hour' if hours <= 24 else 'day'} - Last {period_name.lower()}"
    )
    plt.xticks(rotation=45, fontsize=8)
    plt.tight_layout()
    plot_path = TMP_DIR / f"fail2ban_current_{period_name.lower()}.png"
    plt.savefig(plot_path)
    plt.close()
    logger.info(f"Generated plot for {period_name}: {plot_path}")
    return str(plot_path)


def generate_comparison_plot(current: int, prev: int, period_name: str) -> str:
    """
    Generate a comparison bar plot between current and previous period bans.

    Args:
        current (int): Number of bans in current period.
        prev (int): Number of bans in previous period.
        period_name (str): Label for period (used in file name and title).

    Returns:
        str: Path to the saved PNG plot.
    """
    logger = logging.getLogger(__name__)
    plt.figure(figsize=(6, 4))
    bars = plt.bar(
        ["Previous", "Current"],
        [prev, current],
        color=["lightcoral", "seagreen"],
        alpha=0.8,
    )
    plt.title(f"Comparison: {period_name}")
    plt.ylabel("Bans")
    for bar in bars:
        h = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            h + max(h * 0.05, 1),
            f"{int(h)}",
            ha="center",
            va="bottom",
            fontsize=10,
        )
    plt.tight_layout()
    plot_path = TMP_DIR / f"fail2ban_compare_{period_name.lower()}.png"
    plt.savefig(plot_path)
    plt.close()
    logger.info(f"Generated comparison plot: {plot_path}")
    return str(plot_path)


def generate_world_map_plot(ips: List[str], title: str) -> Optional[str]:
    """
    Generate a world map highlighting countries with banned IPs.

    Args:
        ips (List[str]): List of IP addresses to geolocate.
        title (str): Plot title.

    Returns:
        Optional[str]: Path to the saved PNG plot, or None if generation failed.
    """
    logger = logging.getLogger(__name__)
    if not ips:
        return None
    try:
        shpfilename = shpreader.natural_earth(
            resolution="110m", category="cultural", name="admin_0_countries"
        )
        reader = shpreader.Reader(shpfilename)
        countries = list(reader.records())

        geo_data = [get_geo_info(ip) for ip in ips]
        df = pd.DataFrame(geo_data)
        country_counts = df["country"].value_counts().to_dict()
        country_colors = {country: stable_color(country) for country in country_counts}

        crs = ccrs.Robinson()
        fig, ax = plt.subplots(1, 1, figsize=(15, 8), subplot_kw={"projection": crs})
        ax.set_global()

        for country in countries:
            name = country.attributes["NAME"]
            geom = country.geometry
            if name in country_counts:
                count = country_counts[name]
                color = country_colors[name]
                label = f"{name}: {count}"
                ax.add_geometries(
                    [geom],
                    crs=ccrs.PlateCarree(),
                    facecolor=color,
                    edgecolor="black",
                    linewidth=0.2,
                    label=label,
                )
            else:
                ax.add_geometries(
                    [geom],
                    crs=ccrs.PlateCarree(),
                    facecolor="white",
                    edgecolor="black",
                    linewidth=0.2,
                )

        plt.title(title, fontsize=14, pad=20)

        from matplotlib.patches import Patch

        legend_patches = [
            Patch(facecolor=country_colors[country], label=f"{country} ({count})")
            for country, count in country_counts.items()
        ]
        if legend_patches:
            ax.legend(
                handles=legend_patches,
                loc="lower left",
                fontsize=8,
                frameon=True,
                title="Countries with bans",
                title_fontsize=9,
            )

        plot_path = TMP_DIR / "geo_world_map.png"
        plt.savefig(plot_path, dpi=100, bbox_inches="tight", pad_inches=0.1)
        plt.close()
        logger.info(f"Generated world map plot: {plot_path}")
        return str(plot_path)
    except Exception as e:
        logger.error(f"Failed to generate world map: {e}")
        return None


def get_period_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(text=label, callback_data=f"period_{key}")]
        for key, (_, label) in PERIODS.items()
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


# === Alerts / DB update (adapted to aiogram: use bot directly) ===
async def _send_telegram_alert(bot: Bot, text: str) -> None:
    logger = logging.getLogger(__name__)
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=f"📦 GeoIP Update\n\n{text}",
            message_thread_id=THREAD_ID,
        )
        logger.info("Sent GeoIP update notification to Telegram.")
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")


async def download_geoip(url: str, dest_path: Path):
    logger = logging.getLogger(__name__)
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                with open(dest_path, "wb") as f:
                    while True:
                        chunk = await resp.content.read(1024)
                        if not chunk:
                            break
                        f.write(chunk)
        logger.info(f"Downloaded GeoIP DB to {dest_path}")
    except Exception as e:
        logger.error(f"Failed to download GeoIP DB: {e}")
        raise


async def update_geoip_db(bot: Bot | None = None) -> None:
    logger = logging.getLogger(__name__)

    db_path = Path(GEOIP_DB_PATH)
    db_dir = db_path.parent
    db_dir.mkdir(exist_ok=True)

    if db_path.exists():
        mtime = datetime.fromtimestamp(db_path.stat().st_mtime)
        if datetime.now() - mtime < timedelta(days=28):
            logger.info("GeoIP DB is up to date.")
            return
        logger.info(f"GeoIP DB is outdated ({mtime.strftime('%Y-%m-%d')}). Updating...")
        update_type = "🔄 Updated GeoIP database"
        body = f"📅 Previous update: {mtime.strftime('%Y-%m-%d')}"
    else:
        logger.info("GeoIP DB not found. Downloading fresh copy...")
        update_type = "🆕 First-time GeoIP setup"
        body = "📂 Database created for the first time"

    account_id = os.getenv("MAXMIND_ACCOUNT_ID")
    license_key = os.getenv("MAXMIND_LICENSE_KEY")

    if not account_id or not license_key:
        error_msg = "❌ GeoIP update failed: MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY not set. GeoIP update skipped."
        logger.error(error_msg)
        if bot:
            await _send_telegram_alert(bot, error_msg + "\nPlease check .env file.")
        return

    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City"
        f"&license_key={license_key}"
        f"&suffix=tar.gz"
    )
    tar_path = db_dir / "GeoLite2-City.tar.gz"

    try:
        logger.info("Downloading GeoLite2-City database with curl...")
        await download_geoip(url, tar_path)
    except subprocess.CalledProcessError as e:
        error_msg = f"❌ Download failed: {e.stderr.strip()}"
        logger.error(error_msg)
        if bot:
            await _send_telegram_alert(bot, error_msg)
        if tar_path.exists():
            tar_path.unlink()
        return
    except Exception as e:
        error_msg = f"❌ Unexpected error during download: {str(e)}"
        logger.error(error_msg)
        if bot:
            await _send_telegram_alert(bot, error_msg)
        return

    try:
        logger.info("Extracting GeoLite2-City.mmdb from archive...")
        extracted = False
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    member.name = db_path.name
                    tar.extract(member, path=db_dir)
                    extracted = True
                    break

        if not extracted:
            error_msg = "❌ No .mmdb file found in archive"
            logger.error(error_msg)
            if bot:
                await _send_telegram_alert(bot, error_msg)
            tar_path.unlink()
            return

        tar_path.unlink()
        logger.info("GeoIP database updated successfully.")

        success_msg = (
            f"{update_type}\n"
            f"{body}\n"
            f"✅ Successfully downloaded and installed new GeoIP database.\n"
            f"🔍 Next check in ~28 days."
        )
        if bot:
            await _send_telegram_alert(bot, success_msg)

    except Exception as e:
        error_msg = f"❌ Extraction failed: {str(e)}"
        logger.error(error_msg)
        if bot:
            await _send_telegram_alert(bot, error_msg)
        if tar_path.exists():
            tar_path.unlink()


# === Handlers (aiogram) ===
async def start(message: Message, bot: Bot):
    logger = logging.getLogger(__name__)
    user_id = message.from_user.id if message.from_user else 0
    if not is_user_admin(user_id):
        await message.answer("Access denied.")
        return
    logger.info(f"User {user_id} started the bot")
    text = (
        "📊 Welcome to fail2ban Monitor Bot!\n\n"
        "Available commands:\n"
        "• /stats — view ban statistics\n"
        "• /status — check service state\n"
        "• /geo — view global geo stats"
    )
    await bot.send_message(
        chat_id=CHAT_ID,
        text=text,
        message_thread_id=THREAD_ID,
    )


async def stats_command(message: Message, bot: Bot):
    logger = logging.getLogger(__name__)
    user_id = message.from_user.id if message.from_user else 0
    if not is_user_admin(user_id):
        await message.answer("Access denied.")
        return
    logger.info(f"User {user_id} opened stats menu")
    await bot.send_message(
        chat_id=CHAT_ID,
        text="📊 Select period:",
        reply_markup=get_period_keyboard(),
        message_thread_id=THREAD_ID,
    )


async def status_command(message: Message, bot: Bot):
    logger = logging.getLogger(__name__)
    user_id = message.from_user.id if message.from_user else 0
    if not is_user_admin(user_id):
        await message.answer("Access denied.")
        return
    logger.info(f"User {user_id} requested service status")
    status = get_service_status()

    running_emoji = "🟢" if status["running"] else "🔴"
    enabled_emoji = "🟢" if status["enabled"] else "🔴"

    text = "🛡️ *fail2ban Service Status*\n\n"
    text += f"🟢 Running: {running_emoji}\n"
    text += f"🔧 Enabled: {enabled_emoji}\n"
    text += f"📦 Version: {status['version']}\n"
    text += f"⏱️ Started at: {status['start_time']}\n\n"
    text += f"🔐 *SSH Jail Status*:\n"
    text += f"```\n{status['sshd_status']}\n```\n"

    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="📅 Select another period", callback_data="stats_menu"
                )
            ]
        ]
    )

    await bot.send_message(
        chat_id=CHAT_ID,
        text=text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )
    logger.info("Sent service status to chat")


async def geo_command(message: Message, bot: Bot):
    logger = logging.getLogger(__name__)
    user_id = message.from_user.id if message.from_user else 0
    if not is_user_admin(user_id):
        await message.answer("Access denied.")
        return

    logger.info("User requested global geo stats")
    ips = extract_banned_ips()  # all time

    if not ips:
        await bot.send_message(
            chat_id=CHAT_ID,
            text="No banned IPs found.",
            message_thread_id=THREAD_ID,
        )
        return

    map_plot = generate_world_map_plot(
        ips, "Global Distribution of Banned IPs — All Time"
    )
    if map_plot and Path(map_plot).exists():
        photo = FSInputFile(str(map_plot))
        await bot.send_photo(
            chat_id=CHAT_ID,
            photo=photo,
            caption="🌍 Geographic distribution of banned IPs — All Time",
            message_thread_id=THREAD_ID,
        )
    else:
        logger.error(f"Map file not found: {map_plot}")
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to generate world map.",
            message_thread_id=THREAD_ID,
        )

    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🗺️ View by Period", callback_data="stats_menu")]
        ]
    )
    await bot.send_message(
        chat_id=CHAT_ID,
        text="Or select a period to view detailed stats:",
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )


async def stats_menu_callback(query: CallbackQuery, bot: Bot):
    logger = logging.getLogger(__name__)
    await query.answer()
    logger.info("User opened period selection menu")
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text="📊 Select period:",
            reply_markup=get_period_keyboard(),
            message_thread_id=THREAD_ID,
        )
        await safe_delete_message(query)
    except Exception as e:
        logger.error(f"Failed to send period menu: {e}")
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to open menu. Use /stats.",
            message_thread_id=THREAD_ID,
        )


async def button_callback(query: CallbackQuery, bot: Bot):
    logger = logging.getLogger(__name__)
    await query.answer()

    if not query.data or not query.data.startswith("period_"):
        return

    period_key = query.data.replace("period_", "")
    if period_key not in PERIODS:
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested stats for period: {label} ({hours}h)")
    current = count_bans_in_period(hours)
    plot_path = generate_single_period_plot(hours, label)

    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=f"📈 Compare with previous {label.lower()}",
                    callback_data=f"compare_{period_key}",
                )
            ],
            [
                InlineKeyboardButton(
                    text="🌏 Geo Stats for This Period",
                    callback_data=f"geo_period_{period_key}",
                )
            ],
            [
                InlineKeyboardButton(
                    text="📅 Select another period", callback_data="stats_menu"
                )
            ],
        ]
    )

    text = f"Bans in the last {label.lower()}:\n\nTotal: {current}\nPeriod: {label}"

    try:
        if plot_path and Path(plot_path).exists():
            photo = FSInputFile(str(plot_path))
            await bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption=text,
                reply_markup=reply_markup,
                message_thread_id=THREAD_ID,
            )
            await safe_delete_message(query)
        else:
            raise FileNotFoundError(f"Plot not found: {plot_path}")
    except Exception as e:
        logger.error(f"Failed to send stats with plot: {e}")
        await bot.send_message(
            chat_id=CHAT_ID,
            text=f"{text}\n\nCould not generate plot.",
            reply_markup=reply_markup,
            message_thread_id=THREAD_ID,
        )


async def compare_callback(query: CallbackQuery, bot: Bot):
    logger = logging.getLogger(__name__)
    await query.answer()

    if not query.data or not query.data.startswith("compare_"):
        return

    period_key = query.data.replace("compare_", "")
    if period_key not in PERIODS:
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested comparison for: {label}")
    current = count_bans_in_period(hours)
    prev = count_bans_in_period(2 * hours) - count_bans_in_period(hours)

    text = f"📊 Comparison: {label} vs Previous {label}\n\n"
    text += f"📌 Current: {current}\n"
    text += f"📌 Previous: {prev}\n"
    diff = current - prev
    trend = "↗️" if diff > 0 else "↘️" if diff < 0 else "➡️"
    change = abs(diff)
    if prev == 0:
        percent = 0.0 if current == 0 else 100.0
    else:
        percent = (change / prev) * 100
    text += f"📈 Change: {trend} {change} ({percent:.1f}%)\n"

    plot_path = generate_comparison_plot(current, prev, label)
    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="📅 Select another period", callback_data="stats_menu"
                )
            ]
        ]
    )

    try:
        if plot_path and Path(plot_path).exists():
            photo = FSInputFile(str(plot_path))
            await bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption=text,
                reply_markup=reply_markup,
                message_thread_id=THREAD_ID,
            )
            await safe_delete_message(query)
        else:
            raise FileNotFoundError(f"Comparison plot not found: {plot_path}")
    except Exception as e:
        logger.error(f"Failed to send comparison: {e}")
        await bot.send_message(
            chat_id=CHAT_ID,
            text=text,
            reply_markup=reply_markup,
            message_thread_id=THREAD_ID,
        )


async def geo_for_period_callback(query: CallbackQuery, bot: Bot):
    logger = logging.getLogger(__name__)
    await query.answer()

    if not query.data or not query.data.startswith("geo_period_"):
        return

    period_key = query.data.replace("geo_period_", "")
    if period_key not in PERIODS:
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested geo stats for period: {label} ({hours}h)")

    ips = extract_banned_ips(since_hours=hours)
    if not ips:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=f"No banned IPs found in the last {label.lower()}.",
            message_thread_id=THREAD_ID,
        )
        return

    map_plot = generate_world_map_plot(
        ips, f"Global Distribution of Banned IPs — Last {label.lower()}"
    )
    if map_plot and Path(map_plot).exists():
        photo = FSInputFile(str(map_plot))
        await bot.send_photo(
            chat_id=CHAT_ID,
            photo=photo,
            caption=f"🌍 Geographic distribution — Last {label.lower()}",
            message_thread_id=THREAD_ID,
        )
    else:
        logger.error(f"Map file not found: {map_plot}")
        await bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to generate world map.",
            message_thread_id=THREAD_ID,
        )

    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Back to Periods", callback_data="stats_menu")]
        ]
    )
    await bot.send_message(
        chat_id=CHAT_ID,
        text="📅 Select another period:",
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )

    await safe_delete_message(query)


async def error_handler(event, bot: Bot):
    """
    Universal error handler for aiogram v3.
    `event` may contain .exception and .update (if any).
    """
    logger = logging.getLogger(__name__)
    exc = getattr(event, "exception", None)
    logger.error(f"Exception while handling update: {exc}", exc_info=exc)

    error_text = "⚠️ Bot error"
    if exc:
        error_text = f"⚠️ Bot error: {type(exc).__name__}\nMessage: {exc}"

    for admin_id in ADMINS:
        try:
            await bot.send_message(chat_id=admin_id, text=error_text)
        except Exception as e:
            logger.error(f"Failed to notify admin {admin_id}: {e}")


# === Main ===
async def on_startup(bot: Bot):
    logger = logging.getLogger(__name__)
    # Clean old charts
    for plot_file in TMP_DIR.glob("fail2ban_*.png"):
        try:
            os.unlink(plot_file)
        except Exception as e:
            logger.warning(f"Failed to remove old plot {plot_file}: {e}")

    # Initial GeoIP update (optional, runs once at startup)
    await update_geoip_db(bot)
    logger.info("Bot is running. Awaiting updates...")


def register_routes(dp: Dispatcher):
    # Commands
    dp.message.register(start, Command("start"))
    dp.message.register(stats_command, Command("stats"))
    dp.message.register(status_command, Command("status"))
    dp.message.register(geo_command, Command("geo"))

    # Callbacks
    dp.callback_query.register(button_callback, F.data.startswith("period_"))
    dp.callback_query.register(compare_callback, F.data.startswith("compare_"))
    dp.callback_query.register(stats_menu_callback, F.data == "stats_menu")
    dp.callback_query.register(
        geo_for_period_callback, F.data.startswith("geo_period_")
    )

    # Errors
    dp.errors.register(error_handler)


async def main():
    setup_logging(LOG_LEVEL)
    logger = logging.getLogger(__name__)
    logger.info("=== Starting fail2ban Telegram bot (aiogram v3.22) ... ===")

    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="Markdown"))
    dp = Dispatcher()

    register_routes(dp)
    dp.startup.register(on_startup)

    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    except (KeyboardInterrupt, SystemExit):
        logger.info("=== Bot stopped by user ===")
    finally:
        await bot.session.close()
        logger.info("=== Shutdown complete ===")


if __name__ == "__main__":
    asyncio.run(main())
