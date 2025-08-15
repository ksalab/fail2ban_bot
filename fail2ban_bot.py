# ==========================================================================
# fail2ban_bot.py
# Telegram bot for fail2ban monitoring: stats, plots, status, logs
# ==========================================================================

import cartopy.crs as ccrs
import cartopy.io.shapereader as shpreader
import geoip2.database
import geopandas as gpd
import logging
import os
import pandas as pd
import re
import subprocess
import tarfile


from collections import Counter
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

# === Load config ===
load_dotenv()

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMINS = (
    list(map(int, os.getenv("ADMINS", "").split(","))) if os.getenv("ADMINS") else []
)
CHAT_ID = os.getenv("CHAT_ID")
MESSAGE_THREAD_ID = os.getenv("MESSAGE_THREAD_ID")
LOG_FILE_PATH = os.getenv("LOG_FILE", "/var/log/fail2ban.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./geoip/GeoLite2-City.mmdb")

THREAD_ID = int(MESSAGE_THREAD_ID) if MESSAGE_THREAD_ID else None

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required in .env")
if not CHAT_ID:
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


# === Logging setup with per-field coloring ===
class ColoredFormatter(logging.Formatter):
    # ANSI colors
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

        asctime = f"{self.CYAN}{record.asctime}{self.RESET}"
        levelname = f"{color}{icon} {record.levelname:<8}{self.RESET}"
        name = f"{self.GREY}{record.name}{self.RESET}"

        # === 🔒 Masking the token in the message ===
        message = (
            record.getMessage()
        )  # This is already a string with substituted arguments
        message = re.sub(r"bot\d+:[\w-]+", "botXXX:XXX", message)

        formatted = f"{asctime} | {levelname} | {name}: {message}"

        if record.exc_info:
            if not message.endswith("\n"):
                formatted += "\n"
            formatted += self.formatException(record.exc_info)
        return formatted


def setup_logging(log_level: str) -> None:
    """Configure root logger to capture all logs with module names and colored output."""
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    level = log_levels.get(log_level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # File handler — no colors
    file_handler = logging.FileHandler("fail2ban_bot.log")
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s: %(message)s",
        datefmt=DATE_FORMAT,
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Console handler — with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter("", datefmt=DATE_FORMAT))
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# === Geo-data cache ===
geo_cache = {}


def get_geo_info(ip: str) -> Dict[str, str]:
    """Get country and city for IP from GeoLite2 DB."""
    logger = logging.getLogger(__name__)
    if ip in geo_cache:
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
    return result


def extract_banned_ips(since_hours: int = None) -> List[str]:
    """Extract all banned IPs from log file in the last N hours."""
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
                # Searching for IP after "Ban"
                match = re.search(r"Ban (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if not match:
                    continue
                ip = match.group(1)
                ts = parse_log_timestamp(line)
                if since_hours and ts and ts < cutoff:
                    continue
                ips.append(ip)
    except Exception as e:
        logger.error(f"Error reading banned IPs: {e}")
    return ips


def generate_world_map_plot(ips: List[str], title: str) -> str:
    """Generate a world map with unique colors for countries that have banned IPs."""
    logger = logging.getLogger(__name__)
    if not ips:
        return None

    try:
        # Load country geometries
        shpfilename = shpreader.natural_earth(
            resolution="110m", category="cultural", name="admin_0_countries"
        )
        reader = shpreader.Reader(shpfilename)
        countries = reader.records()

        # Get geo data and count by country
        geo_data = [get_geo_info(ip) for ip in ips]
        df = pd.DataFrame(geo_data)
        country_counts = df["country"].value_counts().to_dict()

        # Assign unique color to each country with bans
        import random

        def random_color():
            return [random.random() for _ in range(3)]  # RGB

        country_colors = {country: random_color() for country in country_counts}

        # Set up plot
        crs = ccrs.Robinson()
        fig, ax = plt.subplots(1, 1, figsize=(15, 8), subplot_kw={"projection": crs})
        ax.set_global()

        # Draw countries
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

        # Add legend (only for countries with bans)
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

        # Save
        plot_path = "/tmp/geo_world_map.png"
        plt.savefig(plot_path, dpi=100, bbox_inches="tight", pad_inches=0.1)
        plt.close()
        logger.info(f"Generated world map plot: {plot_path}")
        return plot_path

    except Exception as e:
        logger.error(f"Failed to generate world map: {e}")
        return None


async def geo_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send global geo stats: world map only."""
    logger = logging.getLogger(__name__)
    if not is_user_admin(update.effective_user.id):
        await update.message.reply_text("Access denied.")
        return

    logger.info("User requested global geo stats")
    ips = extract_banned_ips()  # all time

    if not ips:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="No banned IPs found.",
            message_thread_id=THREAD_ID,
        )
        return

    # Generate world map
    map_plot = generate_world_map_plot(
        ips, "Global Distribution of Banned IPs — All Time"
    )
    if map_plot:
        with open(map_plot, "rb") as photo:
            await context.bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption="🌍 Geographic distribution of banned IPs — All Time",
                message_thread_id=THREAD_ID,
            )
    else:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to generate world map.",
            message_thread_id=THREAD_ID,
        )

    # Add button to open period selection
    reply_markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("🗺️ View by Period", callback_data="stats_menu")]]
    )
    await context.bot.send_message(
        chat_id=CHAT_ID,
        text="Or select a period to view detailed stats:",
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )


async def geo_for_period_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Send geo stats for the selected period — world map only."""
    logger = logging.getLogger(__name__)
    query = update.callback_query
    await query.answer()

    period_key = query.data.replace("geo_period_", "")
    if period_key not in PERIODS:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested geo stats for period: {label} ({hours}h)")

    ips = extract_banned_ips(since_hours=hours)
    if not ips:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text=f"No banned IPs found in the last {label.lower()}.",
            message_thread_id=THREAD_ID,
        )
        return

    # Only world map
    map_plot = generate_world_map_plot(
        ips, f"Global Distribution of Banned IPs — Last {label.lower()}"
    )
    if map_plot:
        with open(map_plot, "rb") as photo:
            await context.bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption=f"🌍 Geographic distribution — Last {label.lower()}",
                message_thread_id=THREAD_ID,
            )
    else:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to generate world map.",
            message_thread_id=THREAD_ID,
        )

    # Back button
    reply_markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("Back to Periods", callback_data="stats_menu")]]
    )
    await context.bot.send_message(
        chat_id=CHAT_ID,
        text="📅 Select another period:",
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )

    await query.delete_message()


# === Helpers ===
def is_user_admin(user_id: int) -> bool:
    return user_id in ADMINS


def parse_log_timestamp(log_line: str) -> Optional[datetime]:
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", log_line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def count_bans_in_period(hours: int) -> int:
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
            if ts and ts >= cutoff:
                count += 1
            elif ts and ts < cutoff:
                break
    except Exception as e:
        logger.error(f"Error reading log file {LOG_FILE_PATH}: {e}")
    logger.info(f"Counted {count} bans in last {hours} hours")
    return count


def get_service_status() -> Dict[str, str]:
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
        if result.returncode == 0:
            sshd_status = result.stdout
        else:
            sshd_status = "Could not get sshd status"
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
            match = re.search(r"\w{3} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", ts_str)
            if match:
                start_time = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                start_str = "Unknown"
        else:
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
    logger = logging.getLogger(__name__)
    now = datetime.now()
    buckets = min(20, hours) if hours <= 24 else 15
    interval = timedelta(seconds=(hours * 3600) // buckets)
    current = now - timedelta(hours=hours)
    times = []
    counts = []

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
    plot_path = f"/tmp/fail2ban_current_{period_name.lower()}.png"
    plt.savefig(plot_path)
    plt.close()
    logger.info(f"Generated plot for {period_name}: {plot_path}")
    return plot_path


def generate_comparison_plot(current: int, prev: int, period_name: str) -> str:
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
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + max(height * 0.05, 1),
            f"{int(height)}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    plt.tight_layout()
    plot_path = f"/tmp/fail2ban_compare_{period_name.lower()}.png"
    plt.savefig(plot_path)
    plt.close()
    logger.info(f"Generated comparison plot: {plot_path}")
    return plot_path


# === Handlers ===
def get_period_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(label, callback_data=f"period_{key}")]
        for key, (_, label) in PERIODS.items()
    ]
    return InlineKeyboardMarkup(buttons)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger = logging.getLogger(__name__)
    if not is_user_admin(update.effective_user.id):
        await context.bot.send_message(
            chat_id=update.effective_chat.id, text="Access denied."
        )
        return
    logger.info(f"User {update.effective_user.id} started the bot")
    text = (
        "📊 Welcome to fail2ban Monitor Bot!\n\n"
        "Available commands:\n"
        "• /stats — view ban statistics\n"
        "• /status — check service state\n"
        "• /geo — view global geo stats"
    )
    await context.bot.send_message(
        chat_id=CHAT_ID,
        text=text,
        message_thread_id=THREAD_ID,
    )


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger = logging.getLogger(__name__)
    if not is_user_admin(update.effective_user.id):
        await update.message.reply_text("Access denied.")
        return
    logger.info(f"User {update.effective_user.id} opened stats menu")
    await context.bot.send_message(
        chat_id=CHAT_ID,
        text="📊 Select period:",
        reply_markup=get_period_keyboard(),
        message_thread_id=THREAD_ID,
    )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle period selection for ban stats and trigger geo."""
    logger = logging.getLogger(__name__)
    query = update.callback_query
    await query.answer()

    period_key = query.data.replace("period_", "")
    if period_key not in PERIODS:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested stats for period: {label} ({hours}h)")
    current = count_bans_in_period(hours)
    plot_path = generate_single_period_plot(hours, label)

    # Button: geo for this period
    reply_markup = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"📈 Compare with previous {label.lower()}",
                    callback_data=f"compare_{period_key}",
                )
            ],
            [
                InlineKeyboardButton(
                    "🌏 Geo Stats for This Period",
                    callback_data=f"geo_period_{period_key}",
                )
            ],
            [
                InlineKeyboardButton(
                    "📅 Select another period", callback_data="stats_menu"
                )
            ],
        ]
    )

    text = f"Bans in the last {label.lower()}:\n\n"
    text += f"Total: {current}\n"
    text += f"Period: {label}"

    try:
        with open(plot_path, "rb") as photo:
            await context.bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption=text,
                reply_markup=reply_markup,
                message_thread_id=THREAD_ID,
            )
        await query.delete_message()
    except Exception as e:
        logger.error(f"Failed to send stats with plot: {e}")
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text=f"{text}\n\nCould not generate plot.",
            reply_markup=reply_markup,
            message_thread_id=THREAD_ID,
        )


async def compare_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger = logging.getLogger(__name__)
    query = update.callback_query
    await query.answer()
    period_key = query.data.replace("compare_", "")
    if period_key not in PERIODS:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Invalid period.",
            message_thread_id=THREAD_ID,
        )
        return

    hours, label = PERIODS[period_key]
    logger.info(f"User requested comparison for: {label}")
    current = count_bans_in_period(hours)
    prev = count_bans_in_period(2 * hours) - current

    text = f"📊 Comparison: {label} vs Previous {label}\n\n"
    text += f"📌 Current: {current}\n"
    text += f"📌 Previous: {prev}\n"
    diff = current - prev
    trend = "↗️" if diff > 0 else "↘️" if diff < 0 else "➡️"
    change = abs(diff)
    percent = (change / (prev or 1)) * 100
    text += f"📈 Change: {trend} {change} ({percent:.1f}%)\n"

    plot_path = generate_comparison_plot(current, prev, label)
    reply_markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("📅 Select another period", callback_data="stats_menu")]]
    )

    try:
        with open(plot_path, "rb") as photo:
            await context.bot.send_photo(
                chat_id=CHAT_ID,
                photo=photo,
                caption=text,
                reply_markup=reply_markup,
                message_thread_id=THREAD_ID,
            )
        await query.delete_message()
    except Exception as e:
        logger.error(f"Failed to send comparison: {e}")
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text=text,
            reply_markup=reply_markup,
            message_thread_id=THREAD_ID,
        )


async def stats_menu_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    logger = logging.getLogger(__name__)
    query = update.callback_query
    await query.answer()
    logger.info("User opened period selection menu")
    try:
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="📊 Select period:",
            reply_markup=get_period_keyboard(),
            message_thread_id=THREAD_ID,
        )
        await query.delete_message()
    except Exception as e:
        logger.error(f"Failed to send period menu: {e}")
        await context.bot.send_message(
            chat_id=CHAT_ID,
            text="Failed to open menu. Use /stats.",
            message_thread_id=THREAD_ID,
        )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger = logging.getLogger(__name__)
    if not is_user_admin(update.effective_user.id):
        await update.message.reply_text("Access denied.")
        return
    logger.info(f"User {update.effective_user.id} requested service status")
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
        [[InlineKeyboardButton("📅 Select another period", callback_data="stats_menu")]]
    )

    await context.bot.send_message(
        chat_id=CHAT_ID,
        text=text,
        parse_mode="Markdown",
        reply_markup=reply_markup,
        message_thread_id=THREAD_ID,
    )
    logger.info("Sent service status to chat")


# === Update GeoIP db ===
def update_geoip_db(context: ContextTypes.DEFAULT_TYPE = None) -> None:
    """Automatically update GeoLite2-City.mmdb if older than 28 days and notify via Telegram."""
    logger = logging.getLogger(__name__)

    db_path = Path(GEOIP_DB_PATH)
    db_dir = db_path.parent
    db_dir.mkdir(exist_ok=True)

    # Check if DB exists and is outdated
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
        error_msg = (
            "❌ GeoIP update failed: MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY not set"
        )
        logger.error(error_msg)
        _send_telegram_alert(context, error_msg + "\nPlease check .env file.")
        return

    # URLs and paths
    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City"
        f"&license_key={license_key}"
        f"&product_id=GeoLite2-City"
        f"&suffix=tar.gz"
    )
    tar_path = db_dir / "GeoLite2-City.tar.gz"

    # Download with curl
    try:
        logger.info("Downloading GeoLite2-City database with curl...")
        result = subprocess.run(
            ["curl", "-f", "-L", "-o", str(tar_path), url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        result.check_returncode()
        logger.info("Download completed.")
    except subprocess.CalledProcessError as e:
        error_msg = f"❌ Download failed: {e.stderr.strip()}"
        logger.error(error_msg)
        _send_telegram_alert(context, error_msg)
        if tar_path.exists():
            tar_path.unlink()
        return
    except Exception as e:
        error_msg = f"❌ Unexpected error during download: {str(e)}"
        logger.error(error_msg)
        _send_telegram_alert(context, error_msg)
        return

    # Extract the .mmdb file
    try:
        logger.info("Extracting GeoLite2-City.mmdb from archive...")
        extracted = False
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    # Extract and rename to target
                    member.name = db_path.name
                    tar.extract(member, path=db_dir)
                    extracted = True
                    break

        if not extracted:
            error_msg = "❌ No .mmdb file found in archive"
            logger.error(error_msg)
            _send_telegram_alert(context, error_msg)
            tar_path.unlink()
            return

        tar_path.unlink()  # Clean up archive
        logger.info("GeoIP database updated successfully.")

        # ✅ Send success message
        success_msg = (
            f"{update_type}\n"
            f"{body}\n"
            f"✅ Successfully downloaded and installed new GeoIP database.\n"
            f"🔍 Next check in ~28 days."
        )
        _send_telegram_alert(context, success_msg)

    except Exception as e:
        error_msg = f"❌ Extraction failed: {str(e)}"
        logger.error(error_msg)
        _send_telegram_alert(context, error_msg)
        if tar_path.exists():
            tar_path.unlink()


def _send_telegram_alert(context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    """Send alert to configured chat/thread. Uses context.bot if available, else creates temporary app."""
    logger = logging.getLogger(__name__)
    try:
        if context and context.bot:
            # Normal case: called during bot runtime
            context.bot.send_message(
                chat_id=CHAT_ID,
                text=f"📦 GeoIP Update\n\n{text}",
                message_thread_id=THREAD_ID,
            )
        else:
            # Fallback: standalone call (e.g. from script)
            from telegram import Bot

            bot = Bot(token=BOT_TOKEN)
            bot.send_message(
                chat_id=CHAT_ID,
                text=f"📦 GeoIP Update\n\n{text}",
                message_thread_id=THREAD_ID,
            )
        logger.info("Sent GeoIP update notification to Telegram.")
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")


# === Main ===
def main() -> None:
    setup_logging(LOG_LEVEL)
    logger = logging.getLogger(__name__)
    logger.info("--------------------------------------------------------")
    logger.info("Starting fail2ban Telegram bot...")
    logger.info("--------------------------------------------------------")

    # ✅ Update GeoIP DB on startup
    update_geoip_db()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("geo", geo_command))
    app.add_handler(CallbackQueryHandler(button_callback, pattern="^period_"))
    app.add_handler(CallbackQueryHandler(compare_callback, pattern="^compare_"))
    app.add_handler(CallbackQueryHandler(stats_menu_callback, pattern="^stats_menu$"))
    app.add_handler(
        CallbackQueryHandler(geo_for_period_callback, pattern="^geo_period_")
    )

    logger.info("Bot is running. Awaiting updates...")
    app.run_polling()


if __name__ == "__main__":
    main()
