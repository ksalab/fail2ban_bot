# app/services/geoip.py
import logging
import tarfile
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

import aiohttp
import geoip2.database
from aiogram import Bot

from app.config import Settings

logger = logging.getLogger(__name__)

# Module-level cache
MAX_CACHE_SIZE = 1000
geo_cache = OrderedDict()


def get_geo_info(ip: str, config: Settings) -> Dict[str, str]:
    """
    Retrieves geolocation information for an IP address, with caching.
    """
    if ip in geo_cache:
        geo_cache.move_to_end(ip)
        return geo_cache[ip]

    result = {"country": "Unknown", "city": "Unknown", "ip": ip}
    try:
        with geoip2.database.Reader(config.GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            result["country"] = response.country.name or "Unknown"
            result["city"] = response.city.name or "Unknown"
    except geoip2.errors.AddressNotFoundError:
        logger.debug("Address %s not found in GeoIP database.", ip)
    except Exception as e:
        logger.debug("Geo lookup failed for %s: %s", ip, e)

    geo_cache[ip] = result
    if len(geo_cache) > MAX_CACHE_SIZE:
        geo_cache.popitem(last=False)

    return result


async def _send_telegram_alert(bot: Bot, config: Settings, text: str):
    """Sends an alert message to the admin chat."""
    try:
        await bot.send_message(
            chat_id=config.CHAT_ID,
            text=f"📦 GeoIP Update\n\n{text}",
            message_thread_id=config.MESSAGE_THREAD_ID,
        )
        logger.info("Sent GeoIP update notification to Telegram.")
    except Exception as e:
        logger.error("Failed to send Telegram alert: %s", e)


async def download_file(url: str, dest_path: Path):
    """Downloads a file asynchronously."""
    try:
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                with open(dest_path, "wb") as f:
                    while True:
                        chunk = await resp.content.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
        logger.info("Successfully downloaded file to %s", dest_path)
    except Exception as e:
        logger.error("Failed to download GeoIP DB from %s: %s", url, e)
        raise


async def update_geoip_db(bot: Bot, config: Settings):
    """Checks for and downloads/updates the GeoLite2-City database."""
    db_path = config.GEOIP_DB_PATH
    db_dir = db_path.parent
    db_dir.mkdir(exist_ok=True, parents=True)

    if db_path.exists():
        mtime = datetime.fromtimestamp(db_path.stat().st_mtime)
        if datetime.now() - mtime < timedelta(days=28):
            logger.info("GeoIP database is up to date. Next check in ~28 days.")
            return
        update_type = "🔄 Updated GeoIP database"
        body = f"📅 Previous update: {mtime.strftime('%Y-%m-%d')}"
    else:
        update_type = "🆕 First-time GeoIP setup"
        body = "📂 Database will be downloaded for the first time."

    logger.info(body)

    if not config.MAXMIND_LICENSE_KEY:
        error_msg = (
            "❌ GeoIP update failed: MAXMIND_LICENSE_KEY is not set in .env file."
        )
        logger.error(error_msg)
        await _send_telegram_alert(bot, config, error_msg)
        return

    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City"
        f"&license_key={config.MAXMIND_LICENSE_KEY}"
        f"&suffix=tar.gz"
    )
    tar_path = db_dir / "GeoLite2-City.tar.gz"

    try:
        logger.info("Downloading GeoLite2-City database...")
        await download_file(url, tar_path)

        logger.info("Extracting .mmdb file from archive...")
        extracted = False
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    # Extract to the final destination with the correct name
                    member.name = db_path.name
                    tar.extract(member, path=db_dir)
                    extracted = True
                    logger.info("Successfully extracted %s", db_path)
                    break

        if not extracted:
            raise FileNotFoundError("No .mmdb file found in the downloaded archive.")

        success_msg = (
            f"{update_type}\n{body}\n\n"
            f"✅ Successfully downloaded and installed new GeoIP database."
        )
        await _send_telegram_alert(bot, config, success_msg)

    except Exception as e:
        error_msg = f"❌ GeoIP update process failed: {e}"
        logger.error(error_msg, exc_info=True)
        await _send_telegram_alert(bot, config, error_msg)
    finally:
        if tar_path.exists():
            tar_path.unlink()
