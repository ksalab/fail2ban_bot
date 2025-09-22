# app/services/fail2ban.py
import asyncio
import logging
import re
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from dateutil import parser

from app.config import Settings
from app.db_manager import DBManager
from app.services.geoip import get_geo_info

logger = logging.getLogger(__name__)


def parse_log_timestamp(log_line: str) -> Optional[datetime]:
    """Parses a timestamp from a log line, trying multiple formats."""
    # ISO format with optional milliseconds: 2023-10-27 10:30:00,123
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?", log_line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            logger.debug("Failed to parse timestamp (ISO basic) from: %s", log_line)

    # ISO 8601 format: 2023-10-27T10:30:00Z
    iso8601_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?", log_line)
    if iso8601_match:
        try:
            return datetime.strptime(iso8601_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            logger.debug("Failed to parse timestamp (ISO8601) from: %s", log_line)
    return None


def extract_banned_ips(
    db_manager: DBManager, config: Settings, since_hours: int = None
) -> List[str]:
    """
    Extracts unique banned IP addresses either from DB or log file.
    Prefers DB for performance and reliability.
    """
    since_dt = datetime.now() - timedelta(hours=since_hours) if since_hours else None

    # Primary method: Use the database
    if db_manager:
        rows = db_manager.fetch_bans(since=since_dt)
        # rows format: (ts, ip, jail, action, reason, country, city, raw_line)
        ips = [r[1] for r in rows if r[3] and "ban" in r[3].lower()]
        # De-duplicate while preserving order
        return list(dict.fromkeys(ips))

    # Fallback method: Parse the log file
    logger.warning(
        "DBManager not available. Falling back to log file parsing for IP extraction."
    )
    ips = []
    try:
        with open(config.LOG_FILE, "r") as f:
            for line in f:
                if "Ban " not in line and "ban " not in line:
                    continue
                m = re.search(
                    r"Ban ([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)", line
                )
                if not m:
                    continue

                ip = m.group(1)
                if since_dt:
                    ts = parse_log_timestamp(line)
                    if not ts or ts < since_dt:
                        continue
                ips.append(ip)
    except Exception as e:
        logger.error("Error reading banned IPs from log file: %s", e)

    return list(dict.fromkeys(ips))


def count_bans_in_period(db_manager: DBManager, config: Settings, hours: int) -> int:
    """
    Counts 'Ban' actions in the last `hours`. Prefers DB; falls back to log parsing.
    """
    since_dt = datetime.now() - timedelta(hours=hours)

    # Primary method: Use the database
    if db_manager:
        rows = db_manager.fetch_bans(since=since_dt)
        count = sum(1 for r in rows if r[3] and "ban" in r[3].lower())
        logger.info("Counted %d bans in last %d hours (from DB)", count, hours)
        return count

    # Fallback method: Parse the log file
    logger.warning(
        "DBManager not available. Falling back to log file parsing for ban count."
    )
    count = 0
    try:
        with open(config.LOG_FILE, "r") as f:
            lines = f.readlines()
        for line in reversed(lines):
            if "Ban " not in line and "ban " not in line:
                continue
            ts = parse_log_timestamp(line)
            if not ts:
                continue
            if ts >= since_dt:
                count += 1
            else:
                break  # Optimization: logs are ordered by time
    except Exception as e:
        logger.error("Error reading log file %s: %s", config.LOG_FILE, e)

    logger.info("Counted %d bans in last %d hours (from log file)", count, hours)
    return count


def get_service_status(
    jail_names: List[str],
) -> Dict[str, any]:  # Изменился входной параметр
    """Retrieves fail2ban service information, including status for multiple jails."""
    status = {
        "running": False,
        "enabled": False,
        "version": "Unknown",
        "start_time": "Unknown",
        "jail_statuses": {},
    }

    def run_command(command: list) -> str:
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                # Return stderr if the command failed, as this is often more informative.
                return (
                    result.stderr.strip()
                    if result.stderr
                    else "Command failed with no output."
                )
            return result.stdout.strip()
        except FileNotFoundError:
            logger.error("Command not found: %s", command[0])
            return f"Error: command '{command[0]}' not found."
        except Exception as e:
            logger.error("Failed to run command '%s': %s", " ".join(command), e)
            return "Error: failed to execute command."

    # Check active and enabled status
    status["running"] = run_command(["systemctl", "is-active", "fail2ban"]) == "active"
    status["enabled"] = (
        run_command(["systemctl", "is-enabled", "fail2ban"]) == "enabled"
    )

    # Get version
    version_output = run_command(["fail2ban-client", "--version"])
    if version_output:
        status["version"] = version_output

    # Get start time
    start_time_output = run_command(
        ["systemctl", "show", "fail2ban", "--property=ActiveEnterTimestamp"]
    )
    if "ActiveEnterTimestamp=" in start_time_output:
        ts_str = start_time_output.split("=", 1)[1]
        try:
            start_dt = parser.parse(ts_str)
            status["start_time"] = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            logger.warning("Could not parse start time: %s", ts_str)

    # Obtaining status for each jail
    for jail in jail_names:
        jail_status_output = run_command(["fail2ban-client", "status", jail])
        status["jail_statuses"][jail] = jail_status_output

    logger.info(
        "Retrieved fail2ban service status for jails: %s", ", ".join(jail_names)
    )
    return status


async def sync_log_to_db(db_manager: DBManager, config: Settings):
    """
    Scans the fail2ban log and inserts new ban/unban records into the database.
    """
    if not db_manager:
        logger.info("DBManager not available; skipping log sync.")
        return

    try:
        with open(config.LOG_FILE, "r") as f:
            lines = f.readlines()
    except Exception as e:
        logger.error("Failed to read log file for sync: %s", e)
        return

    inserted_count = 0
    for line in lines:
        action = None
        if "Ban " in line or " ban " in line:
            action = "Ban"
        elif "Unban " in line or " unban " in line:
            action = "Unban"
        else:
            continue

        ip_match = re.search(
            r"(Ban|Unban) ([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)", line
        )
        if not ip_match:
            continue
        ip = ip_match.group(2)

        ts = parse_log_timestamp(line) or datetime.now()

        if db_manager.ban_exists(ts, ip):
            continue

        jail_match = re.search(r"\[([^\]]+)\]", line)
        jail = jail_match.group(1) if jail_match else "Unknown"

        geo_info = get_geo_info(ip, config)

        db_manager.insert_ban(
            ip=ip,
            jail=jail,
            action=action,
            country=geo_info.get("country"),
            city=geo_info.get("city"),
            raw_line=line.strip(),
            ts=ts,
        )
        inserted_count += 1

    if inserted_count > 0:
        logger.info("Log sync completed. Inserted %d new records.", inserted_count)
    else:
        logger.info("Log sync completed. No new records to insert.")


async def periodic_log_sync(
    db_manager: DBManager, config: Settings, interval_seconds: int = 300
):
    """Background task for periodic log synchronization."""
    logger.info("Starting periodic log sync every %d seconds.", interval_seconds)
    while True:
        try:
            await sync_log_to_db(db_manager, config)
        except Exception as e:
            logger.error("Error during periodic log sync: %s", e, exc_info=True)
        await asyncio.sleep(interval_seconds)
