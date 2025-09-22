# app/utils/plotting.py
import hashlib
import logging
from datetime import datetime, timedelta
from dateutil import parser
from pathlib import Path
from typing import List, Optional

import cartopy.crs as ccrs
import cartopy.io.shapereader as shpreader
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Patch

from app.config import Settings
from app.db_manager import DBManager
from app.services.fail2ban import parse_log_timestamp
from app.services.geoip import get_geo_info

# Use a non-interactive backend for matplotlib
matplotlib.use("Agg")
logger = logging.getLogger(__name__)


def stable_color(text: str) -> str:
    """Generates a stable hex color based on a string hash."""
    h = hashlib.sha1(text.encode("utf-8")).hexdigest()
    return f"#{h[:6]}"


def generate_single_period_plot(
    db_manager: DBManager, config: Settings, hours: int, period_name: str
) -> Optional[str]:
    """Generates a bar plot showing ban counts per interval within a period."""
    now = datetime.now()
    start_time = now - timedelta(hours=hours)

    # Determine number of buckets and interval duration
    if hours <= 24:
        buckets = hours
        interval = timedelta(hours=1)
        time_format = "%H:00"
        title_interval = "hour"
    elif hours <= 7 * 24:
        buckets = 7
        interval = timedelta(days=1)
        time_format = "%m-%d"
        title_interval = "day"
    else:
        buckets = 12
        interval = timedelta(days=hours * 24 / buckets)
        time_format = "%m-%d"
        title_interval = "interval"

    times, counts = [], []
    current_bucket_start = start_time

    # Fetch all bans for the period at once to avoid re-reading file
    all_bans_in_period = []
    if db_manager:
        rows = db_manager.fetch_bans(since=start_time)
        all_bans_in_period = [
            parser.parse(r[0]) for r in rows if r[3] and "ban" in r[3].lower()
        ]
    else:  # Fallback to log file
        try:
            with open(config.LOG_FILE, "r") as f:
                for line in f:
                    if "Ban " in line or "ban " in line:
                        ts = parse_log_timestamp(line)
                        if ts and ts >= start_time:
                            all_bans_in_period.append(ts)
        except Exception as e:
            logger.error("Failed to read log for plotting: %s", e)

    # Aggregate counts into buckets
    for _ in range(buckets):
        next_bucket_end = current_bucket_start + interval
        count = sum(
            1
            for ts in all_bans_in_period
            if current_bucket_start <= ts < next_bucket_end
        )

        counts.append(count)
        times.append(current_bucket_start.strftime(time_format))
        current_bucket_start = next_bucket_end

    plt.figure(figsize=(10, 5))
    plt.bar(times, counts, color="steelblue", alpha=0.8)
    plt.title(f"Bans per {title_interval} - Last {period_name}")
    plt.ylabel("Number of Bans")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    plot_path = config.TMP_DIR / f"fail2ban_plot_{period_name.lower()}.png"
    try:
        plt.savefig(plot_path)
        plt.close()
        logger.info("Generated plot: %s", plot_path)
        return str(plot_path)
    except Exception as e:
        logger.error("Failed to save plot %s: %s", plot_path, e)
        return None


def generate_comparison_plot(
    current_bans: int, prev_bans: int, period_name: str, config: Settings
) -> Optional[str]:
    """Generates a comparison bar plot between current and previous period bans."""
    plt.figure(figsize=(6, 4))
    bars = plt.bar(
        ["Previous Period", "Current Period"],
        [prev_bans, current_bans],
        color=["lightcoral", "seagreen"],
        alpha=0.8,
    )
    plt.title(f"Ban Comparison: {period_name}")
    plt.ylabel("Number of Bans")

    # Add labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{int(height)}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    plt.tight_layout()
    plot_path = config.TMP_DIR / f"fail2ban_compare_{period_name.lower()}.png"
    try:
        plt.savefig(plot_path)
        plt.close()
        logger.info("Generated comparison plot: %s", plot_path)
        return str(plot_path)
    except Exception as e:
        logger.error("Failed to save comparison plot %s: %s", plot_path, e)
        return None


def generate_world_map_plot(
    ips: List[str], title: str, config: Settings
) -> Optional[str]:
    """Generates a world map highlighting countries with banned IPs."""
    if not ips:
        logger.warning("Attempted to generate world map with no IPs.")
        return None

    try:
        geo_data = [get_geo_info(ip, config) for ip in ips]
        df = pd.DataFrame(geo_data)
        country_counts = df["country"].value_counts().to_dict()

        # Remove 'Unknown' country from plotting if it exists
        country_counts.pop("Unknown", None)
        if not country_counts:
            logger.info("No IPs with known countries to plot on map.")
            return None

        shpfilename = shpreader.natural_earth(
            resolution="110m", category="cultural", name="admin_0_countries"
        )
        countries_shape = list(shpreader.Reader(shpfilename).records())

        crs = ccrs.Robinson()
        fig, ax = plt.subplots(figsize=(15, 8), subplot_kw={"projection": crs})
        ax.set_global()
        ax.stock_img()

        for country_shape in countries_shape:
            name = country_shape.attributes["NAME"]
            if name in country_counts:
                color = stable_color(name)
                ax.add_geometries(
                    [country_shape.geometry],
                    crs=ccrs.PlateCarree(),
                    facecolor=color,
                    edgecolor="black",
                    linewidth=0.5,
                )

        legend_patches = [
            Patch(color=stable_color(country), label=f"{country} ({count})")
            for country, count in sorted(
                country_counts.items(), key=lambda item: item[1], reverse=True
            )[
                :20
            ]  # Top 20
        ]
        if legend_patches:
            ax.legend(
                handles=legend_patches,
                loc="lower left",
                fontsize=8,
                title="Top Countries by Bans",
                title_fontsize=9,
            )

        plt.title(title, fontsize=16, pad=20)

        plot_path = config.TMP_DIR / "fail2ban_world_map.png"
        plt.savefig(plot_path, dpi=120, bbox_inches="tight")
        plt.close()

        logger.info("Generated world map plot: %s", plot_path)
        return str(plot_path)

    except Exception as e:
        logger.error("Failed to generate world map: %s", e, exc_info=True)
        return None
