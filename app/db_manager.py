import os
import sqlite3
import logging
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(__file__), "db")
DB_PATH = os.path.join(DB_DIR, "fail2ban.db")

# We use a shared logger as in the main module.
logger = logging.getLogger(__name__)


class DBManager:
    def __init__(self):
        if not os.path.exists(DB_DIR):
            os.makedirs(DB_DIR)
            logger.info("📂 Created directory for DB: %s", DB_DIR)

        try:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            logger.info("🗄 Connected to SQLite DB: %s", DB_PATH)
            self._create_tables()
        except Exception as e:
            logger.error("❌ Failed to initialize DB: %s", e)

    def _create_tables(self):
        query = """
        CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ip TEXT NOT NULL,
            jail TEXT,
            action TEXT,
            reason TEXT,
            country TEXT,
            city TEXT,
            raw_line TEXT
        );
        """
        try:
            self.conn.execute(query)
            self.conn.commit()
            logger.info("✅ Ensured table 'bans' exists")
        except Exception as e:
            logger.error("❌ Failed to create tables: %s", e)

    def ban_exists(self, ts, ip):
        """Return True if a ban with the same timestamp and IP already exists."""
        if isinstance(ts, datetime):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(ts)
        try:
            cur = self.conn.execute(
                "SELECT 1 FROM bans WHERE ts = ? AND ip = ? LIMIT 1", (ts_str, ip)
            )
            return cur.fetchone() is not None
        except Exception as e:
            logger.error("❌ Failed to check ban existence: %s", e)
            return False

    def insert_ban(
        self,
        ip,
        jail,
        action,
        reason=None,
        country=None,
        city=None,
        raw_line=None,
        ts=None,
    ):
        """Insert a ban record into the database.
        If ts is provided (datetime or str), use it; otherwise use current time.
        """
        # Normalize timestamp to DB string
        if ts is None:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(ts, datetime):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(ts)

        query = """
        INSERT INTO bans (ts, ip, jail, action, reason, country, city, raw_line)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            self.conn.execute(
                query, (ts_str, ip, jail, action, reason, country, city, raw_line)
            )
            self.conn.commit()
            logger.info("➕ Inserted %s for %s at %s", action, ip, ts_str)
        except Exception as e:
            logger.error("❌ Failed to insert ban record: %s", e)

    def fetch_bans(self, since=None):
        """Fetch bans. Returns rows including raw_line for deduplication/inspection."""
        query = "SELECT ts, ip, jail, action, reason, country, city, raw_line FROM bans"
        params = []
        if since:
            query += " WHERE ts >= ?"
            params.append(since.strftime("%Y-%m-%d %H:%M:%S"))

        try:
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            logger.info("📊 Fetched %d ban records", len(rows))
            return rows
        except Exception as e:
            logger.error("❌ Failed to fetch bans: %s", e)
            return []

    def close(self):
        try:
            self.conn.close()
            logger.info("🔒 Closed SQLite connection")
        except Exception as e:
            logger.error("❌ Failed to close DB connection: %s", e)
