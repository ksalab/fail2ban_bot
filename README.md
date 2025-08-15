# fail2ban-bot 🛡️📊

A Telegram bot for monitoring `fail2ban` activity: bans, statistics, service status, and **geolocation mapping** of attackers.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Docker](https://img.shields.io/badge/Docker-Supported-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🚀 Features

- ✅ Real-time ban statistics (hour, day, week, month, year)
- ✅ Comparison with previous periods
- ✅ Service status: `fail2ban` running/enabled/version/start time
- ✅ SSH jail details via `fail2ban-client status sshd`
- 🌍 **Geo-mapping of banned IPs**:
  - World map with unique colors per country
  - Countries without bans → white
  - Legend with country + ban count
- 🔁 Auto-update of GeoIP database (monthly)
- 📢 Telegram notifications on GeoIP update
- 🐳 Fully Dockerized
- 📦 Easy deployment with `.env` config

---

## 📦 Prerequisites

- `fail2ban` installed and running
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- MaxMind account for GeoLite2 (free tier)

---

## 🛠️ Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/fail2ban_bot.git
cd fail2ban_bot
```

### 2. Create .env

```env
BOT_TOKEN=your:bot_token
ADMINS=123456789,987654321
CHAT_ID=-1001234567890
MESSAGE_THREAD_ID=123  # Optional
LOG_FILE=/var/log/fail2ban.log
GEOIP_DB_PATH=./geoip/GeoLite2-City.mmdb
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=your_license_key_here
LOG_LEVEL=INFO
```

### 3. Run with Docker

```bash
docker build -t fail2ban-bot .
docker run -d \
  --name fail2ban-bot \
  --restart unless-stopped \
  -v $(pwd)/geoip:/app/geoip \
  -v /var/log/fail2ban.log:/var/log/fail2ban.log:ro \
  --env-file .env \
  fail2ban-bot
```

> 🔹 The bot will auto-download GeoIP DB on first run.

## 📅 Commands

| COMMANDS | DESCRIPTIONS |
| :------- | :------ |
| `/start` | Welcome message |
| `/stats` | Ban stats by period|
| `/status` | Service status |
| `/geo` | Global geo map of banned IPs|

## 🗺️ Geo Features

- `/geo` → world map with colored countries
- From stats menu → "🗺️ Geo Stats for This Period"
- Auto-updates GeoIP DB every 28 days
- Sends Telegram alert on update

## 📄 License

MIT License — see [LICENSE](./LICENSE)

## 🤝 Contributing

PRs welcome! Please follow Python best practices and keep code clean.
