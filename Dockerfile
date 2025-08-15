# Dockerfile
# Docker image for fail2ban Telegram monitoring bot
# Uses Python 3.12-slim for minimal size and security

# Base image: official Python slim image
FROM python:3.12-slim

# Metadata labels
LABEL org.opencontainers.image.title="fail2ban-bot" \
      org.opencontainers.image.description="Telegram bot for monitoring fail2ban bans, stats, geo-mapping and service status" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://github.com/ksalab/fail2ban_bot" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="ksalab0@gmail.com"

# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Forces Python output to be unbuffered
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies required for GeoIP and cartography
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        libproj-dev \
        libgeos-dev \
        libgdal-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies file
COPY requirements.txt .

# Install Python packages
# geopandas, cartopy, geoip2, matplotlib, python-telegram-bot, python-dotenv
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY fail2ban_bot.py .env* ./

# Create directory for GeoIP database
RUN mkdir -p /app/geoip

# Expose no ports — bot runs in polling mode
# No healthcheck needed — bot logs indicate status

# Run the bot as non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Command to run the bot
CMD ["python", "fail2ban_bot.py"]
