# Dockerfile
# Docker image for fail2ban Telegram monitoring bot

# ARG allows to easily change the Python version during build
ARG PYTHON_VERSION=3.12-slim
# Base image: official Python slim image
FROM python:${PYTHON_VERSION}

# Metadata labels
# ... (labels section remains the same)

# Prevents Python from writing .pyc files and forces unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
# ... (apt-get section remains the same)

# Copy the project definition file
COPY pyproject.toml .

# Install Python packages from pyproject.toml
RUN pip install --no-cache-dir .

# Copy the application code into the container
COPY main.py .
COPY app ./app/

# Copy the environment file
COPY .env .

# Create directories for the database and GeoIP data
RUN mkdir -p /app/db /app/geoip

# Run the bot as a non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Command to run the bot
CMD ["python", "main.py"]
