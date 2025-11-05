# Dockerfile for detection engine - Auto Mode
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir \
    yara-python>=4.0.0 \
    psutil>=5.8.0 \
    capstone>=4.0.0 \
    PyYAML>=6.0 \
    requests>=2.28.0 \
    reportlab>=3.6.0 \
    pefile>=2023.2.7 \
    pytz>=2023.3

# Copy application code
COPY detection/ ./detection/
COPY utils/ ./utils/
COPY config/ ./config/
COPY agent/ ./agent/

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /quarantine

# Set environment variables for auto mode
ENV PYTHONUNBUFFERED=1
ENV AUTO_MODE=true

# Run orchestrator in continuous mode (auto mode)
CMD ["python", "detection/orchestrator.py"] 