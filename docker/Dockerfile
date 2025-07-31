# Dockerfile for detection engine
FROM python:3.10-slim
RUN apt-get update && apt-get install -y gcc yara libyara-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir yara-python psutil capstone
WORKDIR /app
COPY detection/ ./detection/
CMD ["python", "detection/yara_scanner.py"] 