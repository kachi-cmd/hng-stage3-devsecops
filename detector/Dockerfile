FROM python:3.11-slim

# Install iptables (needed for blocking) and other system deps
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy detector source
COPY *.py ./
COPY config.yaml ./

# Create log directory
RUN mkdir -p /var/log/detector

# The daemon must run as root for iptables access
USER root

CMD ["python", "-u", "main.py"]
