# Use Python 3.11 slim image as base (as specified in requirements)
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies required for network scanning
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir \
    asyncio \
    aiofiles \
    click \
    scapy \
    python-nmap \
    netaddr

# Copy application code
COPY app/ ./app/
COPY monitor.py ./

# Create output directory with proper permissions
RUN mkdir -p /app/output && \
    chmod 755 /app/output

# Create non-root user for security (network scanning needs some privileges)
RUN groupadd -r netsniff && \
    useradd -r -g netsniff -d /app -s /bin/bash netsniff && \
    chown -R netsniff:netsniff /app

# Switch to non-root user
USER netsniff

# Set default command to run the monitoring script
CMD ["python", "monitor.py"]