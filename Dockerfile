# Base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    APP_DIR=/opt/satsiem \
    LOG_DIR=/opt/satsiem/logs \
    UDP_PORT=1514 \
    TCP_PORT=1514 \
    FLASK_APP=startappserver.py

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directories
RUN mkdir -p $APP_DIR $LOG_DIR
WORKDIR $APP_DIR

# Copy app code
COPY . $APP_DIR

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose ports (UDP and TCP for logs, plus Flask port)
EXPOSE 1514/udp
EXPOSE 1514/tcp
EXPOSE 5000/tcp

# Healthcheck (simple)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD curl -f http://localhost:5000/health || exit 1

# Start the app
CMD ["python3", "startappserver.py"]
