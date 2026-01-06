# Use official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production \
    PORT=5000

# Create app directory
WORKDIR /opt/theqsecofrsiem

#proxy
ENV HTTP_PROXY=http://192.168.68.93:3128
ENV HTTPS_PROXY=http://192.168.68.93:3128

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Create logs directory
RUN mkdir -p /opt/theqsecofrsiem/logs

# Expose Flask port and UDP/TCP syslog port
EXPOSE 5000/tcp
EXPOSE 1514/tcp
EXPOSE 1514/udp

# Run the app
CMD ["python", "startappserver.py"]
