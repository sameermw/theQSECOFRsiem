#!/bin/bash
# satsiem-setup.sh
# Production setup for IBM i SIEM Log Collector on RHEL

# -------------------------
# Variables (change as needed)
# -------------------------
APP_DIR="/opt/satsiem2"
LOG_DIR="$APP_DIR/logs"
PYTHON_SCRIPT="$APP_DIR/startappserver.py"
USER_NAME="satsiemuser"       # Non-root user
GROUP_NAME="satsiemuser"
POSTGRES_USER="postgres"
POSTGRES_DB="satsiem"
POSTGRES_HOST="localhost"
APP_PORT_UDP=1514
APP_PORT_TCP=1514
SYSLOG_PORT=514

# -------------------------
# Create user if not exists
# -------------------------
if ! id "$USER_NAME" &>/dev/null; then
    echo "Creating user $USER_NAME..."
    sudo useradd -r -s /bin/false $USER_NAME
fi

# -------------------------
# Create directories
# -------------------------
echo "Creating directories..."
sudo mkdir -p "$APP_DIR"
sudo mkdir -p "$LOG_DIR"
sudo chown -R $USER_NAME:$GROUP_NAME "$APP_DIR"

# -------------------------
# PostgreSQL DB setup check
# -------------------------
echo "Checking PostgreSQL connectivity..."
#PG_CMD="psql -U $POSTGRES_USER -h $POSTGRES_HOST -d $POSTGRES_DB -c '\q'"
#if ! sudo -u $POSTGRES_USER bash -c "$PG_CMD" &>/dev/null; then
#    echo "Database $POSTGRES_DB does not exist. Creating..."
#    sudo -u $POSTGRES_USER createdb $POSTGRES_DB
#else
#    echo "Database $POSTGRES_DB exists."
#fi

# -------------------------
# IPTables port redirection
# -------------------------
echo "Configuring iptables redirection from $SYSLOG_PORT to $APP_PORT_UDP/TCP..."
#sudo iptables -t nat -C PREROUTING -p udp --dport $SYSLOG_PORT -j REDIRECT --to-port $APP_PORT_UDP 2>/dev/null || \
#sudo iptables -t nat -A PREROUTING -p udp --dport $SYSLOG_PORT -j REDIRECT --to-port $APP_PORT_UDP

#sudo iptables -t nat -C PREROUTING -p tcp --dport $SYSLOG_PORT -j REDIRECT --to-port $APP_PORT_TCP 2>/dev/null || \
#sudo iptables -t nat -A PREROUTING -p tcp --dport $SYSLOG_PORT -j REDIRECT --to-port $APP_PORT_TCP

# Save iptables
#sudo sh -c "iptables-save > /etc/iptables/rules.v4"

# -------------------------
# Log rotation setup
# -------------------------
echo "Setting up log rotation..."
LOGROTATE_FILE="/etc/logrotate.d/satsiem"
sudo bash -c "cat > $LOGROTATE_FILE" <<EOL
$LOG_DIR/access.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOL

# -------------------------
# Systemd service
# -------------------------
echo "Creating systemd service..."
SERVICE_FILE="/etc/systemd/system/satsiem2.service"
sudo bash -c "cat > $SERVICE_FILE" <<EOL
[Unit]
Description=IBM i SIEM Log Collector
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $PYTHON_SCRIPT
Restart=always
RestartSec=5
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOL

# -------------------------
# Enable & start service
# -------------------------
echo "Reloading systemd and starting service..."
#sudo systemctl daemon-reload
#sudo systemctl enable satsiem2
#sudo systemctl start satsiem2

# -------------------------
# Status check
# -------------------------
echo "Service status:"
#sudo systemctl status satsiem2 --no-pager

echo "Setup completed! Logs: $LOG_DIR/access.log"
echo "Python app listens on UDP/TCP port $APP_PORT_UDP, syslog port $SYSLOG_PORT is redirected via iptables."
