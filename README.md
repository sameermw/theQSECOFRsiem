# theQSECOFRsiem IBM i Event Monitor

**theQSECOFR SIEM IBM i Event Monitor**

This project provides a lightweight SIEM event monitor for IBM i systems. It parses and displays log events in **RFC5424**, **CEF**, **LEEF**, and **BSD** formats with a live web interface.

---

## Features

- Real-time UDP log collection (default port **1514**)
- Supports **RFC5424**, **CEF**, **LEEF**, and **BSD** formats
- Stores events in **SQLite** database (`logs/logs.db`)
- Modern web UI:
  - Table view with filtering by format
  - Expandable log messages
  - Light/Dark theme toggle
  - Auto-refresh every 30 seconds
- Systemd service for automatic startup
- Logging to `/opt/satsiem/logs`

---

## Project Structure

```
/opt/theqsecofrsiem/
├── logs
│   ├── access.log
│   ├── access.log.1
│   ├── access.log-20250905.gz
│   ├── access.log-20250909.gz
│   ├── access.log-20250911
│   ├── access.log.2.gz
│   ├── access.log.3.gz
│   ├── eventgen.log
│   └── logs.db
├── README.md
├── requirements.txt
├── startappserver.py
├── static
│   └── styles.css
├── systemd
│   └── theqsecofrsiem.service
└── templates
    └── index.html

4 directories, 15 files
```

---

## Setup Instructions
## Option 1 - By cloning git repo

### 1. Python Environment

```bash

#### # Clone repo
cd /opt/theqsecofrsiem
git clone git@github.com:sameermw/theQSECOFRsiem.git

#### Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

#### Enable and start service:

sudo cp systemd/theqsecofrsiem.service
sudo systemctl daemon-reload
sudo systemctl enable theqsecofrsiem
sudo systemctl start theqsecofrsiem
sudo systemctl status theqsecofrsiem



```

## Detail Configuration

### 2. Systemd Service

Create /etc/systemd/system/theqsecofrsiem.service

```
[Unit]
Description=theQSECOFRsiem IBM i Event Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=sam
Group=sam
WorkingDirectory=/opt/theqsecofrsiem
ExecStart=/usr/bin/python3 /opt/theqsecofrsiem/startappserver.py

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

# Logging
#StandardOutput=append:/opt/theqsecofrsiem/logs/service.out.log
#StandardError=append:/opt/theqsecofrsiem/logs/service.err.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/theqsecofrsiem

[Install]
WantedBy=multi-user.target
```

Enable and start service:

sudo systemctl daemon-reload
sudo systemctl enable theqsecofrsiem
sudo systemctl start theqsecofrsiem
sudo systemctl status theqsecofrsiem


### 3. Web Interface

Open browser at:

```http://<server-ip>:5000```

```sudo systemctl status satsiem```

-- Filter by log format using dropdown

-- Click table rows to expand full message

-- Auto-refresh every 30 seconds

-- Light/Dark theme toggle available

### 4. Logging & Database

-- Logs: /opt/satsiem/logs/access.log

-- Error logs: /opt/satsiem/logs/service.err.log

-- SQLite DB: /opt/satsiem/logs/logs.db

Note: Logs and DB are ignored in Git to prevent bloat.

### 5. Git Setup

```
cd /opt/satsiem
git init
git branch -M main

#### Add files
git add .
git commit -m "Initial SIEM service with RFC5424, CEF, LEEF parsing and systemd support"

#### Add remote
git remote add origin git@github.com:<your-username>/satsiem.git

#### Push
git push -u origin main
```

#### Recommended .gitignore

```#### Python
__pycache__/
*.pyc
*.pyo
*.pyd
.env
venv/
.env.*

#### Logs
logs/*.log
logs/*.gz
logs/service.out.log
logs/service.err.log

#### Database
*.db

#### OS
.DS_Store
Thumbs.db

#### IDE
.vscode/
.idea/

#### Systemd runtime artifacts
*.pid
```

## 6. Notes / Best Practices

The Flask server runs with allow_unsafe_werkzeug=True for systemd production environment.

Ensure UDP port 1514 and HTTP port 5000 are open in firewall.

The logs folder must be writable by the service user (sam).

## 7. Troubleshooting

Check service logs:

```sudo journalctl -u satsiem -f```

Check socket listening:
```
ss -lunpt | grep 1514
ss -lntp | grep 5000
```

If the service fails at startup, verify log paths in startappserver.py.

## Option 2 - using docker image.

## 8. Docker 

- Download docker image archive from above github repo to /tmp or different location.
ex: image archive name - theqsecofrsiem_x.xx.tar
```scp theqsecofrsiem_1.0.tar user@otherpc:/tmp/```
- Load image on the target machine
```docker load -i /tmp/theqsecofrsiem_1.0.tar ```
- verify
```docker images ```
- Run container on the new PC
```
docker run -d \
  --name theqsecofrsiwm \
  -p 5000:5000 \
  -p 1514:1514/udp \
  -p 1514:1514/tcp \
  theqsecofrsiem:1.0

```
- Your SIEM is now running on the new machine.
- Persist Logs & Database (VERY IMPORTANT). For your SIEM, always use volumes:
```
docker run -d \
  --name theqsecofrsiem \
  -p 5000:5000 \
  -p 1514:1514/udp \
  -p 1514:1514/tcp \
  -v satsiem_logs:/opt/theqsecofrsiem/logs \
  theqsecofrsiem:1.0

```
- Check Container Health
```
docker ps
docker logs -f satsiem
```

## 9. License

aaa .Sameera Wijayasiri, 2025

