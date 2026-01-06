import re
import logging
from datetime import datetime
import threading
import socket
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from queue import Queue
import psutil
import signal
import sys
import pycef
import chardet

# ---------------------------
# Configuration
# ---------------------------
LOG_FILE = '/opt/theqsecofrsiem/logs/access.log'
DB_URI = 'sqlite:////opt/theqsecofrsiem/logs/logs.db'
UDP_PORT = 1514
TCP_PORT = 1514
MAX_LOGS = 1000
SOCKETIO_BATCH_INTERVAL = 1.0  # seconds

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logging.info(f"Process started, memory usage: {psutil.Process().memory_info().rss / 1024 / 1024:.2f} MB")

# ---------------------------
# Flask & SocketIO
# ---------------------------
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')  # <-- Use threading mode

# ---------------------------
# Database
# ---------------------------
engine = create_engine(DB_URI, pool_size=5, max_overflow=10)
Session = scoped_session(sessionmaker(bind=engine))

def init_db():
    session = Session()
    session.execute(text('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            message TEXT,
            format_type TEXT,
            raw TEXT,
            sev TEXT,
            user TEXT,
            dvc TEXT,
            msgid TEXT
        )
    '''))
    session.commit()
    Session.remove()
    logging.info("Database initialized with IBM i fields")

# ---------------------------
# Queue for DB Inserts
# ---------------------------
log_queue = Queue()

def db_worker():
    while True:
        log_item = log_queue.get()
        if log_item is None:
            break
        try:
            print("🧱 DB INSERT:", log_item)   # <-- ADD THIS
            session = Session()
            session.execute(
                text('''
                    INSERT INTO logs (timestamp, host, message, format_type, raw, sev, user, dvc, msgid)
                    VALUES (:timestamp, :host, :message, :format_type, :raw, :sev, :user, :dvc, :msgid)
                '''),
                log_item
            )
            session.commit()
            # Purge old logs
            count = session.execute(text('SELECT COUNT(*) FROM logs')).scalar()
            if count > MAX_LOGS:
                session.execute(
                    text('DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY id ASC LIMIT :limit)'),
                    {'limit': count - MAX_LOGS}
                )
                session.commit()
                logging.info(f"Purged {count - MAX_LOGS} old records")
        except Exception as e:
            logging.error(f"DB worker error: {e}, log: {log_item}")
            session.rollback()
        finally:
            Session.remove()
        log_queue.task_done()

threading.Thread(target=db_worker, daemon=True).start()

# ---------------------------
# Parsing Helpers
# ---------------------------
def detect_encoding(data_bytes):
    result = chardet.detect(data_bytes)
    return result['encoding'] or 'utf-8'

def parse_leef(data):
    try:
        parts = data.split('\t')
        parsed = {
            'host': 'unknown',
            'message': data,
            'sev': None,
            'user': None,
            'dvc': None,
            'msgid': None
        }
        for attr in parts[1:]:
            if '=' in attr:
                key, value = attr.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                if key == 'src':
                    parsed['host'] = value
                elif key == 'msg':
                    parsed['message'] = value
                elif key == 'sev':
                    parsed['sev'] = value
                elif key in ('usr', 'user'):
                    parsed['user'] = value
                elif key == 'dvc':
                    parsed['dvc'] = value
                elif key == 'msgid':
                    parsed['msgid'] = value
        return parsed
    except Exception as e:
        logging.error(f"LEEF parse error: {e}, raw: '{data[:100]}'")
        return None

def parse_bsd_syslog(data):
    try:
        bsd_regex = re.compile(r'<(\d+)>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w.-]+)\s+(.+)')
        match = bsd_regex.match(data)
        if match:
            _, timestamp_str, host, message = match.groups()
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", '%Y %b %d %H:%M:%S').isoformat()
            return {
                'timestamp': timestamp,
                'host': host,
                'message': message,
                'format_type': 'SYSLOG_BSD'
            }
        return None
    except Exception as e:
        logging.error(f"BSD parse error: {e}")
        return None


def parse_rfc5424(data):
    """
    Parse RFC5424 syslog.
    IBM i often has optional APP-NAME, PROCID, MSGID
    Example: <165>1 2026-01-05T12:00:00Z testhost app 12345 ID1 - Message
    """
    try:
        # Pattern breakdown:
        # <PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID - MSG
        rfc_regex = re.compile(
            r'<(\d+)>1\s+'                           # <PRI>1
            r'([\d\-T:\.]+(?:Z|[+\-]\d{2}:\d{2}))\s+'  # timestamp with optional microseconds and timezone
            r'([\w\.-]+)\s+'                         # host
            r'([\w\.-]+|-)\s+'                        # app-name (or -)
            r'([\w\.-]+|-)\s+'                        # procid (or -)
            r'([\w\.-]+|-)\s+'                        # msgid
            r'-\s+'                                   # literal -
            r'(.+)'                                   # message
        )
        match = rfc_regex.match(data)
        if match:
            _, timestamp_str, host, app, proc, msgid, msg = match.groups()
            # Convert timestamp to ISO format
            timestamp = datetime.fromisoformat(timestamp_str).isoformat()
            return {
                'timestamp': timestamp,
                'host': host,
                'message': msg,
                'msgid': None if msgid == '-' else msgid,
                'format_type': 'SYSLOG_RFC5424'
            }
        return None
    except Exception as e:
        logging.error(f"RFC5424 parse error: {e}, raw: {data[:100]}")
        return None

def parse_cef(data):
    try:
        parsed = pycef.parse(data)
        return {
            'host': parsed.get('src', 'unknown'),
            'message': f"CEF Event: {parsed.get('Name','')} msg={parsed.get('msg','')}",
            'timestamp': parsed.get('rt', datetime.now().isoformat()),  # use CEF timestamp if available
            'sev': parsed.get('sev'),
            'user': parsed.get('usr') or parsed.get('user'),
            'dvc': parsed.get('dvc'),
            'msgid': parsed.get('msgid'),
            'format_type': 'CEF'  # <-- ensures proper classification
        }
    except Exception as e:
        logging.error(f"CEF parse error: {e}")
        return None


# ---------------------------
# Log Processing
# ---------------------------
socketio_buffer = []

def process_log(raw_data, client_address):
    if isinstance(raw_data, bytes):
        encoding = detect_encoding(raw_data)
        raw_data = raw_data.decode(encoding, errors='ignore')
    raw_data = raw_data.strip('\x00\n\r\t ')

    host = client_address[0]
    timestamp = datetime.now().isoformat()
    format_type = 'UNKNOWN'
    message = raw_data
    sev = user = dvc = msgid = None

    parsed = None

    # First, try to detect CEF anywhere in the message
    if 'CEF:' in raw_data:
        parsed = parse_cef(raw_data)
        format_type = 'CEF'
    # Otherwise, fallback to prefix-based detection
    elif raw_data.startswith('LEEF:'):
        parsed = parse_leef(raw_data)
        format_type = 'LEEF'
    elif raw_data.startswith('<'):
        parsed = parse_rfc5424(raw_data)
        if parsed:
            format_type = parsed.get('format_type', 'SYSLOG_RFC5424')
        else:
            parsed = parse_bsd_syslog(raw_data)
            if parsed:
                format_type = parsed.get('format_type', 'SYSLOG_BSD')

    if parsed:
        host = parsed.get('host', host)
        message = parsed.get('message', message)
        timestamp = parsed.get('timestamp', timestamp)
        sev = parsed.get('sev')
        user = parsed.get('user')
        dvc = parsed.get('dvc')
        msgid = parsed.get('msgid')
        format_type = parsed.get('format_type', format_type)

    log_item = {
        'timestamp': timestamp,
        'host': host,
        'message': message,
        'format_type': format_type,
        'raw': raw_data,
        'sev': sev,
        'user': user,
        'dvc': dvc,
        'msgid': msgid
    }

    log_queue.put(log_item)
    socketio_buffer.append(log_item)


# ---------------------------
# UDP/TCP Servers (Threading)
# ---------------------------
def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', UDP_PORT))
    logging.info(f"UDP server listening on 0.0.0.0:{UDP_PORT}")
    while True:
        data, addr = sock.recvfrom(8192)
        print("🔥 UDP RECEIVED:", addr, data.decode(errors="ignore"))
        process_log(data, addr)

def tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', TCP_PORT))
    sock.listen(50)
    logging.info(f"TCP server listening on 0.0.0.0:{TCP_PORT}")
    while True:
        conn, addr = sock.accept()
        data = conn.recv(8192)
        process_log(data, addr)
        conn.close()

# ---------------------------
# SocketIO Emitter
# ---------------------------
def socketio_emitter():
    while True:
        if socketio_buffer:
            batch = socketio_buffer.copy()
            socketio_buffer.clear()
            # emit each log individually
            for log_item in batch:
                socketio.emit('new_log', log_item)
        threading.Event().wait(SOCKETIO_BATCH_INTERVAL)

threading.Thread(target=udp_server, daemon=True).start()
threading.Thread(target=tcp_server, daemon=True).start()
threading.Thread(target=socketio_emitter, daemon=True).start()

# ---------------------------
# Flask Routes
# ---------------------------
@app.route('/')
def index():
    try:
        session = Session()
        result = session.execute(
            text('''
                SELECT timestamp, host, message, format_type, raw, sev, user, dvc, msgid
                FROM logs
                ORDER BY id DESC
                LIMIT :limit
            '''),
            {'limit': MAX_LOGS}
        )

        logs = []
        for row in result:
            logs.append({
                'timestamp': row[0],
                'host': row[1],
                'message': row[2],
                'format_type': row[3],
                'raw': row[4],
                'sev': row[5],
                'user': row[6],
                'dvc': row[7],
                'msgid': row[8],
            })

        return render_template('index.html', logs=logs)

    except Exception as e:
        logging.error(f"Index error: {e}")
        return render_template('index.html', logs=[])
    finally:
        Session.remove()

@app.route('/api/logs')
def api_logs():
    try:
        session = Session()
        result = session.execute(
            text('SELECT timestamp, host, message, format_type, raw, sev, user, dvc, msgid FROM logs ORDER BY id DESC LIMIT :limit'),
            {'limit': MAX_LOGS}
        )
        logs = [[item.decode('utf-8', errors='ignore') if isinstance(item, bytes) else item for item in row] for row in result]
        return jsonify(logs)
    except Exception as e:
        logging.error(f"/api/logs error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        Session.remove()

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'memory_mb': psutil.Process().memory_info().rss / 1024 / 1024
    })

@socketio.on('connect')
def handle_connect():
    logging.info("Client connected")

# ---------------------------
# Signal Handling
# ---------------------------
def shutdown_handler(sig, frame):
    logging.info("Shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------
# Main
# ---------------------------
if __name__ == '__main__':
    init_db()
    logging.info("Starting Flask SocketIO server")
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        allow_unsafe_werkzeug=True
    )
