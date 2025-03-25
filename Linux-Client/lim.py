import os
import json
import pyinotify
import re
import sys
import signal
import time
from datetime import datetime
from multiprocessing import Process
from log_detection_engine import LogDetectionEngine

# ---- Configuration ----
CONFIG_FILE = "fim.config"
ALERT_DIR = "logs"
ALERT_LOG = os.path.join(ALERT_DIR, "log_integrity_alerts.log")
PID_FILE = "lim.pid"
from collections import defaultdict
import time

# Alert suppression: max frequency (in seconds) per unique message
ALERT_SUPPRESSION_WINDOW = 60  # suppress duplicates for 60 seconds
recent_alerts = defaultdict(lambda: 0)

# ---- Help Menu ----
def print_help():
    print("""
  python lim               Start the LIM monitoring service in foreground mode
  python lim -s or stop    Stop the LIM service if running in background (daemon) mode
  python lim restart       Restart the LIM monitoring service
  python lim -d or daemon  Run LIM in background (daemon) mode
  python lim help          Show this help message
""")

# ---- Alert Logging ----
def log_alert(message, tags=None, extra=None):
    now = datetime.utcnow().isoformat()
    os.makedirs(ALERT_DIR, exist_ok=True)

    alert_entry = {
        "timestamp": now,
        "source": "LIM",
        "message": message,
    }

    if tags:
        alert_entry["tags"] = tags
    if extra:
        alert_entry.update(extra)

    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert_entry) + "\n")

    print(json.dumps(alert_entry))

# ---- Load or Update fim.config ----
def get_all_log_files(base_dir="/var/log"):
    log_files = []
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            # Only .log files, skip rotated or compressed versions
            if (
                name.endswith(".log")
                and not re.match(r".*\.log\.\d+$", name)
                and not name.endswith(".log.gz")
            ):
                full_path = os.path.join(root, name)
                log_files.append(full_path)
    return sorted(log_files)

def load_or_update_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: {CONFIG_FILE} not found.")
        sys.exit(1)

    with open(CONFIG_FILE, 'r') as f:
        data = json.load(f)

    current_logs = get_all_log_files()

    if "log_integrity_monitor" not in data:
        lim_config = {
            "enabled": True,
            "monitored_logs": current_logs
        }

        updated_data = {}
        for key in data:
            if key == "siem_settings":
                updated_data["log_integrity_monitor"] = lim_config
            updated_data[key] = data[key]

        with open(CONFIG_FILE, 'w') as f:
            json.dump(updated_data, f, indent=4)

        print(f"[LIM] log_integrity_monitor section inserted into fim.config with {len(current_logs)} .log files")

        return lim_config

    # Check if monitored_logs is out of date and update if needed
    existing_logs = sorted(data["log_integrity_monitor"].get("monitored_logs", []))
    if existing_logs != current_logs:
        data["log_integrity_monitor"]["monitored_logs"] = current_logs
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[LIM] monitored_logs updated in fim.config with {len(current_logs)} .log files")

    return data["log_integrity_monitor"]

# ---- Pattern Matching ----
def scan_file_for_patterns(path, patterns):
    alerts = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        alerts.append((path, line.strip()))
    except Exception as e:
        log_alert(f"ERROR reading {path}: {e}")
    return alerts

# ---- Pyinotify Handler ----
class LogEventHandler(pyinotify.ProcessEvent):
    def __init__(self, excluded_ips, excluded_users):
        self.engine = LogDetectionEngine(excluded_ips, excluded_users)

    def process_IN_MODIFY(self, event):
        try:
            with open(event.pathname, 'r', errors='ignore') as f:
                lines = f.readlines()[-50:]  # Analyze last 50 lines on modification
        except Exception as e:
            log_alert(f"ERROR reading {event.pathname}: {e}")
            return

        for line in lines:
            alert = self.engine.analyze_line(line)
            if alert:
                msg = f"Suspicious activity from IP={alert['ip']} USER={alert['user']}: score={alert['score']} ({', '.join(alert['tags'])})"
                extra = {
                    "reason": alert["reason"],
                    "raw_log": alert["line"],
                    "ip": alert["ip"],
                    "user": alert["user"],
                    "score": alert["score"]
                }
                log_alert(msg, tags=alert["tags"], extra=extra)

    def process_IN_DELETE_SELF(self, event):
        log_alert(f"DELETED: {event.pathname} was deleted!")

    def process_IN_MOVE_SELF(self, event):
        log_alert(f"MOVED: {event.pathname} was rotated or renamed!")

# ---- Main Monitor Logic ----
def monitor_logs():
    config = load_or_update_config()
    if not config.get("enabled", True):
        print("Log integrity monitoring is disabled in fim.config.")
        return

    log_files = config.get("monitored_logs", [])
    excluded_ips = set(config.get("excluded_ips", []))
    excluded_users = set(config.get("excluded_users", []))

    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_MODIFY | pyinotify.IN_DELETE_SELF | pyinotify.IN_MOVE_SELF
    handler = LogEventHandler(excluded_ips, excluded_users)
    notifier = pyinotify.Notifier(wm, handler)

    for path in log_files:
        if os.path.exists(path) and os.access(path, os.R_OK):
            try:
                wm.add_watch(path, mask)
            except Exception as e:
                log_alert(f"ERROR adding watch to {path}: {e}")
        else:
            if not os.path.exists(path):
                log_alert(f"ERROR: Log file {path} does not exist.")
            elif not os.access(path, os.R_OK):
                log_alert(f"ERROR: No read permission for log file {path}.")

    log_alert("LIM is running...")
    notifier.loop()

# ---- Daemon Management ----
def start_daemon():
    if os.path.exists(PID_FILE):
        print("LIM already running or PID file exists.")
        return
    p = Process(target=monitor_logs)
    p.start()
    with open(PID_FILE, 'w') as f:
        f.write(str(p.pid))
    print(f"LIM started in daemon mode with PID {p.pid}")

def stop_daemon():
    if not os.path.exists(PID_FILE):
        print("No LIM daemon is running.")
        return
    with open(PID_FILE, 'r') as f:
        pid = int(f.read())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"LIM process {pid} terminated.")
    except ProcessLookupError:
        print("Process not found. Removing stale PID file.")
    os.remove(PID_FILE)

def restart_daemon():
    stop_daemon()
    time.sleep(1)
    start_daemon()

# ---- Entry Point ----
if __name__ == "__main__":
    if len(sys.argv) == 1:
        monitor_logs()
    elif sys.argv[1] in ("-d", "daemon"):
        start_daemon()
    elif sys.argv[1] in ("-s", "stop"):
        stop_daemon()
    elif sys.argv[1] == "restart":
        restart_daemon()
    elif sys.argv[1] == "help":
        print_help()
    else:
        print("Unknown command.")
        print_help()
