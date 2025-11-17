import time
import requests
import os
import getpass
import sys  
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta

# --- Configuration ---
SERVER_URL = "http://127.0.0.1:5000/log"
path_to_watch = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\aashi\OneDrive\Documents\InsiderThreatDetector\test"

# Check if path exists
if not os.path.exists(path_to_watch):
    print(f"[Agent] Error: Path {path_to_watch} does not exist.")
    exit(1)

def check_for_anomaly(alert_data, alert_time_utc):
    """
    Analyzes alert data for suspicion.
    Returns level: 0 (Normal), 1 (Suspicious), 2 (Critical)
    """
    file_name_lower = alert_data.get('file_name', '').lower()

    # --- Rule 0: Critical (Level 2) ---
    if '_honey_' in file_name_lower:
        return 2  # CRITICAL

    # --- Rule 1: Suspicious (Level 1) - Time ---
    ist_time = alert_time_utc + timedelta(hours=5, minutes=30)
    if ist_time.hour < 7 or ist_time.hour >= 22:
        return 1  # Suspicious

    # --- Rule 2: Suspicious (Level 1) - Keywords ---
    suspicious_keywords = ['confidential', 'salary', 'private', 'password']
    for keyword in suspicious_keywords:
        if keyword in file_name_lower:
            return 1  # Suspicious

    return 0

def deploy_honeyfile(original_path):
    """Creates a honeyfile in the same directory as the suspicious event."""
    directory = os.path.dirname(original_path)
    honey_filename = f"legacy_credentials_{getpass.getuser()}.bak"
    honey_path = os.path.join(directory, honey_filename)

    if os.path.exists(honey_path):
        return

    try:
        with open(honey_path, 'w') as f:
            f.write("--- FAKE SENSITIVE DATA ---\n")
            f.write("AWS_ACCESS_KEY_ID = AKIAFAKEKEY12345\n")
            f.write("AWS_SECRET_ACCESS_KEY = FAKESECRETKEYabc123xyz\n")
        print(f"[Agent] *** Honeyfile Deployed at {honey_path} ***")
    except Exception as e:
        print(f"[Agent] Error: Could not deploy honeyfile: {e}")

# --- Watchdog Event Handler ---
class MyHandler(FileSystemEventHandler):

    def send_alert(self, action, file_path):
        
        file_name = os.path.basename(file_path)

        if file_name == 'desktop.ini':
            return
            
        if action == "created" and "legacy_credentials_" in file_name.lower():
            print(f"[Agent] Honeyfile {file_name} planted. Ignoring 'created' alert.")
            return 
        
        current_user = getpass.getuser()
        data = {
            "action": action,
            "file_path": file_path,
            "file_name": file_name,
            "user": current_user
        }
        
        try:
            requests.post(SERVER_URL, json=data)
            print(f"[Agent] Sent alert: {action} on {file_path} by {current_user}")
        except requests.exceptions.ConnectionError:
            print(f"[Agent] Error: Could not connect to server at {SERVER_URL}")

        if check_for_anomaly(data, datetime.utcnow()) > 0:
            if "_honey_" not in file_name.lower():
                deploy_honeyfile(file_path)

    def on_created(self, event):
        self.send_alert(action="created", file_path=event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.send_alert(action="modified", file_path=event.src_path)
            
    def on_deleted(self, event):
        self.send_alert(action="deleted", file_path=event.src_path)

# --- Setup the monitoring ---
print(f"[Agent] Monitoring folder: {path_to_watch}")
print(f"[Agent] Sending alerts to: {SERVER_URL}")

event_handler = MyHandler()
observer = Observer()
observer.schedule(event_handler, path_to_watch, recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
    print("[Agent] Monitoring stopped.")
observer.join()
