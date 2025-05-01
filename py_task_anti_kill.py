import os.path
import sys
import time
import psutil
import subprocess

WATCHDOG_INTERVAL = 1
MAIN_APP_PATH = "py_task_manager.exe"
PID_FILE = "main_app.pid"

def is_main_running():
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read())
        return psutil.pid_exists(pid)
    except Exception:
        return False

def start_main():
    proc = subprocess.Popen([MAIN_APP_PATH])
    with open(PID_FILE, 'w') as f:
        f.write(str(proc.pid))

while True:
    if not is_main_running():
        print("[!] Процесс остановлен. Перезапуск...")
        start_main()
    elif os.path.exists("process_closed_by_user.flag"):
        sys.exit()
    time.sleep(WATCHDOG_INTERVAL)