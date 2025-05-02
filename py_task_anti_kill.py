import os
import sys
import time
import psutil
import subprocess
import signal

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

def signal_handler(sig, frame):
    print("Закрытие приложения...")
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    if os.path.exists("process_closed_by_user.flag"):
        os.remove("process_closed_by_user.flag")
    sys.exit(0)


def start_main():
    if os.path.exists(MAIN_APP_PATH):
        proc = subprocess.Popen([MAIN_APP_PATH])
        with open(PID_FILE, 'w') as f:
            f.write(str(proc.pid))
    else:
        print("Ошибка! Файл py_task_manager.exe не обнаружен!")
        time.sleep(3)
# Устанавливаем обработчик сигнала
signal.signal(signal.SIGINT, signal_handler)

while True:
    if not is_main_running():
        print("[!] Процесс остановлен. Перезапуск...")
        start_main()
    elif os.path.exists("process_closed_by_user.flag"):
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        if os.path.exists("process_closed_by_user.flag"):
            os.remove("process_closed_by_user.flag")
        sys.exit(0)
    time.sleep(WATCHDOG_INTERVAL)