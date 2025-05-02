import os
import sys
import re
import psutil
import hashlib
import requests
import winreg
import platform
import webbrowser
import tkinter.messagebox as messagebox
import ctypes
import time
import subprocess

from datetime import datetime, timedelta
from dotenv import dotenv_values
from threading import Thread, Lock
from packaging import version

# Загрузка конфигурации
try:
    config = dotenv_values(".env")
    VIRUSTOTAL_API_KEY = config.get("KEY")
except:
    VIRUSTOTAL_API_KEY = ""

# Глобальные переменные
lock = Lock()
results_cache = {}  # Кэш для хранения результатов VirusTotal
suspicious_files = []
CURRENT_VERSION = "1.2"  # Обновлена версия

def check_hosts_file():
    """Проверяет файл hosts на наличие подозрительных перенаправлений, особенно антивирусных сайтов."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

    if not os.path.exists(hosts_path):
        print("Файл hosts не найден!")
        return False

    # Список подозрительных IP-адресов (часто используются вредоносами)
    MALICIOUS_IPS = {
        '127.0.0.1',
        '0.0.0.0',
        '192.168.1.1',    # Пример внутреннего IP
        '10.0.0.1'
    }

    # Домены антивирусных компаний, которые ни при каких не должны быть перенаправлены
    ANTIVIRUS_DOMAINS = {
        'kaspersky.com', 'kaspersky.ru', 'avp.ru', 'drweb.com',
        'eset.com', 'bitdefender.com', 'malwarebytes.com', 'avg.com',
        'norton.com', 'avast.com', 'adaware.com', 'bullguard.com',
        'clamav.net', 'f-secure.com', 'trendmicro.com', 'nod32.com'
    }

    suspicious_lines = []

    # Регулярное выражение для поиска строк формата: IP domain
    pattern = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([\w\-\.]+)', re.IGNORECASE)

    with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = pattern.search(line.strip())
            if match:
                ip, domain = match.groups()
                lower_domain = domain.lower()

                # Проверяем, совпадает ли домен с антивирусным
                for av_domain in ANTIVIRUS_DOMAINS:
                    if lower_domain.endswith(av_domain):
                        if ip in MALICIOUS_IPS:
                            suspicious_lines.append(f"{ip} {domain}")
                            break

    if suspicious_lines:
        print("\033[91mПредупреждение: Файл hosts содержит опасные перенаправления антивирусных сайтов!\033[0m")
        for line in suspicious_lines:
            print(f"  → {line}")
        print("Это может указывать на вредоносную активность.")
        if messagebox.askyesno("Проверка hosts",
                               "Обнаружены подозрительные записи в файле hosts. Хотите восстановить стандартный файл?"):
            restore_hosts()
        return True

    print("Файл hosts в порядке.")
    return False

def check_registry_restrictions():
    """
    Проверяет наличие ограничений в реестре для системных утилит.
    Считает блокировкой любое существующее значение, независимо от его содержания.
    При разблокировке удаляет параметр из реестра.
    """
    # Список корневых разделов реестра для проверки
    root_keys = [
        (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
        (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
    ]

    # Описание ограничений с корректными путями для каждого раздела
    restrictions = {
        "DisableTaskMgr": {
            "paths": {
                winreg.HKEY_CURRENT_USER: r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                winreg.HKEY_LOCAL_MACHINE: r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            },
            "description": "Диспетчер задач"
        },
        "DisableCMD": {
            "paths": {
                winreg.HKEY_CURRENT_USER: r"Software\Policies\Microsoft\Windows\System",
                winreg.HKEY_LOCAL_MACHINE: r"Software\Policies\Microsoft\Windows\System"
            },
            "description": "Командная строка"
        },
        "ExecutionPolicy": {
            "paths": {
                winreg.HKEY_CURRENT_USER: r"Software\Policies\Microsoft\Windows\PowerShell\ScriptPolicies",
                winreg.HKEY_LOCAL_MACHINE: r"Software\Policies\Microsoft\Windows\PowerShell\ScriptPolicies"
            },
            "description": "PowerShell"
        },
        "disablegpedit": {
            "paths": {
                winreg.HKEY_CURRENT_USER: r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                winreg.HKEY_LOCAL_MACHINE: r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            },
            "description": "Редактор групповых политик"
        },
        "DisableRegistryTools": {
            "paths": {
                winreg.HKEY_CURRENT_USER: r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                winreg.HKEY_LOCAL_MACHINE: r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            },
            "description": "Редактор реестра (regedit)"
        }
    }

    detected = []  # Список обнаруженных ограничений

    # Проверяем каждый ключ в каждом корневом разделе
    for key_name, info in restrictions.items():
        for root_key, root_name in root_keys:
            path = info["paths"][root_key]
            try:
                with winreg.OpenKey(root_key, path, 0, winreg.KEY_READ) as key:
                    try:
                        # Пытаемся прочитать значение — если оно есть, значит ограничение установлено
                        value, regtype = winreg.QueryValueEx(key, key_name)
                        detected.append((root_key, root_name, path, key_name, info))
                        print(f"[DEBUG] Обнаружено ограничение: {root_name}\\{path}\\{key_name} = {value} (тип: {regtype})")
                    except FileNotFoundError:
                        print(f"[DEBUG] Ключ не найден: {root_name}\\{path}\\{key_name}")
            except (FileNotFoundError, OSError):
                continue  # Пропускаем, если путь отсутствует

    # Выводим результаты
    if detected:
        print("\nОбнаружены блокировки в реестре:")
        for idx, (root_key, root_name, path, key_name, info) in enumerate(detected):
            print(f"{idx + 1}. {info['description']} (ключ: {root_name}\\{path})")

        if messagebox.askyesno("Блокировки найдены", "Обнаружены ограничения в реестре. Удалить?"):
            for root_key, root_name, path, key_name, info in detected:
                try:
                    # Открываем ключ с правами на запись
                    with winreg.OpenKey(root_key, path, 0, winreg.KEY_WRITE) as key:
                        winreg.DeleteValue(key, key_name)
                        print(f"[+] Блокировка удалена: {info['description']} ({root_name})")
                except Exception as e:
                    print(f"[!] Ошибка при удалении {info['description']} ({root_name}): {e}")
    else:
        print("Ограничений в реестре не обнаружено")
    return bool(detected)

def port_menu():
    """Меню управления портами"""
    while True:
        print("\n=== Управление портами ===")
        print("1. Открыть порт")
        print("2. Закрыть порт")
        print("3. Вернуться в главное меню")

        choice = input("Выберите действие: ").strip()

        if choice == '3':
            return

        if choice in ('1', '2'):
            try:
                port = int(input("Введите номер порта (1-65535): "))
                if not 1 <= port <= 65535:
                    print("Неверный номер порта")
                    continue

                protocol = input("Протокол (TCP/UDP): ").upper()
                if protocol not in ("TCP", "UDP"):
                    print("Неверный протокол")
                    continue

                direction = input("Направление (in/out): ").lower()
                if direction not in ("in", "out"):
                    print("Неверное направление")
                    continue

                action = "add" if choice == '1' else "delete"
                manage_ports(action, port, protocol, direction)

            except ValueError:
                print("Введите корректный номер порта")
        else:
            print("Неверный выбор")

def manage_ports(action, port, protocol="TCP", direction="in"):
    """
    Управление портами через брандмауэр Windows
    action: "add" или "delete"
    port: номер порта
    protocol: TCP или UDP
    direction: in или out
    """
    try:
        rule_name = f"Port_{port}_{protocol}_{direction}"
        cmd = ["netsh", "advfirewall", "firewall", f"{action} rule",
               f"name={rule_name}"]

        if action == "add":
            cmd.extend([
                f"dir={direction}", "action=allow",
                f"protocol={protocol}", f"localport={port}"
            ])

        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(f"[+] Порт {port}/{protocol} {direction} {'открыт' if action == 'add' else 'закрыт'}")
            return True
        else:
            print(f"[!] Ошибка: {result.stderr}")
            return False
    except Exception as e:
        print(f"[!] Ошибка управления портами: {e}")
        return False

def restore_hosts():
    """Восстанавливает стандартный файл hosts"""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    backup_path = hosts_path + ".bak"

    try:
        # Создаем резервную копию
        if os.path.exists(hosts_path):
            os.rename(hosts_path, backup_path)

        # Создаем стандартный файл hosts
        with open(hosts_path, 'w') as f:
            f.write("# Copyright (c) 1993-2009 Microsoft Corp.\n")
            f.write("#\n")
            f.write("# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n")
            f.write("#\n")
            f.write("# This file contains the mappings of IP addresses to host names. Each\n")
            f.write("# entry should be kept on an individual line. The IP address should\n")
            f.write("# be placed in the first column followed by the corresponding host name.\n")
            f.write("# The IP address and the host name should be separated by at least one\n")
            f.write("# space.\n")
            f.write("#\n")
            f.write("# Additionally, comments (such as these) may be inserted on individual\n")
            f.write("# lines or following the machine name denoted by a '#' symbol.\n")
            f.write("#\n")
            f.write("# For example:\n")
            f.write("#\n")
            f.write("#      102.54.94.97     rhino.acme.com          # source server\n")
            f.write("#       38.25.63.10    x.acme.com              # x client host\n")
            f.write("\n# localhost name resolution is handled within DNS itself.\n")
            f.write("127.0.0.1       localhost\n")
            f.write("::1             localhost\n")

        print("Файл hosts успешно восстановлен!")
        messagebox.showinfo("Восстановление hosts", "Стандартный файл hosts успешно восстановлен!")
    except Exception as e:
        print(f"Ошибка восстановления hosts: {e}")
        messagebox.showerror("Ошибка", f"Не удалось восстановить файл hosts: {e}")


def is_process_closed_by_user():
    """Проверяет, был ли процесс остановлен пользователем"""
    return os.path.exists("process_closed_by_user.flag")


def clear_exit_flag():
    """Очищает флаг выхода при запуске"""
    if os.path.exists("process_closed_by_user.flag"):
        try:
            os.remove("process_closed_by_user.flag")
        except:
            pass

def remove_disallow_run():
    """Удаляет ограничения на запуск программ из реестра"""
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    winreg.DeleteKey(key, subkey_name)
                    i += 1
                except OSError:
                    break
            print("Ограничения на запуск программ удалены!")
            messagebox.showinfo("Реестр", "Ограничения на запуск программ удалены!")
    except FileNotFoundError:
        print("Ограничений на запуск программ не обнаружено")
    except Exception as e:
        print(f"Ошибка при удалении ограничений: {e}")
        messagebox.showerror("Ошибка", f"Не удалось удалить ограничения: {e}")

def download_antivirus_scanners():
    """Предлагает скачать антивирусные сканеры"""
    scanners = {
        "KVRT (оф. сайт)": "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe",
        "KVRT (comss.ru)": "https://dl.comss.org/download/KVRT.exe",
        "KVRT (Linux)": "https://devbuilds.s.kaspersky-labs.com/kvrt_linux/latest/kvrt.run",
        "AdwCleaner (comss.ru)": "https://dl.comss.org/download/adwcleaner_8.5.1.exe",
        "ESET Online Scanner (comss.ru)": "https://dl.comss.org/download/esetonlinescanner.exe",
        "ESET Online Scanner (оф. сайт)": "https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe",
        "RogueKiller (comss.ru)": "https://dl.comss.org/download/RogueKiller_portable64.exe",
        "Kaspersky TDSSKiller (оф.сайт)": "http://media.kaspersky.com/utilities/VirusUtilities/RU/tdsskiller.exe",
        "Comodo Cleaning Essentials (оф. сайт)": "https://download.comodo.com/cce/download/setups/cce_public_x64.zip",
        "Comodo Cleaning Essentials (comss.ru)": "https://dl.comss.org/download/cce_public_x64.zip",
        "HitmanPro (Win64)": "https://dl.surfright.nl/HitmanPro_x64.exe",
        "Malwarebytes  - требуется установка": "https://dl.comss.org/download/mb5-setup-consumer-5.2.11.183-131.0.5227-1.0.98137.exe",
        "Anvir - продвинутый диспетчер задач":"https://www.anvir.com/downloads/taskfree.zip"
    }

    print("\n=== Антивирусные сканеры ===")
    for i, (name, url) in enumerate(scanners.items()):
        print(f"{i + 1}. {name}: {url}")

    choice = input("\nВведите номер сканера для загрузки (или Enter для выхода): ")
    if choice.isdigit() and 0 < int(choice) <= len(scanners):
        selected = list(scanners.items())[int(choice) - 1]
        download_file(*selected)
    elif choice:
        print("Неверный выбор")

def download_file(name, url):
    """Скачивает файл и сохраняет его с уникальным именем (включая секунды)"""
    try:
        # Имя файла: добавляем секунды
        filename = f"{name}_{datetime.now().strftime('%y%m%d%H%M%S')}.{url.split('.')[-1]}"

        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"[+] Сканер '{name}' успешно скачан: {filename}")
        messagebox.showinfo("Загрузка", f"Файл '{name}' успешно сохранён как '{filename}'")

    except Exception as e:
        print(f"[!] Ошибка при скачивании '{name}': {e}")
        messagebox.showerror("Ошибка загрузки", f"Не удалось скачать '{name}': {e}")

def check_for_updates():
    try:
        # Получение информации о последнем релизе на GitHub
        response = requests.get("https://api.github.com/repos/Processori7/pytaskmanager/releases/latest")
        response.raise_for_status()
        latest_release = response.json()
        # Получение ссылки на файл llm.exe последней версии
        download_url = None
        assets = latest_release["assets"]
        for asset in assets:
            if asset["name"] == "py_task_manager.exe":
                download_url = asset["browser_download_url"]
                break
        if download_url is None:
            print("Не удалось найти файл pytaskmanager.exe для последней версии.")
            return
        # Сравнение текущей версии с последней версией
        latest_version_str = latest_release["tag_name"]
        match = re.search(r'\d+\.\d+', latest_version_str)
        if match:
            latest_version = match.group()
        else:
            latest_version = latest_version_str
        if version.parse(latest_version) > version.parse(CURRENT_VERSION):
            if platform.system() == "Windows":
                # Предложение пользователю обновление
                if messagebox.askwarning("Доступно обновление",
                                         f"Доступна новая версия {latest_version}. Хотите обновить?", icon='warning',
                                         type='yesno') == 'yes':
                    update_app(download_url)
            else:
                if messagebox.askwarning("Доступно обновление",
                                         f"Доступна новая версия {latest_version}. Хотите обновить?", icon='warning',
                                         type='yesno') == 'yes':
                    os.system("git pull")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", str(e))


def update_app(update_url):
    webbrowser.open(update_url)


def get_file_hash(file_path):
    """Вычисляет SHA-256 хеш файла."""
    if not os.path.isfile(file_path):
        return None
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_virus_total(file_hash):
    """Проверяет файл по его хешу через VirusTotal API."""
    if file_hash in results_cache:
        return results_cache[file_hash]
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']
        scans = attributes.get('last_analysis_results', {})
        detected_by = {name: details['result'] for name, details in scans.items() if details['category'] == 'malicious'}
        result = {
            'positives': stats.get('malicious', 0),
            'total': sum(stats.values()),
            'detected_by': detected_by
        }
        results_cache[file_hash] = result
        return result
    elif response.status_code == 404:
        results_cache[file_hash] = {'error': 'File not found in VirusTotal database'}
        return results_cache[file_hash]
    else:
        results_cache[file_hash] = {'error': 'Failed to retrieve data'}
        return results_cache[file_hash]


def list_processes():
    """Возвращает список запущенных процессов с их исполняемыми файлами."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'status']):
        try:
            process_info = proc.info
            processes.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def scan_process(process, results):
    """Сканирует процесс на вирусы и сохраняет результат."""
    exe_path = process.get('exe')  # Используем .get() для безопасного доступа
    if not exe_path or not os.path.isfile(exe_path):  # Проверяем, существует ли файл
        with lock:
            results.append((process, {'error': 'Executable file not found'}))
        return
    file_hash = get_file_hash(exe_path)
    if file_hash:
        vt_result = check_virus_total(file_hash)
        with lock:
            results.append((process, vt_result))
            if vt_result and 'positives' in vt_result and vt_result['positives'] > 0:
                suspicious_files.append(
                    f"Process: {process['name']}, PID: {process['pid']}, File: {exe_path}, Positives: {vt_result['positives']}"
                )
    else:
        with lock:
            results.append((process, {'error': 'Failed to calculate file hash'}))

def print_ui(processes, results):
    """Выводит информацию о процессах в консоль с нумерацией."""
    os.system('cls' if os.name == 'nt' else 'clear')  # Очистка консоли
    print("=== Улучшенный Htop с проверкой на вирусы ===")
    for idx, (process, vt_result) in enumerate(results):
        name = process['name']
        pid = process['pid']
        cpu = process['cpu_percent']
        memory = process['memory_info'].rss / (1024 * 1024)  # В мегабайтах
        exe_path = process['exe']
        status = process['status']
        # Определяем цвет в зависимости от результата VirusTotal и состояния процесса
        if status == 'stopped':
            color_start = "\033[93m"  # Желтый (заморожен)
            color_end = "\033[0m"
        elif vt_result and 'positives' in vt_result and vt_result['positives'] > 0:
            color_start = "\033[91m"  # Красный (подозрительный)
            color_end = "\033[0m"
        else:
            color_start = "\033[92m"  # Зеленый (обычный)
            color_end = "\033[0m"
        # Форматируем строку
        line = f"{color_start}{idx + 1}: PID: {pid} | Name: {name} | CPU: {cpu:.2f}% | Memory: {memory:.2f} MB | Path: {exe_path}"
        if vt_result:
            if 'error' in vt_result:
                line += f" | VirusTotal: {vt_result['error']}"
            else:
                positives = vt_result['positives']
                total = vt_result['total']
                line += f" | VirusTotal: Positives: {positives}/{total}"
        if status == 'stopped':
            line += " (Заморожен)"
        line += color_end
        print(line)

def save_to_file(results):
    """Сохраняет вывод в файл с кодировкой UTF-8."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"process_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"=== Диспетчер задач с проверкой на вирусы ===\n")
        f.write(f"Дата и время: {timestamp}\n")
        for process, vt_result in results:
            name = process['name']
            pid = process['pid']
            cpu = process['cpu_percent']
            memory = process['memory_info'].rss / (1024 * 1024)  # В мегабайтах
            exe_path = process['exe']
            f.write(f"PID: {pid} | Name: {name} | CPU: {cpu:.2f}% | Memory: {memory:.2f} MB | Path: {exe_path}\n")
            if vt_result:
                if 'error' in vt_result:
                    f.write(f"VirusTotal: {vt_result['error']}\n")
                else:
                    positives = vt_result['positives']
                    total = vt_result['total']
                    f.write(f"VirusTotal: Positives: {positives}/{total}\n")
            f.write("\n")
        f.write("=== Подозрительные файлы ===\n")
        if suspicious_files:
            for file in suspicious_files:
                f.write(f"{file}\n")
        else:
            f.write("Нет подозрительных файлов.\n")
    print(f"Результаты сохранены в файл: {filename}")


def get_autostart_entries():
    """Получает список файлов из автозагрузки из реестра и папок автозагрузки."""
    autostart_entries = []
    registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    startup_folders = [
        os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    ]
    # Чтение из реестра
    try:
        for reg_key, reg_path in registry_paths:
            try:
                with winreg.OpenKey(reg_key, reg_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            file_path = value
                            is_hidden = False
                            recent = False
                            if os.path.isfile(file_path):
                                is_hidden = os.stat(file_path).st_file_attributes & 0x2
                                recent = datetime.fromtimestamp(
                                    os.path.getctime(file_path)) > datetime.now() - timedelta(days=7)
                            autostart_entries.append({
                                'name': name,
                                'path': file_path,
                                'hidden': is_hidden,
                                'recent': recent,
                                'source': 'Registry'
                            })
                        except OSError:
                            break
                        i += 1
            except FileNotFoundError:
                print(f"Ключ реестра не найден: {reg_path}")
            except PermissionError:
                print(f"Недостаточно прав для доступа к ключу: {reg_path}")
    except Exception as e:
        print(f"Ошибка при получении автозагрузки из реестра: {e}")
    # Чтение из папок автозагрузки
    try:
        for folder in startup_folders:
            if os.path.exists(folder):
                for entry in os.listdir(folder):
                    entry_path = os.path.join(folder, entry)
                    if os.path.isfile(entry_path):
                        is_hidden = os.stat(entry_path).st_file_attributes & 0x2
                        recent = datetime.fromtimestamp(os.path.getctime(entry_path)) > datetime.now() - timedelta(
                            days=7)
                        autostart_entries.append({
                            'name': entry,
                            'path': entry_path,
                            'hidden': is_hidden,
                            'recent': recent,
                            'source': 'Startup Folder'
                        })
    except Exception as e:
        print(f"Ошибка при получении автозагрузки из папок: {e}")
    return autostart_entries


def remove_from_autostart(index, autostart_entries):
    """Удаляет запись из автозагрузки по индексу."""
    if index < 0 or index >= len(autostart_entries):
        print("Неверный номер записи.")
        return
    entry = autostart_entries[index]
    source = entry['source']
    if source == 'Registry':
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            # RunOnce
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            # Устаревшие ключи:
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")
        ]
        try:
            for reg_key, reg_path in registry_paths:
                try:
                    with winreg.OpenKey(reg_key, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        winreg.DeleteValue(key, entry['name'])
                        print(f"Запись удалена из автозагрузки: {entry['name']}")
                        return
                except FileNotFoundError:
                    continue
            print(f"Запись не найдена: {entry['name']}")
        except Exception as e:
            print(f"Ошибка при удалении записи: {e}")
    elif source == 'Startup Folder':
        try:
            os.remove(entry['path'])
            print(f"Файл удален из автозагрузки: {entry['path']}")
        except Exception as e:
            print(f"Ошибка при удалении файла: {e}")


def print_autostart_entries(autostart_entries):
    """Выводит список файлов из автозагрузки с цветовой маркировкой и номерами."""
    print("\n=== Файлы из автозагрузки ===")
    if not autostart_entries:
        print("Нет записей в автозагрузке.")
        return
    for idx, entry in enumerate(autostart_entries):
        name = entry['name']
        path = entry['path']
        hidden = entry['hidden']
        recent = entry['recent']
        source = entry['source']
        # Определяем цвет
        if hidden:
            color_start = "\033[91m"  # Красный (скрытый файл)
            status = " (скрыт, подозрителен)"
        elif recent:
            color_start = "\033[93m"  # Желтый (недавно добавленный)
            status = " (недавно добавлен)"
        else:
            color_start = "\033[92m"  # Зеленый (обычный файл)
            status = ""
        color_end = "\033[0m"
        print(f"{color_start}{idx + 1}: {name}: {path} [{source}]{status}{color_end}")

def kill_process_by_number(pid):
    """Завершает процесс по номеру."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"Процесс с PID {pid} завершен.")
        return
    except psutil.NoSuchProcess:
        print(f"Процесс с PID {pid} не найден.")
    except psutil.AccessDenied:
        print(f"Недостаточно прав для завершения процесса с PID {pid}.")
    except Exception as e:
        print(f"Ошибка при завершении процесса: {e}")

def open_file_in_explorer(index, entries):
    """Открывает файл в проводнике."""
    if index < 0 or index >= len(entries):
        print("Неверный номер.")
        return
    entry = entries[index]
    file_path = entry['exe'] if 'exe' in entry else entry['path']
    # Извлекаем только путь к исполняемому файлу, игнорируя аргументы командной строки
    match = re.match(r'^"([^"]+)"', file_path)  # Находим путь в кавычках
    if match:
        file_path = match.group(1)
    elif " " in file_path:  # Если путь без кавычек, но с пробелами
        file_path = file_path.split()[0]
    if file_path and os.path.exists(file_path):
        dir_path = os.path.dirname(file_path)
        if os.name == 'nt':  # Windows
            os.startfile(dir_path)
        elif os.name == 'posix':  # Linux/Mac
            os.system(f'xdg-open "{dir_path}"')
        print(f"Открыта директория: {dir_path}")
    else:
        print(f"Файл не найден: {file_path}")

def mark_process_closed_by_user():
    """Создаёт флаг, чтобы антикиллер не перезапускал процесс"""
    try:
        with open("process_closed_by_user.flag", 'w') as f:
            f.write("closed-by-user")
        print("[+] Флаг выхода установлен")
    except Exception as e:
        print(f"[!] Не удалось создать флаг выхода: {e}")

def menu():
    """Отображает меню и обрабатывает выбор пользователя."""
    while True:
        print("\n=== Меню ===")
        print("1. Показать процессы")
        print("2. Открыть расположение файла процесса")
        print("3. Показать автозагрузку")
        print("4. Открыть расположение файла из автозагрузки")
        print("5. Удалить запись из автозагрузки")
        print("6. Завершить процесс")
        print("7. Проверить файл hosts")
        print("8. Восстановить файл hosts")
        print("9. Удалить ограничения на запуск файлов")
        print("10. Скачать антивирусные сканеры")
        print("11. Выход")
        print("12. Проверить/разблокировать CMD, Диспетчер задач, PowerShell, Редактор реестра и тд.")
        print("13. Управление портами")

        choice = input("Выберите действие: ").strip()

        if choice == '1':
            processes = list_processes()
            results = []
            threads = []
            for process in processes:
                thread = Thread(target=scan_process, args=(process, results))
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()
            save_to_file(results)
            print_ui(processes, results)
        elif choice == '2':
            processes = list_processes()
            results = []
            for process in processes:
                results.append((process, None))  # Без сканирования VirusTotal
            print_ui(processes, results)
            try:
                index = int(input("Введите номер процесса для открытия: ").strip()) - 1
                open_file_in_explorer(index, [p for p, _ in results])
            except ValueError:
                print("Неверный ввод. Введите число.")
        elif choice == '3':
            autostart_entries = get_autostart_entries()
            print_autostart_entries(autostart_entries)
        elif choice == '4':
            autostart_entries = get_autostart_entries()
            print_autostart_entries(autostart_entries)
            try:
                index = int(input("Введите номер записи для открытия: ").strip()) - 1
                open_file_in_explorer(index, autostart_entries)
            except ValueError:
                print("Неверный ввод. Введите число.")
        elif choice == '5':
            autostart_entries = get_autostart_entries()
            print_autostart_entries(autostart_entries)
            try:
                index = int(input("Введите номер записи для удаления: ").strip()) - 1
                remove_from_autostart(index, autostart_entries)
            except ValueError:
                print("Неверный ввод. Введите число.")
        elif choice == '6':
            try:
                pid = int(input("Введите PID процесса для завершения: ").strip())
                kill_process_by_number(pid)
            except ValueError:
                print("Неверный ввод. Введите число.")
        elif choice == '7':
            check_hosts_file()
        elif choice == '8':
            restore_hosts()
        elif choice == '9':
            remove_disallow_run()
        elif choice == '10':
            download_antivirus_scanners()
        elif choice == '11':
            print("[+] Выход по выбору пользователя")
            mark_process_closed_by_user()
            time.sleep(2)  # Даём watchdog время увидеть флаг
            os._exit(0)
        elif choice == '12':
            check_registry_restrictions()
        elif choice == '13':
            port_menu()
        else:
            print("Неверный выбор. Попробуйте снова.")

def is_already_running():
    """Проверяет, запущено ли приложение уже"""
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, "PyTaskManagerSingleInstanceMutex")
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return True
    return False

def main():
    # if "--anti-killer" in sys.argv:
    check_for_updates()
    check_hosts_file()  # Проверяем hosts при запуске
    menu()

if __name__ == "__main__":
    if is_already_running():
        sys.exit(0)
    clear_exit_flag()  # Очищаем флаг при запуске
    # Сохраняем PID основного процесса
    main_pid = os.getpid()
    main()