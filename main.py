import os
import re
import psutil
import hashlib
import requests
from datetime import datetime, timedelta
from dotenv import dotenv_values
from threading import Thread, Lock
import winreg


# Загрузка конфигурации
try:
    config = dotenv_values(".env")
    VIRUSTOTAL_API_KEY = config.get("KEY")
except:
    VIRUSTOTAL_API_KEY=""

# Глобальные переменные
lock = Lock()
results_cache = {}  # Кэш для хранения результатов VirusTotal
suspicious_files = []


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
            'total': stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious', 0) + stats.get(
                'undetected', 0),
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
    print("=== Улучшенный Htop с проверкой на вирусы ===\n")
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
        f.write(f"Дата и время: {timestamp}\n\n")
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

def kill_process_by_number(index, processes):
    """Завершает процесс по номеру."""
    if index < 0 or index >= len(processes):
        print("Неверный номер процесса.")
        return

    process = processes[index]
    pid = process['pid']
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
        print("7. Выход")
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
            break
        else:
            print("Неверный выбор. Попробуйте снова.")


def main():
    menu()

if __name__ == "__main__":
    main()