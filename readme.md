Этот проект представляет собой улучшенную версию диспетчера задач, которая позволяет:  
- Просматривать запущенные процессы.  
- Проверять исполняемые файлы процессов на вирусы через VirusTotal API.
- Просматривать и управлять автозагрузкой системы.
- Открывать расположение файлов процессов или записей автозагрузки в проводнике.
- Завершать процессы по PID.

Основные функции:
1. **Просмотр процессов**:
   - Список всех запущенных процессов с информацией о CPU, памяти и пути к исполняемому файлу.
   - Проверка файлов процессов на вирусы через VirusTotal.

2. **Автозагрузка**:
   - Просмотр всех записей автозагрузки (из реестра и папок автозагрузки).
   - Удаление ненужных записей из автозагрузки.
   - Цветовая маркировка подозрительных записей (скрытые файлы, недавно добавленные).

3. **Управление процессами**:
   - Завершение процесса по PID.
   - Открытие папки с исполняемым файлом процесса в проводнике.

4. **Сохранение отчетов**:
   - Результаты проверки процессов сохраняются в текстовый файл для дальнейшего анализа.

---

## Project Description (English)

This project is an enhanced version of the task manager that allows you to:
- View running processes.
- Check process executable files for viruses using the VirusTotal API.
- View and manage system startup entries.
- Open the location of process files or startup entries in Explorer.
- Terminate processes by PID.

Key features:
1. **Process Viewer**:
   - List all running processes with information about CPU, memory, and the path to the executable file.
   - Check process files for viruses via VirusTotal.

2. **Startup Manager**:
   - View all startup entries (from the registry and startup folders).
   - Remove unnecessary entries from the startup list.
   - Color-coded highlighting of suspicious entries (hidden files, recently added).

3. **Process Management**:
   - Terminate a process by PID.
   - Open the folder containing the process's executable file in Explorer.

4. **Report Saving**:
   - The results of process checks are saved to a text file for further analysis.

---

## Требования / Requirements

### Python
- Версия Python: 3.8 или выше.
- Python version: 3.8 or higher.

### Зависимости / Dependencies
Все зависимости перечислены в файле `requirements.txt`. Для установки выполните команду:
All dependencies are listed in the `requirements.txt` file. To install them, run:  
```pip install -r requirements.txt ```  

## VirusTotal API Key  
Получите API ключ на VirusTotal.  
Create an API key on VirusTotal.  
Создайте файл .env в корневой директории проекта и добавьте туда ваш API ключ:  
Create .env file in root directory and add you API key  
KEY=api_key  

### Установка и запуск / Installation and Running
1. Клонирование репозитория / Clone the Repository:  
```git clone https://github.com/Processori7/pytaskmanager.git```  
```cd pytaskmanager```  
2. Создание виртуального окружения / Create a Virtual Environment :
```python -m venv venv```  
На Unix/On Unix: ```python3 -m venv venv```  
3. Активировать виртуальное окружение / Activate virtual environment:  
. Windows:  
```venv\Scripts\activate```  
. Unix:  
```source venv/bin/activate```
4. Установить зависимости / Install dependencies:
```pip install -r requirements.txt```  
5. Запустить файл / Run file: ```python main.py```