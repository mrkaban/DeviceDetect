# -*- coding: utf-8 -*-
"""
Модуль работы с SQLite базой данных
"""

import sqlite3
import os
import socket
import base64
import hashlib
from datetime import datetime

DB_PATH = 'network_scan.db'


def _get_computer_name():
    """Получить имя компьютера для использования в качестве ключа шифрования"""
    return socket.gethostname()


def _derive_key(computer_name):
    """Создать 32-байтный ключ из имени компьютера"""
    return hashlib.sha256(computer_name.encode('utf-8')).digest()


def _pad_data(data, block_size=16):
    """Добавить PKCS7 padding"""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def _unpad_data(data):
    """Удалить PKCS7 padding"""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > 16 or padding_len == 0:
        return data
    return data[:-padding_len]


def encrypt_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications):
    """Зашифровать настройки email с использованием имени компьютера как ключа"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        # Если pycryptodome не установлен, возвращаем данные в открытом виде
        return {
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'login': login,
            'password': password,
            'from_address': from_address,
            'use_tls': use_tls,
            'enable_notifications': enable_notifications,
            'encrypted': False
        }
    
    computer_name = _get_computer_name()
    key = _derive_key(computer_name)
    
    # Собираем данные в строку
    data = f"{smtp_server}|{smtp_port}|{login}|{password}|{from_address}|{int(use_tls)}|{int(enable_notifications)}"
    data_bytes = data.encode('utf-8')
    
    # Добавляем padding
    padded_data = _pad_data(data_bytes)
    
    # Создаём вектор инициализации
    iv = os.urandom(16)
    
    # Шифруем
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data)
    
    # Кодируем в base64 для хранения
    encrypted_b64 = base64.b64encode(iv + encrypted).decode('utf-8')
    
    return {
        'encrypted_data': encrypted_b64,
        'encrypted': True
    }


def decrypt_email_settings(encrypted_data):
    """Расшифровать настройки email с использованием имени компьютера как ключа"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None
    
    try:
        computer_name = _get_computer_name()
        key = _derive_key(computer_name)
        
        # Декодируем из base64
        data = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Извлекаем IV и зашифрованные данные
        iv = data[:16]
        encrypted = data[16:]
        
        # Расшифровываем
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        
        # Удаляем padding
        unpadded = _unpad_data(decrypted)
        data_str = unpadded.decode('utf-8')
        
        # Разбираем строку
        parts = data_str.split('|')
        if len(parts) != 7:
            return None
        
        return {
            'smtp_server': parts[0],
            'smtp_port': int(parts[1]),
            'login': parts[2],
            'password': parts[3],
            'from_address': parts[4],
            'use_tls': int(parts[5]) == 1,
            'enable_notifications': int(parts[6]) == 1,
            'encrypted': True
        }
    except Exception as e:
        print(f"Ошибка расшифровки настроек email: {e}")
        return None

def get_connection():
    """Получить соединение с базой данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Инициализация базы данных"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Таблица устройств
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            hostname TEXT,
            ports TEXT,
            comment TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    
    # Добавляем поле ports если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE devices ADD COLUMN ports TEXT')
        conn.commit()
        print("База: добавлено поле 'ports' в devices")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Таблица исключённых MAC
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS excluded_macs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE NOT NULL
        )
    ''')
    
    # Таблица истории сканирований
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            message TEXT
        )
    ''')
    
    # Таблица настроек email
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            smtp_server TEXT,
            smtp_port INTEGER DEFAULT 587,
            login TEXT,
            password TEXT,
            from_address TEXT,
            use_tls INTEGER DEFAULT 1,
            enable_notifications INTEGER DEFAULT 1,
            encrypted_data TEXT
        )
    ''')
    
    # Добавляем поле encrypted_data если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE email_settings ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в email_settings")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Инициализируем запись настроек email если нет
    cursor.execute('SELECT COUNT(*) FROM email_settings')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO email_settings (id, smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications)
            VALUES (1, 'smtp.example.com', 587, 'user@example.ru', 'password123', 'DeviceDetect <alert@example.ru>', 1, 1)
        ''')
        conn.commit()
    
    # Добавляем поле enable_notifications если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE email_settings ADD COLUMN enable_notifications INTEGER DEFAULT 1')
        conn.commit()
        print("База: добавлено поле 'enable_notifications' в email_settings")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Таблица настроек сканирования
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet TEXT,
            start_ip TEXT,
            end_ip TEXT,
            email_recipients TEXT,
            scan_delay INTEGER DEFAULT 14400,
            auto_scan INTEGER DEFAULT 0,
            nmap_dir TEXT
        )
    ''')
    
    # Добавляем поле nmap_dir если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE scan_settings ADD COLUMN nmap_dir TEXT')
        conn.commit()
        print("База: добавлено поле 'nmap_dir' в scan_settings")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    conn.commit()
    conn.close()

# ==================== Устройства ====================

def get_all_devices():
    """Получить все устройства"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT ip, mac, hostname, ports, comment, created_at, updated_at FROM devices ORDER BY ip')
        devices = cursor.fetchall()
        conn.close()
        # Преобразуем sqlite3.Row в dict
        return [dict(d) for d in devices]
    except sqlite3.OperationalError:
        # Старая база без поля ports
        cursor.execute('SELECT ip, mac, hostname, comment, created_at, updated_at FROM devices ORDER BY ip')
        devices = cursor.fetchall()
        conn.close()
        # Добавляем пустое поле ports
        return [{'ip': d['ip'], 'mac': d['mac'], 'hostname': d['hostname'], 'ports': '', 'comment': d['comment'], 'created_at': d['created_at'], 'updated_at': d['updated_at']} for d in devices]

def get_device(ip):
    """Получить устройство по IP"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT ip, mac, hostname, ports, comment, created_at, updated_at FROM devices WHERE ip = ?', (ip,))
        device = cursor.fetchone()
        conn.close()
        if device:
            return dict(device)
        return None
    except sqlite3.OperationalError:
        # Старая база без поля ports
        cursor.execute('SELECT ip, mac, hostname, comment, created_at, updated_at FROM devices WHERE ip = ?', (ip,))
        device = cursor.fetchone()
        conn.close()
        if device:
            return {'ip': device['ip'], 'mac': device['mac'], 'hostname': device['hostname'], 'ports': '', 'comment': device['comment'], 'created_at': device['created_at'], 'updated_at': device['updated_at']}
        return None

def add_device(ip, mac='None', hostname='None', ports='', comment=''):
    """Добавить или обновить устройство"""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        cursor.execute('''
            INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = excluded.hostname,
                ports = excluded.ports,
                updated_at = excluded.updated_at
        ''', (ip, mac, hostname, ports, comment, now, now))
    except sqlite3.OperationalError:
        # Старая база без поля ports
        cursor.execute('''
            INSERT INTO devices (ip, mac, hostname, comment, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = excluded.hostname,
                updated_at = excluded.updated_at
        ''', (ip, mac, hostname, comment, now, now))
    conn.commit()
    conn.close()

def update_device(ip, mac=None, hostname=None, ports=None, comment=None):
    """Обновить устройство"""
    conn = get_connection()
    cursor = conn.cursor()
    updates = []
    values = []
    if mac is not None:
        updates.append('mac = ?')
        values.append(mac)
    if hostname is not None:
        updates.append('hostname = ?')
        values.append(hostname)
    if ports is not None:
        updates.append('ports = ?')
        values.append(ports)
    if comment is not None:
        updates.append('comment = ?')
        values.append(comment)
    updates.append('updated_at = ?')
    values.append(datetime.now().strftime("%Y-%m-%d %H:%M"))
    values.append(ip)
    cursor.execute(f'''
        UPDATE devices SET {', '.join(updates)} WHERE ip = ?
    ''', values)
    conn.commit()
    conn.close()

def delete_device(ip):
    """Удалить устройство"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM devices WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

def delete_all_devices():
    """Удалить все устройства"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM devices')
    conn.commit()
    conn.close()

def save_devices(devices_dict):
    """Сохранить словарь устройств (ip -> {mac, hostname, comment, ports})"""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    for ip, data in devices_dict.items():
        mac = data.get('mac', 'None') or 'None'
        hostname = data.get('hostname', 'None') or 'None'
        ports = data.get('ports', '') or ''
        comment = data.get('comment', '')
        cursor.execute('''
            INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = excluded.hostname,
                ports = excluded.ports,
                updated_at = excluded.updated_at
        ''', (ip, mac, hostname, ports, comment, now, now))
    conn.commit()
    conn.close()

# ==================== Исключённые MAC ====================

def get_excluded_macs():
    """Получить все исключённые MAC"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT mac FROM excluded_macs ORDER BY mac')
    macs = [row['mac'] for row in cursor.fetchall()]
    conn.close()
    return macs

def add_excluded_mac(mac):
    """Добавить MAC в исключения"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO excluded_macs (mac) VALUES (?)', (mac,))
    conn.commit()
    conn.close()

def remove_excluded_mac(mac):
    """Удалить MAC из исключений"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM excluded_macs WHERE mac = ?', (mac,))
    conn.commit()
    conn.close()

# ==================== История ====================

def add_history_entry(message):
    """Добавить запись в историю"""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    cursor.execute('INSERT INTO scan_history (timestamp, message) VALUES (?, ?)', (timestamp, message))
    conn.commit()
    conn.close()

def get_history(limit=100):
    """Получить историю сканирований"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, message FROM scan_history ORDER BY id DESC LIMIT ?', (limit,))
    history = cursor.fetchall()
    conn.close()
    # Преобразуем sqlite3.Row в dict
    return [dict(h) for h in history] if history else []

def clear_history():
    """Очистить историю"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history')
    conn.commit()
    conn.close()

# ==================== Настройки Email ====================

def get_email_settings():
    """Получить настройки email (с расшифровкой если зашифровано)"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM email_settings WHERE id = 1')
        settings = cursor.fetchone()
        conn.close()
        if settings:
            settings_dict = dict(settings)
            # Проверяем, есть ли зашифрованные данные
            if settings_dict.get('encrypted_data'):
                decrypted = decrypt_email_settings(settings_dict['encrypted_data'])
                if decrypted:
                    return decrypted
                # Если не удалось расшифровать, возвращаем None (сигнал для сброса)
                return None
            # Для обратной совместимости - если данные в открытом виде
            if settings_dict.get('login') or settings_dict.get('smtp_server'):
                return {
                    'smtp_server': settings_dict.get('smtp_server', ''),
                    'smtp_port': settings_dict.get('smtp_port', 587),
                    'login': settings_dict.get('login', ''),
                    'password': settings_dict.get('password', ''),
                    'from_address': settings_dict.get('from_address', ''),
                    'use_tls': settings_dict.get('use_tls', 1),
                    'enable_notifications': settings_dict.get('enable_notifications', 1),
                    'encrypted': False
                }
            return None
        return None
    except sqlite3.OperationalError:
        # Таблица не существует или неправильная структура
        conn.close()
        return None


def update_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications):
    """Обновить настройки email (с шифрованием)"""
    encrypted = encrypt_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications)
    
    conn = get_connection()
    cursor = conn.cursor()
    
    if encrypted.get('encrypted'):
        # Сохраняем зашифрованные данные
        cursor.execute('''
            UPDATE email_settings SET
                encrypted_data = ?,
                smtp_server = '',
                smtp_port = 587,
                login = '',
                password = '',
                from_address = '',
                use_tls = 1,
                enable_notifications = 1
            WHERE id = 1
        ''', (encrypted['encrypted_data'],))
    else:
        # Сохраняем в открытом виде (если библиотека не доступна)
        cursor.execute('''
            UPDATE email_settings SET
                smtp_server = ?,
                smtp_port = ?,
                login = ?,
                password = ?,
                from_address = ?,
                use_tls = ?,
                enable_notifications = ?,
                encrypted_data = NULL
            WHERE id = 1
        ''', (smtp_server, smtp_port, login, password, from_address, 1 if use_tls else 0, 1 if enable_notifications else 0))
    
    conn.commit()
    conn.close()


def reset_email_settings():
    """Сбросить настройки email на дефолтные значения (с отключёнными уведомлениями)"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE email_settings SET
            smtp_server = 'smtp.example.com',
            smtp_port = 587,
            login = 'user@example.ru',
            password = 'password123',
            from_address = 'DeviceDetect <alert@example.ru>',
            use_tls = 1,
            enable_notifications = 0,
            encrypted_data = NULL
        WHERE id = 1
    ''')
    conn.commit()
    conn.close()


def clear_database():
    """Очистить базу: удалить все устройства, историю и сбросить настройки email"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Удаляем все устройства
    cursor.execute('DELETE FROM devices')
    
    # Удаляем всю историю
    cursor.execute('DELETE FROM scan_history')
    
    # Сбрасываем настройки email на дефолтные (с отключёнными уведомлениями)
    cursor.execute('''
        UPDATE email_settings SET
            smtp_server = 'smtp.example.com',
            smtp_port = 587,
            login = 'user@example.ru',
            password = 'password123',
            from_address = 'DeviceDetect <alert@example.ru>',
            use_tls = 1,
            enable_notifications = 0,
            encrypted_data = NULL
        WHERE id = 1
    ''')
    
    conn.commit()
    conn.close()

# ==================== Настройки сканирования ====================

def get_scan_settings():
    """Получить последние настройки сканирования"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM scan_settings WHERE id = 1')
        settings = cursor.fetchone()
        conn.close()
        if settings:
            return dict(settings)
        return None
    except sqlite3.OperationalError:
        # Таблица не существует или неправильная структура
        conn.close()
        return None

def update_scan_settings(subnet, start_ip, end_ip, email_recipients, scan_delay, auto_scan, nmap_dir=''):
    """Обновить настройки сканирования"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Проверяем, есть ли запись
    cursor.execute('SELECT COUNT(*) FROM scan_settings WHERE id = 1')
    count = cursor.fetchone()[0]
    
    if count > 0:
        cursor.execute('''
            UPDATE scan_settings SET
                subnet = ?,
                start_ip = ?,
                end_ip = ?,
                email_recipients = ?,
                scan_delay = ?,
                auto_scan = ?,
                nmap_dir = ?
            WHERE id = 1
        ''', (subnet, start_ip, end_ip, email_recipients, scan_delay, 1 if auto_scan else 0, nmap_dir))
    else:
        cursor.execute('''
            INSERT INTO scan_settings (id, subnet, start_ip, end_ip, email_recipients, scan_delay, auto_scan, nmap_dir)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        ''', (subnet, start_ip, end_ip, email_recipients, scan_delay, 1 if auto_scan else 0, nmap_dir))
    
    conn.commit()
    conn.close()

# ==================== Миграция из текстовых файлов ====================

def migrate_from_files():
    """Миграция данных из текстовых файлов в базу данных"""
    if not os.path.exists(DB_PATH):
        init_database()
    
    # Миграция output.txt
    if os.path.exists('output.txt'):
        conn = get_connection()
        cursor = conn.cursor()
        try:
            with open('output.txt', 'r', encoding='cp1251') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1] if len(parts) > 1 else 'None'
                        hostname = parts[2] if len(parts) > 2 else 'None'
                        cursor.execute('''
                            INSERT OR IGNORE INTO devices (ip, mac, hostname, comment)
                            VALUES (?, ?, ?, '')
                        ''', (ip, mac, hostname))
            conn.commit()
        except Exception as e:
            print(f"Ошибка миграции output.txt: {e}")
        conn.close()
        # Переименовываем файл
        os.rename('output.txt', 'output.txt.bak')
    
    # Миграция exclude_mac.txt
    if os.path.exists('exclude_mac.txt'):
        conn = get_connection()
        cursor = conn.cursor()
        try:
            with open('exclude_mac.txt', 'r', encoding='cp1251') as f:
                for line in f:
                    mac = line.strip()
                    if mac:
                        cursor.execute('INSERT OR IGNORE INTO excluded_macs (mac) VALUES (?)', (mac,))
            conn.commit()
        except Exception as e:
            print(f"Ошибка миграции exclude_mac.txt: {e}")
        conn.close()
        os.rename('exclude_mac.txt', 'exclude_mac.txt.bak')
    
    # Миграция history.txt
    if os.path.exists('history.txt'):
        conn = get_connection()
        cursor = conn.cursor()
        try:
            with open('history.txt', 'r', encoding='cp1251') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Формат: "2023-08-09 14:30 : сообщение"
                        if ' : ' in line:
                            parts = line.split(' : ', 1)
                            timestamp = parts[0]
                            message = parts[1] if len(parts) > 1 else line
                        else:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                            message = line
                        cursor.execute('INSERT INTO scan_history (timestamp, message) VALUES (?, ?)', (timestamp, message))
            conn.commit()
        except Exception as e:
            print(f"Ошибка миграции history.txt: {e}")
        conn.close()
        os.rename('history.txt', 'history.txt.bak')

# Инициализация при импорте
init_database()
# migrate_from_files()  # Отключено - импорт через меню
