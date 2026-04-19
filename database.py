# -*- coding: utf-8 -*-
"""
Модуль работы с SQLite базой данных
"""

import sqlite3
import os
import socket
import base64
import hashlib
import json
from datetime import datetime

DB_PATH = 'network_scan.db'

# Глобальная переменная для хранения пользовательского ключа (устанавливается после проверки)
CUSTOM_KEY = ''


def set_custom_key(key):
    """Установить пользовательский ключ для шифрования (вызывается из main.py после проверки)"""
    global CUSTOM_KEY
    CUSTOM_KEY = key


def _get_computer_name():
    """Получить имя компьютера для использования в качестве ключа шифрования"""
    return socket.gethostname()


def _derive_key(key_material):
    """Создать 32-байтный ключ из переданного материала (имя компьютера или пользовательский ключ)"""
    return hashlib.sha256(key_material.encode('utf-8')).digest()


def _get_key(key_type='computer_name', custom_key=''):
    """Получить ключ шифрования в зависимости от типа"""
    if key_type == 'custom' and custom_key:
        return _derive_key(custom_key)
    else:
        return _derive_key(_get_computer_name())


def _hash_ip(ip):
    """Вычислить SHA-256 хэш IP для использования в качестве уникального ключа в таблице"""
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()


def _get_stored_ip(ip):
    """
    Возвращает IP для хранения в поле ip таблицы devices.
    Если включено шифрование таблицы, возвращает хэш IP, иначе исходный IP.
    """
    if _should_encrypt_table():
        return _hash_ip(ip)
    else:
        return ip


def _lookup_ip(ip):
    """
    Преобразовать IP для поиска в таблице devices.
    Если включено шифрование таблицы, ищем по хэшу, иначе по исходному IP.
    """
    if _should_encrypt_table():
        return _hash_ip(ip)
    else:
        return ip


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


def encrypt_data(plaintext, key_type='computer_name', custom_key=''):
    """Зашифровать произвольные данные строкой и вернуть base64 строку (IV + ciphertext)"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        # Если pycryptodome не установлен, возвращаем исходные данные (не зашифровано)
        return plaintext
    
    key = _get_key(key_type, custom_key)
    data_bytes = plaintext.encode('utf-8')
    padded_data = _pad_data(data_bytes)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data)
    encrypted_b64 = base64.b64encode(iv + encrypted).decode('utf-8')
    return encrypted_b64


def decrypt_data(encrypted_b64, key_type='computer_name', custom_key=''):
    """Расшифровать данные из base64 строки (IV + ciphertext) и вернуть исходную строку"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        # Если pycryptodome не установлен, возвращаем исходные данные (предполагаем, что они не зашифрованы)
        return encrypted_b64
    
    try:
        key = _get_key(key_type, custom_key)
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        unpadded = _unpad_data(decrypted)
        return unpadded.decode('utf-8')
    except Exception:
        # Ошибка расшифровки (неверный ключ или повреждённые данные)
        return None


def encrypt_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications,
                           key_type='computer_name', custom_key=''):
    """Зашифровать настройки email с использованием указанного ключа"""
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
    
    key = _get_key(key_type, custom_key)
    
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


def decrypt_email_settings(encrypted_data, key_type='computer_name', custom_key=''):
    """Расшифровать настройки email с использованием указанного ключа"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None
    
    try:
        key = _get_key(key_type, custom_key)
        if key is None:
            return None
        
        # Проверяем, что encrypted_data не пустое
        if not encrypted_data:
            return None
        
        # Декодируем из base64
        try:
            data = base64.b64decode(encrypted_data.encode('utf-8'))
        except (base64.binascii.Error, UnicodeEncodeError):
            return None
        
        # Извлекаем IV и зашифрованные данные
        if len(data) < 16:
            return None
        iv = data[:16]
        encrypted = data[16:]
        
        # Расшифровываем
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        
        # Удаляем padding
        unpadded = _unpad_data(decrypted)
        if unpadded is None:
            return None
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
    except Exception:
        # Ошибка расшифровки (неверный ключ или повреждённые данные)
        return None

def get_connection():
    """Получить соединение с базой данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _get_encryption_info():
    """Получить текущие настройки шифрования из таблицы email_settings"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT encryption_level, encryption_key_type, custom_key_hash FROM email_settings WHERE id = 1')
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'encryption_level': row['encryption_level'] if row['encryption_level'] else 'email_only',
                'encryption_key_type': row['encryption_key_type'] if row['encryption_key_type'] else 'computer_name',
                'custom_key_hash': row['custom_key_hash'] if row['custom_key_hash'] else ''
            }
        else:
            return {
                'encryption_level': 'email_only',
                'encryption_key_type': 'computer_name',
                'custom_key_hash': ''
            }
    except sqlite3.OperationalError:
        conn.close()
        return {
            'encryption_level': 'email_only',
            'encryption_key_type': 'computer_name',
            'custom_key_hash': ''
        }


def _should_encrypt_table():
    """Возвращает True, если уровень шифрования 'all' (шифровать все таблицы)"""
    info = _get_encryption_info()
    return info['encryption_level'] == 'all'


def _get_key_for_encryption():
    """Получить ключ шифрования на основе текущих настроек"""
    info = _get_encryption_info()
    key_type = info['encryption_key_type']
    if key_type == 'custom':
        if CUSTOM_KEY:
            return _derive_key(CUSTOM_KEY)
        else:
            # Ключ не известен, шифрование невозможно
            return None
    else:
        return _get_key(key_type, '')


def _encrypt_row(data_dict):
    """Зашифровать словарь данных в строку base64"""
    if not _should_encrypt_table():
        return None
    # Получаем параметры шифрования
    info = _get_encryption_info()
    key_type = info['encryption_key_type']
    custom_key = CUSTOM_KEY if key_type == 'custom' else ''
    json_str = json.dumps(data_dict, ensure_ascii=False)
    encrypted = encrypt_data(json_str, key_type=key_type, custom_key=custom_key)
    return encrypted


def _encrypt_row_force(data_dict, key_type='computer_name', custom_key=''):
    """Зашифровать словарь данных в строку base64 без проверки уровня шифрования"""
    json_str = json.dumps(data_dict, ensure_ascii=False)
    encrypted = encrypt_data(json_str, key_type=key_type, custom_key=custom_key)
    return encrypted


def _decrypt_row(encrypted_b64):
    """Расшифровать строку base64 в словарь данных"""
    if not encrypted_b64:
        return None
    
    # Получаем текущие настройки шифрования
    info = _get_encryption_info()
    key_type = info['encryption_key_type']
    custom_key = CUSTOM_KEY if key_type == 'custom' else ''
    
    # Пробуем расшифровать с текущим ключом
    decrypted = decrypt_data(encrypted_b64, key_type=key_type, custom_key=custom_key)
    if decrypted is not None:
        try:
            return json.loads(decrypted)
        except:
            pass  # Не удалось разобрать JSON, пробуем другие варианты
    
    # Если не удалось с текущим ключом, пробуем с ключом "имя компьютера" (fallback)
    if key_type != 'computer_name':
        decrypted = decrypt_data(encrypted_b64, key_type='computer_name', custom_key='')
        if decrypted is not None:
            try:
                return json.loads(decrypted)
            except:
                pass
    
    # Если не удалось расшифровать, возможно данные не зашифрованы (plain JSON)
    try:
        return json.loads(encrypted_b64)
    except:
        return None


def migrate_encryption_level(new_level):
    """
    Мигрировать данные при изменении уровня шифрования.
    new_level: 'none', 'email_only', 'all'
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Получаем текущий уровень шифрования
    info = _get_encryption_info()
    old_level = info['encryption_level']
    
    if old_level == new_level:
        conn.close()
        return  # Ничего не делать
    
    print(f"Миграция уровня шифрования: {old_level} -> {new_level}")
    
    # Получаем текущий ключ шифрования (может быть None, если ключ пользовательский и неизвестен)
    key = _get_key_for_encryption()
    
    # Если ключ недоступен (пользовательский ключ не известен), не можем мигрировать
    if key is None and new_level == 'all':
        print("ОШИБКА: Не удалось получить ключ шифрования. Миграция невозможна.")
        conn.close()
        return
    
    # Обработка перехода с 'all' на 'none' или 'email_only'
    if old_level == 'all' and new_level != 'all':
        # Расшифровать все таблицы
        _decrypt_all_tables(cursor, key)
    
    # Обработка перехода с 'none' или 'email_only' на 'all'
    if new_level == 'all' and old_level != 'all':
        # Зашифровать все таблицы
        _encrypt_all_tables(cursor, key)
    
    # При переходе между 'none' и 'email_only' ничего не делаем для других таблиц
    # (настройки email обрабатываются в update_email_settings)
    
    conn.commit()
    conn.close()


def _encrypt_all_tables(cursor, key):
    """Зашифровать все строки во всех таблицах (кроме email_settings)"""
    # Получаем текущие настройки шифрования
    info = _get_encryption_info()
    key_type = info['encryption_key_type']
    custom_key = CUSTOM_KEY if key_type == 'custom' else ''
    
    print(f"Начинаем шифрование всех таблиц. Тип ключа: {key_type}, пользовательский ключ: {'установлен' if custom_key else 'нет'}")
    
    # 1. Таблица devices
    cursor.execute('SELECT id, ip, mac, hostname, ports, comment, created_at, updated_at FROM devices WHERE encrypted_data IS NULL')
    rows = cursor.fetchall()
    print(f"Найдено {len(rows)} незашифрованных записей в devices")
    
    for row in rows:
        row_id = row['id']
        original_ip = row['ip']
        
        # Создаём словарь с данными
        data_dict = {
            'ip': original_ip,
            'mac': row['mac'],
            'hostname': row['hostname'],
            'ports': row['ports'],
            'comment': row['comment'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }
        
        # Шифруем данные
        encrypted = _encrypt_row_force(data_dict, key_type=key_type, custom_key=custom_key)
        if not encrypted:
            print(f"Ошибка шифрования строки {row_id} в devices")
            continue
        
        # Вычисляем хэш IP для хранения в открытом поле
        ip_hash = _hash_ip(original_ip)
        
        # Обновляем запись: сохраняем хэш IP в поле ip, зашифрованные данные в encrypted_data, очищаем остальные поля
        cursor.execute('''
            UPDATE devices SET
                ip = ?, mac = '', hostname = '', ports = '', comment = '',
                created_at = '', updated_at = '', encrypted_data = ?
            WHERE id = ?
        ''', (ip_hash, encrypted, row_id))
        
        print(f"Зашифрована запись devices id={row_id}, IP={original_ip} -> хэш={ip_hash[:16]}...")
    
    # 2. Таблица excluded_macs
    cursor.execute('SELECT id, mac FROM excluded_macs WHERE encrypted_data IS NULL')
    rows = cursor.fetchall()
    print(f"Найдено {len(rows)} незашифрованных записей в excluded_macs")
    
    for row in rows:
        row_id = row['id']
        mac = row['mac']
        
        # Проверяем, не является ли уже хэшем (если строка уже зашифрована в предыдущих версиях)
        if len(mac) == 64 and all(c in '0123456789abcdef' for c in mac.lower()):
            print(f"Пропуск записи excluded_macs id={row_id}: поле mac уже выглядит как хэш SHA-256")
            continue
        
        data_dict = {
            'mac': mac
        }
        
        encrypted = _encrypt_row_force(data_dict, key_type=key_type, custom_key=custom_key)
        if not encrypted:
            print(f"Ошибка шифрования строки {row_id} в excluded_macs")
            continue
        
        # Вычисляем хэш MAC для хранения в открытом поле
        mac_hash = hashlib.sha256(mac.encode()).hexdigest()
        
        cursor.execute('''
            UPDATE excluded_macs SET
                mac = ?, encrypted_data = ?
            WHERE id = ?
        ''', (mac_hash, encrypted, row_id))
        
        print(f"Зашифрована запись excluded_macs id={row_id}, MAC={mac} -> хэш={mac_hash[:16]}...")
    
    # 3. Таблица scan_history
    cursor.execute('SELECT id, message, timestamp FROM scan_history WHERE encrypted_data IS NULL')
    rows = cursor.fetchall()
    print(f"Найдено {len(rows)} незашифрованных записей в scan_history")
    
    for row in rows:
        row_id = row['id']
        data_dict = {
            'message': row['message'],
            'timestamp': row['timestamp']
        }
        
        encrypted = _encrypt_row_force(data_dict, key_type=key_type, custom_key=custom_key)
        if not encrypted:
            print(f"Ошибка шифрования строки {row_id} в scan_history")
            continue
        
        cursor.execute('''
            UPDATE scan_history SET
                message = '', timestamp = '', encrypted_data = ?
            WHERE id = ?
        ''', (encrypted, row_id))
        
        print(f"Зашифрована запись scan_history id={row_id}")
    
    # 4. Таблица scan_settings
    cursor.execute('SELECT id, subnet, start_ip, end_ip, email_recipients, scan_delay, auto_scan, nmap_dir FROM scan_settings WHERE encrypted_data IS NULL')
    rows = cursor.fetchall()
    print(f"Найдено {len(rows)} незашифрованных записей в scan_settings")
    
    for row in rows:
        row_id = row['id']
        data_dict = {
            'subnet': row['subnet'],
            'start_ip': row['start_ip'],
            'end_ip': row['end_ip'],
            'email_recipients': row['email_recipients'],
            'scan_delay': row['scan_delay'],
            'auto_scan': row['auto_scan'],
            'nmap_dir': row['nmap_dir']
        }
        
        encrypted = _encrypt_row_force(data_dict, key_type=key_type, custom_key=custom_key)
        if not encrypted:
            print(f"Ошибка шифрования строки {row_id} в scan_settings")
            continue
        
        cursor.execute('''
            UPDATE scan_settings SET
                subnet = '', start_ip = '', end_ip = '', email_recipients = '',
                scan_delay = '', auto_scan = '', nmap_dir = '', encrypted_data = ?
            WHERE id = ?
        ''', (encrypted, row_id))
        
        print(f"Зашифрована запись scan_settings id={row_id}")
    
    print("Шифрование всех таблиц завершено.")


def _decrypt_all_tables(cursor, key):
    """Расшифровать все строки во всех таблицах (кроме email_settings)"""
    # Расшифровать таблицу devices
    cursor.execute('SELECT id, encrypted_data FROM devices WHERE encrypted_data IS NOT NULL')
    rows = cursor.fetchall()
    for row in rows:
        row_id = row['id']
        encrypted = row['encrypted_data']
        decrypted = _decrypt_row(encrypted)
        if not decrypted:
            print(f"Ошибка расшифровки строки {row_id} в devices")
            continue
        
        original_ip = decrypted.get('ip', '')
        if not original_ip:
            print(f"В расшифрованных данных отсутствует IP для строки {row_id}")
            continue
        
        # Проверим, есть ли уже запись с таким IP (но другим id)
        cursor.execute('SELECT id FROM devices WHERE ip = ? AND id != ?', (original_ip, row_id))
        duplicate = cursor.fetchone()
        
        if duplicate:
            duplicate_id = duplicate['id']
            print(f"Обнаружен дубликат IP {original_ip}: строки {row_id} (зашифрованная) и {duplicate_id} (открытая). Объединяем...")
            # Обновим дублирующую запись данными из расшифрованной (если поля не пустые)
            cursor.execute('''
                UPDATE devices SET
                    mac = COALESCE(NULLIF(?, ''), mac),
                    hostname = COALESCE(NULLIF(?, ''), hostname),
                    ports = COALESCE(NULLIF(?, ''), ports),
                    comment = COALESCE(NULLIF(?, ''), comment),
                    created_at = COALESCE(NULLIF(?, ''), created_at),
                    updated_at = COALESCE(NULLIF(?, ''), updated_at)
                WHERE id = ?
            ''', (
                decrypted.get('mac', ''),
                decrypted.get('hostname', ''),
                decrypted.get('ports', ''),
                decrypted.get('comment', ''),
                decrypted.get('created_at', ''),
                decrypted.get('updated_at', ''),
                duplicate_id
            ))
            # Удаляем зашифрованную строку
            cursor.execute('DELETE FROM devices WHERE id = ?', (row_id,))
            print(f"Удалена зашифрованная строка {row_id}, данные объединены в строку {duplicate_id}")
        else:
            # Нет дубликатов, просто обновляем текущую строку
            cursor.execute('''
                UPDATE devices SET
                    ip = ?, mac = ?, hostname = ?, ports = ?, comment = ?,
                    created_at = ?, updated_at = ?, encrypted_data = NULL
                WHERE id = ?
            ''', (
                original_ip,
                decrypted.get('mac', ''),
                decrypted.get('hostname', ''),
                decrypted.get('ports', ''),
                decrypted.get('comment', ''),
                decrypted.get('created_at', ''),
                decrypted.get('updated_at', ''),
                row_id
            ))
    
    # Расшифровать таблицу excluded_macs
    cursor.execute('SELECT id, encrypted_data FROM excluded_macs WHERE encrypted_data IS NOT NULL')
    rows = cursor.fetchall()
    for row in rows:
        row_id = row['id']
        encrypted = row['encrypted_data']
        decrypted = _decrypt_row(encrypted)
        if decrypted:
            cursor.execute('''
                UPDATE excluded_macs SET
                    mac = ?, encrypted_data = NULL
                WHERE id = ?
            ''', (decrypted.get('mac', ''), row_id))
        else:
            print(f"Ошибка расшифровки строки {row_id} в excluded_macs")
    
    # Расшифровать таблицу scan_history
    cursor.execute('SELECT id, encrypted_data FROM scan_history WHERE encrypted_data IS NOT NULL')
    rows = cursor.fetchall()
    for row in rows:
        row_id = row['id']
        encrypted = row['encrypted_data']
        decrypted = _decrypt_row(encrypted)
        if decrypted:
            cursor.execute('''
                UPDATE scan_history SET
                    timestamp = ?, message = ?, encrypted_data = NULL
                WHERE id = ?
            ''', (decrypted.get('timestamp', ''), decrypted.get('message', ''), row_id))
        else:
            print(f"Ошибка расшифровки строки {row_id} в scan_history")
    
    # Расшифровать таблицу scan_settings
    cursor.execute('SELECT id, encrypted_data FROM scan_settings WHERE encrypted_data IS NOT NULL')
    rows = cursor.fetchall()
    for row in rows:
        row_id = row['id']
        encrypted = row['encrypted_data']
        decrypted = _decrypt_row(encrypted)
        if decrypted:
            cursor.execute('''
                UPDATE scan_settings SET
                    subnet = ?, start_ip = ?, end_ip = ?, email_recipients = ?,
                    scan_delay = ?, auto_scan = ?, nmap_dir = ?, encrypted_data = NULL
                WHERE id = ?
            ''', (
                decrypted.get('subnet', ''),
                decrypted.get('start_ip', ''),
                decrypted.get('end_ip', ''),
                decrypted.get('email_recipients', ''),
                decrypted.get('scan_delay', 14400),
                decrypted.get('auto_scan', 0),
                decrypted.get('nmap_dir', ''),
                row_id
            ))
        else:
            print(f"Ошибка расшифровки строки {row_id} в scan_settings")
    
    print("Расшифровка всех таблиц завершена.")


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
            updated_at TEXT,
            encrypted_data TEXT
        )
    ''')
    
    # Добавляем поле ports если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE devices ADD COLUMN ports TEXT')
        conn.commit()
        print("База: добавлено поле 'ports' в devices")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Добавляем поле encrypted_data если нет
    try:
        cursor.execute('ALTER TABLE devices ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в devices")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Таблица исключённых MAC
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS excluded_macs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE NOT NULL,
            encrypted_data TEXT
        )
    ''')
    
    # Добавляем поле encrypted_data если нет
    try:
        cursor.execute('ALTER TABLE excluded_macs ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в excluded_macs")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Таблица истории сканирований
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            message TEXT,
            encrypted_data TEXT
        )
    ''')
    
    # Добавляем поле encrypted_data если нет
    try:
        cursor.execute('ALTER TABLE scan_history ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в scan_history")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
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
            encrypted_data TEXT,
            encryption_level TEXT DEFAULT 'email_only',
            encryption_key_type TEXT DEFAULT 'computer_name',
            custom_key_hash TEXT
        )
    ''')
    
    # Добавляем поле encrypted_data если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE email_settings ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в email_settings")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Добавляем поля шифрования если нет
    for column in ['encryption_level', 'encryption_key_type', 'custom_key_hash']:
        try:
            cursor.execute(f'ALTER TABLE email_settings ADD COLUMN {column} TEXT')
            conn.commit()
            print(f"База: добавлено поле '{column}' в email_settings")
        except sqlite3.OperationalError:
            pass  # Поле уже есть
    
    # Инициализируем запись настроек email если нет
    cursor.execute('SELECT COUNT(*) FROM email_settings')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO email_settings (id, smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications,
                encrypted_data, encryption_level, encryption_key_type, custom_key_hash)
            VALUES (1, 'smtp.example.com', 587, 'user@example.ru', 'password123', 'DeviceDetect <alert@example.ru>', 1, 1,
                NULL, 'email_only', 'computer_name', '')
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
            nmap_dir TEXT,
            encrypted_data TEXT
        )
    ''')
    
    # Добавляем поле nmap_dir если нет (для старых баз)
    try:
        cursor.execute('ALTER TABLE scan_settings ADD COLUMN nmap_dir TEXT')
        conn.commit()
        print("База: добавлено поле 'nmap_dir' в scan_settings")
    except sqlite3.OperationalError:
        pass  # Поле уже есть
    
    # Добавляем поле encrypted_data если нет
    try:
        cursor.execute('ALTER TABLE scan_settings ADD COLUMN encrypted_data TEXT')
        conn.commit()
        print("База: добавлено поле 'encrypted_data' в scan_settings")
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
        cursor.execute('SELECT ip, mac, hostname, ports, comment, created_at, updated_at, encrypted_data FROM devices ORDER BY ip')
        devices = cursor.fetchall()
        conn.close()
        result = []
        for d in devices:
            row = dict(d)
            encrypted = row.get('encrypted_data')
            if encrypted:
                decrypted = _decrypt_row(encrypted)
                if decrypted:
                    # Объединяем: ip из строки (оно же есть в decrypted), но предпочтём decrypted
                    row.update(decrypted)
                # Удаляем encrypted_data из результата
                del row['encrypted_data']
            result.append(row)
        return result
    except sqlite3.OperationalError:
        # Старая база без поля ports или encrypted_data
        cursor.execute('SELECT ip, mac, hostname, comment, created_at, updated_at FROM devices ORDER BY ip')
        devices = cursor.fetchall()
        conn.close()
        # Добавляем пустое поле ports
        return [{'ip': d['ip'], 'mac': d['mac'], 'hostname': d['hostname'], 'ports': '', 'comment': d['comment'], 'created_at': d['created_at'], 'updated_at': d['updated_at']} for d in devices]

def get_device(ip):
    """Получить устройство по IP"""
    conn = get_connection()
    cursor = conn.cursor()
    lookup_ip = _lookup_ip(ip)
    try:
        cursor.execute('SELECT ip, mac, hostname, ports, comment, created_at, updated_at, encrypted_data FROM devices WHERE ip = ?', (lookup_ip,))
        device = cursor.fetchone()
        conn.close()
        if device:
            row = dict(device)
            encrypted = row.get('encrypted_data')
            if encrypted:
                decrypted = _decrypt_row(encrypted)
                if decrypted:
                    row.update(decrypted)
                del row['encrypted_data']
            return row
        return None
    except sqlite3.OperationalError:
        # Старая база без поля ports или encrypted_data
        cursor.execute('SELECT ip, mac, hostname, comment, created_at, updated_at FROM devices WHERE ip = ?', (lookup_ip,))
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
    
    if _should_encrypt_table():
        stored_ip = _hash_ip(ip)
        # Шифруем данные
        data_dict = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'ports': ports,
            'comment': comment,
            'created_at': now,
            'updated_at': now
        }
        encrypted = _encrypt_row(data_dict)
        if encrypted:
            # Сохраняем зашифрованные данные, остальные поля оставляем пустыми
            cursor.execute('''
                INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at, encrypted_data)
                VALUES (?, '', '', '', '', ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    encrypted_data = excluded.encrypted_data,
                    updated_at = excluded.updated_at
            ''', (stored_ip, now, now, encrypted))
        else:
            # Если шифрование не удалось, сохраняем открыто, но ip храним как хэш
            cursor.execute('''
                INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    ports = excluded.ports,
                    updated_at = excluded.updated_at
            ''', (stored_ip, mac, hostname, ports, comment, now, now))
    else:
        stored_ip = ip  # оригинальный IP
        try:
            cursor.execute('''
                INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    ports = excluded.ports,
                    updated_at = excluded.updated_at
            ''', (stored_ip, mac, hostname, ports, comment, now, now))
        except sqlite3.OperationalError:
            # Старая база без поля ports
            cursor.execute('''
                INSERT INTO devices (ip, mac, hostname, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    updated_at = excluded.updated_at
            ''', (stored_ip, mac, hostname, comment, now, now))
    conn.commit()
    conn.close()

def update_device(ip, mac=None, hostname=None, ports=None, comment=None):
    """Обновить устройство"""
    conn = get_connection()
    cursor = conn.cursor()
    lookup_ip = _lookup_ip(ip)
    
    if _should_encrypt_table():
        # Получаем текущие зашифрованные данные
        cursor.execute('SELECT encrypted_data FROM devices WHERE ip = ?', (lookup_ip,))
        row = cursor.fetchone()
        encrypted_data = row['encrypted_data'] if row else None
        
        if encrypted_data:
            # Расшифровываем
            decrypted = _decrypt_row(encrypted_data)
            if decrypted:
                # Обновляем поля в словаре
                if mac is not None:
                    decrypted['mac'] = mac
                if hostname is not None:
                    decrypted['hostname'] = hostname
                if ports is not None:
                    decrypted['ports'] = ports
                if comment is not None:
                    decrypted['comment'] = comment
                # Шифруем обратно
                new_encrypted = _encrypt_row(decrypted)
                if new_encrypted:
                    cursor.execute('''
                        UPDATE devices SET encrypted_data = ?, updated_at = ?
                        WHERE ip = ?
                    ''', (new_encrypted, datetime.now().strftime("%Y-%m-%d %H:%M"), lookup_ip))
            else:
                # Не удалось расшифровать - создаём новый словарь
                data_dict = {
                    'mac': mac if mac is not None else '',
                    'hostname': hostname if hostname is not None else '',
                    'ports': ports if ports is not None else '',
                    'comment': comment if comment is not None else ''
                }
                new_encrypted = _encrypt_row(data_dict)
                if new_encrypted:
                    cursor.execute('''
                        UPDATE devices SET encrypted_data = ?, updated_at = ?
                        WHERE ip = ?
                    ''', (new_encrypted, datetime.now().strftime("%Y-%m-%d %H:%M"), lookup_ip))
        else:
            # Зашифрованных данных нет - создаём новый словарь
            # Сначала получим текущие значения из обычных полей
            cursor.execute('SELECT mac, hostname, ports, comment FROM devices WHERE ip = ?', (lookup_ip,))
            row = cursor.fetchone()
            if row:
                current_mac = row['mac'] if row['mac'] else ''
                current_hostname = row['hostname'] if row['hostname'] else ''
                current_ports = row['ports'] if row['ports'] else ''
                current_comment = row['comment'] if row['comment'] else ''
            else:
                current_mac = current_hostname = current_ports = current_comment = ''
            
            # Обновляем переданными значениями
            data_dict = {
                'mac': mac if mac is not None else current_mac,
                'hostname': hostname if hostname is not None else current_hostname,
                'ports': ports if ports is not None else current_ports,
                'comment': comment if comment is not None else current_comment
            }
            new_encrypted = _encrypt_row(data_dict)
            if new_encrypted:
                cursor.execute('''
                    UPDATE devices SET encrypted_data = ?, updated_at = ?
                    WHERE ip = ?
                ''', (new_encrypted, datetime.now().strftime("%Y-%m-%d %H:%M"), lookup_ip))
    else:
        # Старая логика (без шифрования)
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
        values.append(lookup_ip)
        cursor.execute(f'''
            UPDATE devices SET {', '.join(updates)} WHERE ip = ?
        ''', values)
    
    conn.commit()
    conn.close()

def delete_device(ip):
    """Удалить устройство"""
    conn = get_connection()
    cursor = conn.cursor()
    lookup_ip = _lookup_ip(ip)
    cursor.execute('DELETE FROM devices WHERE ip = ?', (lookup_ip,))
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
        
        if _should_encrypt_table():
            stored_ip = _hash_ip(ip)
            # Шифруем данные, включая IP
            data_dict = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'ports': ports,
                'comment': comment
            }
            encrypted = _encrypt_row(data_dict)
            if encrypted:
                # Сохраняем зашифрованные данные, очищаем открытые поля
                cursor.execute('''
                    INSERT INTO devices (ip, mac, hostname, ports, comment, encrypted_data, created_at, updated_at)
                    VALUES (?, '', '', '', '', ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        encrypted_data = excluded.encrypted_data,
                        updated_at = excluded.updated_at
                ''', (stored_ip, encrypted, now, now))
            else:
                # Если шифрование не удалось, сохраняем открыто, но ip храним как хэш
                cursor.execute('''
                    INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = excluded.mac,
                        hostname = excluded.hostname,
                        ports = excluded.ports,
                        updated_at = excluded.updated_at
                ''', (stored_ip, mac, hostname, ports, comment, now, now))
        else:
            stored_ip = ip
            # Без шифрования
            cursor.execute('''
                INSERT INTO devices (ip, mac, hostname, ports, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    ports = excluded.ports,
                    updated_at = excluded.updated_at
            ''', (stored_ip, mac, hostname, ports, comment, now, now))
    conn.commit()
    conn.close()

# ==================== Исключённые MAC ====================

def get_excluded_macs():
    """Получить все исключённые MAC"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT mac, encrypted_data FROM excluded_macs ORDER BY mac')
    rows = cursor.fetchall()
    conn.close()
    
    macs = []
    for row in rows:
        mac_field = row['mac']
        encrypted = row['encrypted_data']
        
        if encrypted and _should_encrypt_table():
            # Данные зашифрованы, расшифровываем
            decrypted = _decrypt_row(encrypted)
            if decrypted and 'mac' in decrypted:
                macs.append(decrypted['mac'])
                continue
        # Если шифрование не используется или расшифровка не удалась, используем поле mac
        # Но поле mac может содержать хэш, если шифрование включено
        # Проверяем, выглядит ли как хэш SHA-256 (64 hex символа)
        if mac_field and len(mac_field) == 64 and all(c in '0123456789abcdef' for c in mac_field.lower()):
            # Это хэш, пропускаем (оригинальный MAC будет в encrypted_data, который мы уже обработали)
            continue
        macs.append(mac_field)
    return macs

def add_excluded_mac(mac):
    """Добавить MAC в исключения"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if _should_encrypt_table():
        # Шифруем MAC
        data_dict = {'mac': mac}
        encrypted = _encrypt_row(data_dict)
        if encrypted:
            # Вычисляем хэш для уникальности и поиска
            mac_hash = hashlib.sha256(mac.encode()).hexdigest()
            cursor.execute('INSERT OR IGNORE INTO excluded_macs (mac, encrypted_data) VALUES (?, ?)',
                          (mac_hash, encrypted))
        else:
            # Если шифрование не удалось, сохраняем открыто
            cursor.execute('INSERT OR IGNORE INTO excluded_macs (mac) VALUES (?)', (mac,))
    else:
        cursor.execute('INSERT OR IGNORE INTO excluded_macs (mac) VALUES (?)', (mac,))
    
    conn.commit()
    conn.close()

def remove_excluded_mac(mac):
    """Удалить MAC из исключений"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if _should_encrypt_table():
        # При шифровании мы храним хэш в поле mac
        mac_hash = hashlib.sha256(mac.encode()).hexdigest()
        cursor.execute('DELETE FROM excluded_macs WHERE mac = ?', (mac_hash,))
    else:
        cursor.execute('DELETE FROM excluded_macs WHERE mac = ?', (mac,))
    
    conn.commit()
    conn.close()

# ==================== История ====================

def add_history_entry(message):
    """Добавить запись в историю"""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    if _should_encrypt_table():
        data_dict = {'timestamp': timestamp, 'message': message}
        encrypted = _encrypt_row(data_dict)
        if encrypted:
            # Сохраняем зашифрованные данные, оставляем открытые поля пустыми
            cursor.execute('INSERT INTO scan_history (timestamp, message, encrypted_data) VALUES (?, ?, ?)',
                          ('', '', encrypted))
        else:
            # Если шифрование не удалось, сохраняем открыто
            cursor.execute('INSERT INTO scan_history (timestamp, message) VALUES (?, ?)', (timestamp, message))
    else:
        cursor.execute('INSERT INTO scan_history (timestamp, message) VALUES (?, ?)', (timestamp, message))
    
    conn.commit()
    conn.close()

def get_history(limit=100):
    """Получить историю сканирований"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, message, encrypted_data FROM scan_history ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        timestamp = row['timestamp']
        message = row['message']
        encrypted = row['encrypted_data']
        
        if encrypted and _should_encrypt_table():
            decrypted = _decrypt_row(encrypted)
            if decrypted and 'timestamp' in decrypted and 'message' in decrypted:
                history.append({'timestamp': decrypted['timestamp'], 'message': decrypted['message']})
                continue
        # Если шифрование не используется или расшифровка не удалась, используем открытые поля
        history.append({'timestamp': timestamp, 'message': message})
    
    return history

def clear_history():
    """Очистить историю"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history')
    conn.commit()
    conn.close()

# ==================== Настройки Email ====================

def get_email_settings(key_type=None, custom_key=''):
    """Получить настройки email (с расшифровкой если зашифровано)
    
    Args:
        key_type: 'computer_name' или 'custom'. Если None, используется сохранённый тип.
        custom_key: Пользовательский ключ (требуется если key_type='custom').
    
    Returns:
        dict с настройками или None если не удалось расшифровать.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM email_settings WHERE id = 1')
        settings = cursor.fetchone()
        conn.close()
        if settings:
            settings_dict = dict(settings)
            # Определяем уровень шифрования
            encryption_level = settings_dict.get('encryption_level', 'email_only')
            
            # Если уровень 'none', читаем открытые поля (игнорируем encrypted_data)
            if encryption_level == 'none':
                # Проверяем, есть ли открытые данные
                if settings_dict.get('login') or settings_dict.get('smtp_server'):
                    return {
                        'smtp_server': settings_dict.get('smtp_server', ''),
                        'smtp_port': settings_dict.get('smtp_port', 587),
                        'login': settings_dict.get('login', ''),
                        'password': settings_dict.get('password', ''),
                        'from_address': settings_dict.get('from_address', ''),
                        'use_tls': settings_dict.get('use_tls', 1),
                        'enable_notifications': settings_dict.get('enable_notifications', 1),
                        'encrypted': False,
                        'encryption_level': encryption_level,
                        'encryption_key_type': settings_dict.get('encryption_key_type', 'computer_name'),
                        'custom_key_hash': settings_dict.get('custom_key_hash', '')
                    }
                else:
                    return None
            
            # Уровень шифрования email_only или all (обрабатываем как зашифрованные данные)
            if settings_dict.get('encrypted_data'):
                # Определяем тип ключа для расшифровки
                saved_key_type = settings_dict.get('encryption_key_type', 'computer_name')
                use_key_type = key_type if key_type is not None else saved_key_type
                use_custom_key = custom_key if use_key_type == 'custom' else ''
                
                # Если ключ пользовательский и не передан, используем глобальную переменную CUSTOM_KEY
                if use_key_type == 'custom' and not use_custom_key:
                    use_custom_key = CUSTOM_KEY
                
                decrypted = decrypt_email_settings(settings_dict['encrypted_data'], use_key_type, use_custom_key)
                if not decrypted and use_key_type != 'computer_name':
                    # Пробуем расшифровать с ключом "имя компьютера" (fallback)
                    decrypted = decrypt_email_settings(settings_dict['encrypted_data'], 'computer_name', '')
                if decrypted:
                    # Добавляем поля шифрования
                    decrypted['encryption_level'] = encryption_level
                    decrypted['encryption_key_type'] = settings_dict.get('encryption_key_type', 'computer_name')
                    decrypted['custom_key_hash'] = settings_dict.get('custom_key_hash', '')
                    return decrypted
                # Если не удалось расшифровать, возвращаем информацию о шифровании (без SMTP данных)
                # Это позволяет правильно отобразить радио-кнопки в настройках
                return {
                    'smtp_server': '',
                    'smtp_port': 587,
                    'login': '',
                    'password': '',
                    'from_address': '',
                    'use_tls': True,
                    'enable_notifications': True,
                    'encrypted': True,
                    'decryption_failed': True,
                    'encryption_level': encryption_level,
                    'encryption_key_type': settings_dict.get('encryption_key_type', 'computer_name'),
                    'custom_key_hash': settings_dict.get('custom_key_hash', '')
                }
            
            # Для обратной совместимости - если данных нет, но есть открытые поля (старая база)
            if settings_dict.get('login') or settings_dict.get('smtp_server'):
                return {
                    'smtp_server': settings_dict.get('smtp_server', ''),
                    'smtp_port': settings_dict.get('smtp_port', 587),
                    'login': settings_dict.get('login', ''),
                    'password': settings_dict.get('password', ''),
                    'from_address': settings_dict.get('from_address', ''),
                    'use_tls': settings_dict.get('use_tls', 1),
                    'enable_notifications': settings_dict.get('enable_notifications', 1),
                    'encrypted': False,
                    'encryption_level': settings_dict.get('encryption_level', 'email_only'),
                    'encryption_key_type': settings_dict.get('encryption_key_type', 'computer_name'),
                    'custom_key_hash': settings_dict.get('custom_key_hash', '')
                }
            return None
        return None
    except sqlite3.OperationalError:
        # Таблица не существует или неправильная структура
        conn.close()
        return None


def update_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications,
                          encryption_level='email_only', encryption_key_type='computer_name', custom_key=''):
    """Обновить настройки email (с шифрованием)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Вычисляем хэш ключа для хранения (если ключ пользовательский)
    stored_key_hash = ''
    if encryption_key_type == 'custom' and custom_key:
        stored_key_hash = hashlib.sha256(custom_key.encode('utf-8')).hexdigest()
    
    # Получаем текущий уровень шифрования для сравнения
    cursor.execute('SELECT encryption_level FROM email_settings WHERE id = 1')
    row = cursor.fetchone()
    old_level = row['encryption_level'] if row and row['encryption_level'] else 'email_only'
    
    # Если уровень изменился, выполняем миграцию данных
    if old_level != encryption_level:
        # Устанавливаем глобальный CUSTOM_KEY, если передан пользовательский ключ
        if encryption_key_type == 'custom' and custom_key:
            set_custom_key(custom_key)
        # Выполняем миграцию
        migrate_encryption_level(encryption_level)
    
    # Проверяем существование записи с id=1 (после миграции, т.к. миграция могла создать запись)
    cursor.execute('SELECT id FROM email_settings WHERE id = 1')
    exists = cursor.fetchone() is not None
    
    if encryption_level == 'none':
        # Сохраняем в открытом виде (без шифрования)
        if exists:
            cursor.execute('''
                UPDATE email_settings SET
                    smtp_server = ?,
                    smtp_port = ?,
                    login = ?,
                    password = ?,
                    from_address = ?,
                    use_tls = ?,
                    enable_notifications = ?,
                    encrypted_data = NULL,
                    encryption_level = ?,
                    encryption_key_type = ?,
                    custom_key_hash = ?
                WHERE id = 1
            ''', (smtp_server, smtp_port, login, password, from_address, 1 if use_tls else 0, 1 if enable_notifications else 0,
                  encryption_level, encryption_key_type, stored_key_hash))
        else:
            cursor.execute('''
                INSERT INTO email_settings (id, smtp_server, smtp_port, login, password, from_address,
                    use_tls, enable_notifications, encrypted_data, encryption_level, encryption_key_type, custom_key_hash)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
            ''', (smtp_server, smtp_port, login, password, from_address, 1 if use_tls else 0, 1 if enable_notifications else 0,
                  encryption_level, encryption_key_type, stored_key_hash))
    else:
        # Пытаемся шифровать с указанным ключом
        encrypted = encrypt_email_settings(smtp_server, smtp_port, login, password, from_address, use_tls, enable_notifications,
                                           encryption_key_type, custom_key)
        
        if encrypted.get('encrypted'):
            # Сохраняем зашифрованные данные
            if exists:
                cursor.execute('''
                    UPDATE email_settings SET
                        encrypted_data = ?,
                        smtp_server = '',
                        smtp_port = 587,
                        login = '',
                        password = '',
                        from_address = '',
                        use_tls = 1,
                        enable_notifications = 1,
                        encryption_level = ?,
                        encryption_key_type = ?,
                        custom_key_hash = ?
                    WHERE id = 1
                ''', (encrypted['encrypted_data'], encryption_level, encryption_key_type, stored_key_hash))
            else:
                cursor.execute('''
                    INSERT INTO email_settings (id, encrypted_data, smtp_server, smtp_port, login, password,
                        from_address, use_tls, enable_notifications, encryption_level, encryption_key_type, custom_key_hash)
                    VALUES (1, ?, '', 587, '', '', '', 1, 1, ?, ?, ?)
                ''', (encrypted['encrypted_data'], encryption_level, encryption_key_type, stored_key_hash))
        else:
            # Сохраняем в открытом виде (если библиотека не доступна)
            if exists:
                cursor.execute('''
                    UPDATE email_settings SET
                        smtp_server = ?,
                        smtp_port = ?,
                        login = ?,
                        password = ?,
                        from_address = ?,
                        use_tls = ?,
                        enable_notifications = ?,
                        encrypted_data = NULL,
                        encryption_level = ?,
                        encryption_key_type = ?,
                        custom_key_hash = ?
                    WHERE id = 1
                ''', (smtp_server, smtp_port, login, password, from_address, 1 if use_tls else 0, 1 if enable_notifications else 0,
                      encryption_level, encryption_key_type, stored_key_hash))
            else:
                cursor.execute('''
                    INSERT INTO email_settings (id, smtp_server, smtp_port, login, password, from_address,
                        use_tls, enable_notifications, encrypted_data, encryption_level, encryption_key_type, custom_key_hash)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                ''', (smtp_server, smtp_port, login, password, from_address, 1 if use_tls else 0, 1 if enable_notifications else 0,
                      encryption_level, encryption_key_type, stored_key_hash))
    
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
            encrypted_data = NULL,
            encryption_level = 'none',
            encryption_key_type = 'computer_name',
            custom_key_hash = ''
        WHERE id = 1
    ''')
    conn.commit()
    conn.close()


def clear_database():
    """Очистить базу: удалить все устройства, историю, исключения и сбросить настройки email"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Удаляем все устройства
    cursor.execute('DELETE FROM devices')
    
    # Удаляем всю историю
    cursor.execute('DELETE FROM scan_history')
    
    # Удаляем все исключённые MAC
    cursor.execute('DELETE FROM excluded_macs')
    
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
            encrypted_data = NULL,
            encryption_level = 'email_only',
            encryption_key_type = 'computer_name',
            custom_key_hash = ''
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
            settings_dict = dict(settings)
            encrypted = settings_dict.get('encrypted_data')
            if encrypted and _should_encrypt_table():
                decrypted = _decrypt_row(encrypted)
                if decrypted:
                    # Объединяем расшифрованные данные с открытыми полями (перезаписывая)
                    for key, value in decrypted.items():
                        settings_dict[key] = value
            return settings_dict
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
    
    if _should_encrypt_table():
        # Шифруем все настройки
        data_dict = {
            'subnet': subnet,
            'start_ip': start_ip,
            'end_ip': end_ip,
            'email_recipients': email_recipients,
            'scan_delay': scan_delay,
            'auto_scan': 1 if auto_scan else 0,
            'nmap_dir': nmap_dir
        }
        encrypted = _encrypt_row(data_dict)
        if encrypted:
            # Сохраняем зашифрованные данные, открытые поля оставляем пустыми
            if count > 0:
                cursor.execute('''
                    UPDATE scan_settings SET
                        subnet = ?,
                        start_ip = ?,
                        end_ip = ?,
                        email_recipients = ?,
                        scan_delay = ?,
                        auto_scan = ?,
                        nmap_dir = ?,
                        encrypted_data = ?
                    WHERE id = 1
                ''', ('', '', '', '', 0, 0, '', encrypted))
            else:
                cursor.execute('''
                    INSERT INTO scan_settings (id, subnet, start_ip, end_ip, email_recipients, scan_delay, auto_scan, nmap_dir, encrypted_data)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', ('', '', '', '', 0, 0, '', encrypted))
        else:
            # Если шифрование не удалось, сохраняем открыто
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
    else:
        # Без шифрования
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
