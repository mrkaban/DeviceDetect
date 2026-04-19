# -*- coding: utf-8 -*-
"""
Network Scanner - PyQt5 приложение для сканирования сети
С базой данных SQLite и меню
"""

import sys
import hashlib
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QVBoxLayout, QWidget, QFileDialog, QGroupBox,
                             QHBoxLayout, QCheckBox, QMenuBar, QMenu, QAction, QMessageBox,
                             QInputDialog)
from PyQt5.QtCore import QCoreApplication
import subprocess
import re
import os
from ipaddress import ip_network, ip_address

from email.mime.text import MIMEText
import smtplib
import socket

import time
from datetime import datetime

# Импорт модулей базы данных и диалогов
import database as db
from device_viewer import DeviceViewerDialog
from email_settings_dialog import EmailSettingsDialog
from scan_results_dialog import ScanResultsDialog


app = QApplication(sys.argv)

# Инициализация базы данных
db.init_database()

# Проверка настроек шифрования
settings = db.get_email_settings()
if settings and settings.get('encryption_key_type') == 'custom' and settings.get('custom_key_hash'):
    # Запрашиваем ключ
    key, ok = QInputDialog.getText(None, "Ввод ключа", "Введите ключ шифрования:", QLineEdit.Password)
    if not ok:
        # Пользователь нажал Отмена
        sys.exit(0)
    # Вычисляем хэш введённого ключа
    key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
    # Сравниваем хэши
    if key_hash != settings.get('custom_key_hash'):
        # Неверный ключ
        reply = QMessageBox.question(None, "Неверный ключ",
                                     "Неверный ключ шифрования. Очистить базу данных?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            db.clear_database()
            QMessageBox.information(None, "База очищена", "База данных очищена. Перезапустите программу.")
        sys.exit(0)
    # Ключ верный, сохраняем его для шифрования новых данных
    db.set_custom_key(key)


class MyWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("DeviceDetect")
        self.setGeometry(100, 100, 550, 650)
        
        # Инициализация базы данных
        db.init_database()
    
        # Создаём меню
        self._create_menu()
        
        # Создаём интерфейс
        self._create_ui()
        
        # Загружаем последние настройки (включая путь к Nmap)
        self._load_settings()
        
        # Проверка Nmap при запуске (после загрузки настроек)
        self._check_nmap_on_startup()
        
        # Флаг для остановки цикла
        self.scan_running = False
        self.stop_requested = False
        
        # Таймер для следующего сканирования в зацикленном режиме
        self._next_scan_timer = None
    
    def _create_menu(self):
        """Создание меню"""
        menubar = self.menuBar()
        
        # Меню Файл
        file_menu = menubar.addMenu("Файл")
        
        exit_action = QAction("Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Меню База
        db_menu = menubar.addMenu("База")
        
        view_action = QAction("Просмотр устройств", self)
        view_action.triggered.connect(self._open_device_viewer)
        db_menu.addAction(view_action)
        
        settings_action = QAction("Настройки", self)
        settings_action.triggered.connect(self._open_email_settings)
        db_menu.addAction(settings_action)
    
        history_action = QAction("История обнаружения", self)
        history_action.triggered.connect(self._open_history_viewer)
        db_menu.addAction(history_action)
        
        exclusions_action = QAction("Исключения", self)
        exclusions_action.triggered.connect(self._open_exclusions_viewer)
        db_menu.addAction(exclusions_action)
        
        db_menu.addSeparator()
        
        import_action = QAction("Импорт старой базы (txt)", self)
        import_action.triggered.connect(self._import_old_database)
        db_menu.addAction(import_action)
    
        db_menu.addSeparator()
        
        clear_action = QAction("Очистить базу", self)
        clear_action.triggered.connect(self._clear_database)
        db_menu.addAction(clear_action)
    
    def _create_ui(self):
        """Создание пользовательского интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Группа: Каталог с NMAP
        group_nmap = QGroupBox("Каталог с NMAP")
        nmap_layout = QHBoxLayout()
        self.nmap_dir_edit = QLineEdit()
        self.browse_button = QPushButton("Обзор")
        nmap_layout.addWidget(self.nmap_dir_edit)
        nmap_layout.addWidget(self.browse_button)
        group_nmap.setLayout(nmap_layout)
        layout.addWidget(group_nmap)
        
        # Группа: Отправка отчетов
        group_email = QGroupBox("Отправка отчетов")
        email_layout = QHBoxLayout()
        label_email = QLabel("Куда слать отчеты:")
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("email1@example.ru, email2@example.ru")
        email_layout.addWidget(label_email)
        email_layout.addWidget(self.email_edit)
        group_email.setLayout(email_layout)
        layout.addWidget(group_email)
        
        # Группа: Задержка автозапуска
        group_delay = QGroupBox("Задержка автозапуска")
        delay_layout = QVBoxLayout()
        self.cbZacilit = QCheckBox("Зациклить обнаружение (интерфейс не отвечает, но работает)")
        self.delay_edit = QLineEdit("14400")
        self.delay_edit.setPlaceholderText("секунды")
        self.delay_label = QLabel("(4 часа)")
        delay_layout.addWidget(self.cbZacilit)
        delay_row = QHBoxLayout()
        delay_row.addWidget(self.delay_edit)
        delay_row.addWidget(self.delay_label)
        delay_layout.addLayout(delay_row)
        group_delay.setLayout(delay_layout)
        layout.addWidget(group_delay)
        
        # Конвертация секунд в читаемый формат
        self.delay_edit.textChanged.connect(self._update_delay_label)
        
        # Группа: Сканирование
        group_scan = QGroupBox("Сканирование")
        scan_layout = QVBoxLayout()
        
        # Диапазон IP (теперь первый)
        range_row = QHBoxLayout()
        label_range = QLabel("Диапазон IP:")
        self.start_ip_edit = QLineEdit()
        self.start_ip_edit.setPlaceholderText("Начальный IP")
        self.end_ip_edit = QLineEdit()
        self.end_ip_edit.setPlaceholderText("Конечный IP")
        range_row.addWidget(label_range)
        range_row.addWidget(self.start_ip_edit)
        range_row.addWidget(self.end_ip_edit)
        scan_layout.addLayout(range_row)
        
        # Маска подсети (теперь вторая, опционально)
        mask_row = QHBoxLayout()
        label_scan = QLabel("Маска подсети (опционально):")
        self.scan_edit = QLineEdit("0.0.0.0/0")
        mask_row.addWidget(label_scan)
        mask_row.addWidget(self.scan_edit)
        scan_layout.addLayout(mask_row)
        
        group_scan.setLayout(scan_layout)
        layout.addWidget(group_scan)
        
        # Лог статуса
        self.status_textedit = QTextEdit()
        self.status_textedit.setReadOnly(True)
        layout.addWidget(self.status_textedit)
        
        # Кнопки
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Обнаружить устройства")
        self.scan_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px 20px; font-weight: bold;")
        self.stop_button = QPushButton("Остановить")
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; padding: 8px 16px;")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Привязываем события
        self.browse_button.clicked.connect(self.browse_nmap_dir)
        self.scan_button.clicked.connect(lambda: self.start_scan())
        self.stop_button.clicked.connect(self.stop_scan)
    
        # Сохранение настроек при закрытии
        self.closeEvent = self._on_close
    
    def _open_device_viewer(self):
        """Открыть окно просмотра устройств"""
        dialog = DeviceViewerDialog(self)
        dialog.exec_()
    
    def _open_email_settings(self):
        """Открыть окно настроек email"""
        dialog = EmailSettingsDialog(self)
        dialog.exec_()
    
    def _open_history_viewer(self):
        """Открыть окно просмотра истории"""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout, QLineEdit, QLabel
        from PyQt5.QtCore import Qt
        
        dialog = QDialog(self)
        dialog.setWindowTitle("История обнаружения")
        dialog.setMinimumSize(700, 500)
        dialog.setModal(True)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Поиск
        search_layout = QHBoxLayout()
        search_label = QLabel("Поиск:")
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("Введите текст для поиска...")
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_edit)
        layout.addLayout(search_layout)
        
        # Текстовое поле
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFontFamily("Consolas")
        layout.addWidget(text_edit)
        
        # Загрузка истории
        all_history = db.get_history(500)
        
        def filter_history():
            search_text = search_edit.text().strip().lower()
            text_edit.clear()
            
            if not search_text:
                # Показать всё
                if all_history:
                    for record in all_history:
                        text_edit.append(f"{record['timestamp']} - {record['message']}")
                else:
                    text_edit.append("История пуста")
                return
            
            # Фильтруем
            found = False
            for record in all_history:
                if (search_text in record.get('timestamp', '').lower() or
                    search_text in record.get('message', '').lower()):
                    text_edit.append(f"{record['timestamp']} - {record['message']}")
                    found = True
            
            if not found:
                text_edit.append("Ничего не найдено")
        
        search_edit.textChanged.connect(filter_history)
        filter_history()  # Первая загрузка
        
        # Кнопки
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        btn_close = QPushButton("Закрыть")
        btn_close.clicked.connect(dialog.close)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
        
        dialog.exec_()
    
    def _open_exclusions_viewer(self):
        """Открыть окно редактирования исключений MAC"""
        from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QListWidget,
                                     QLineEdit, QPushButton, QLabel, QMessageBox)
        from PyQt5.QtCore import Qt
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Исключённые MAC-адреса")
        dialog.setMinimumSize(500, 400)
        dialog.setModal(True)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Список исключений
        list_label = QLabel("Текущие исключённые MAC-адреса:")
        layout.addWidget(list_label)
        
        mac_list = QListWidget()
        layout.addWidget(mac_list)
        
        # Загрузка текущих исключений
        excluded_macs = db.get_excluded_macs()
        for mac in excluded_macs:
            mac_list.addItem(mac)
        
        # Панель добавления
        add_layout = QHBoxLayout()
        add_label = QLabel("Новый MAC:")
        mac_edit = QLineEdit()
        mac_edit.setPlaceholderText("00:11:22:33:44:55")
        add_button = QPushButton("Добавить")
        add_layout.addWidget(add_label)
        add_layout.addWidget(mac_edit)
        add_layout.addWidget(add_button)
        layout.addLayout(add_layout)
        
        # Панель удаления
        button_layout = QHBoxLayout()
        remove_button = QPushButton("Удалить выбранное")
        clear_button = QPushButton("Очистить все")
        close_button = QPushButton("Закрыть")
        button_layout.addWidget(remove_button)
        button_layout.addWidget(clear_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        
        # Функции
        def refresh_list():
            mac_list.clear()
            for mac in db.get_excluded_macs():
                mac_list.addItem(mac)
        
        def add_mac():
            mac = mac_edit.text().strip()
            if not mac:
                QMessageBox.warning(dialog, "Ошибка", "Введите MAC-адрес")
                return
            # Простая валидация
            if len(mac) < 6:
                QMessageBox.warning(dialog, "Ошибка", "MAC-адрес слишком короткий")
                return
            db.add_excluded_mac(mac)
            refresh_list()
            mac_edit.clear()
        
        def remove_selected():
            selected = mac_list.currentItem()
            if not selected:
                QMessageBox.warning(dialog, "Ошибка", "Выберите MAC-адрес для удаления")
                return
            mac = selected.text()
            db.remove_excluded_mac(mac)
            refresh_list()
        
        def clear_all():
            reply = QMessageBox.question(dialog, "Подтверждение",
                                         "Удалить все исключённые MAC-адреса?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                conn = db.get_connection()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM excluded_macs')
                conn.commit()
                conn.close()
                refresh_list()
        
        # Привязка событий
        add_button.clicked.connect(add_mac)
        remove_button.clicked.connect(remove_selected)
        clear_button.clicked.connect(clear_all)
        close_button.clicked.connect(dialog.close)
        
        dialog.exec_()
    
    def _clear_database(self):
        """Очистка базы данных"""
        reply = QMessageBox.question(
            self,
            "Подтверждение очистки базы",
            "Вы уверены, что хотите очистить базу?\n\n"
            "Будут удалены:\n"
            "• Все найденные устройства\n"
            "• Вся история сканирований\n"
            "• Настройки почты будут сброшены на примерные значения\n"
            "• Отправка уведомлений будет ОТКЛЮЧЕНА\n\n"
            "Это действие нельзя отменить!",
            QMessageBox.Yes | QMessageBox.No
        )
    
        if reply != QMessageBox.Yes:
            return
        
        # Очищаем базу
        db.clear_database()
        
        # Очищаем поле email в интерфейсе
        self.email_edit.setText("email1@example.ru, email2@example.ru")
        
        QMessageBox.information(
            self,
            "Готово",
            "База данных очищена!\n\n"
            "• Все устройства удалены\n"
            "• История очищена\n"
            "• Настройки почты сброшены на примерные значения\n"
            "• Отправка уведомлений ОТКЛЮЧЕНА"
        )
    
    def _import_old_database(self):
        """Импорт данных из старых txt файлов"""
        print("\n=== Импорт старой базы ===")
        
        # Сначала пытаемся найти в папке исполняемого файла
        if getattr(sys, 'frozen', False):
            # Запущен как exe
            import_dir = os.path.dirname(sys.executable)
        else:
            # Запущен как скрипт
            import_dir = os.path.dirname(os.path.abspath(__file__))
        
        print(f"Папка импорта: {import_dir}")
        
        output_file = os.path.join(import_dir, 'output.txt')
        exclude_file = os.path.join(import_dir, 'exclude_mac.txt')
        history_file = os.path.join(import_dir, 'history.txt')
        
        files_found = []
        if os.path.exists(output_file):
            files_found.append('output.txt')
        if os.path.exists(exclude_file):
            files_found.append('exclude_mac.txt')
        if os.path.exists(history_file):
            files_found.append('history.txt')
        
        # Если файлы не найдены, предлагаем выбрать папку
        if not files_found:
            QMessageBox.information(self, "Поиск файлов",
                "Файлы output.txt, exclude_mac.txt, history.txt не найдены в папке программы.\n\n"
                f"Папка: {import_dir}\n\n"
                "Сейчас откроется диалог выбора папки с этими файлами.")
            
            import_dir = QFileDialog.getExistingDirectory(self, "Выберите папку с файлами базы")
            if not import_dir:
                print("Импорт отменён пользователем")
                return
            
            output_file = os.path.join(import_dir, 'output.txt')
            exclude_file = os.path.join(import_dir, 'exclude_mac.txt')
            history_file = os.path.join(import_dir, 'history.txt')
            
            if os.path.exists(output_file):
                files_found.append('output.txt')
            if os.path.exists(exclude_file):
                files_found.append('exclude_mac.txt')
            if os.path.exists(history_file):
                files_found.append('history.txt')
            
            if not files_found:
                QMessageBox.warning(self, "Предупреждение", 
                    "Файлы не найдены в выбранной папке.")
                print("Файлы не найдены в выбранной папке")
                return
        
        print(f"Найдены файлы: {', '.join(files_found)}")
        
        reply = QMessageBox.question(self, "Подтверждение",
            f"Найдены файлы:\n{', '.join(files_found)}\n\n"
            f"Папка: {import_dir}\n\n"
            "Импортировать данные в базу SQLite?",
            QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            print("Импорт отменён пользователем")
            return
        
        # Импорт
        imported_count = {'devices': 0, 'excluded': 0, 'history': 0}
        
        # output.txt
        if os.path.exists(output_file):
            print("Импорт output.txt...")
            try:
                with open(output_file, 'r', encoding='cp1251') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1] if len(parts) > 1 else 'None'
                            hostname = parts[2] if len(parts) > 2 else 'None'
                            db.add_device(ip, mac, hostname, '', '')
                            imported_count['devices'] += 1
                print(f"  Импортировано устройств: {imported_count['devices']}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка чтения output.txt: {e}")
                print(f"  Ошибка: {e}")
                return
        
        # exclude_mac.txt
        if os.path.exists(exclude_file):
            print("Импорт exclude_mac.txt...")
            try:
                with open(exclude_file, 'r', encoding='cp1251') as f:
                    for line in f:
                        mac = line.strip()
                        if mac:
                            db.add_excluded_mac(mac)
                            imported_count['excluded'] += 1
                print(f"  Импортировано исключённых MAC: {imported_count['excluded']}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка чтения exclude_mac.txt: {e}")
                print(f"  Ошибка: {e}")
                return
        
        # history.txt
        if os.path.exists(history_file):
            print("Импорт history.txt...")
            try:
                with open(history_file, 'r', encoding='cp1251') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            db.add_history_entry(line)
                            imported_count['history'] += 1
                print(f"  Импортировано записей истории: {imported_count['history']}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка чтения history.txt: {e}")
                print(f"  Ошибка: {e}")
                return
        
        # Переименовываем файлы
        print("Переименование файлов в .bak...")
        for filename in files_found:
            src = os.path.join(import_dir, filename)
            dst = os.path.join(import_dir, f"{filename}.bak")
            if os.path.exists(src):
                os.rename(src, dst)
                print(f"  {filename} → {filename}.bak")
        
        print(f"=== Импорт завершён ===\n")
        
        QMessageBox.information(self, "Готово",
            f"Импорт завершён!\n\n"
            f"Устройств: {imported_count['devices']}\n"
            f"Исключённых MAC: {imported_count['excluded']}\n"
            f"Записей истории: {imported_count['history']}\n\n"
            f"Файлы переименованы в .bak")
    
    def _load_settings(self):
        """Загрузить последние настройки сканирования"""
        # Сначала проверяем настройки почты (с проверкой расшифровки)
        email_settings = db.get_email_settings()
        if email_settings is None:
            # Не удалось расшифровать настройки - показываем диалог
            self._handle_decrypt_error()
            # После этого загружаем уже сброшенные настройки
            email_settings = db.get_email_settings()
        
        if email_settings:
            # Если настройки есть в базе — используем их
            # Для email_recipients берём из scan_settings, не из email_settings
            pass
        
        settings = db.get_scan_settings()
        if settings:
            # Если настройки есть в базе — используем их
            self.nmap_dir_edit.setText(settings.get('nmap_dir', '') or '')
            self.scan_edit.setText(settings.get('subnet', '') or '0.0.0.0/0')
            self.start_ip_edit.setText(settings.get('start_ip', '') or '')
            self.end_ip_edit.setText(settings.get('end_ip', '') or '')
            self.email_edit.setText(settings.get('email_recipients', '') or 'email1@example.ru, email2@example.ru')
            self.delay_edit.setText(str(settings.get('scan_delay', 14400)) if settings.get('scan_delay') else '14400')
            if settings.get('auto_scan'):
                self.cbZacilit.setChecked(True)
        # else: оставляем значения по умолчанию из UI (0.0.0.0/0)
        
        # Авто-определение маски по диапазону, если диапазон задан
        self.start_ip_edit.textChanged.connect(self._auto_detect_mask)
        self.end_ip_edit.textChanged.connect(self._auto_detect_mask)
    
    def _handle_decrypt_error(self):
        """Обработка ошибки расшифровки настроек почты"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Ошибка расшифровки настроек")
        msg_box.setText(
            "Не удалось расшифровать настройки почты.\n\n"
            "Возможно, база данных была перенесена с другого компьютера.\n\n"
            "Настройки будут сброшены на значения по умолчанию."
        )
        msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg_box.button(QMessageBox.Ok).setText("Сбросить настройки")
        msg_box.button(QMessageBox.Cancel).setText("Отмена")
    
        reply = msg_box.exec_()
        
        if reply == QMessageBox.Ok:
            # Сбрасываем настройки
            db.reset_email_settings()
        else:
            # Закрываем программу
            self.close()
    
    def _save_settings(self):
        """Сохранить текущие настройки сканирования"""
        db.update_scan_settings(
            subnet=self.scan_edit.text(),
            start_ip=self.start_ip_edit.text().strip(),
            end_ip=self.end_ip_edit.text().strip(),
            email_recipients=self.email_edit.text(),
            scan_delay=int(self.delay_edit.text() or '300'),
            auto_scan=1 if self.cbZacilit.isChecked() else 0,
            nmap_dir=self.nmap_dir_edit.text().strip()
        )
    
    def _on_close(self, event):
        """Обработка закрытия окна - сохранение настроек"""
        self._save_settings()
        event.accept()
        
    def _update_delay_label(self):
        """Обновление метки задержки в читаемом формате"""
        try:
            seconds = int(self.delay_edit.text() or '0')
            if seconds >= 3600:
                hours = seconds / 3600
                self.delay_label.setText(f"({hours:.1f} ч.)")
            elif seconds >= 60:
                minutes = seconds / 60
                self.delay_label.setText(f"({minutes:.0f} мин.)")
            else:
                self.delay_label.setText(f"({seconds} сек.)")
        except:
            self.delay_label.setText("")
    
    def _auto_detect_mask(self):
        """Автоматическое определение маски сети по диапазону IP"""
        start_ip = self.start_ip_edit.text().strip()
        end_ip = self.end_ip_edit.text().strip()
        
        if start_ip and end_ip:
            try:
                start_parts = start_ip.split('.')
                end_parts = end_ip.split('.')
                
                # Определяем минимальную маску, покрывающую весь диапазон
                # Сравниваем октеты слева направо
                if start_parts[0] != end_parts[0]:
                    # Разные первые октеты - маска /8 или меньше
                    self.scan_edit.setText(f"{start_parts[0]}.0.0.0/8")
                elif start_parts[1] != end_parts[1]:
                    # Разные вторые октеты - маска /16
                    self.scan_edit.setText(f"{start_parts[0]}.{start_parts[1]}.0.0/16")
                elif start_parts[2] != end_parts[2]:
                    # Разные третьи октеты - вычисляем маску
                    # Для диапазона 192.168.0.0 - 192.168.36.255 нужна маска /18
                    diff = int(end_parts[2]) - int(start_parts[2])
                    if diff <= 0:
                        mask = 24
                    elif diff <= 1:
                        mask = 23
                    elif diff <= 3:
                        mask = 22
                    elif diff <= 7:
                        mask = 21
                    elif diff <= 15:
                        mask = 20
                    elif diff <= 31:
                        mask = 19
                    elif diff <= 63:
                        mask = 18
                    elif diff <= 127:
                        mask = 17
                    else:
                        mask = 16
                    self.scan_edit.setText(f"{start_parts[0]}.{start_parts[1]}.0.0/{mask}")
                else:
                    # Третьи октеты одинаковые - маска /24
                    self.scan_edit.setText(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.0/24")
            except:
                pass
    
    def _validate_scan_inputs(self):
        """Проверка корректности входных данных для сканирования"""
        # Проверка пути к Nmap
        path = self.nmap_dir_edit.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "Ошибка", "Укажите корректный путь к каталогу с Nmap")
            return False
        
        # Проверка email
        emails = self.email_edit.text().strip()
        if not emails:
            QMessageBox.critical(self, "Ошибка", "Укажите хотя бы один email для отчётов")
            return False
        
        # Проверка маски подсети
        scan_text = self.scan_edit.text().strip()
        if scan_text and '/' in scan_text:
            try:
                ip_network(scan_text)
            except ValueError:
                QMessageBox.critical(self, "Ошибка", f"Некорректная маска сети: {scan_text}")
                return False
        
        # Проверка диапазона IP
        start_ip = self.start_ip_edit.text().strip()
        end_ip = self.end_ip_edit.text().strip()
        if start_ip and end_ip:
            try:
                ip_address(start_ip)
                ip_address(end_ip)
            except ValueError:
                QMessageBox.critical(self, "Ошибка", "Некорректный диапазон IP")
                return False
        
        return True
    
    def _get_scan_command(self, path):
        """Получить команду для сканирования с учётом диапазона и маски"""
        scan_text = self.scan_edit.text().strip()
        start_ip = self.start_ip_edit.text().strip()
        end_ip = self.end_ip_edit.text().strip()
        
        # Если маска не указана, пустая или 0.0.0.0/0, определяем по диапазону
        if not scan_text or '/' not in scan_text or scan_text == '0.0.0.0/0':
            if start_ip and end_ip:
                try:
                    start_parts = start_ip.split('.')
                    scan_text = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.0/24"
                except:
                    scan_text = None
            else:
                scan_text = None
        
        if scan_text:
            try:
                ip_network(scan_text)
            except ValueError:
                return None
        
        # Формируем команду - используем ТОЛЬКО из поля маски!
        if scan_text:
            command = f'"{path}\\nmap.exe" -p 1 --system-dns {scan_text}'
        else:
            # Если нет ни маски, ни диапазона — ошибка
            return None
        
        return command
    
    def _log(self, text):
        """Выводит сообщение в status_textedit и в консоль одновременно"""
        self.status_textedit.append(text)
        QCoreApplication.processEvents()
        print(text)
    
    def _ip_in_range(self, ip, start_ip, end_ip):
        """Проверяет, попадает ли IP в заданный диапазон"""
        try:
            ip_obj = ip_address(ip)
            start_obj = ip_address(start_ip)
            end_obj = ip_address(end_ip)
            return start_obj <= ip_obj <= end_obj
        except:
            return True
    
    def set_defaults(self):
        """Установка пути к nmap по умолчанию"""
        possible_paths = [
            r"C:\nmap\nmap.exe",
            os.path.join(os.path.dirname(sys.argv[0]), "nmap.exe"),
            os.path.join(os.path.dirname(sys.argv[0]), "nmap", "nmap.exe"),
        ]
        for p in possible_paths:
            if os.path.exists(p):
                self.nmap_dir_edit.setText(os.path.dirname(p))
                return True
        return False
    
    def _check_nmap_on_startup(self):
        """Проверка наличия Nmap при запуске"""
        # Сначала проверяем, загружен ли путь из настроек
        nmap_path = self.nmap_dir_edit.text().strip()
        if nmap_path:
            nmap_exe = os.path.join(nmap_path, "nmap.exe")
            if os.path.exists(nmap_exe):
                return  # Nmap найден по сохранённому пути
        
        # Пытаемся найти автоматически в стандартных путях
        if self.set_defaults():
            return  # Nmap найден
        
        # Если не найден - показываем уведомление
        QMessageBox.warning(
            self,
            "Nmap не найден",
            "Пожалуйста, укажите каталог с Nmap.\n\n"
            "По умолчанию ожидается путь: C:\\nmap\\nmap.exe"
        )
    
    def browse_nmap_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "Выберите каталог с NMAP")
        self.nmap_dir_edit.setText(directory)
    
    def deep_scan_ip(self, ip, nmap_dir):
        """Глубокое сканирование IP для уточнения hostname и MAC"""
        nmap_exe = os.path.join(nmap_dir, "nmap.exe")
        if not os.path.exists(nmap_exe):
            return None
        
        # Быстрая проверка доступности хоста (ping)
        try:
            ping_result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                         shell=False, timeout=3)
            if ping_result.returncode != 0:
                print(f"  deep_scan: хост {ip} недоступен (ping)")
                return {'hostname': 'None', 'mac': 'None', 'ping_ok': False}
        except Exception as e:
            print(f"  deep_scan: ping {ip} ошибка: {e}")
        
        info = {}
        
        # Этап 1: RDP (3389)
        try:
            cmd = f'"{nmap_exe}" -T4 -p 3389 --script ssl-cert,rdp-ntlm-info {ip}'
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=25)
            output = result.stdout.decode('cp1251', errors='replace')
            
            patterns = [
                r'DNS_Computer_Name:\s*([^\r\n]+)',
                r'NetBIOS_Computer_Name:\s*([^\r\n]+)',
                r'commonName=([^\s\r\n]+)',
                r'Target_Name:\s*([^\r\n]+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    info['hostname'] = match.group(1).strip()
                    break
                
            mac_match = re.search(r'MAC Address:\s*([0-9A-Fa-f:]{17})', output)
            if mac_match:
                info['mac'] = mac_match.group(1)
        except subprocess.TimeoutExpired:
            print(f"  deep_scan этап1 таймаут для {ip}")
        except Exception as e:
            print(f"  deep_scan этап1 ошибка для {ip}: {e}")
        
        # Этап 2: SMB (445), если на 3389 ничего не нашли
        if 'hostname' not in info or not info.get('hostname'):
            try:
                cmd = f'"{nmap_exe}" -T4 -p 445 --script smb-os-discovery {ip}'
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=20)
                output = result.stdout.decode('cp1251', errors='replace')
                
                nb_match = re.search(r'NetBIOS name:\s*([^\r\n]+)', output, re.IGNORECASE)
                if nb_match:
                    info['hostname'] = nb_match.group(1).strip()
                
                if 'mac' not in info or not info.get('mac'):
                    mac_match = re.search(r'MAC Address:\s*([0-9A-Fa-f:]{17})', output)
                    if mac_match:
                        info['mac'] = mac_match.group(1)
            except subprocess.TimeoutExpired:
                print(f"  deep_scan этап2 таймаут для {ip}")
            except Exception as e:
                print(f"  deep_scan этап2 ошибка для {ip}: {e}")
        
        if 'hostname' not in info or not info.get('hostname'):
            info['hostname'] = 'None'
        if 'mac' not in info or not info.get('mac'):
            info['mac'] = 'None'
        info['ping_ok'] = True
        return info
    
    def _extract_ports_info(self, nmap_output):
        """Извлекает информацию о портах из вывода nmap"""
        lines = nmap_output.split('\n')
        port_lines = []
        capture = False
        for line in lines:
            if re.match(r'^PORT\s+STATE\s+SERVICE', line):
                capture = True
                continue
            if capture and ('MAC Address' in line or 'Nmap done' in line or 'Service detection' in line):
                capture = False
            if capture and line.strip():
                port_lines.append(line.rstrip())
        return '\n'.join(port_lines) if port_lines else ''
            
    def _get_email_settings(self):
        """Получить настройки email из базы"""
        settings = db.get_email_settings()
        if not settings:
            return None
        
        return {
            'smtp_server': settings.get('smtp_server', ''),
            'smtp_port': settings.get('smtp_port', 587),
            'login': settings.get('login', ''),
            'password': settings.get('password', ''),
            'from_address': settings.get('from_address', ''),
            'use_tls': settings.get('use_tls', 1),
            'enable_notifications': settings.get('enable_notifications', 1)
        }
    
    def _send_email(self, tema, text_mail, email):
        """Отправка email (максимально близко к рабочему оригиналу)"""
        email_settings = self._get_email_settings()
        
        # Проверка: включены ли уведомления
        if not email_settings or not email_settings.get('enable_notifications'):
            self._log("Уведомления отключены в настройках")
            return
        
        # Проверка: заполнены ли настройки
        if not email_settings.get('smtp_server') or not email_settings.get('login') or not email_settings.get('password'):
            self._log("Настройки SMTP не заполнены (База → Настройки)")
            return
        
        # Разбираем сервер - если указан с портом в одном поле
        smtp_server = email_settings['smtp_server'].strip()
        smtp_port = email_settings['smtp_port']
        
        # Если сервер указан как "server:port" или "server port"
        if ':' in smtp_server and smtp_server.count(':') == 1:
            parts = smtp_server.split(':')
            smtp_server = parts[0].strip()
            try:
                smtp_port = int(parts[1].strip())
            except:
                pass
        elif ' ' in smtp_server:
            parts = smtp_server.split()
            smtp_server = parts[0].strip()
            try:
                smtp_port = int(parts[1].strip())
            except:
                pass
        
        max_retries = 3
        retry_delay = 10  # увеличил задержку
        
        for attempt in range(max_retries):
            try:
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText
                
                password = email_settings['password']
                from_address = email_settings['from_address'] or email_settings['login']
                
                # Формируем сообщение как в оригинальном рабочем коде
                msg = MIMEMultipart()
                msg['From'] = from_address
                msg['To'] = email
                msg['Subject'] = tema
                
                # Формат сообщения как в оригинале
                message = f"From: {from_address}\nTo: {email}\nSubject: {tema}\n\n{text_mail}"
                msg.attach(MIMEText(message, 'plain'))
                
                # Подключение к серверу
                if attempt > 0:
                    self._log(f"Повторная попытка {attempt+1}/{max_retries}...")
                
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
                server.starttls()
                server.login(email_settings['login'], password)
                server.sendmail(msg['From'], msg['To'], message.encode())
                server.quit()
                
                now = datetime.now()
                rounded_time = now.strftime("%Y-%m-%d %H:%M")
                self._log(f"{rounded_time} - отправил письмо на {email}")
                
                # Запись в историю
                db.add_history_entry(f"{tema}: {text_mail}")
                
                return  # Успех
                
            except smtplib.SMTPAuthenticationError:
                self._log(f'Ошибка авторизации SMTP. Проверьте логин/пароль в настройках')
                return  # Нет смысла повторять
            except smtplib.SMTPRecipientsRefused as e:
                # Ошибка получателя -可能是服务器临时问题
                error_info = str(e)
                if '451' in error_info or 'Temporary' in error_info:
                    self._log(f'Сервер временно недоступен (451). Повтор через {retry_delay} сек...')
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    continue
                else:
                    self._log(f'Получатель отклонён: {e}')
                    return
            except smtplib.SMTPConnectError as e:
                self._log(f'Ошибка подключения к SMTP серверу: {e}')
                if attempt < max_retries - 1:
                    self._log(f"Повтор через {retry_delay} сек...")
                    time.sleep(retry_delay)
            except socket.gaierror as e:
                # Ошибка DNS (getaddrinfo failed) - errno 11001
                error_msg = str(e)
                if '11001' in error_msg or 'getaddrinfo' in error_msg:
                    self._log(f'Ошибка DNS: не удалось разрешить имя сервера "{smtp_server}"')
                    # Показываем уведомление только при первой ошибке
                    if attempt == 0:
                        QMessageBox.warning(
                            self,
                            "Ошибка DNS",
                            f"Не удалось подключиться к SMTP-серверу.\n\n"
                            f"Сервер: {smtp_server}\n\n"
                            f"Ошибка: имя сервера не разрешается (DNS error).\n\n"
                            f"Проверьте настройки SMTP (База → Настройки Email) или отключите уведомления."
                        )
                else:
                    self._log(f'Ошибка DNS (getaddrinfo failed): {smtp_server}')
                if attempt < max_retries - 1:
                    self._log(f"Повтор через {retry_delay} сек...")
                    time.sleep(retry_delay)
            except smtplib.SMTPServerDisconnected as e:
                self._log(f'Сервер разорвал соединение: {e}')
                if attempt < max_retries - 1:
                    self._log(f"Повтор через {retry_delay} сек...")
                    time.sleep(retry_delay)
            except Exception as e:
                self._log(f'Ошибка при отправке письма: {e}')
                if attempt < max_retries - 1:
                    self._log(f"Повтор через {retry_delay} сек...")
                    time.sleep(retry_delay)
        
        self._log(f"Не удалось отправить письмо после {max_retries} попыток")
    
    def _scan_network(self):
        """Сканирование сети и возврат словаря устройств"""
        path = self.nmap_dir_edit.text()
        now = datetime.now()
        rounded_time = now.strftime("%Y-%m-%d %H:%M")
        
        if path and os.path.exists(path):
            self._log(f"{rounded_time} - Путь существует {path}")
        else:
            self.status_textedit.clear()
            text = "Указан неверный путь к NMAP! Сканирование отменено."
            self.status_textedit.append(text)
            return None
        
        now = datetime.now()
        rounded_time = now.strftime("%Y-%m-%d %H:%M")
        self._log(f"{rounded_time} - Приступаю к сканированию")
        
        # Получаем команду для сканирования
        command = self._get_scan_command(path)
        if not command:
            self.status_textedit.clear()
            text = "Некорректная маска сети! Сканирование отменено."
            self.status_textedit.append(text)
            return None
        
        result = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        output_text = result.stdout.decode('cp1251')
        
        ip_mac_hostname_dict = {}
        lines = output_text.split('\n')
    
        for i in range(len(lines)):
            line = lines[i]
            if 'Nmap scan report' in line:
                ip_address_str = line.split()[-1]
                if '(' in ip_address_str:
                    ip_address_str = ip_address_str.replace('(', '')
                if ')' in ip_address_str:
                    ip_address_str = ip_address_str.replace(')', '')
                hostname_match = re.search(r'Nmap scan report for (.*) \(', line)
                hostname = hostname_match.group(1).strip() if hostname_match else ''
                ip_mac_hostname_dict[ip_address_str] = {
                    'hostname': hostname if hostname else 'None',
                    'mac': 'None'
                }
            elif 'MAC Address' in line:
                mac_address = re.search(r'(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)\b', line).group(0)
                ip_mac_hostname_dict[ip_address_str]['mac'] = mac_address
        
        # Получаем диапазон IP
        start_ip = self.start_ip_edit.text().strip() or None
        end_ip = self.end_ip_edit.text().strip() or None
        
        # Дополнительное сканирование
        self._log("Поиск устройств с неполными данными...")
        for ip, data in list(ip_mac_hostname_dict.items()):
            if start_ip and end_ip:
                if not self._ip_in_range(ip, start_ip, end_ip):
                    self._log(f"  {ip} вне диапазона {start_ip}-{end_ip}, удаляем")
                    del ip_mac_hostname_dict[ip]
                    continue
            
            need_deep = False
            if 'mac' not in data or not data.get('mac'):
                need_deep = True
            if not data.get('hostname') or data['hostname'] == 'None':
                need_deep = True
            if need_deep:
                self._log(f"Детальное сканирование {ip}...")
                deep_info = self.deep_scan_ip(ip, path)
                if deep_info:
                    if deep_info.get('ping_ok') == False:
                        self._log(f"  {ip} недоступен, удаляем")
                        del ip_mac_hostname_dict[ip]
                        continue
                    
                    if 'mac' in deep_info and deep_info['mac'] and deep_info['mac'] != 'None':
                        ip_mac_hostname_dict[ip]['mac'] = deep_info['mac']
                    if 'hostname' in deep_info and deep_info['hostname'] and deep_info['hostname'] != 'None':
                        if not ip_mac_hostname_dict[ip].get('hostname') or ip_mac_hostname_dict[ip].get('hostname') == 'None':
                            ip_mac_hostname_dict[ip]['hostname'] = deep_info['hostname']
                        elif deep_info['hostname'] != ip_mac_hostname_dict[ip]['hostname']:
                            ip_mac_hostname_dict[ip]['hostname'] = deep_info['hostname']
                    if 'ports_info' in deep_info and deep_info['ports_info']:
                        ip_mac_hostname_dict[ip]['ports_info'] = deep_info['ports_info']
        
        # Нормализация
        for ip, data in list(ip_mac_hostname_dict.items()):
            if not data.get('mac') or data['mac'] == '' or data['mac'] is None:
                data['mac'] = 'None'
            if not data.get('hostname') or data['hostname'] == '' or data['hostname'] is None:
                data['hostname'] = 'None'
        
        return ip_mac_hostname_dict
    
    def _compare_and_notify(self, ip_mac_hostname_dict):
        """Сравнение устройств с базой и отправка уведомлений"""
        # Загружаем устройства из базы
        devices = db.get_all_devices()
        stored_ips_macs_hostnames = {}
        spisok_mac = []
        spisok_hostname = []
        
        for device in devices:
            ip = device['ip']
            mac = device['mac'] or 'None'
            hostname = device['hostname'] or 'None'
            stored_ips_macs_hostnames[ip] = {'mac': mac, 'hostname': hostname}
            spisok_mac.append(mac)
            spisok_hostname.append(hostname)
        
        # Исключённые MAC
        excluded_macs = db.get_excluded_macs()
        
        for ip, data in ip_mac_hostname_dict.items():
            # Нормализация (БЕЗ capitalize - сохраняем оригинальный регистр)
            if data['hostname'] == None or data['hostname'] == '':
                data['hostname'] = 'None'
            elif len(data['hostname']) < 2:
                data['hostname'] = 'None'
            # Убрал: data['hostname'] = data['hostname'].capitalize()
            
            if data['mac'] == None or data['mac'] == '':
                data['mac'] = 'None'
            elif len(data['mac']) < 2:
                data['mac'] = 'None'
            
            # Пропуск исключённых
            if data['mac'] in excluded_macs:
                self._log(f'Пропускаем {ip} {data}')
                continue
            
            emails = self.email_edit.text()
            email_list = [e.strip() for e in emails.split(",") if e.strip()]
            
            if ip not in stored_ips_macs_hostnames:
                # Новое устройство
                if str(data['mac']) != 'None' and str(data['mac']) in spisok_mac:
                    existing_ips = [ip_h for ip_h, d in stored_ips_macs_hostnames.items() if d.get('mac') == data['mac']]
                    self._log(f"  {ip} — MAC {data['mac']} уже известен для: {', '.join(existing_ips)} (второе IP)")
                elif str(data['hostname']) != 'None' and str(data['hostname']) in spisok_hostname:
                    for ip_host, data_host in stored_ips_macs_hostnames.items():
                        # Сравниваем БЕЗ учёта регистра
                        if data_host['hostname'].lower() == data['hostname'].lower():
                            ip_changed = (ip != ip_host)
                            mac_changed = (data.get('mac', '') != data_host['mac'])
                            
                            if ip_changed and mac_changed:
                                s1 = f"Устройство {data['hostname']} сменило IP и MAC.\nСтарые: IP - {ip_host}, MAC - {data_host['mac']}\nНовые: IP - {ip}, MAC - {data.get('mac', '')}"
                                tema = f"Устройство {data['hostname']} сменило IP и MAC"
                            elif ip_changed:
                                s1 = f"Устройство {data['hostname']} сменило IP.\nСтарый: {ip_host}\nНовый: {ip}"
                                tema = f"Устройство {data['hostname']} сменило IP"
                            elif mac_changed:
                                s1 = f"Устройство {data['hostname']} сменило MAC.\nСтарый: {data_host['mac']}\nНовый: {data.get('mac', '')}"
                                tema = f"Устройство {data['hostname']} сменило MAC"
                            else:
                                continue
                            
                            for email in email_list:
                                self._send_email(tema, s1, email)
                            db.add_history_entry(s1)
                else:
                    s1 = f"Новое устройство: IP - {ip}, MAC - {data.get('mac', '')}, Hostname - {data.get('hostname', '')}"
                    if data.get('mac', '') == 'None' and data.get('hostname', '') == 'None' and data.get('ports_info'):
                        s1 += f"\r\n\r\nПорты:\r\n{data['ports_info']}"
                    for email in email_list:
                        self._send_email('Новое устройство обнаружено', s1, email)
                    db.add_history_entry(s1)
            else:
                stored_data = stored_ips_macs_hostnames[ip]
                if data['mac'] != stored_data.get('mac', ''):
                    if stored_data.get('mac', '') in excluded_macs:
                        self._log(f'Пропускаем {ip} {data}')
                    else:
                        s2 = f"MAC устройства {ip} изменился: {stored_data.get('mac', '')} -> {data['mac']}"
                        for email in email_list:
                            self._send_email(f'MAC устройства {ip} изменился', s2, email)
                        db.add_history_entry(s2)
                
                # Сравниваем hostname БЕЗ учёта регистра
                if data['hostname'].lower() != stored_data.get('hostname', '').lower():
                    ggg = True
                    # Проверка на .krasmed.ru (без учёта регистра)
                    hostname_lower = data['hostname'].lower()
                    stored_lower = stored_data.get('hostname', '').lower()
                    
                    if '.krasmed.ru' in hostname_lower:
                        if hostname_lower.replace('.krasmed.ru', '') == stored_lower:
                            ggg = False
                    elif '.krasmed.ru' in stored_lower:
                        if stored_lower.replace('.krasmed.ru', '') == hostname_lower:
                            ggg = False
                    if ggg:
                        s3 = f"Hostname устройства {ip} ({data['mac']}) изменился: {stored_data.get('hostname', '')} -> {data['hostname']}"
                        for email in email_list:
                            self._send_email(f'Hostname устройства {ip} изменился', s3, email)
                        db.add_history_entry(s3)
    
    def start_scan(self):
        """Сканирование сети"""
        # Проверка входных данных
        if not self._validate_scan_inputs():
            return
        
        # Сохраняем настройки
        self._save_settings()
        
        # Обновляем состояние кнопок
        self.scan_running = True
        self.stop_requested = False
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Запускаем сканирование
        self._run_scan_cycle()
    
    def _run_scan_cycle(self):
        """Один цикл сканирования"""
        if self.stop_requested:
            self.scan_running = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
        
        now = datetime.now()
        rounded_time = now.strftime("%Y-%m-%d %H:%M")
        self.status_textedit.clear()
        self._log(f'Запускаю поиск {rounded_time}')
        
        # Сканирование
        new_devices = self._scan_network()
        
        if new_devices and not self.stop_requested:
            # Отправляем уведомления (старая функция)
            self._compare_and_notify(new_devices)
            
            # Логируем количество обнаруженных устройств (только если не зациклено)
            if not self.cbZacilit.isChecked():
                self._log(f"Обнаружено устройств: {len(new_devices)}")
            
            # Если НЕ зациклено - показываем результаты и сохраняем
            if not self.cbZacilit.isChecked():
                # Сравниваем с базой и определяем статус
                scan_results = self._compare_with_base(new_devices)
                
                # Фильтруем только новые и изменённые и second_ip
                filtered_results = {
                    ip: data for ip, data in scan_results.items()
                    if data.get('status') in ('new', 'changed', 'second_ip')
                }
                
                if filtered_results:
                    # Открываем окно результатов
                    from PyQt5.QtCore import QTimer
                    QTimer.singleShot(0, lambda: self._show_scan_results(filtered_results))
                else:
                    self._log("Изменений не обнаружено")
                
                # Завершаем
                self.scan_running = False
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
            else:
                # Зацикленный режим - только лог
                self._log(f"Обнаружено устройств: {len(new_devices)}")
                
                # Планируем следующий цикл
                delay = int(self.delay_edit.text() or '14400')
                self._log(f"Пауза {delay} сек...")
                
                # Используем QTimer для задержки (безопасно для UI)
                from PyQt5.QtCore import QTimer
                self._next_scan_timer = QTimer(self)
                self._next_scan_timer.setSingleShot(True)
                self._next_scan_timer.timeout.connect(self._run_scan_cycle)
                self._next_scan_timer.start(delay * 1000)  # мс
        else:
            # Завершаем
            self.scan_running = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
        
        if not self.cbZacilit.isChecked():
            now = datetime.now()
            rounded_time = now.strftime("%Y-%m-%d %H:%M")
            self._log(f"{rounded_time} - Поиск завершён")
    
    def _compare_with_base(self, new_devices):
        """Сравнение новых устройств с базой и определение статуса"""
        # Загружаем устройства из базы
        devices = db.get_all_devices()
        stored_ips_macs_hostnames = {}
        spisok_mac = []
        spisok_hostname = []
        
        for device in devices:
            ip = device['ip']
            mac = device['mac'] or 'None'
            hostname = device['hostname'] or 'None'
            stored_ips_macs_hostnames[ip] = {'mac': mac, 'hostname': hostname}
            spisok_mac.append(mac)
            spisok_hostname.append(hostname)
        
        # Исключённые MAC
        excluded_macs = db.get_excluded_macs()
        
        scan_results = {}
        
        for ip, data in new_devices.items():
            # Пропуск исключённых
            if data['mac'] in excluded_macs:
                self._log(f'Пропускаем {ip} (исключён)')
                continue
            
            status = 'unchanged'
            old_data = {}
            
            if ip not in stored_ips_macs_hostnames:
                # Новое устройство или второе IP
                if str(data['mac']) != 'None' and str(data['mac']) in spisok_mac:
                    # Второе IP известного устройства
                    existing_ips = [ip_h for ip_h, d in stored_ips_macs_hostnames.items() if d.get('mac') == data['mac']]
                    self._log(f"  {ip} — MAC {data['mac']} уже известен для: {', '.join(existing_ips)} (второе IP)")
                    status = 'second_ip'
                    old_data = stored_ips_macs_hostnames.get(existing_ips[0], {})
                elif str(data['hostname']) != 'None' and str(data['hostname']) in spisok_hostname:
                    # Устройство сменило IP/MAC (сравниваем без учёта регистра)
                    status = 'changed'
                    for ip_host, data_host in stored_ips_macs_hostnames.items():
                        if data_host['hostname'].lower() == data['hostname'].lower():
                            old_data = data_host
                            break
                else:
                    # Полностью новое устройство
                    status = 'new'
            else:
                # Устройство существует - проверяем изменения (сравниваем без учёта регистра)
                stored_data = stored_ips_macs_hostnames[ip]
                mac_changed = data['mac'] != stored_data.get('mac', '')
                hostname_changed = data['hostname'].lower() != stored_data.get('hostname', '').lower()
                
                if mac_changed or hostname_changed:
                    status = 'changed'
                    old_data = stored_data
            
            scan_results[ip] = {
                'mac': data['mac'],
                'hostname': data['hostname'],
                'ports_info': data.get('ports_info', ''),
                'comment': '',
                'status': status,
                'old_data': old_data
            }
        
        return scan_results
    
    def _show_scan_results(self, scan_results):
        """Показать окно результатов сканирования"""
        dialog = ScanResultsDialog(self, scan_results)
        dialog.exec_()
    
    def stop_scan(self):
        """Остановка сканирования"""
        if self.scan_running:
            self.stop_requested = True
            self._log("Запрошена остановка сканирования...")
            
            # Отменяем таймер если есть
            if hasattr(self, '_next_scan_timer'):
                self._next_scan_timer.stop()
            
            self.scan_running = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
        else:
            self._log("Сканирование не запущено")


window = MyWindow()
window.show()

sys.exit(app.exec_())
