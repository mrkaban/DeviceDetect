# -*- coding: utf-8 -*-
"""
Окно просмотра и редактирования базы устройств
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QHeaderView, QMessageBox, QAbstractItemView, QLabel,
                             QLineEdit, QFileDialog)
from PyQt5.QtCore import Qt
import database as db


class DeviceViewerDialog(QDialog):
    """Окно просмотра и редактирования устройств"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Просмотр устройств")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)
        
        # Хранилище для отслеживания изменений
        self.original_data = {}  # ip -> {mac, hostname, comment}
        self.modified_rows = set()  # номера изменённых строк
        self.all_devices = []  # все устройства для фильтрации
        
        self.init_ui()
        self.load_devices()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Заголовок
        header_label = QLabel("База устройств (редактирование)")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 5px;")
        layout.addWidget(header_label)
        
        # Поиск
        search_layout = QHBoxLayout()
        search_label = QLabel("Поиск:")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Введите IP, MAC, hostname или комментарий...")
        self.search_edit.textChanged.connect(self.filter_devices)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        layout.addLayout(search_layout)
        
        # Таблица
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname", "Порты", "Комментарий", "Создан", "Обновлён"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemChanged.connect(self.on_item_changed)
        layout.addWidget(self.table)
        
        # Статус бар
        self.status_label = QLabel("Готово")
        self.status_label.setStyleSheet("padding: 5px; background-color: #f0f0f0;")
        layout.addWidget(self.status_label)
        
        # Кнопки
        btn_layout = QHBoxLayout()
        
        self.btn_add = QPushButton("Добавить")
        self.btn_add.clicked.connect(self.add_device)
        btn_layout.addWidget(self.btn_add)
        
        self.btn_delete = QPushButton("Удалить выбранные")
        self.btn_delete.clicked.connect(self.delete_selected)
        btn_layout.addWidget(self.btn_delete)
        
        btn_layout.addStretch()
        
        self.btn_save = QPushButton("Сохранить изменения")
        self.btn_save.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px 16px;")
        self.btn_save.clicked.connect(self.save_changes)
        btn_layout.addWidget(self.btn_save)
        
        self.btn_reload = QPushButton("Обновить")
        self.btn_reload.clicked.connect(self.load_devices)
        btn_layout.addWidget(self.btn_reload)
        
        self.btn_close = QPushButton("Закрыть")
        self.btn_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
    
    def load_devices(self):
        """Загрузить устройства из базы"""
        # Отключаем сигнал itemChanged на время загрузки
        try:
            self.table.itemChanged.disconnect(self.on_item_changed)
        except TypeError:
            pass  # Сигнал не был подключен
        
        devices = db.get_all_devices()
        self.all_devices = devices  # Сохраняем для фильтрации
        self.table.setRowCount(len(devices))
        self.original_data = {}
        self.modified_rows = set()
        
        for row, device in enumerate(devices):
            # Преобразуем sqlite3.Row в dict
            if hasattr(device, 'keys'):
                device = dict(device)
            
            ip = device['ip']
            mac = device['mac'] or 'None'
            hostname = device['hostname'] or 'None'
            ports = device.get('ports', '') or ''  # Для старых баз без поля ports
            comment = device['comment'] or ''
            created_at = device['created_at'] or ''
            updated_at = device['updated_at'] or ''
            
            self.original_data[ip] = {
                'mac': mac,
                'hostname': hostname,
                'ports': ports,
                'comment': comment
            }
            
            # IP (не редактируется)
            item_ip = QTableWidgetItem(ip)
            item_ip.setFlags(item_ip.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 0, item_ip)
            
            # MAC
            item_mac = QTableWidgetItem(mac)
            self.table.setItem(row, 1, item_mac)
            
            # Hostname
            item_hostname = QTableWidgetItem(hostname)
            self.table.setItem(row, 2, item_hostname)
            
            # Порты
            item_ports = QTableWidgetItem(ports)
            self.table.setItem(row, 3, item_ports)
            
            # Комментарий
            item_comment = QTableWidgetItem(comment)
            self.table.setItem(row, 4, item_comment)
            
            # Создан
            item_created = QTableWidgetItem(created_at)
            item_created.setFlags(item_created.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 5, item_created)
            
            # Обновлён
            item_updated = QTableWidgetItem(updated_at)
            item_updated.setFlags(item_updated.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 6, item_updated)
        
        # Включаем сигнал обратно
        self.table.itemChanged.connect(self.on_item_changed)
        
        self.update_status()
    
    def filter_devices(self):
        """Фильтрация устройств по поисковому запросу"""
        search_text = self.search_edit.text().strip().lower()
        
        if not search_text:
            # Показать все
            self.table.setRowCount(len(self.all_devices))
            self.load_devices()
            return
        
        # Фильтруем
        filtered = []
        for device in self.all_devices:
            if hasattr(device, 'keys'):
                device = dict(device)
            
            # Ищем во всех полях
            if (search_text in device.get('ip', '').lower() or
                search_text in (device.get('mac') or '').lower() or
                search_text in (device.get('hostname') or '').lower() or
                search_text in (device.get('comment') or '').lower() or
                search_text in (device.get('ports') or '').lower()):
                filtered.append(device)
        
        # Обновляем таблицу
        self.table.setRowCount(len(filtered))
        self.original_data = {}
        self.modified_rows = set()
        
        for row, device in enumerate(filtered):
            ip = device['ip']
            mac = device['mac'] or 'None'
            hostname = device['hostname'] or 'None'
            ports = device.get('ports', '') or ''
            comment = device['comment'] or ''
            created_at = device['created_at'] or ''
            updated_at = device['updated_at'] or ''
            
            self.original_data[ip] = {
                'mac': mac,
                'hostname': hostname,
                'ports': ports,
                'comment': comment
            }
            
            item_ip = QTableWidgetItem(ip)
            item_ip.setFlags(item_ip.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 0, item_ip)
            
            item_mac = QTableWidgetItem(mac)
            self.table.setItem(row, 1, item_mac)
            
            item_hostname = QTableWidgetItem(hostname)
            self.table.setItem(row, 2, item_hostname)
            
            item_ports = QTableWidgetItem(ports)
            self.table.setItem(row, 3, item_ports)
            
            item_comment = QTableWidgetItem(comment)
            self.table.setItem(row, 4, item_comment)
            
            item_created = QTableWidgetItem(created_at)
            item_created.setFlags(item_created.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 5, item_created)
            
            item_updated = QTableWidgetItem(updated_at)
            item_updated.setFlags(item_updated.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 6, item_updated)
    
    def on_item_changed(self, item):
        """Обработка изменения ячейки"""
        row = item.row()
        self.modified_rows.add(row)
        # Проверяем существование ячейки перед обращением
        ip_item = self.table.item(row, 0)
        if ip_item:
            ip_item.setBackground(Qt.lightGray)
        self.update_status()
    
    def update_status(self):
        """Обновить статус бар"""
        count = len(self.modified_rows)
        if count > 0:
            self.status_label.setText(f"Изменений: {count} (требуется сохранение)")
            self.status_label.setStyleSheet("padding: 5px; background-color: #fff3cd;")
        else:
            self.status_label.setText("Готово")
            self.status_label.setStyleSheet("padding: 5px; background-color: #d4edda;")
    
    def add_device(self):
        """Добавить новое устройство"""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Пустые поля (7 колонок)
        for col in range(7):
            self.table.setItem(row, col, QTableWidgetItem(""))
        
        # IP должно быть заполнено
        self.table.setItem(row, 0, QTableWidgetItem("0.0.0.0"))
        self.table.setItem(row, 1, QTableWidgetItem("None"))
        self.table.setItem(row, 2, QTableWidgetItem("None"))
        self.table.setItem(row, 3, QTableWidgetItem(""))  # ports
        self.table.setItem(row, 4, QTableWidgetItem(""))  # comment
        self.table.setItem(row, 5, QTableWidgetItem(""))
        self.table.setItem(row, 6, QTableWidgetItem(""))
        
        self.modified_rows.add(row)
        self.table.setCurrentCell(row, 0)
        self.update_status()
    
    def delete_selected(self):
        """Удалить выбранные строки"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "Предупреждение", "Выберите строки для удаления")
            return
        
        reply = QMessageBox.question(self, "Подтверждение", 
                                     f"Удалить {len(selected_rows)} устройств(а)?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            # Собираем IP для удаления из базы
            ips_to_delete = []
            for row in sorted(selected_rows, reverse=True):
                ip_item = self.table.item(row, 0)
                if ip_item and ip_item.text():
                    ips_to_delete.append(ip_item.text())
                self.table.removeRow(row)
            
            # Удаляем из базы
            for ip in ips_to_delete:
                db.delete_device(ip)
            
            self.modified_rows.clear()
            self.update_status()
            QMessageBox.information(self, "Готово", f"Удалено {len(ips_to_delete)} устройств")
    
    def save_changes(self):
        """Сохранить изменения в базу"""
        saved_count = 0
        error_count = 0
        
        for row in self.modified_rows:
            ip_item = self.table.item(row, 0)
            if not ip_item or not ip_item.text():
                error_count += 1
                continue
            
            ip = ip_item.text()
            mac_item = self.table.item(row, 1)
            hostname_item = self.table.item(row, 2)
            ports_item = self.table.item(row, 3)
            comment_item = self.table.item(row, 4)
            
            mac = mac_item.text() if mac_item else 'None'
            hostname = hostname_item.text() if hostname_item else 'None'
            ports = ports_item.text() if ports_item else ''
            comment = comment_item.text() if comment_item else ''
            
            try:
                if ip in self.original_data:
                    # Обновление существующего
                    db.update_device(ip, mac, hostname, ports, comment)
                else:
                    # Добавление нового
                    db.add_device(ip, mac, hostname, ports, comment)
                saved_count += 1
            except Exception as e:
                error_count += 1
                print(f"Ошибка сохранения {ip}: {e}")
        
        if error_count == 0:
            QMessageBox.information(self, "Готово", f"Сохранено {saved_count} устройств")
            self.modified_rows.clear()
            self.load_devices()  # Перезагрузить для обновления timestamps
        else:
            QMessageBox.warning(self, "Ошибка", f"Сохранено: {saved_count}, Ошибок: {error_count}")
        
        self.update_status()
    
    def closeEvent(self, event):
        """Обработка закрытия окна"""
        if self.modified_rows:
            reply = QMessageBox.question(self, "Подтверждение",
                                         "Есть несохранённые изменения. Закрыть?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
        event.accept()
