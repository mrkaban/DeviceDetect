# -*- coding: utf-8 -*-
"""
Окно просмотра и редактирования базы устройств
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QHeaderView, QMessageBox, QAbstractItemView, QLabel,
                             QLineEdit, QFileDialog, QCheckBox, QGroupBox, QButtonGroup, QRadioButton,
                             QApplication)
from PySide6.QtCore import Qt
import database as db
import csv
import os


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
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname", "Порты", "Комментарий", "Создан", "Обновлён", "Коммутатор", "Шлюз"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeToContents)
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
        
        self.btn_export = QPushButton("Экспорт...")
        self.btn_export.clicked.connect(self.export_devices)
        btn_layout.addWidget(self.btn_export)
        
        self.btn_network_map = QPushButton("Карта сети")
        self.btn_network_map.clicked.connect(self.show_network_map)
        btn_layout.addWidget(self.btn_network_map)
        
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
            is_switch = device.get('is_switch', 0) or 0
            is_gateway = device.get('is_gateway', 0) or 0
            
            self.original_data[ip] = {
                'mac': mac,
                'hostname': hostname,
                'ports': ports,
                'comment': comment,
                'is_switch': is_switch,
                'is_gateway': is_gateway
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
            
            # Коммутатор (чекбокс)
            item_switch = QTableWidgetItem()
            item_switch.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            item_switch.setCheckState(Qt.Checked if is_switch else Qt.Unchecked)
            self.table.setItem(row, 7, item_switch)
            
            # Шлюз (чекбокс)
            item_gateway = QTableWidgetItem()
            item_gateway.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            item_gateway.setCheckState(Qt.Checked if is_gateway else Qt.Unchecked)
            self.table.setItem(row, 8, item_gateway)
        
        # Включаем сигнал обратно
        self.table.itemChanged.connect(self.on_item_changed)
        
        self.update_status()
    
    def filter_devices(self):
        """Фильтрация устройств по поисковому запросу"""
        search_text = self.search_edit.text().strip().lower()
        
        # Отключаем сигнал itemChanged на время обновления таблицы
        try:
            self.table.itemChanged.disconnect(self.on_item_changed)
        except TypeError:
            pass
        
        if not search_text:
            # Показать все устройства из self.all_devices
            self.table.setRowCount(len(self.all_devices))
            self.original_data = {}
            self.modified_rows = set()  # Сбрасываем изменённые строки, так как отображаем все заново
            for row, device in enumerate(self.all_devices):
                if hasattr(device, 'keys'):
                    device = dict(device)
                
                ip = device['ip']
                mac = device['mac'] or 'None'
                hostname = device['hostname'] or 'None'
                ports = device.get('ports', '') or ''
                comment = device['comment'] or ''
                created_at = device['created_at'] or ''
                updated_at = device['updated_at'] or ''
                is_switch = device.get('is_switch', 0) or 0
                is_gateway = device.get('is_gateway', 0) or 0
                
                self.original_data[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'ports': ports,
                    'comment': comment,
                    'is_switch': is_switch,
                    'is_gateway': is_gateway
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
                
                # Коммутатор (чекбокс)
                item_switch = QTableWidgetItem()
                item_switch.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
                item_switch.setCheckState(Qt.Checked if is_switch else Qt.Unchecked)
                self.table.setItem(row, 7, item_switch)
                
                # Шлюз (чекбокс)
                item_gateway = QTableWidgetItem()
                item_gateway.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
                item_gateway.setCheckState(Qt.Checked if is_gateway else Qt.Unchecked)
                self.table.setItem(row, 8, item_gateway)
        else:
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
            self.modified_rows = set()  # Сбрасываем изменённые строки, так как отображаем отфильтрованные
            
            for row, device in enumerate(filtered):
                ip = device['ip']
                mac = device['mac'] or 'None'
                hostname = device['hostname'] or 'None'
                ports = device.get('ports', '') or ''
                comment = device['comment'] or ''
                created_at = device['created_at'] or ''
                updated_at = device['updated_at'] or ''
                is_switch = device.get('is_switch', 0) or 0
                is_gateway = device.get('is_gateway', 0) or 0
                
                self.original_data[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'ports': ports,
                    'comment': comment,
                    'is_switch': is_switch,
                    'is_gateway': is_gateway
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
                
                # Коммутатор (чекбокс)
                item_switch = QTableWidgetItem()
                item_switch.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
                item_switch.setCheckState(Qt.Checked if is_switch else Qt.Unchecked)
                self.table.setItem(row, 7, item_switch)
                
                # Шлюз (чекбокс)
                item_gateway = QTableWidgetItem()
                item_gateway.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
                item_gateway.setCheckState(Qt.Checked if is_gateway else Qt.Unchecked)
                self.table.setItem(row, 8, item_gateway)
        
        # Включаем сигнал обратно
        self.table.itemChanged.connect(self.on_item_changed)
        self.update_status()
    
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
        
        # Пустые поля для всех 9 колонок
        for col in range(9):
            self.table.setItem(row, col, QTableWidgetItem(""))
        
        # IP должно быть заполнено
        self.table.setItem(row, 0, QTableWidgetItem("0.0.0.0"))
        self.table.setItem(row, 1, QTableWidgetItem("None"))
        self.table.setItem(row, 2, QTableWidgetItem("None"))
        self.table.setItem(row, 3, QTableWidgetItem(""))  # ports
        self.table.setItem(row, 4, QTableWidgetItem(""))  # comment
        self.table.setItem(row, 5, QTableWidgetItem(""))  # created (пусто)
        self.table.setItem(row, 6, QTableWidgetItem(""))  # updated (пусто)
        
        # Коммутатор (чекбокс выключен)
        item_switch = QTableWidgetItem()
        item_switch.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        item_switch.setCheckState(Qt.Unchecked)
        self.table.setItem(row, 7, item_switch)
        
        # Шлюз (чекбокс выключен)
        item_gateway = QTableWidgetItem()
        item_gateway.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        item_gateway.setCheckState(Qt.Unchecked)
        self.table.setItem(row, 8, item_gateway)
        
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
        
        # Проходим по всем строкам таблицы
        for row in range(self.table.rowCount()):
            ip_item = self.table.item(row, 0)
            if not ip_item or not ip_item.text():
                continue
            
            ip = ip_item.text()
            mac_item = self.table.item(row, 1)
            hostname_item = self.table.item(row, 2)
            ports_item = self.table.item(row, 3)
            comment_item = self.table.item(row, 4)
            switch_item = self.table.item(row, 7)
            gateway_item = self.table.item(row, 8)
            
            mac = mac_item.text() if mac_item else 'None'
            hostname = hostname_item.text() if hostname_item else 'None'
            ports = ports_item.text() if ports_item else ''
            comment = comment_item.text() if comment_item else ''
            is_switch = 1 if (switch_item and switch_item.checkState() == Qt.Checked) else 0
            is_gateway = 1 if (gateway_item and gateway_item.checkState() == Qt.Checked) else 0
            
            # Проверяем, изменились ли данные по сравнению с оригинальными
            original = self.original_data.get(ip)
            if original:
                if (original['mac'] == mac and original['hostname'] == hostname and
                    original['ports'] == ports and original['comment'] == comment and
                    original.get('is_switch', 0) == is_switch and original.get('is_gateway', 0) == is_gateway):
                    continue  # Нет изменений
            else:
                # Новое устройство (добавленное через кнопку Добавить)
                pass
            
            try:
                if ip in self.original_data:
                    # Обновление существующего
                    db.update_device(ip, mac, hostname, ports, comment, is_switch, is_gateway)
                else:
                    # Добавление нового
                    db.add_device(ip, mac, hostname, ports, comment, is_switch, is_gateway)
                saved_count += 1
            except Exception as e:
                error_count += 1
                print(f"Ошибка сохранения {ip}: {e}")
            
            # Обработка событий UI после каждого устройства, чтобы окно не зависало
            QApplication.processEvents()
        
        if saved_count == 0 and error_count == 0:
            QMessageBox.information(self, "Готово", "Нет изменений для сохранения")
        elif error_count == 0:
            QMessageBox.information(self, "Готово", f"Сохранено {saved_count} устройств")
            # Обновляем original_data и очищаем modified_rows
            self.load_devices()  # Перезагрузить для обновления timestamps и синхронизации
        else:
            QMessageBox.warning(self, "Ошибка", f"Сохранено: {saved_count}, Ошибок: {error_count}")
        
        self.update_status()
    
    def show_network_map(self):
        """Показать диалог создания карты сети"""
        # Импортируем здесь, чтобы избежать циклических зависимостей
        try:
            from network_map import NetworkMapDialog
            dialog = NetworkMapDialog(self)
            dialog.exec_()
        except ImportError:
            QMessageBox.information(self, "В разработке", "Функция карты сети находится в разработке.")
    
    def export_devices(self):
        """Экспорт устройств в файл"""
        # Диалог выбора полей и формата
        dialog = QDialog(self)
        dialog.setWindowTitle("Экспорт устройств")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout()
        
        # Группа выбора полей
        fields_group = QGroupBox("Выберите поля для экспорта")
        fields_layout = QVBoxLayout()
        self.export_checkboxes = {}
        fields = [
            ("IP", True),
            ("MAC", True),
            ("Hostname", True),
            ("Порты", True),
            ("Комментарий", True),
            ("Создан", False),
            ("Обновлён", False)
        ]
        for field_name, default_checked in fields:
            cb = QCheckBox(field_name)
            cb.setChecked(default_checked)
            fields_layout.addWidget(cb)
            self.export_checkboxes[field_name] = cb
        fields_group.setLayout(fields_layout)
        layout.addWidget(fields_group)
        
        # Группа выбора формата
        format_group = QGroupBox("Формат экспорта")
        format_layout = QVBoxLayout()
        self.format_xlsx = QRadioButton("Excel (.xlsx)")
        self.format_txt = QRadioButton("Текстовый файл (.txt)")
        self.format_csv = QRadioButton("CSV (.csv)")
        self.format_xlsx.setChecked(True)
        format_layout.addWidget(self.format_xlsx)
        format_layout.addWidget(self.format_txt)
        format_layout.addWidget(self.format_csv)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)
        
        # Кнопки
        btn_layout = QHBoxLayout()
        btn_ok = QPushButton("Экспорт")
        btn_ok.clicked.connect(lambda: self.do_export(dialog))
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(dialog.reject)
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def do_export(self, dialog):
        """Выполнить экспорт с выбранными параметрами"""
        # Определяем выбранные поля
        field_order = ["IP", "MAC", "Hostname", "Порты", "Комментарий", "Создан", "Обновлён"]
        selected_fields = []
        for field in field_order:
            if self.export_checkboxes[field].isChecked():
                selected_fields.append(field)
        
        if not selected_fields:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного поля для экспорта")
            return
        
        # Определяем формат
        if self.format_xlsx.isChecked():
            file_filter = "Excel files (*.xlsx)"
            default_ext = ".xlsx"
        elif self.format_txt.isChecked():
            file_filter = "Text files (*.txt)"
            default_ext = ".txt"
        else:
            file_filter = "CSV files (*.csv)"
            default_ext = ".csv"
        
        # Выбор файла
        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить файл", "",
            f"{file_filter};;All files (*.*)",
            options=QFileDialog.Options()
        )
        if not filename:
            return
        
        # Добавляем расширение, если отсутствует
        if not filename.endswith(default_ext):
            filename += default_ext
        
        # Собираем данные из таблицы (все строки, включая отфильтрованные)
        data = []
        for row in range(self.table.rowCount()):
            row_data = {}
            for col, field in enumerate(field_order):
                item = self.table.item(row, col)
                row_data[field] = item.text() if item else ""
            data.append(row_data)
        
        # Экспорт
        try:
            if self.format_xlsx.isChecked():
                self.export_to_xlsx(filename, selected_fields, data)
            elif self.format_txt.isChecked():
                self.export_to_txt(filename, selected_fields, data)
            else:
                self.export_to_csv(filename, selected_fields, data)
            QMessageBox.information(self, "Готово", f"Данные экспортированы в {filename}")
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка экспорта: {str(e)}")
    
    def export_to_xlsx(self, filename, fields, data):
        """Экспорт в Excel (xlsx)"""
        try:
            import openpyxl
            from openpyxl import Workbook
        except ImportError:
            QMessageBox.critical(self, "Ошибка",
                "Модуль openpyxl не установлен. Установите его командой: pip install openpyxl")
            raise
        
        wb = Workbook()
        ws = wb.active
        ws.title = "Устройства"
        
        # Заголовки
        for col, field in enumerate(fields, start=1):
            ws.cell(row=1, column=col, value=field)
        
        # Данные
        for row_idx, row_data in enumerate(data, start=2):
            for col_idx, field in enumerate(fields, start=1):
                ws.cell(row=row_idx, column=col_idx, value=row_data.get(field, ""))
        
        wb.save(filename)
    
    def export_to_txt(self, filename, fields, data):
        """Экспорт в текстовый файл (построчный)"""
        with open(filename, 'w', encoding='utf-8') as f:
            # Заголовки
            f.write("\t".join(fields) + "\n")
            # Данные
            for row_data in data:
                line = "\t".join(str(row_data.get(field, "")) for field in fields)
                f.write(line + "\n")
    
    def export_to_csv(self, filename, fields, data):
        """Экспорт в CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(fields)
            for row_data in data:
                writer.writerow([row_data.get(field, "") for field in fields])
    
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
