# -*- coding: utf-8 -*-
"""
Окно результатов сканирования - показывает только новые и изменённые устройства
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QHeaderView, QMessageBox, QAbstractItemView, QLabel,
                             QGroupBox, QFormLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
import database as db


class ScanResultsDialog(QDialog):
    """Окно результатов сканирования"""
    
    def __init__(self, parent=None, scan_results=None, save_callback=None):
        super().__init__(parent)
        self.setWindowTitle("Результаты сканирования")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 800)
        
        self.scan_results = scan_results or {}  # ip -> {mac, hostname, ports_info, status, old_data}
        self.save_callback = save_callback  # Функция для сохранения в базу
        
        # Хранилище для отслеживания изменений
        self.modified_rows = set()
        
        self.init_ui()
        self.load_results()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Заголовок
        header_label = QLabel("Результаты сканирования")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; padding: 5px;")
        layout.addWidget(header_label)
        
        # Статистика
        stats_layout = QHBoxLayout()
        self.lbl_total = QLabel("Всего: 0")
        self.lbl_new = QLabel("Новых: 0")
        self.lbl_changed = QLabel("Изменено: 0")
        self.lbl_unchanged = QLabel("Без изменений: 0")
        
        self.lbl_total.setStyleSheet("font-weight: bold; padding: 5px;")
        self.lbl_new.setStyleSheet("color: green; font-weight: bold; padding: 5px;")
        self.lbl_changed.setStyleSheet("color: orange; font-weight: bold; padding: 5px;")
        self.lbl_unchanged.setStyleSheet("color: gray; padding: 5px;")
        
        stats_layout.addWidget(self.lbl_total)
        stats_layout.addWidget(self.lbl_new)
        stats_layout.addWidget(self.lbl_changed)
        stats_layout.addWidget(self.lbl_unchanged)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        # Таблица
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname", "Статус", "Старые данные", "Комментарий", "Порты"])
        # ResizeToContents - автоподбор по содержимому, но можно менять вручную
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)  # IP
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # MAC
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Hostname
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Статус
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)  # Старые данные - можно менять
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Interactive)  # Комментарий - можно менять
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Interactive)  # Порты - можно менять
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemChanged.connect(self.on_item_changed)
        layout.addWidget(self.table)
        
        # Кнопки
        btn_layout = QHBoxLayout()
        
        self.btn_scan_ports = QPushButton("Сканировать порты")
        self.btn_scan_ports.setStyleSheet("background-color: #FF9800; color: white; padding: 8px 16px;")
        self.btn_scan_ports.clicked.connect(self.scan_selected_ports)
        btn_layout.addWidget(self.btn_scan_ports)
        
        self.btn_delete = QPushButton("Удалить выбранные")
        self.btn_delete.clicked.connect(self.delete_selected)
        btn_layout.addWidget(self.btn_delete)
        
        btn_layout.addStretch()
        
        self.btn_save = QPushButton("Записать в базу")
        self.btn_save.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px 20px; font-weight: bold;")
        self.btn_save.clicked.connect(self.save_to_database)
        btn_layout.addWidget(self.btn_save)
        
        self.btn_close = QPushButton("Закрыть")
        self.btn_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
    
    def load_results(self):
        """Загрузить результаты сканирования в таблицу"""
        # Отключаем сигнал на время загрузки
        try:
            self.table.itemChanged.disconnect(self.on_item_changed)
        except TypeError:
            pass
        
        self.table.setRowCount(len(self.scan_results))
        self.modified_rows = set()
        
        new_count = 0
        changed_count = 0
        unchanged_count = 0
        
        for row, (ip, data) in enumerate(self.scan_results.items()):
            status = data.get('status', 'new')
            old_data = data.get('old_data', {})
            
            # Подсчёт статистики
            if status == 'new':
                new_count += 1
                bg_color = QColor(144, 238, 144)  # light green
            elif status == 'changed':
                changed_count += 1
                bg_color = QColor(255, 255, 224)  # light yellow
            else:
                unchanged_count += 1
                bg_color = QColor(255, 255, 255)  # white
            
            # IP
            item_ip = QTableWidgetItem(ip)
            item_ip.setFlags(item_ip.flags() & ~Qt.ItemIsEditable)
            item_ip.setBackground(bg_color)
            self.table.setItem(row, 0, item_ip)
            
            # MAC
            item_mac = QTableWidgetItem(data.get('mac', 'None'))
            item_mac.setBackground(bg_color)
            self.table.setItem(row, 1, item_mac)
            
            # Hostname
            item_hostname = QTableWidgetItem(data.get('hostname', 'None'))
            item_hostname.setBackground(bg_color)
            self.table.setItem(row, 2, item_hostname)
            
            # Статус
            status_text = {
                'new': 'Новое',
                'changed': 'Изменено',
                'unchanged': 'Без изм.',
                'second_ip': 'Второе IP'
            }.get(status, status)
            item_status = QTableWidgetItem(status_text)
            item_status.setFlags(item_status.flags() & ~Qt.ItemIsEditable)
            item_status.setBackground(bg_color)
            self.table.setItem(row, 3, item_status)
            
            # Старые данные
            old_str = ""
            if old_data:
                old_mac = old_data.get('mac', 'None')
                old_hostname = old_data.get('hostname', 'None')
                if old_mac != data.get('mac') or old_hostname != data.get('hostname'):
                    old_str = f"MAC: {old_mac}, Host: {old_hostname}"
            item_old = QTableWidgetItem(old_str)
            item_old.setFlags(item_old.flags() & ~Qt.ItemIsEditable)
            item_old.setBackground(bg_color)
            self.table.setItem(row, 4, item_old)
            
            # Комментарий (редактируемый)
            item_comment = QTableWidgetItem(data.get('comment', ''))
            item_comment.setBackground(bg_color)
            self.table.setItem(row, 5, item_comment)
            
            # Порты
            item_ports = QTableWidgetItem(data.get('ports_info', ''))
            item_ports.setFlags(item_ports.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 6, item_ports)
        
        # Включаем сигнал обратно
        try:
            self.table.itemChanged.connect(self.on_item_changed)
        except TypeError:
            pass
        
        # Обновляем статистику
        self.lbl_total.setText(f"Всего: {len(self.scan_results)}")
        self.lbl_new.setText(f"Новых: {new_count}")
        self.lbl_changed.setText(f"Изменено: {changed_count}")
        self.lbl_unchanged.setText(f"Без изменений: {unchanged_count}")
        
        self.update_status()
    
    def on_item_changed(self, item):
        """Обработка изменения ячейки"""
        row = item.row()
        self.modified_rows.add(row)
        self.update_status()
    
    def update_status(self):
        """Обновить статус бар"""
        count = len(self.modified_rows)
        if count > 0:
            self.setWindowTitle(f"Результаты сканирования (изменений: {count})")
        else:
            self.setWindowTitle("Результаты сканирования")
    
    def delete_selected(self):
        """Удалить выбранные строки"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "Предупреждение", "Выберите строки для удаления")
            return
        
        reply = QMessageBox.question(self, "Подтверждение", 
                                     f"Удалить {len(selected_rows)} устройств(а) из результатов?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            # Удаляем из таблицы
            ips_to_remove = []
            for row in sorted(selected_rows, reverse=True):
                ip_item = self.table.item(row, 0)
                if ip_item and ip_item.text():
                    ips_to_remove.append(ip_item.text())
                self.table.removeRow(row)
            
            # Удаляем из данных
            for ip in ips_to_remove:
                if ip in self.scan_results:
                    del self.scan_results[ip]
            
            self.modified_rows.clear()
            self.load_results()  # Перезагрузить для обновления статистики
    
    def scan_selected_ports(self):
        """Сканировать порты для выбранных устройств"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "Предупреждение", "Выберите строки для сканирования портов")
            return
        
        # Получаем путь к nmap из главного окна
        nmap_path = self.parent().nmap_dir_edit.text().strip() if self.parent() else ''
        if not nmap_path:
            QMessageBox.warning(self, "Ошибка", "Не указан путь к nmap")
            return
        
        import subprocess
        
        for row in selected_rows:
            ip_item = self.table.item(row, 0)
            if not ip_item or not ip_item.text():
                continue
            
            ip = ip_item.text()
            self.setWindowTitle(f"Сканирование портов: {ip}...")
            
            try:
                # Команда: nmap -sV -T4 -O -F --version-light
                cmd = f'"{nmap_path}\\nmap.exe" -sV -T4 -O -F --version-light {ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                
                # Парсим вывод
                ports_info = ""
                for line in result.stdout.split('\n'):
                    if '/' in line and ('open' in line or 'filtered' in line):
                        ports_info += line.strip() + '\n'
                
                if not ports_info:
                    ports_info = "Нет открытых портов"
                
                # Обновляем ячейку
                item_ports = self.table.item(row, 6)
                if not item_ports:
                    item_ports = QTableWidgetItem(ports_info.strip())
                    self.table.setItem(row, 6, item_ports)
                else:
                    item_ports.setText(ports_info.strip())
                
                # Сохраняем в scan_results
                if ip in self.scan_results:
                    self.scan_results[ip]['ports_info'] = ports_info.strip()
                
            except subprocess.TimeoutExpired:
                self.table.setItem(row, 6, QTableWidgetItem("Таймаут сканирования"))
            except Exception as e:
                self.table.setItem(row, 6, QTableWidgetItem(f"Ошибка: {str(e)}"))
        
        self.setWindowTitle("Результаты сканирования")
        QMessageBox.information(self, "Готово", f"Просканировано {len(selected_rows)} устройств")
    
    def save_to_database(self):
        """Сохранить результаты в базу данных"""
        # Собираем данные из таблицы
        devices_to_save = {}
        for row in range(self.table.rowCount()):
            ip_item = self.table.item(row, 0)
            if not ip_item or not ip_item.text():
                continue
            
            ip = ip_item.text()
            mac_item = self.table.item(row, 1)
            hostname_item = self.table.item(row, 2)
            comment_item = self.table.item(row, 5)
            ports_item = self.table.item(row, 6)
            
            mac = mac_item.text() if mac_item else 'None'
            hostname = hostname_item.text() if hostname_item else 'None'
            comment = comment_item.text() if comment_item else ''
            ports = ports_item.text() if ports_item else ''
            
            devices_to_save[ip] = {
                'mac': mac,
                'hostname': hostname,
                'comment': comment,
                'ports': ports
            }
        
        if not devices_to_save:
            QMessageBox.warning(self, "Предупреждение", "Нет устройств для сохранения")
            return
        
        # Сохраняем в базу
        db.save_devices(devices_to_save)
        
        QMessageBox.information(self, "Готово", f"Сохранено {len(devices_to_save)} устройств в базу данных")
        
        # Вызываем callback если есть
        if self.save_callback:
            self.save_callback(devices_to_save)
        
        self.accept()
    
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
