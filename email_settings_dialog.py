# -*- coding: utf-8 -*-
"""
Окно настроек email
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QCheckBox, QMessageBox, QGroupBox, QFormLayout,
                             QRadioButton, QButtonGroup)
from PyQt5.QtCore import Qt
import database as db


class EmailSettingsDialog(QDialog):
    """Окно настроек email"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumSize(600, 650)
        self.setModal(True)
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Группа настроек SMTP
        smtp_group = QGroupBox("Настройки SMTP сервера")
        smtp_layout = QFormLayout()
        
        # SMTP сервер
        self.smtp_server_edit = QLineEdit()
        self.smtp_server_edit.setPlaceholderText("например: mail.hosting.reg.ru")
        smtp_layout.addRow("SMTP сервер:", self.smtp_server_edit)
        
        # Порт
        self.smtp_port_edit = QLineEdit()
        self.smtp_port_edit.setPlaceholderText("587")
        self.smtp_port_edit.setMaximumWidth(100)
        smtp_layout.addRow("Порт:", self.smtp_port_edit)
        
        # Use TLS/STARTTLS
        self.use_tls_checkbox = QCheckBox("Использовать STARTTLS")
        smtp_layout.addRow("", self.use_tls_checkbox)
        
        # Кнопка теста отправки
        test_btn_layout = QHBoxLayout()
        test_btn_layout.addStretch()
        self.btn_test = QPushButton("Тест отправки")
        self.btn_test.clicked.connect(self.test_email)
        test_btn_layout.addWidget(self.btn_test)
        smtp_layout.addRow("", test_btn_layout)
        
        smtp_group.setLayout(smtp_layout)
        layout.addWidget(smtp_group)
        
        # Группа учётных данных
        auth_group = QGroupBox("Учётные данные")
        auth_layout = QFormLayout()
        
        # Логин
        self.login_edit = QLineEdit()
        self.login_edit.setPlaceholderText("ваш логин")
        auth_layout.addRow("Логин:", self.login_edit)
        
        # Пароль
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("ваш пароль")
        self.password_edit.setEchoMode(QLineEdit.Password)
        auth_layout.addRow("Пароль:", self.password_edit)
        
        # From адрес
        self.from_address_edit = QLineEdit()
        self.from_address_edit.setPlaceholderText("например: DeviceDetect <alert@example.ru>")
        auth_layout.addRow("От кого:", self.from_address_edit)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Группа уведомлений
        notify_group = QGroupBox("Уведомления")
        notify_layout = QVBoxLayout()
        self.enable_notifications_checkbox = QCheckBox("Отправлять уведомления при обнаружении новых устройств")
        notify_layout.addWidget(self.enable_notifications_checkbox)
        notify_group.setLayout(notify_layout)
        layout.addWidget(notify_group)
        
        # Группа шифрования
        encryption_group = QGroupBox("Шифрование")
        encryption_layout = QVBoxLayout()
        
        # Уровень шифрования
        level_label = QLabel("Уровень шифрования:")
        encryption_layout.addWidget(level_label)
        
        self.encrypt_none_rb = QRadioButton("Без шифрования")
        self.encrypt_email_rb = QRadioButton("Только настройки почты")
        self.encrypt_all_rb = QRadioButton("Шифровать всю базу данных")
        self.encrypt_email_rb.setChecked(True)  # по умолчанию
        
        # Группа кнопок уровня шифрования
        self.level_button_group = QButtonGroup()
        self.level_button_group.addButton(self.encrypt_none_rb)
        self.level_button_group.addButton(self.encrypt_email_rb)
        self.level_button_group.addButton(self.encrypt_all_rb)
        
        encryption_layout.addWidget(self.encrypt_none_rb)
        encryption_layout.addWidget(self.encrypt_email_rb)
        encryption_layout.addWidget(self.encrypt_all_rb)
        
        # Ключ шифрования
        key_label = QLabel("Ключ шифрования:")
        encryption_layout.addWidget(key_label)
        
        self.key_computer_rb = QRadioButton("Имя компьютера")
        self.key_custom_rb = QRadioButton("Свой ключ")
        self.key_computer_rb.setChecked(True)
        
        # Группа кнопок типа ключа
        self.key_button_group = QButtonGroup()
        self.key_button_group.addButton(self.key_computer_rb)
        self.key_button_group.addButton(self.key_custom_rb)
        
        encryption_layout.addWidget(self.key_computer_rb)
        encryption_layout.addWidget(self.key_custom_rb)
        
        # Поле для своего ключа
        key_hbox = QHBoxLayout()
        self.custom_key_edit = QLineEdit()
        self.custom_key_edit.setPlaceholderText("Введите свой ключ шифрования")
        self.custom_key_edit.setEnabled(False)
        key_hbox.addWidget(self.custom_key_edit)
        encryption_layout.addLayout(key_hbox)
        
        # Привязка активации поля
        def update_key_field():
            self.custom_key_edit.setEnabled(self.key_custom_rb.isChecked())
        
        self.key_computer_rb.toggled.connect(update_key_field)
        self.key_custom_rb.toggled.connect(update_key_field)
        
        # Обновление доступности группы ключа в зависимости от уровня шифрования
        self.encrypt_none_rb.toggled.connect(self._update_encryption_ui)
        self.encrypt_email_rb.toggled.connect(self._update_encryption_ui)
        self.encrypt_all_rb.toggled.connect(self._update_encryption_ui)
        
        encryption_group.setLayout(encryption_layout)
        layout.addWidget(encryption_group)
        
        # Инициализируем состояние UI
        self._update_encryption_ui()
        
        # Кнопки
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        
        self.btn_save = QPushButton("Сохранить")
        self.btn_save.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px 16px;")
        self.btn_save.clicked.connect(self.save_settings)
        btn_layout.addWidget(self.btn_save)
        
        self.btn_cancel = QPushButton("Отмена")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)
        
        layout.addLayout(btn_layout)
    
    def _update_encryption_ui(self):
        """Обновить доступность элементов управления шифрованием"""
        none_selected = self.encrypt_none_rb.isChecked()
        # Если выбран "Без шифрования", отключаем выбор типа ключа и поле ввода
        self.key_computer_rb.setEnabled(not none_selected)
        self.key_custom_rb.setEnabled(not none_selected)
        self.custom_key_edit.setEnabled(not none_selected and self.key_custom_rb.isChecked())
        # Если отключено, сбрасываем выбор на "Имя компьютера" (опционально)
        if none_selected:
            self.key_computer_rb.setChecked(True)
    
    def load_settings(self):
        """Загрузить настройки из базы"""
        settings = db.get_email_settings()
        if settings:
            # Если есть сохранённые настройки — используем их
            self.smtp_server_edit.setText(settings.get('smtp_server', '') or '')
            self.smtp_port_edit.setText(str(settings.get('smtp_port', 587)) if settings.get('smtp_port') else '587')
            self.login_edit.setText(settings.get('login', '') or '')
            self.password_edit.setText(settings.get('password', '') or '')
            self.from_address_edit.setText(settings.get('from_address', '') or '')
            self.use_tls_checkbox.setChecked(bool(settings.get('use_tls', 1)))
            # enable_notifications может отсутствовать в старой базе
            self.enable_notifications_checkbox.setChecked(bool(settings.get('enable_notifications', 1)))
            
            # Настройки шифрования
            encryption_level = settings.get('encryption_level', 'email_only')
            if encryption_level == 'none':
                self.encrypt_none_rb.setChecked(True)
            elif encryption_level == 'all':
                self.encrypt_all_rb.setChecked(True)
            else:
                self.encrypt_email_rb.setChecked(True)  # по умолчанию (email_only)
            
            encryption_key_type = settings.get('encryption_key_type', 'computer_name')
            if encryption_key_type == 'custom':
                self.key_custom_rb.setChecked(True)
                # Не показываем хэш, оставляем поле пустым (ключ не хранится)
                self.custom_key_edit.setText('')
            else:
                self.key_computer_rb.setChecked(True)
        else:
            # Настройки не найдены или не удалось расшифровать - показываем дефолтные (с отключёнными уведомлениями)
            self.smtp_server_edit.setText('smtp.example.com')
            self.smtp_port_edit.setText('587')
            self.login_edit.setText('user@example.ru')
            self.password_edit.setText('password123')
            self.from_address_edit.setText('DeviceDetect <alert@example.ru>')
            self.use_tls_checkbox.setChecked(True)
            self.enable_notifications_checkbox.setChecked(False)  # Отключено по умолчанию
            # Шифрование по умолчанию
            self.encrypt_email_rb.setChecked(True)
            self.key_computer_rb.setChecked(True)
        
        # Обновляем состояние UI шифрования
        self._update_encryption_ui()
    
    def save_settings(self):
        """Сохранить настройки в базу"""
        smtp_server = self.smtp_server_edit.text().strip()
        smtp_port = self.smtp_port_edit.text().strip()
        login = self.login_edit.text().strip()
        password = self.password_edit.text().strip()
        from_address = self.from_address_edit.text().strip()
        use_tls = self.use_tls_checkbox.isChecked()
        enable_notifications = self.enable_notifications_checkbox.isChecked()
        
        # Валидация
        if not smtp_server:
            QMessageBox.warning(self, "Ошибка", "Укажите SMTP сервер")
            return
        
        try:
            port = int(smtp_port)
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Некорректный номер порта (1-65535)")
            return
        
        if not login:
            QMessageBox.warning(self, "Ошибка", "Укажите логин")
            return
        
        if not password:
            QMessageBox.warning(self, "Ошибка", "Укажите пароль")
            return
        
        # Определение уровня шифрования
        if self.encrypt_none_rb.isChecked():
            encryption_level = 'none'
        elif self.encrypt_all_rb.isChecked():
            encryption_level = 'all'
        else:
            encryption_level = 'email_only'  # по умолчанию
        
        # Определение типа ключа
        if self.key_custom_rb.isChecked():
            encryption_key_type = 'custom'
            custom_key = self.custom_key_edit.text().strip()
            if not custom_key:
                QMessageBox.warning(self, "Ошибка", "При выборе 'Свой ключ' необходимо ввести ключ")
                return
        else:
            encryption_key_type = 'computer_name'
            custom_key = ''
        
        # Сохранение
        db.update_email_settings(smtp_server, port, login, password, from_address, use_tls, enable_notifications,
                                 encryption_level, encryption_key_type, custom_key)
        
        # Обновляем глобальный ключ в памяти, если используется пользовательский ключ
        if encryption_key_type == 'custom' and custom_key:
            db.set_custom_key(custom_key)
        
        QMessageBox.information(self, "Готово", "Настройки сохранены")
        self.accept()
    
    def test_email(self):
        """Тест отправки email"""
        import smtplib
        from email.mime.text import MIMEText
        
        smtp_server = self.smtp_server_edit.text().strip()
        smtp_port = int(self.smtp_port_edit.text().strip() or '587')
        login = self.login_edit.text().strip()
        password = self.password_edit.text().strip()
        from_address = self.from_address_edit.text().strip()
        use_tls = self.use_tls_checkbox.isChecked()
        
        if not smtp_server or not login or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните SMTP сервер, логин и пароль")
            return
        
        try:
            # Создаём тестовое сообщение
            msg = MIMEText("Тестовое сообщение от DeviceDetect")
            msg['Subject'] = "Тест SMTP настроек - DeviceDetect"
            msg['From'] = from_address or login
            msg['To'] = login  # Отправляем самому себе для теста
            
            # Подключение
            if use_tls:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            
            server.login(login, password)
            server.send_message(msg)
            server.quit()
            
            QMessageBox.information(self, "Успех", "Тестовое письмо успешно отправлено!")
            
        except smtplib.SMTPAuthenticationError:
            QMessageBox.critical(self, "Ошибка", "Неверный логин или пароль")
        except smtplib.SMTPConnectError:
            QMessageBox.critical(self, "Ошибка", f"Не удалось подключиться к {smtp_server}:{smtp_port}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка: {str(e)}")
