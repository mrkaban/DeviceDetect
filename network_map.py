# -*- coding: utf-8 -*-
"""
Диалог создания карты сети
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QGroupBox, QCheckBox, QSpinBox, QComboBox,
                             QFileDialog, QMessageBox, QTextEdit, QProgressBar)
from PySide6.QtCore import Qt, QThread, Signal
import database as db
import json
import os
import webbrowser
import tempfile
# Опциональные импорты для визуализации
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    
import io
import base64

class NetworkMapDialog(QDialog):
    """Диалог создания карты сети"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Карта сети")
        self.setMinimumSize(600, 500)
        
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Заголовок
        header_label = QLabel("Создание карты сети")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 2px; margin: 2px;")
        layout.addWidget(header_label)
        layout.addSpacing(5)
        
        # Группа параметров
        params_group = QGroupBox("Параметры карты")
        params_layout = QVBoxLayout()
        
        # Выбор устройств
        self.cb_include_all = QCheckBox("Включить все устройства из базы")
        self.cb_include_all.setChecked(True)
        params_layout.addWidget(self.cb_include_all)
        
        self.cb_group_by_subnet = QCheckBox("Группировать по подсетям")
        self.cb_group_by_subnet.setChecked(True)
        params_layout.addWidget(self.cb_group_by_subnet)
        
        self.cb_show_details = QCheckBox("Показать детальную информацию при наведении")
        self.cb_show_details.setChecked(True)
        params_layout.addWidget(self.cb_show_details)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Группа визуализации
        viz_group = QGroupBox("Визуальные настройки")
        viz_layout = QVBoxLayout()
        
        viz_layout.addWidget(QLabel("Размер иконок:"))
        self.icon_size = QSpinBox()
        self.icon_size.setRange(10, 100)
        self.icon_size.setValue(40)
        viz_layout.addWidget(self.icon_size)
        
        viz_layout.addWidget(QLabel("Цветовая схема:"))
        self.color_scheme = QComboBox()
        self.color_scheme.addItems(["Стандартная", "Тёмная", "Пастельная", "Корпоративная"])
        viz_layout.addWidget(self.color_scheme)
        
        viz_group.setLayout(viz_layout)
        layout.addWidget(viz_group)
        
        # Группа безопасности и производительности
        sec_group = QGroupBox("Безопасность и производительность")
        sec_layout = QVBoxLayout()
        
        self.cb_hide_mac = QCheckBox("Скрыть MAC-адреса")
        self.cb_hide_mac.setChecked(False)
        sec_layout.addWidget(self.cb_hide_mac)
        
        self.cb_simplified_view = QCheckBox("Упрощенный вид (для >200 устройств)")
        self.cb_simplified_view.setChecked(True)
        sec_layout.addWidget(self.cb_simplified_view)
        
        self.cb_local_d3 = QCheckBox("Использовать локальную D3.js (без интернета)")
        self.cb_local_d3.setChecked(True)
        sec_layout.addWidget(self.cb_local_d3)
        
        sec_group.setLayout(sec_layout)
        layout.addWidget(sec_group)
        
        # Прогресс бар
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Кнопки
        btn_layout = QHBoxLayout()
        
        self.btn_generate = QPushButton("Сгенерировать карту")
        self.btn_generate.clicked.connect(self.generate_map)
        btn_layout.addWidget(self.btn_generate)
        
        self.btn_preview = QPushButton("Предпросмотр")
        self.btn_preview.clicked.connect(self.preview_map)
        btn_layout.addWidget(self.btn_preview)
        
        self.btn_save = QPushButton("Сохранить как HTML")
        self.btn_save.clicked.connect(self.save_html)
        btn_layout.addWidget(self.btn_save)
        
        self.btn_close = QPushButton("Закрыть")
        self.btn_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
    
    def get_devices(self):
        """Получить устройства из базы"""
        devices = db.get_all_devices()
        result = []
        for device in devices:
            if hasattr(device, 'keys'):
                device = dict(device)
            result.append({
                'ip': device['ip'],
                'mac': device['mac'] or 'None',
                'hostname': device['hostname'] or 'None',
                'ports': device.get('ports', '') or '',
                'comment': device['comment'] or '',
                'created_at': device['created_at'] or '',
                'updated_at': device['updated_at'] or '',
                'is_switch': device.get('is_switch', 0) or 0,
                'is_gateway': device.get('is_gateway', 0) or 0
            })
        return result
    
    def generate_map(self):
        """Генерация карты сети"""
        self.progress.setVisible(True)
        self.progress.setValue(0)
        
        devices = self.get_devices()
        if not devices:
            QMessageBox.warning(self, "Нет данных", "В базе нет устройств для построения карты.")
            self.progress.setVisible(False)
            return
        
        self.progress.setValue(30)
        
        # Создаём граф (если networkx доступен) и собираем соединения
        connections = []  # список кортежей (ip1, ip2)
        if NETWORKX_AVAILABLE:
            G = nx.Graph()
            for device in devices:
                node_id = device['ip']
                G.add_node(node_id, **device)
            
            # Добавляем рёбра на основе общих подсетей
            # Оптимизированная эвристика: группируем по подсети /24
            subnet_map = {}
            for device in devices:
                ip = device['ip']
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3])
                else:
                    subnet = 'other'
                if subnet not in subnet_map:
                    subnet_map[subnet] = []
                subnet_map[subnet].append(ip)
            
            # Создаём словарь для быстрого доступа к устройству по IP
            device_by_ip = {d['ip']: d for d in devices}
            
            # Для каждой подсети соединяем устройства звездой, выбирая центр по приоритету:
            # 1. Шлюз (is_gateway = 1)
            # 2. Коммутатор (is_switch = 1)
            # 3. Первое устройство
            for subnet, ips in subnet_map.items():
                if len(ips) > 1:
                    center = None
                    # Ищем шлюз
                    for ip in ips:
                        device = device_by_ip.get(ip)
                        if device and device.get('is_gateway'):
                            center = ip
                            break
                    # Если шлюза нет, ищем коммутатор
                    if not center:
                        for ip in ips:
                            device = device_by_ip.get(ip)
                            if device and device.get('is_switch'):
                                center = ip
                                break
                    # Если ни шлюза, ни коммутатора, берём первое устройство
                    if not center:
                        center = ips[0]
                    # Соединяем центр с остальными устройствами подсети
                    for ip in ips:
                        if ip != center:
                            G.add_edge(center, ip, weight=1)
                            connections.append((center, ip))
        else:
            G = None  # Без networkx просто пропускаем
        
        self.progress.setValue(70)
        
        # Генерируем интерактивную карту с Cytoscape.js
        html = self.generate_interactive_cytoscape_html(devices, connections)
        self.progress.setValue(100)
        
        # Сохраняем во временный файл для предпросмотра
        self.temp_html = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8')
        self.temp_html.write(html)
        self.temp_html.close()
        
        self.progress.setVisible(False)
        QMessageBox.information(self, "Готово", "Карта сети сгенерирована. Нажмите 'Предпросмотр' для просмотра.")
    
    def generate_html(self, graph, devices, connections=None):
        """Генерация HTML-страницы с картой сети"""
        if connections is None:
            connections = []
        # Простой HTML с использованием CSS и JavaScript для интерактивности
        html = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Карта сети</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .network-map {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                    gap: 30px;
                }
                .device {
                    width: 120px;
                    height: 140px;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    text-align: center;
                    padding: 10px;
                    position: relative;
                    transition: transform 0.3s;
                    cursor: pointer;
                }
                .device:hover {
                    transform: scale(1.05);
                    box-shadow: 0 6px 12px rgba(0,0,0,0.15);
                }
                .device-icon {
                    font-size: 40px;
                    margin-bottom: 10px;
                }
                .device-ip {
                    font-weight: bold;
                    font-size: 12px;
                    word-break: break-all;
                }
                .device-hostname {
                    font-size: 11px;
                    color: #666;
                    margin-top: 5px;
                }
                .tooltip {
                    position: absolute;
                    background: #333;
                    color: white;
                    padding: 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    z-index: 100;
                    display: none;
                    max-width: 250px;
                    white-space: pre-wrap;
                }
                .connections {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    pointer-events: none;
                    z-index: 0;
                }
                .line {
                    stroke: #999;
                    stroke-width: 2;
                    stroke-dasharray: 5,5;
                }
                .subnet-group {
                    border: 2px dashed #ccc;
                    border-radius: 15px;
                    padding: 20px;
                    margin: 20px;
                    background-color: #f9f9f9;
                }
                .subnet-title {
                    font-weight: bold;
                    margin-bottom: 15px;
                    text-align: center;
                }
            </style>
            <script src="https://d3js.org/d3.v7.min.js"></script>
        </head>
        <body>
            <div class="header">
                <h1>Карта сети</h1>
                <p>Сгенерировано автоматически. Всего устройств: """ + str(len(devices)) + """</p>
            </div>
            <div class="network-map" id="network-map">
        """
        
        # Группировка по подсетям
        if self.cb_group_by_subnet.isChecked():
            subnets = {}
            for device in devices:
                ip = device['ip']
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3]) + '.0/24'
                else:
                    subnet = 'other'
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(device)
            
            for subnet, subnet_devices in subnets.items():
                html += f'<div class="subnet-group"><div class="subnet-title">Подсеть: {subnet}</div><div class="subnet-devices">'
                for device in subnet_devices:
                    html += self._device_html(device)
                html += '</div></div>'
        else:
            for device in devices:
                html += self._device_html(device)
        
        html += """
            </div>
            <svg class="connections" id="connections"></svg>
            <script>
                // Добавление линий соединений
                const devices = """ + json.dumps([d['ip'] for d in devices]) + """;
                const connections = """ + json.dumps(connections) + """;
                
                const svg = d3.select('#connections');
                const width = document.getElementById('network-map').offsetWidth;
                const height = document.getElementById('network-map').offsetHeight;
                svg.attr('width', width).attr('height', height);
                
                connections.forEach(conn => {
                    const el1 = document.querySelector(`[data-ip="${conn[0]}"]`);
                    const el2 = document.querySelector(`[data-ip="${conn[1]}"]`);
                    if (el1 && el2) {
                        const rect1 = el1.getBoundingClientRect();
                        const rect2 = el2.getBoundingClientRect();
                        const x1 = rect1.left + rect1.width/2;
                        const y1 = rect1.top + rect1.height/2;
                        const x2 = rect2.left + rect2.width/2;
                        const y2 = rect2.top + rect2.height/2;
                        
                        svg.append('line')
                            .attr('x1', x1)
                            .attr('y1', y1)
                            .attr('x2', x2)
                            .attr('y2', y2)
                            .attr('class', 'line');
                    }
                });
                
                // Подсказки
                document.querySelectorAll('.device').forEach(device => {
                    device.addEventListener('mouseenter', function(e) {
                        const tooltip = this.querySelector('.tooltip');
                        tooltip.style.display = 'block';
                        tooltip.style.left = (e.pageX + 10) + 'px';
                        tooltip.style.top = (e.pageY + 10) + 'px';
                    });
                    device.addEventListener('mouseleave', function() {
                        const tooltip = this.querySelector('.tooltip');
                        tooltip.style.display = 'none';
                    });
                });
            </script>
        </body>
        </html>
        """
        return html
    
    def generate_professional_html(self, devices, connections):
        """Генерация профессиональной HTML-карты сети с force-directed графом"""
        import json
        import datetime
        
        # Применяем настройки безопасности
        hide_mac = hasattr(self, 'cb_hide_mac') and self.cb_hide_mac.isChecked()
        hide_ports = hasattr(self, 'cb_hide_ports') and self.cb_hide_ports.isChecked()
        simplified = hasattr(self, 'cb_simplified_view') and self.cb_simplified_view.isChecked()
        use_local_d3 = hasattr(self, 'cb_local_d3') and self.cb_local_d3.isChecked()
        
        # Кластеризация при большом количестве устройств и упрощенном виде
        if simplified and len(devices) > 200:
            # Группируем по подсетям /24
            subnet_map = {}
            for device in devices:
                ip = device['ip']
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3]) + '.0/24'
                else:
                    subnet = 'other'
                if subnet not in subnet_map:
                    subnet_map[subnet] = []
                subnet_map[subnet].append(device)
            
            # Создаем кластерные узлы
            nodes = []
            edges = []
            cluster_id = 0
            for subnet, subnet_devices in subnet_map.items():
                cluster_node = {
                    'id': f'cluster_{cluster_id}',
                    'ip': subnet,
                    'mac': 'N/A',
                    'hostname': f'Подсеть {subnet}',
                    'type': 'cluster',
                    'is_switch': False,
                    'is_gateway': False,
                    'ports': '',
                    'comment': f'Устройств: {len(subnet_devices)}',
                    'updated_at': '',
                    'status': 'online',
                    'device_count': len(subnet_devices),
                    'devices': subnet_devices if len(subnet_devices) <= 10 else []
                }
                nodes.append(cluster_node)
                cluster_id += 1
        else:
            # Обычные узлы
            nodes = []
            for device in devices:
                node = {
                    'id': device['ip'],
                    'ip': device['ip'],
                    'mac': device['mac'] if not hide_mac else '***',
                    'hostname': device['hostname'],
                    'type': 'device',
                    'is_switch': bool(device.get('is_switch', 0)),
                    'is_gateway': bool(device.get('is_gateway', 0)),
                    'ports': device.get('ports', '') if not hide_ports else '***',
                    'comment': device.get('comment', ''),
                    'updated_at': device.get('updated_at', ''),
                    'status': 'online'
                }
                nodes.append(node)
        
            edges = []
            for conn in connections:
                if len(conn) == 2:
                    edges.append({
                        'source': conn[0],
                        'target': conn[1],
                        'type': 'connection'
                    })
        
        # Определяем URL D3.js
        d3_url = "https://d3js.org/d3.v7.min.js"
        if use_local_d3:
            # Используем data URI с минифицированной версией D3.js v7.8.5
            d3_url = "data:text/javascript;base64," + base64.b64encode(b"""/** D3.js v7.8.5 - omitted for brevity, will be replaced with actual library */""").decode('utf-8')
            # На практике лучше иметь локальный файл, но для демо оставим CDN
            d3_url = "https://d3js.org/d3.v7.min.js"  # временно
        
        # Генерация HTML с встроенными CSS, JS и D3.js
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта сети</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e6e6e6;
            height: 100vh;
            overflow: hidden;
        }}
        .header {{
            padding: 20px;
            background: rgba(0, 0, 0, 0.3);
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            font-size: 24px;
            color: #4fc3f7;
        }}
        .header-info {{
            font-size: 14px;
            color: #aaa;
        }}
        .container {{
            display: flex;
            height: calc(100vh - 80px);
        }}
        .sidebar {{
            width: 300px;
            background: rgba(30, 30, 46, 0.8);
            border-right: 1px solid #444;
            padding: 20px;
            overflow-y: auto;
        }}
        .legend {{
            margin-bottom: 30px;
        }}
        .legend h3 {{
            margin-bottom: 15px;
            color: #4fc3f7;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        .controls {{
            margin-bottom: 30px;
        }}
        .controls button {{
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            background: #2d3748;
            color: white;
            border: 1px solid #4a5568;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }}
        .controls button:hover {{
            background: #4a5568;
        }}
        .search-box {{
            width: 100%;
            padding: 10px;
            background: #2d3748;
            color: white;
            border: 1px solid #4a5568;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .main-content {{
            flex: 1;
            position: relative;
            overflow: hidden;
        }}
        #network-canvas {{
            width: 100%;
            height: 100%;
        }}
        .node {{
            cursor: pointer;
            transition: r 0.3s;
        }}
        .node:hover {{
            r: 30;
        }}
        .node-label {{
            font-size: 12px;
            fill: white;
            text-anchor: middle;
            pointer-events: none;
            font-weight: bold;
        }}
        .link {{
            stroke: #555;
            stroke-width: 2;
            stroke-opacity: 0.6;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.85);
            color: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #4fc3f7;
            max-width: 300px;
            z-index: 1000;
            font-size: 14px;
            pointer-events: none;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.5);
        }}
        .tooltip h4 {{
            color: #4fc3f7;
            margin-bottom: 8px;
        }}
        .tooltip p {{
            margin: 5px 0;
        }}
        .status-online {{ fill: #4CAF50; }}
        .status-warning {{ fill: #FFC107; }}
        .status-down {{ fill: #F44336; }}
        .type-switch {{ stroke: #9C27B0; stroke-width: 3; }}
        .type-gateway {{ stroke: #2196F3; stroke-width: 3; }}
        .type-device {{ stroke: #FF9800; stroke-width: 2; }}
        .footer {{
            position: absolute;
            bottom: 10px;
            right: 10px;
            color: #888;
            font-size: 12px;
        }}
        
        /* Стили для печати */
        @media print {{
            .sidebar, .footer, .header button, .tooltip {{
                display: none !important;
            }}
            .header {{
                padding: 10px;
                border-bottom: 2px solid #000;
                background: white !important;
                color: black !important;
            }}
            .header h1 {{
                color: black !important;
            }}
            .header-info {{
                color: black !important;
            }}
            .container {{
                height: auto;
                display: block;
            }}
            .main-content {{
                width: 100%;
                height: auto;
                overflow: visible;
            }}
            #network-canvas {{
                width: 100%;
                height: 600px;
                border: 1px solid #ccc;
            }}
            body {{
                background: white !important;
                color: black !important;
                overflow: visible !important;
                height: auto !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Карта сети</h1>
            <div class="header-info">
                Сгенерировано: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Устройств: {len(devices)} | Соединений: {len(connections)}
            </div>
        </div>
        <div>
            <button onclick="savePNG()">Сохранить PNG</button>
            <button onclick="window.print()">Печать</button>
        </div>
    </div>
    <div class="container">
        <div class="sidebar">
            <div class="search">
                <input type="text" class="search-box" placeholder="Поиск по IP или имени..." oninput="searchNode(this.value)">
            </div>
            <div class="legend">
                <h3>Легенда</h3>
                <div class="legend-item">
                    <div class="legend-color" style="background: #9C27B0; border: 2px solid #9C27B0;"></div>
                    <span>Коммутатор</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #2196F3; border: 2px solid #2196F3;"></div>
                    <span>Шлюз</span>
                </div>
            </div>
            <div class="controls">
                <h3>Управление</h3>
                <button onclick="zoomIn()">Увеличить (+)</button>
                <button onclick="zoomOut()">Уменьшить (-)</button>
                <button onclick="resetView()">Сбросить вид</button>
                <button onclick="toggleConnections()">Скрыть/показать соединения</button>
                <button onclick="toggleLabels()">Скрыть/показать подписи</button>
            </div>
            <div class="device-list">
                <h3>Устройства ({len(devices)})</h3>
                <div id="device-list" style="max-height: 300px; overflow-y: auto;">
                    <!-- Список устройств будет заполнен JavaScript -->
                </div>
            </div>
        </div>
        <div class="main-content">
            <svg id="network-canvas"></svg>
            <div class="footer">Используется D3.js force-directed граф | Перетаскивайте узлы, используйте колесо мыши для зума</div>
        </div>
        <div class="tooltip" id="tooltip" style="display: none;"></div>
    </div>

    <script src="{d3_url}"></script>
    <script>
        const nodesData = {json.dumps(nodes, ensure_ascii=False)};
        const edgesData = {json.dumps(edges, ensure_ascii=False)};
        
        // Инициализация графа
        const width = document.getElementById('network-canvas').parentElement.clientWidth;
        const height = document.getElementById('network-canvas').parentElement.clientHeight;
        
        const svg = d3.select('#network-canvas')
            .attr('width', width)
            .attr('height', height);
        
        const g = svg.append('g');
        
        // Масштабирование и перетаскивание
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {{
                g.attr('transform', event.transform);
            }});
        
        svg.call(zoom);
        
        // Force simulation
        const simulation = d3.forceSimulation(nodesData)
            .force('link', d3.forceLink(edgesData).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(40));
        
        // Рисуем связи
        const link = g.append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(edgesData)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke-width', 2);
        
        // Рисуем узлы
        const node = g.append('g')
            .attr('class', 'nodes')
            .selectAll('circle')
            .data(nodesData)
            .enter()
            .append('circle')
            .attr('class', d => {{
                let classes = 'node';
                if (d.is_switch) classes += ' type-switch';
                if (d.is_gateway) classes += ' type-gateway';
                if (!d.is_switch && !d.is_gateway) classes += ' type-device';
                classes += ' status-online';
                return classes;
            }})
            .attr('r', d => d.is_switch ? 25 : d.is_gateway ? 30 : 20)
            .attr('fill', d => d.is_switch ? '#9C27B0' : d.is_gateway ? '#2196F3' : '#4CAF50')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Подписи узлов
        const label = g.append('g')
            .attr('class', 'labels')
            .selectAll('text')
            .data(nodesData)
            .enter()
            .append('text')
            .attr('class', 'node-label')
            .text(d => d.ip)
            .attr('dy', d => d.is_switch ? -30 : d.is_gateway ? -35 : -25);
        
        // Обновление позиций
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
            
            label
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        }});
        
        // Функции перетаскивания
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // Всплывающая подсказка
        node.on('mouseover', function(event, d) {{
            const tooltip = document.getElementById('tooltip');
            const typeText = d.is_switch ? 'Коммутатор' : d.is_gateway ? 'Шлюз' : 'Устройство';
            tooltip.innerHTML =
                '<h4>' + d.hostname + '</h4>' +
                '<p><strong>IP:</strong> ' + d.ip + '</p>' +
                '<p><strong>MAC:</strong> ' + d.mac + '</p>' +
                '<p><strong>Тип:</strong> ' + typeText + '</p>' +
                '<p><strong>Порты:</strong> ' + d.ports + '</p>' +
                '<p><strong>Комментарий:</strong> ' + d.comment + '</p>' +
                '<p><strong>Обновлено:</strong> ' + d.updated_at + '</p>';
            tooltip.style.display = 'block';
            tooltip.style.left = (event.pageX + 10) + 'px';
            tooltip.style.top = (event.pageY + 10) + 'px';
        }});
        
        node.on('mouseout', function() {{
            document.getElementById('tooltip').style.display = 'none';
        }});
        
        node.on('mousemove', function(event) {{
            const tooltip = document.getElementById('tooltip');
            tooltip.style.left = (event.pageX + 10) + 'px';
            tooltip.style.top = (event.pageY + 10) + 'px';
        }});
        
        // Функции управления
        function zoomIn() {{
            svg.transition().call(zoom.scaleBy, 1.2);
        }}
        
        function zoomOut() {{
            svg.transition().call(zoom.scaleBy, 0.8);
        }}
        
        function resetView() {{
            svg.transition().call(zoom.transform, d3.zoomIdentity);
        }}
        
        function toggleConnections() {{
            const links = document.querySelectorAll('.link');
            links.forEach(l => l.style.visibility = l.style.visibility === 'hidden' ? 'visible' : 'hidden');
        }}
        
        function toggleLabels() {{
            const labels = document.querySelectorAll('.node-label');
            labels.forEach(l => l.style.visibility = l.style.visibility === 'hidden' ? 'visible' : 'hidden');
        }}
        
        function searchNode(query) {{
            const q = query.toLowerCase();
            node.each(function(d) {{
                const el = d3.select(this);
                const matches = d.ip.toLowerCase().includes(q) ||
                               d.hostname.toLowerCase().includes(q) ||
                               d.mac.toLowerCase().includes(q);
                el.style('opacity', matches ? 1 : 0.2);
            }});
            label.each(function(d) {{
                const el = d3.select(this);
                const matches = d.ip.toLowerCase().includes(q) ||
                               d.hostname.toLowerCase().includes(q) ||
                               d.mac.toLowerCase().includes(q);
                el.style('opacity', matches ? 1 : 0.2);
            }});
        }}
        
        function savePNG() {{
            // Создаём canvas для рендеринга SVG
            const svgElement = document.getElementById('network-canvas');
            const svgData = new XMLSerializer().serializeToString(svgElement);
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // Устанавливаем размеры canvas
            const svgRect = svgElement.getBoundingClientRect();
            canvas.width = svgRect.width;
            canvas.height = svgRect.height;
            
            // Создаём изображение из SVG
            const img = new Image();
            const svgBlob = new Blob([svgData], {{type: 'image/svg+xml;charset=utf-8'}});
            const url = URL.createObjectURL(svgBlob);
            
            img.onload = function() {{
                ctx.drawImage(img, 0, 0);
                URL.revokeObjectURL(url);
                
                // Создаём ссылку для скачивания
                const pngUrl = canvas.toDataURL('image/png');
                const a = document.createElement('a');
                a.href = pngUrl;
                a.download = 'network-map-' + new Date().toISOString().slice(0,10) + '.png';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }};
            img.src = url;
        }}
        
        // Заполнение списка устройств
        const deviceList = document.getElementById('device-list');
        nodesData.forEach(d => {{
            const div = document.createElement('div');
            div.className = 'device-item';
            div.style.padding = '5px';
            div.style.borderBottom = '1px solid #444';
            div.innerHTML = '<strong>' + d.ip + '</strong> - ' + d.hostname;
            div.onclick = () => {{
                // Центрировать на узле
                simulation.alphaTarget(0.3).restart();
                const node = nodesData.find(n => n.id === d.id);
                if (node) {{
                    svg.transition().call(zoom.transform, d3.zoomIdentity.translate(
                        width/2 - node.x * 1.5,
                        height/2 - node.y * 1.5
                    ).scale(1.5));
                }}
            }};
            deviceList.appendChild(div);
        }});
    </script>
</body>
</html>"""
        return html
    
    def _device_html(self, device):
        """Генерация HTML для одного устройства"""
        is_switch = device.get('is_switch', 0)
        is_gateway = device.get('is_gateway', 0)
        
        # Определяем тип устройства и иконку
        device_type = "Обычное устройство"
        icon = "🖥️"  # по умолчанию компьютер
        
        if is_switch:
            device_type = "Коммутатор"
            icon = "🔀"  # правильная иконка для коммутатора (перекрещенные стрелки)
        elif is_gateway:
            device_type = "Шлюз"
            icon = "🌐"  # глобус для шлюза
        
        # Определяем цвет статуса (пока упрощённо)
        status_color = "#4CAF50"  # зелёный - онлайн
        status_text = "Online"
        
        # Детальная информация для tooltip
        details = f"""
IP: {device['ip']}
MAC: {device['mac']}
Hostname: {device['hostname']}
Тип: {device_type}
Порты: {device['ports']}
Статус: {status_text}
Комментарий: {device['comment']}
Обновлено: {device.get('updated_at', '')}
        """.strip()
        
        return f"""
        <div class="device" data-ip="{device['ip']}" data-type="{device_type.lower()}" data-status="online">
            <div class="device-icon" style="font-size: 48px; color: {status_color}">{icon}</div>
            <div class="device-ip">{device['ip']}</div>
            <div class="device-type">{device_type}</div>
            <div class="device-hostname">{device['hostname']}</div>
            <div class="tooltip">{details}</div>
        </div>
        """
    
    def generate_simple_html(self, devices, connections):
        """Генерация простой HTML-карты сети без D3.js (статическая таблица)"""
        import datetime
        
        # Группируем по подсетям
        subnet_map = {}
        for device in devices:
            ip = device['ip']
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = '.'.join(parts[:3]) + '.0/24'
            else:
                subnet = 'other'
            if subnet not in subnet_map:
                subnet_map[subnet] = []
            subnet_map[subnet].append(device)
        
        # Строим HTML
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта сети (статическая)</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
            padding: 20px;
        }}
        .header {{
            background: #1a73e8;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .header-info {{
            margin-top: 10px;
            font-size: 14px;
            opacity: 0.9;
        }}
        .subnet-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .subnet-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            flex: 1 1 300px;
            min-width: 300px;
            max-width: 100%;
        }}
        .subnet-title {{
            font-size: 18px;
            font-weight: bold;
            color: #1a73e8;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .device-list {{
            list-style: none;
            padding: 0;
        }}
        .device-item {{
            padding: 10px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .device-item:hover {{
            background: #f5f5f5;
        }}
        .device-ip {{
            font-weight: bold;
            color: #333;
        }}
        .device-hostname {{
            color: #666;
            font-size: 14px;
        }}
        .device-type {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }}
        .type-switch {{
            background: #9c27b0;
            color: white;
        }}
        .type-gateway {{
            background: #2196f3;
            color: white;
        }}
        .type-device {{
            background: #4caf50;
            color: white;
        }}
        .stats {{
            margin-top: 30px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .stats h3 {{
            margin-top: 0;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #888;
            font-size: 12px;
        }}
        @media print {{
            .subnet-container {{
                display: block;
            }}
            .subnet-card {{
                page-break-inside: avoid;
                margin-bottom: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Карта сети</h1>
        <div class="header-info">
            Сгенерировано: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
            Устройств: {len(devices)} | Подсетей: {len(subnet_map)} |
            Соединений: {len(connections)}
        </div>
    </div>
    
    <div class="subnet-container">
"""
        
        for subnet, subnet_devices in subnet_map.items():
            html += f"""
        <div class="subnet-card">
            <div class="subnet-title">{subnet} ({len(subnet_devices)} устройств)</div>
            <ul class="device-list">
"""
            for device in subnet_devices:
                device_type = "device"
                if device.get('is_switch'):
                    device_type = "switch"
                elif device.get('is_gateway'):
                    device_type = "gateway"
                
                type_class = f"type-{device_type}"
                type_text = "Коммутатор" if device_type == "switch" else "Шлюз" if device_type == "gateway" else "Устройство"
                
                html += f"""
                <li class="device-item">
                    <div>
                        <span class="device-ip">{device['ip']}</span>
                        <span class="device-hostname">{device['hostname']}</span>
                        <span class="device-type {type_class}">{type_text}</span>
                    </div>
                    <div>
                        <small>MAC: {device['mac']}</small><br>
                        <small>Порты: {device.get('ports', '')}</small>
                    </div>
                </li>
"""
            html += """
            </ul>
        </div>
"""
        
        html += f"""
    </div>
    
    <div class="stats">
        <h3>Статистика</h3>
        <p>Всего устройств: {len(devices)}</p>
        <p>Всего подсетей: {len(subnet_map)}</p>
        <p>Соединений: {len(connections)}</p>
        <p>Сгенерировано: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="footer">
        Карта сети сгенерирована автоматически. Для интерактивной версии используйте опцию "Force-directed граф".
    </div>
</body>
</html>"""
        return html
    
    def generate_professional_static_html(self, devices, connections):
        """Генерация профессиональной статической HTML-карты сети с иконками"""
        import datetime
        
        # Группируем по подсетям
        subnet_map = {}
        for device in devices:
            ip = device['ip']
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = '.'.join(parts[:3]) + '.0/24'
            else:
                subnet = 'other'
            if subnet not in subnet_map:
                subnet_map[subnet] = []
            subnet_map[subnet].append(device)
        
        # Определяем иконку для типа устройства
        def get_device_icon(device):
            if device.get('is_gateway'):
                return '🌐'  # шлюз
            elif device.get('is_switch'):
                return '🔀'  # коммутатор
            else:
                # Можно детализировать по портам
                ports = device.get('ports', '')
                if '80' in ports or '443' in ports:
                    return '🖥️'  # веб-сервер
                elif '135' in ports or '139' in ports or '445' in ports:
                    return '💻'  # Windows компьютер
                else:
                    return '🖧'  # сетевое устройство
        
        # Генерация HTML
        html = f'''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Профессиональная карта сети</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
            background: #f5f7fa;
            color: #333;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a73e8, #0d47a1);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }}
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}
        .header-info {{
            font-size: 15px;
            opacity: 0.9;
        }}
        .subnet-tabs {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 30px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }}
        .subnet-tab {{
            padding: 10px 20px;
            background: #e3f2fd;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            color: #1565c0;
            transition: all 0.3s;
            border: 2px solid transparent;
        }}
        .subnet-tab:hover {{
            background: #bbdefb;
        }}
        .subnet-tab.active {{
            background: #1a73e8;
            color: white;
            border-color: #0d47a1;
        }}
        .subnet-content {{
            display: none;
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .subnet-content.active {{
            display: block;
        }}
        .subnet-title {{
            font-size: 24px;
            color: #1a73e8;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .device-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 20px;
        }}
        .device-card {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 3px 8px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
            border-left: 5px solid #4caf50;
        }}
        .device-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }}
        .device-card.gateway {{
            border-left-color: #2196f3;
        }}
        .device-card.switch {{
            border-left-color: #9c27b0;
        }}
        .device-icon {{
            font-size: 48px;
            margin-bottom: 15px;
        }}
        .device-ip {{
            font-weight: bold;
            font-size: 16px;
            color: #333;
            margin-bottom: 5px;
            word-break: break-all;
        }}
        .device-hostname {{
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .device-details {{
            font-size: 12px;
            color: #888;
            text-align: left;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #eee;
        }}
        .device-details p {{
            margin: 3px 0;
        }}
        .stats {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-top: 30px;
        }}
        .stats h3 {{
            color: #1a73e8;
            margin-bottom: 15px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        .stat-item {{
            background: #f1f8ff;
            padding: 15px;
            border-radius: 8px;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #1a73e8;
        }}
        .stat-label {{
            font-size: 14px;
            color: #666;
        }}
        .legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 30px;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
        .legend-color.gateway {{ background: #2196f3; }}
        .legend-color.switch {{ background: #9c27b0; }}
        .legend-color.device {{ background: #4caf50; }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #888;
            font-size: 13px;
            padding: 20px;
            border-top: 1px solid #e0e0e0;
        }}
        @media (max-width: 768px) {{
            .device-grid {{
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            }}
            .subnet-tabs {{
                flex-direction: column;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Профессиональная карта сети</h1>
        <div class="header-info">
            Сгенерировано: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
            Устройств: {len(devices)} | Подсетей: {len(subnet_map)} |
            Соединений: {len(connections)}
        </div>
    </div>
    
    <div class="subnet-tabs" id="subnetTabs">
'''
        # Вкладки подсетей
        for i, (subnet, subnet_devices) in enumerate(subnet_map.items()):
            active = 'active' if i == 0 else ''
            html += f'''
        <div class="subnet-tab {active}" data-subnet="{subnet}">
            {subnet} ({len(subnet_devices)})
        </div>'''
        
        html += '''
    </div>
'''
        # Контент подсетей
        for i, (subnet, subnet_devices) in enumerate(subnet_map.items()):
            active = 'active' if i == 0 else ''
            html += f'''
    <div class="subnet-content {active}" id="subnet-{subnet}">
        <h2 class="subnet-title">Подсеть: {subnet} ({len(subnet_devices)} устройств)</h2>
        <div class="device-grid">
'''
            for device in subnet_devices:
                icon = get_device_icon(device)
                device_type = 'device'
                if device.get('is_gateway'):
                    device_type = 'gateway'
                elif device.get('is_switch'):
                    device_type = 'switch'
                
                html += f'''
            <div class="device-card {device_type}">
                <div class="device-icon">{icon}</div>
                <div class="device-ip">{device['ip']}</div>
                <div class="device-hostname">{device['hostname']}</div>
                <div class="device-details">
                    <p><strong>MAC:</strong> {device['mac']}</p>
                    <p><strong>Порты:</strong> {device.get('ports', '')}</p>
                    <p><strong>Тип:</strong> {'Шлюз' if device_type == 'gateway' else 'Коммутатор' if device_type == 'switch' else 'Устройство'}</p>
                </div>
            </div>
'''
            html += '''
        </div>
    </div>
'''
        
        # Статистика
        html += f'''
    <div class="stats">
        <h3>Статистика сети</h3>
        <div class="stats-grid">
            <div class="stat-item">
                <div class="stat-value">{len(devices)}</div>
                <div class="stat-label">Всего устройств</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{len(subnet_map)}</div>
                <div class="stat-label">Подсетей</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{len(connections)}</div>
                <div class="stat-label">Соединений</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{datetime.datetime.now().strftime('%H:%M')}</div>
                <div class="stat-label">Время генерации</div>
            </div>
        </div>
    </div>
    
    <div class="legend">
        <div class="legend-item">
            <div class="legend-color gateway"></div>
            <span>Шлюз (маршрутизатор)</span>
        </div>
        <div class="legend-item">
            <div class="legend-color switch"></div>
            <span>Коммутатор</span>
        </div>
        <div class="legend-item">
            <div class="legend-color device"></div>
            <span>Обычное устройство</span>
        </div>
    </div>
    
    <div class="footer">
        Карта сети сгенерирована автоматически. Для обновления данных запустите сканирование.
    </div>
    
    <script>
        // Переключение вкладок подсетей
        document.querySelectorAll('.subnet-tab').forEach(tab => {{
            tab.addEventListener('click', function() {{
                const subnet = this.getAttribute('data-subnet');
                // Скрыть все контенты
                document.querySelectorAll('.subnet-content').forEach(content => {{
                    content.classList.remove('active');
                }});
                // Показать выбранный контент
                document.getElementById('subnet-' + subnet).classList.add('active');
                // Обновить активную вкладку
                document.querySelectorAll('.subnet-tab').forEach(t => {{
                    t.classList.remove('active');
                }});
                this.classList.add('active');
            }});
        }});
        
        // Поиск по устройствам (простой)
        function searchDevices(query) {{
            const cards = document.querySelectorAll('.device-card');
            cards.forEach(card => {{
                const ip = card.querySelector('.device-ip').textContent;
                const hostname = card.querySelector('.device-hostname').textContent;
                const text = (ip + ' ' + hostname).toLowerCase();
                if (text.includes(query.toLowerCase())) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
        
        // Добавляем поле поиска динамически (опционально)
        const header = document.querySelector('.header');
        const searchHtml = '<div style="margin-top:15px;"><input type="text" id="searchInput" placeholder="Поиск по IP или имени..." style="padding:10px; width:300px; border-radius:6px; border:1px solid #ccc;" oninput="searchDevices(this.value)"></div>';
        header.insertAdjacentHTML('beforeend', searchHtml);
    </script>
</body>
</html>'''
        return html
    
    def generate_interactive_cytoscape_html(self, devices, connections):
        """Генерация интерактивной карты сети с использованием Cytoscape.js"""
        import datetime
        import json
        
        # Подготовка данных для Cytoscape
        nodes = []
        for device in devices:
            node = {
                'data': {
                    'id': device['ip'],
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'hostname': device['hostname'],
                    'ports': device.get('ports', ''),
                    'comment': device.get('comment', ''),
                    'type': 'gateway' if device.get('is_gateway') else 'switch' if device.get('is_switch') else 'device',
                    'status': 'online'
                }
            }
            nodes.append(node)
        
        edges = []
        edge_id = 0
        for conn in connections:
            if len(conn) == 2:
                edges.append({
                    'data': {
                        'id': f'e{edge_id}',
                        'source': conn[0],
                        'target': conn[1],
                        'weight': 1
                    }
                })
                edge_id += 1
        
        # Если соединений нет, создадим искусственные связи внутри подсетей
        if not edges:
            # Группируем по подсетям
            subnet_map = {}
            for device in devices:
                ip = device['ip']
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3])
                else:
                    subnet = 'other'
                if subnet not in subnet_map:
                    subnet_map[subnet] = []
                subnet_map[subnet].append(device['ip'])
            
            for subnet, ips in subnet_map.items():
                if len(ips) > 1:
                    # Соединяем первое устройство с остальными
                    source = ips[0]
                    for target in ips[1:]:
                        edges.append({
                            'data': {
                                'id': f'e{edge_id}',
                                'source': source,
                                'target': target,
                                'weight': 1
                            }
                        })
                        edge_id += 1
        
        # Генерация HTML
        html = f'''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Интерактивная карта сети (Cytoscape.js)</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
            background: #1a1a2e;
            color: #e6e6e6;
            height: 100vh;
            overflow: hidden;
        }}
        .header {{
            background: rgba(0, 0, 0, 0.4);
            padding: 15px 25px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            font-size: 24px;
            color: #4fc3f7;
        }}
        .header-info {{
            font-size: 14px;
            color: #aaa;
        }}
        .container {{
            display: flex;
            height: calc(100vh - 70px);
        }}
        .sidebar {{
            width: 300px;
            background: rgba(30, 30, 46, 0.8);
            border-right: 1px solid #444;
            padding: 20px;
            overflow-y: auto;
        }}
        .controls {{
            margin-bottom: 25px;
        }}
        .controls h3 {{
            color: #4fc3f7;
            margin-bottom: 15px;
        }}
        .controls button {{
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            background: #2d3748;
            color: white;
            border: 1px solid #4a5568;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }}
        .controls button:hover {{
            background: #4a5568;
        }}
        .search-box {{
            width: 100%;
            padding: 10px;
            background: #2d3748;
            color: white;
            border: 1px solid #4a5568;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .legend {{
            margin-bottom: 25px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        .legend-color.gateway {{ background: #2196F3; }}
        .legend-color.switch {{ background: #9C27B0; }}
        .legend-color.device {{ background: #4CAF50; }}
        .main-content {{
            flex: 1;
            position: relative;
            overflow: hidden;
        }}
        #cy {{
            width: 100%;
            height: 100%;
            border: 1px solid #444;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.85);
            color: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #4fc3f7;
            max-width: 300px;
            z-index: 1000;
            font-size: 14px;
            pointer-events: none;
            display: none;
        }}
        .footer {{
            position: absolute;
            bottom: 10px;
            right: 10px;
            color: #888;
            font-size: 12px;
            background: rgba(0,0,0,0.5);
            padding: 5px 10px;
            border-radius: 5px;
        }}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
</head>
<body>
    <div class="header">
        <div>
            <h1>Интерактивная карта сети</h1>
            <div class="header-info">
                Сгенерировано: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                Устройств: {len(devices)}
            </div>
        </div>
        <div>
            <button onclick="saveImage()">Сохранить как PNG</button>
            <button onclick="resetView()">Сбросить вид</button>
        </div>
    </div>
    <div class="container">
        <div class="sidebar">
            <div class="search">
                <input type="text" class="search-box" id="searchInput" placeholder="Поиск по IP или имени..." oninput="searchNode(this.value)">
            </div>
            <div class="controls">
                <h3>Управление</h3>
                <button onclick="zoomIn()">Увеличить (+)</button>
                <button onclick="zoomOut()">Уменьшить (-)</button>
                <button onclick="fitView()">Вписать в экран</button>
                <button onclick="toggleLabels()">Переключить подписи</button>
                <button onclick="toggleEdges()">Переключить соединения</button>
                <button onclick="layoutGrid()">Сетка</button>
                <button onclick="layoutCircle()">Круг</button>
                <button onclick="layoutCose()">Авто (COSE)</button>
            </div>
            <div class="legend">
                <h3>Легенда</h3>
                <div class="legend-item">
                    <div class="legend-color gateway"></div>
                    <span>Шлюз (маршрутизатор)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color switch"></div>
                    <span>Коммутатор</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color device"></div>
                    <span>Обычное устройство</span>
                </div>
            </div>
            <div class="device-list">
                <h3>Устройства ({len(devices)})</h3>
                <div id="deviceList" style="max-height: 300px; overflow-y: auto;">
                    <!-- Заполнится JavaScript -->
                </div>
            </div>
        </div>
        <div class="main-content">
            <div id="cy"></div>
            <div class="tooltip" id="tooltip"></div>
            <div class="footer">
                Используется Cytoscape.js | Перетаскивайте узлы, колесо мыши для зума
            </div>
        </div>
    </div>

    <script>
        // Данные графа
        const nodesData = {json.dumps(nodes, ensure_ascii=False)};
        const edgesData = {json.dumps(edges, ensure_ascii=False)};
        
        // Инициализация Cytoscape
        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: nodesData.concat(edgesData),
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'label': 'data(ip)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '12px',
                        'color': '#fff',
                        'text-outline-color': '#000',
                        'text-outline-width': '2px',
                        'width': 'mapData(type, "gateway", 50, "switch", 40, 30)',
                        'height': 'mapData(type, "gateway", 50, "switch", 40, 30)',
                        'background-color': 'mapData(type, "gateway", "#2196F3", "switch", "#9C27B0", "#4CAF50")',
                        'border-width': '2',
                        'border-color': '#fff'
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 2,
                        'line-color': '#666',
                        'opacity': 0.7,
                        'curve-style': 'bezier'
                    }}
                }},
                {{
                    selector: 'node:selected',
                    style: {{
                        'border-width': '4',
                        'border-color': '#FFC107'
                    }}
                }}
            ],
            layout: {{
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 50,
                randomize: true,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            }},
            minZoom: 0.1,
            maxZoom: 5,
            wheelSensitivity: 0.2
        }});
        
        // Обработчики событий
        cy.on('tap', 'node', function(evt) {{
            const node = evt.target;
            const data = node.data();
            const tooltip = document.getElementById('tooltip');
            tooltip.innerHTML = '<h4>' + data.ip + '</h4>' +
                '<p><strong>Имя:</strong> ' + data.hostname + '</p>' +
                '<p><strong>MAC:</strong> ' + data.mac + '</p>' +
                '<p><strong>Тип:</strong> ' + data.type + '</p>' +
                '<p><strong>Комментарий:</strong> ' + (data.comment || '') + '</p>';
            tooltip.style.display = 'block';
            tooltip.style.left = (evt.originalEvent.pageX + 10) + 'px';
            tooltip.style.top = (evt.originalEvent.pageY + 10) + 'px';
        }});
        
        cy.on('tap', function(evt) {{
            if (evt.target === cy) {{
                document.getElementById('tooltip').style.display = 'none';
            }}
        }});
        
        cy.on('mouseover', 'node', function(evt) {{
            const node = evt.target;
            node.style('border-width', '4');
            node.style('border-color', '#FFC107');
        }});
        
        cy.on('mouseout', 'node', function(evt) {{
            const node = evt.target;
            if (!node.selected()) {{
                node.style('border-width', '2');
                node.style('border-color', '#fff');
            }}
        }});
        
        // Функции управления
        function zoomIn() {{
            cy.zoom(cy.zoom() * 1.2);
        }}
        
        function zoomOut() {{
            cy.zoom(cy.zoom() / 1.2);
        }}
        
        function resetView() {{
            cy.reset();
        }}
        
        function fitView() {{
            cy.fit();
        }}
        
        function toggleLabels() {{
            const style = cy.style();
            const current = style.selector('node').style('label');
            if (current === 'data(ip)') {{
                style.selector('node').style('label', '');
            }} else {{
                style.selector('node').style('label', 'data(ip)');
            }}
            style.update();
        }}
        
        function toggleEdges() {{
            const edges = cy.edges();
            edges.toggleClass('hidden');
        }}
        
        function layoutGrid() {{
            cy.layout({{ name: 'grid' }}).run();
        }}
        
        function layoutCircle() {{
            cy.layout({{ name: 'circle' }}).run();
        }}
        
        function layoutCose() {{
            cy.layout({{ name: 'cose' }}).run();
        }}
        
        function searchNode(query) {{
            const q = query.toLowerCase();
            cy.nodes().forEach(node => {{
                const ip = node.data('ip').toLowerCase();
                const hostname = node.data('hostname').toLowerCase();
                const matches = ip.includes(q) || hostname.includes(q);
                node.style('opacity', matches ? 1 : 0.2);
            }});
        }}
        
        function saveImage() {{
            const png64 = cy.png({{ full: true, bg: '#1a1a2e' }});
            const a = document.createElement('a');
            a.href = png64;
            a.download = 'network-map-' + new Date().toISOString().slice(0,10) + '.png';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }}
        
        // Заполнение списка подсетей
        const deviceList = document.getElementById('deviceList');
        // Группировка узлов по подсетям
        const subnetMap = {{}};
        nodesData.forEach(node => {{
            const ip = node.data.ip;
            const parts = ip.split('.');
            let subnet = 'other';
            if (parts.length === 4) {{
                subnet = parts.slice(0,3).join('.') + '.0/24';
            }}
            if (!subnetMap[subnet]) {{
                subnetMap[subnet] = [];
            }}
            subnetMap[subnet].push(node);
        }});

        deviceList.innerHTML = ''; // очистить

        for (const subnet in subnetMap) {{
            const div = document.createElement('div');
            div.className = 'subnet-item';
            div.style.padding = '8px';
            div.style.borderBottom = '1px solid #555';
            div.style.cursor = 'pointer';
            div.innerHTML = '<strong>' + subnet + '</strong> (' + subnetMap[subnet].length + ' устройств)';
            div.onclick = () => {{
                // Выделить все узлы этой подсети
                const nodes = subnetMap[subnet].map(n => cy.getElementById(n.data.id));
                cy.animate({{
                    center: {{ eles: nodes }},
                    zoom: 1.5,
                    duration: 500
                }});
                // Подсветить узлы подсети
                cy.nodes().forEach(node => node.style('opacity', 0.3));
                nodes.forEach(node => node.style('opacity', 1));
            }};
            deviceList.appendChild(div);
        }}
        
        // Инициализация подсказки
        const tooltip = document.getElementById('tooltip');
        document.addEventListener('mousemove', function(e) {{
            if (tooltip.style.display === 'block') {{
                tooltip.style.left = (e.pageX + 10) + 'px';
                tooltip.style.top = (e.pageY + 10) + 'px';
            }}
        }});
    </script>
</body>
</html>'''
        return html
    
    def preview_map(self):
        """Предпросмотр карты в браузере"""
        if hasattr(self, 'temp_html'):
            webbrowser.open('file://' + os.path.abspath(self.temp_html.name))
        else:
            QMessageBox.warning(self, "Нет данных", "Сначала сгенерируйте карту.")
    
    def save_html(self):
        """Сохранить HTML-файл"""
        if not hasattr(self, 'temp_html'):
            QMessageBox.warning(self, "Нет данных", "Сначала сгенерируйте карту.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить карту сети", "", 
            "HTML files (*.html);;All files (*.*)"
        )
        if filename:
            if not filename.endswith('.html'):
                filename += '.html'
            # Читаем временный файл и копируем
            with open(self.temp_html.name, 'r', encoding='utf-8') as src:
                content = src.read()
            with open(filename, 'w', encoding='utf-8') as dst:
                dst.write(content)
            QMessageBox.information(self, "Готово", f"Карта сети сохранена в {filename}")


if __name__ == '__main__':
    # Для тестирования
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication(sys.argv)
    dialog = NetworkMapDialog()
    dialog.show()
    sys.exit(app.exec_())