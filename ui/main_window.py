"""
Головний модуль графічного інтерфейсу програми NetSentinel.
Реалізує сучасний світлий дизайн, багатопотоковість та взаємодію з модулями аналізу.
"""

import threading
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QLineEdit, QFrame, QStackedWidget,
    QHeaderView, QScrollArea, QComboBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QColor

from capture.packet_capture import PacketCapture, FILTER_PRESETS
from analysis.traffic_analyzer import TrafficAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from storage.data_export import DataExporter
from visualization.charts import plot_top_ips, plot_top_ports, plot_protocol_pie, plot_traffic_timeline
from analysis.app_analyzer import AppAnalyzer


# Шрифти
UI_FONT = "Segoe UI"
DATA_FONT = "Consolas"

# Світла кольорова палітра
COLORS = {
    "bg_main": "#F3F4F6",        # Основний фон (сірий)
    "bg_panel": "#FFFFFF",       # Фон панелей (білий)
    "border": "#E5E7EB",         # Межі
    "text_primary": "#111827",   # Основний текст
    "text_muted": "#6B7280",     # Вторинний текст
    "primary": "#3B82F6",        # Синій (акценти)
    "success": "#10B981",        # Зелений (старт/ок)
    "danger": "#EF4444",         # Червоний (стоп/помилки)
    "warning": "#F59E0B",        # Жовтий (алерти)
    "purple": "#8B5CF6",         # Фіолетовий (дод. акцент)
    "sidebar_bg": "#111827",     # Темний сайдбар (для глибокого контрасту)
    "sidebar_text": "#9CA3AF",   # Текст сайдбару (неактивний)
    "sidebar_active": "#F9FAFB", # Текст сайдбару (активний)
}


class SignalBridge(QObject):
    """Клас для безпечної міжпотокової передачі даних (від бекенду до GUI)."""
    packet_received = pyqtSignal(dict)
    alert_received = pyqtSignal(str)


def _lbl(text: str, size: int = 12, bold: bool = False, color: str = COLORS["text_primary"]) -> QLabel:
    """Допоміжна функція для створення текстових міток (QLabel)."""
    label = QLabel(text)
    font = QFont(UI_FONT, size)
    font.setBold(bold)
    label.setFont(font)
    label.setStyleSheet(f"color: {color}; background: transparent; border: none;")
    return label


class StatCard(QFrame):
    """Віджет картки статистики."""

    def __init__(self, title: str, value: str = "0", accent: str = COLORS["primary"]):
        super().__init__()
        self.setObjectName("StatCardBox")
        self.setFixedHeight(80)

        self.setStyleSheet(f"""
            #StatCardBox {{
                background: {COLORS['bg_panel']};
                border: 1px solid {COLORS['border']};
                border-top: 4px solid {accent};
                border-radius: 6px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(2)

        self.val = _lbl(value, 20, True, accent)
        self.ttl = QLabel(title)
        self.ttl.setFont(QFont(UI_FONT, 9, QFont.Bold))
        self.ttl.setStyleSheet(f"color: {COLORS['text_muted']}; background: transparent; border: none; letter-spacing: 1px;")

        layout.addWidget(self.val)
        layout.addWidget(self.ttl)

    def set_value(self, value: any):
        """Оновлює значення на картці."""
        self.val.setText(str(value))


class NavBtn(QPushButton):
    """Кнопка навігаційного меню з роздільними іконкою та текстом."""

    def __init__(self, icon: str, text: str):
        super().__init__()
        self.setCheckable(True)
        self.setFixedHeight(44)

        # Внутрішній компонувальник для розділення іконки і тексту
        self.lay = QHBoxLayout(self)
        self.lay.setContentsMargins(16, 0, 0, 0)
        self.lay.setSpacing(14)

        # Мітка для іконки (БІЛЬШИЙ ШРИФТ)
        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setAttribute(Qt.WA_TransparentForMouseEvents)  # Клік проходить крізь текст на кнопку

        # Мітка для тексту (ЗВИЧАЙНИЙ ШРИФТ)
        self.text_lbl = QLabel(text)
        self.text_lbl.setAttribute(Qt.WA_TransparentForMouseEvents)

        self.lay.addWidget(self.icon_lbl)
        self.lay.addWidget(self.text_lbl)
        self.lay.addStretch()

        # Базовий стиль фону кнопки
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 6px;
            }}
            QPushButton:hover {{
                background: #1F2937;
            }}
            QPushButton:checked {{
                background: #1F2937;
                border-left: 4px solid {COLORS['primary']};
                border-radius: 4px;
            }}
        """)

        self.update_colors()
        self.toggled.connect(self.update_colors)

    # Перехоплюємо наведення миші для плавного підсвічування тексту/іконки
    def enterEvent(self, event):
        super().enterEvent(event)
        self.update_colors(hovered=True)

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.update_colors(hovered=False)

    def update_colors(self, hovered=False):
        if self.isChecked():
            color = COLORS['primary']
        elif hovered:
            color = COLORS['sidebar_active']
        else:
            color = COLORS['sidebar_text']

        # ДОДАНО border: none; щоб скинути випадкові рамки від батьківських QFrame
        self.icon_lbl.setStyleSheet(
            f"color: {color}; font-size: 36px; font-family: 'Segoe UI'; background: transparent; border: none;")
        self.text_lbl.setStyleSheet(
            f"color: {color}; font-size: 13px; font-weight: bold; font-family: '{UI_FONT}', sans-serif; background: transparent; border: none;")

class MainWindow(QMainWindow):
    """Головне вікно програми NetSentinel."""

    STYLE = f"""
    QMainWindow, QStackedWidget {{
        background: {COLORS['bg_main']};
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 12px;
    }}
    QTableWidget {{
        background: {COLORS['bg_panel']};
        alternate-background-color: #F9FAFB;
        color: {COLORS['text_primary']};
        gridline-color: {COLORS['border']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        selection-background-color: #DBEAFE;
        selection-color: {COLORS['text_primary']};
    }}
    QHeaderView::section {{
        background: #F3F4F6;
        color: {COLORS['text_muted']};
        border: none;
        border-bottom: 1px solid {COLORS['border']};
        padding: 8px 10px;
        font-family: 'Segoe UI';
        font-size: 11px;
        font-weight: bold;
        letter-spacing: 1px;
    }}
    QScrollBar:vertical {{ background: #F3F4F6; width: 10px; }}
    QScrollBar::handle:vertical {{ background: #D1D5DB; border-radius: 5px; }}
    QScrollBar::handle:vertical:hover {{ background: #9CA3AF; }}
    QTextEdit {{
        background: {COLORS['bg_panel']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 8px;
        font-family: Consolas, monospace;
        line-height: 1.5;
    }}
    QLineEdit, QComboBox {{
        background: {COLORS['bg_panel']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 5px;
        padding: 6px 12px;
        font-family: 'Segoe UI';
    }}
    QLineEdit:focus, QComboBox:focus {{ border: 1px solid {COLORS['primary']}; }}
    QComboBox::drop-down {{ border: none; }}
    QComboBox QAbstractItemView {{
        background: {COLORS['bg_panel']};
        color: {COLORS['text_primary']};
        selection-background-color: {COLORS['primary']};
        selection-color: white;
    }}
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel · Traffic Analyzer")
        self.resize(1380, 840)
        self.setMinimumSize(1080, 660)
        self.setStyleSheet(self.STYLE)

        # Стан програми
        self.packets = []
        self.alerts = []
        self._start_ts = None
        self._bytes = 0
        self._pkt_last = 0
        self._pkt_t = time.time()
        self._is_sidebar_expanded = True

        # Модулі аналізу
        self.analyzer = TrafficAnalyzer()
        self.app_analyzer = AppAnalyzer()
        self.detector = AnomalyDetector()
        self.capture = PacketCapture(self._raw_callback)

        # Мости сигналів
        self.bridge = SignalBridge()
        self.bridge.packet_received.connect(self._on_packet)
        self.bridge.alert_received.connect(self._on_alert)

        self._build_ui()

        # Таймер оновлення статистики
        self._clock = QTimer()
        self._clock.timeout.connect(self._tick)
        self._clock.start(1000)

    def _build_ui(self):
        """Побудова головної структури інтерфейсу."""
        root = QWidget()
        root.setStyleSheet(f"background: {COLORS['bg_main']};")
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # Ліва бокова панель (Sidebar)
        self.sidebar = self._build_sidebar()
        root_layout.addWidget(self.sidebar)

        # Основна робоча область
        main_area = QWidget()
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self._build_topbar())
        main_layout.addWidget(self._build_statstrip())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_capture())
        self.stack.addWidget(self._page_analysis())
        self.stack.addWidget(self._page_alerts())
        self.stack.addWidget(self._page_export())
        self.stack.addWidget(self._page_apps())
        main_layout.addWidget(self.stack, 1)

        main_layout.addWidget(self._build_statusbar())

        root_layout.addWidget(main_area, 1)

    def _build_sidebar(self) -> QFrame:
        """Створює бокове навігаційне меню."""
        sb = QFrame()
        sb.setFixedWidth(240)
        sb.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['sidebar_bg']};
                border-right: 1px solid #000000;
            }}
        """)
        layout = QVBoxLayout(sb)
        layout.setContentsMargins(12, 16, 12, 20)
        layout.setSpacing(6)

        # Заголовок меню
        header_layout = QHBoxLayout()
        self.menu_toggle_btn = QPushButton("≡")
        self.menu_toggle_btn.setFont(QFont(UI_FONT, 16))
        self.menu_toggle_btn.setFixedSize(36, 36)
        self.menu_toggle_btn.setStyleSheet(f"""
            QPushButton {{ color: {COLORS['sidebar_text']}; border: none; background: transparent; border-radius: 6px; }}
            QPushButton:hover {{ background: #1F2937; color: #FFFFFF; }}
        """)
        self.menu_toggle_btn.clicked.connect(self.toggle_sidebar)

        # Сучасний логотип (зменшено шрифт)
        self.logo_label = QLabel()
        self.logo_label.setText(f"""<span style="color: #FFFFFF; font-weight: bold; font-size: 15px; font-family: '{UI_FONT}'; letter-spacing: 1px;">Net</span><span style="color: {COLORS['primary']}; font-weight: bold; font-size: 15px; font-family: '{UI_FONT}'; letter-spacing: 1px;">Sentinel</span>""")
        self.logo_label.setStyleSheet("background: transparent; border: none; padding-left: 4px;")

        header_layout.addWidget(self.menu_toggle_btn)
        header_layout.addWidget(self.logo_label, 1)
        layout.addLayout(header_layout)

        layout.addSpacing(24)

        # Навігаційні кнопки
        self._navs = []
        nav_items = [
            ("◉", "Capture", 0),
            ("◈", "Analysis", 1),
            ("⚑", "Alerts", 2),
            ("⤓", "Export", 3),
            ("◫", "Applications", 4)
        ]

        for icon, text, idx in nav_items:
            btn = NavBtn(icon, text)
            btn.clicked.connect(lambda _, i=idx: self._navigate(i))
            self._navs.append(btn)
            layout.addWidget(btn)


        self._navs[0].setChecked(True)
        layout.addStretch()

        # Нижня частина сайдбару
        self._clock_lbl = _lbl("--:--:--", 11, True, COLORS["sidebar_text"])
        self._clock_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._clock_lbl)

        return sb

    def toggle_sidebar(self):
        """Анімація згортання та розгортання бокового меню."""
        width = self.sidebar.width()
        target = 60 if self._is_sidebar_expanded else 240
        self._is_sidebar_expanded = not self._is_sidebar_expanded

        # Ховаємо текст логотипу при згортанні
        self.logo_label.setVisible(self._is_sidebar_expanded)

        # Ховаємо текст на кнопках, залишаючи тільки іконки ідеально по центру
        for btn in self._navs:
            btn.text_lbl.setVisible(self._is_sidebar_expanded)
            if self._is_sidebar_expanded:
                btn.lay.setContentsMargins(16, 0, 0, 0)  # Звичайний відступ
            else:
                btn.lay.setContentsMargins(8, 0, 0, 0)  # Центрує іконку у вузькій кнопці

        self.anim = QPropertyAnimation(self.sidebar, b"minimumWidth")
        self.anim.setDuration(250)
        self.anim.setStartValue(width)
        self.anim.setEndValue(target)
        self.anim.setEasingCurve(QEasingCurve.InOutQuart)
        self.anim.start()

        self.anim2 = QPropertyAnimation(self.sidebar, b"maximumWidth")
        self.anim2.setDuration(250)
        self.anim2.setStartValue(width)
        self.anim2.setEndValue(target)
        self.anim2.setEasingCurve(QEasingCurve.InOutQuart)
        self.anim2.start()

    def _navigate(self, idx: int):
        """Перемикає активну сторінку в QStackedWidget."""
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._navs):
            btn.setChecked(i == idx)
        if idx == 4:
            self._refresh_apps()

    def _build_topbar(self) -> QFrame:
        """Створює верхню панель керування."""
        bar = QFrame()
        bar.setFixedHeight(64)
        bar.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_panel']};
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)

        title = _lbl("Live Packet Capture", 13, True, COLORS["text_primary"])
        layout.addWidget(title)
        layout.addStretch()

        # Фільтри
        layout.addWidget(_lbl("Filter:", 10, False, COLORS["text_muted"]))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(list(FILTER_PRESETS.keys()))
        self.filter_combo.setFixedWidth(160)
        self.filter_combo.currentTextChanged.connect(self._on_preset_changed)
        layout.addWidget(self.filter_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp port 80 or udp")
        self.filter_input.setFixedWidth(240)
        self.filter_input.setVisible(False)
        layout.addWidget(self.filter_input)

        # Кнопки керування
        layout.addSpacing(10)

        # Сучасні закруглені кнопки з Hover ефектом
        self.start_btn = self._action_btn("▶ Start", COLORS["success"], "#059669")
        self.stop_btn = self._action_btn("■ Stop", COLORS["danger"], "#DC2626")
        self.stop_btn.setEnabled(False)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        return bar

    def _action_btn(self, text: str, color: str, hover_bg: str) -> QPushButton:
        """Створює сучасну заокруглену кнопку для верхньої панелі."""
        btn = QPushButton(text)
        btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        btn.setFixedSize(110, 36)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {color};
                border: 2px solid {color};
                border-radius: 18px;
            }}
            QPushButton:hover {{ 
                background: {hover_bg};
                color: #FFFFFF;
                border: 2px solid {hover_bg};
            }}
            QPushButton:disabled {{
                background: {COLORS['bg_main']};
                color: {COLORS['text_muted']};
                border: 2px solid {COLORS['border']};
            }}
        """)
        return btn

    def _on_preset_changed(self, text: str):
        """Відображає поле ручного вводу, якщо вибрано Custom."""
        self.filter_input.setVisible(text == "Custom…")

    def _build_statstrip(self) -> QFrame:
        """Створює стрічку з картками статистики."""
        strip = QFrame()
        strip.setFixedHeight(116)
        strip.setStyleSheet(f"background: transparent; border-bottom: 1px solid {COLORS['border']};")
        layout = QHBoxLayout(strip)
        layout.setContentsMargins(24, 14, 24, 14)
        layout.setSpacing(16)

        self.c_total = StatCard("TOTAL PACKETS", "0", COLORS["primary"])
        self.c_ips = StatCard("UNIQUE IPs", "0", COLORS["purple"])
        self.c_alerts = StatCard("ALERTS", "0", COLORS["danger"])
        self.c_bw = StatCard("AVG BANDWIDTH", "0 B/s", COLORS["warning"])
        self.c_tcp = StatCard("TCP PACKETS", "0", COLORS["success"])
        self.c_udp = StatCard("UDP PACKETS", "0", COLORS["success"])

        for card in [self.c_total, self.c_ips, self.c_alerts, self.c_bw, self.c_tcp, self.c_udp]:
            layout.addWidget(card)

        return strip

    def _page_capture(self) -> QWidget:
        """Створює сторінку захоплення трафіку (таблиця + інспектор)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(12)

        header_layout = QHBoxLayout()
        header_layout.addWidget(_lbl("Packet Stream", 12, True, COLORS["text_primary"]))
        header_layout.addStretch()

        clear_btn = QPushButton("Clear Stream")
        clear_btn.setFont(QFont(UI_FONT, 9, QFont.Bold))
        clear_btn.setFixedSize(100, 28)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_panel']}; color: {COLORS['text_muted']};
                border: 1px solid {COLORS['border']}; border-radius: 5px;
            }}
            QPushButton:hover {{ color: {COLORS['danger']}; border-color: {COLORS['danger']}; background: #FEE2E2; }}
        """)
        clear_btn.clicked.connect(self._clear_all)
        header_layout.addWidget(clear_btn)
        layout.addLayout(header_layout)

        # Таблиця пакетів
        self.tbl = QTableWidget()
        self.tbl.setColumnCount(6)
        self.tbl.setHorizontalHeaderLabels(
            ["TIME", "SOURCE IP", "DESTINATION IP", "PROTOCOL", "SRC PORT", "DST PORT / LEN"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setShowGrid(False)
        self.tbl.verticalHeader().setDefaultSectionSize(30)
        self.tbl.cellClicked.connect(self._inspect_packet)
        layout.addWidget(self.tbl, 3)

        layout.addWidget(_lbl("Packet Inspector", 11, True, COLORS["primary"]))

        # Інспектор пакетів
        self.inspector = QTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setFont(QFont(DATA_FONT, 11))
        self.inspector.setFixedHeight(160)
        self.inspector.setPlaceholderText("Select a row in the stream to inspect packet details...")
        layout.addWidget(self.inspector)

        return page

    def _page_analysis(self) -> QWidget:
        """Створює сторінку графічного аналізу."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        layout.addWidget(_lbl("Traffic Analytics", 13, True, COLORS["text_primary"]))

        btn_row = QHBoxLayout()
        buttons = [
            ("Bar: Top 10 IPs", self._show_chart_ips),
            ("Bar: Top Ports", self._show_chart_ports),
            ("Pie: Protocols", self._show_chart_proto),
            ("Line: Timeline", self._show_chart_time)
        ]

        for text, func in buttons:
            btn = QPushButton(text)
            btn.setFont(QFont(UI_FONT, 11))
            btn.setFixedHeight(38)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {COLORS['bg_panel']}; color: {COLORS['primary']};
                    border: 1px solid {COLORS['border']}; border-radius: 6px;
                }}
                QPushButton:hover {{ background: #EFF6FF; border-color: {COLORS['primary']}; }}
            """)
            btn.clicked.connect(func)
            btn_row.addWidget(btn)
        layout.addLayout(btn_row)

        split = QHBoxLayout()
        split.setSpacing(20)

        left_v = QVBoxLayout()
        left_v.addWidget(_lbl("Top Active Sources", 11, True, COLORS["text_primary"]))
        self.tbl_ips = self._create_mini_table(["IP Address", "Packets"])
        left_v.addWidget(self.tbl_ips)

        right_v = QVBoxLayout()
        right_v.addWidget(_lbl("Top Targeted Ports", 11, True, COLORS["text_primary"]))
        self.tbl_ports = self._create_mini_table(["Port", "Packets"])
        right_v.addWidget(self.tbl_ports)

        split.addLayout(left_v)
        split.addLayout(right_v)
        layout.addLayout(split, 1)

        ref_btn = QPushButton("⟳ Refresh Tables")
        ref_btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        ref_btn.setFixedHeight(34)
        ref_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_panel']}; color: {COLORS['success']};
                border: 1px solid {COLORS['border']}; border-radius: 6px;
            }}
            QPushButton:hover {{ border-color: {COLORS['success']}; background: #ECFDF5; }}
        """)
        ref_btn.clicked.connect(self._refresh_analysis_tables)
        layout.addWidget(ref_btn)

        return page

    def _create_mini_table(self, headers: list) -> QTableWidget:
        """Створює допоміжну таблицю для статистики."""
        tbl = QTableWidget()
        tbl.setColumnCount(len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        tbl.setAlternatingRowColors(True)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        tbl.verticalHeader().setVisible(False)
        tbl.setShowGrid(False)
        tbl.verticalHeader().setDefaultSectionSize(28)
        return tbl

    def _page_alerts(self) -> QWidget:
        """Створює сторінку сповіщень безпеки."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(12)

        header_layout = QHBoxLayout()
        header_layout.addWidget(_lbl("Security Anomalies", 13, True, COLORS["text_primary"]))
        header_layout.addStretch()

        clear_btn = QPushButton("Clear Alerts")
        clear_btn.setFont(QFont(UI_FONT, 10))
        clear_btn.setFixedSize(110, 30)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_panel']}; color: {COLORS['danger']};
                border: 1px solid {COLORS['border']}; border-radius: 5px;
            }}
            QPushButton:hover {{ background: #FEE2E2; border-color: {COLORS['danger']}; }}
        """)
        clear_btn.clicked.connect(self._clear_alerts)
        header_layout.addWidget(clear_btn)
        layout.addLayout(header_layout)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: 1px solid {COLORS['border']}; border-radius: 6px; background: {COLORS['bg_panel']}; }}")

        self.alerts_box = QWidget()
        self.alerts_box.setStyleSheet("background: transparent;")
        self.alerts_lay = QVBoxLayout(self.alerts_box)
        self.alerts_lay.setContentsMargins(12, 12, 12, 12)
        self.alerts_lay.setSpacing(8)
        self.alerts_lay.addStretch()

        scroll.setWidget(self.alerts_box)
        layout.addWidget(scroll)

        thr_layout = QHBoxLayout()
        thr_layout.addWidget(_lbl("Alert Threshold (pkts/IP):", 11, False, COLORS["text_muted"]))

        self.thr_input = QLineEdit("300")
        self.thr_input.setFixedWidth(80)

        apply_btn = QPushButton("Apply")
        apply_btn.setFont(QFont(UI_FONT, 10))
        apply_btn.setFixedSize(80, 30)
        apply_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['success']}; color: white;
                border: none; border-radius: 5px;
            }}
            QPushButton:hover {{ background: #059669; }}
        """)
        apply_btn.clicked.connect(self._apply_threshold)

        thr_layout.addWidget(self.thr_input)
        thr_layout.addWidget(apply_btn)
        thr_layout.addStretch()
        layout.addLayout(thr_layout)

        return page

    def _page_export(self) -> QWidget:
        """Створює сторінку експорту даних."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(16)

        layout.addWidget(_lbl("Data Export", 13, True, COLORS["text_primary"]))
        layout.addWidget(_lbl("Save captured packets and statistics to CSV or Excel format.", 11, False, COLORS["text_muted"]))

        exports = [
            ("⤓ Export Packets to CSV", self._export_csv, COLORS["primary"]),
            ("⤓ Export Packets to Excel", self._export_excel, COLORS["success"]),
            ("⤓ Export IP Statistics", self._export_stats, COLORS["purple"]),
        ]

        for text, func, color in exports:
            btn = QPushButton(text)
            btn.setFont(QFont(UI_FONT, 12, QFont.Bold))
            btn.setFixedHeight(50)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {COLORS['bg_panel']}; color: {color};
                    border: 1px solid {COLORS['border']}; border-radius: 6px;
                    text-align: left; padding-left: 24px;
                }}
                QPushButton:hover {{ background: #F9FAFB; border: 1px solid {color}; }}
            """)
            btn.clicked.connect(func)
            layout.addWidget(btn)

        layout.addStretch()

        layout.addWidget(_lbl("Export Log:", 11, True, COLORS["text_primary"]))
        self.exp_log = QTextEdit()
        self.exp_log.setReadOnly(True)
        self.exp_log.setFixedHeight(120)
        self.exp_log.setFont(QFont(DATA_FONT, 10))
        self.exp_log.setPlaceholderText("Export actions will appear here...")
        layout.addWidget(self.exp_log)

        return page

    def _page_apps(self) -> QWidget:
        """Створює сторінку моніторингу додатків (Endopints)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.addWidget(_lbl("Application Endpoints", 13, True, COLORS["text_primary"]))
        header.addStretch()

        ref_btn = QPushButton("⟳ Refresh")
        ref_btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        ref_btn.setFixedSize(100, 30)
        ref_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_panel']}; color: {COLORS['primary']};
                border: 1px solid {COLORS['border']}; border-radius: 5px;
            }}
            QPushButton:hover {{ border-color: {COLORS['primary']}; background: #EFF6FF; }}
        """)
        ref_btn.clicked.connect(self._refresh_apps)
        header.addWidget(ref_btn)
        layout.addLayout(header)

        layout.addWidget(_lbl(
            "Traffic breakdown by identified application (auto-refreshes every 2s)",
            10, False, COLORS["text_muted"]
        ))

        cols = ["APPLICATION", "PACKETS", "TRAFFIC", "CONNECTIONS", "PROTOCOLS"]
        self.tbl_apps = QTableWidget()
        self.tbl_apps.setColumnCount(len(cols))
        self.tbl_apps.setHorizontalHeaderLabels(cols)
        self.tbl_apps.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_apps.setAlternatingRowColors(True)
        self.tbl_apps.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_apps.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_apps.verticalHeader().setVisible(False)
        self.tbl_apps.setShowGrid(False)
        self.tbl_apps.verticalHeader().setDefaultSectionSize(32)

        self.tbl_apps.horizontalHeader().sectionClicked.connect(self._sort_apps)
        self._apps_sort_col = 1
        self._apps_sort_asc = False

        layout.addWidget(self.tbl_apps, 1)

        # Легенда
        leg = QHBoxLayout()
        for color, label in [(COLORS["danger"], "High > 1 MB"),
                             (COLORS["warning"], "Medium > 100 KB"),
                             (COLORS["success"], "Low ≤ 100 KB")]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; background: transparent; font-size: 16px; border: none;")
            leg.addWidget(dot)
            leg.addWidget(_lbl(label, 10, False, COLORS["text_muted"]))
            leg.addSpacing(16)
        leg.addStretch()
        layout.addLayout(leg)

        self._app_timer = QTimer()
        self._app_timer.timeout.connect(self._refresh_apps)
        self._app_timer.start(2000)

        return page

    def _build_statusbar(self) -> QFrame:
        """Створює нижній рядок стану."""
        bar = QFrame()
        bar.setFixedHeight(34)
        bar.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_panel']};
                border-top: 1px solid {COLORS['border']};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)

        self.st_lbl = _lbl("● Idle", 10, True, COLORS["text_muted"])
        layout.addWidget(self.st_lbl)
        layout.addStretch()

        self.rate_lbl = _lbl("0 pkt/s", 10, False, COLORS["text_primary"])
        layout.addWidget(self.rate_lbl)
        layout.addSpacing(24)

        self.total_lbl = _lbl("0 packets total", 10, False, COLORS["text_primary"])
        layout.addWidget(self.total_lbl)

        return bar

    # --- Capture Control ---

    def start_capture(self):
        """Запускає перехоплення пакетів."""
        preset = self.filter_combo.currentText()
        if preset == "Custom…":
            bpf = self.filter_input.text().strip()
        else:
            bpf = FILTER_PRESETS.get(preset, "")

        self.capture.set_filter(bpf)
        self._start_ts = time.time()
        self._bytes = self._pkt_last = 0
        self._pkt_t = time.time()

        t = threading.Thread(target=self.capture.start, daemon=True)
        t.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.st_lbl.setText("● Capturing...")
        self.st_lbl.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; border: none;")

    def stop_capture(self):
        """Зупиняє перехоплення пакетів."""
        self.capture.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.st_lbl.setText("● Stopped")
        self.st_lbl.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; border: none;")

    # --- Packet Pipeline ---

    def _raw_callback(self, packet: dict):
        """Викликається з фонового потоку. Передає дані через SignalBridge."""
        if packet.get("__error__"):
            self.bridge.packet_received.emit(packet)
            return

        packet["time"] = time.strftime("%H:%M:%S")
        self._bytes += packet.get("length", 0)

        try:
            self.analyzer.analyze(packet)
            self.app_analyzer.process_packet(packet)
            alert = self.detector.check(packet)
        except Exception:
            alert = None

        self.bridge.packet_received.emit(packet)
        if alert:
            self.bridge.alert_received.emit(alert)

    def _on_packet(self, packet: dict):
        """Викликається в головному потоці для оновлення GUI."""
        if packet.get("__error__"):
            self._show_error(packet.get("message", "Unknown error"))
            self.stop_capture()
            return

        self.packets.append(packet)
        self._add_table_row(packet)

        n = len(self.packets)
        self.c_total.set_value(n)
        self.c_ips.set_value(len(self.analyzer.ip_counter))
        self.c_tcp.set_value(sum(1 for p in self.packets if p["protocol"] == "TCP"))
        self.c_udp.set_value(sum(1 for p in self.packets if p["protocol"] == "UDP"))
        self.total_lbl.setText(f"{n} packets total")

        if self.stack.currentIndex() == 4 and n % 30 == 0:
            self._refresh_apps()

    def _on_alert(self, msg: str):
        """Додає сповіщення про загрозу."""
        self.alerts.append(msg)
        self.c_alerts.set_value(len(self.alerts))

        color = COLORS["danger"] if "🔴" in msg else COLORS["warning"]
        ts = datetime.now().strftime("%H:%M:%S")

        row = QFrame()
        row.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_panel']};
                border: 1px solid {COLORS['border']};
                border-left: 4px solid {color};
                border-radius: 4px;
                margin: 2px 0;
            }}
        """)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.addWidget(_lbl(ts, 10, False, COLORS["text_muted"]))
        layout.addWidget(_lbl(msg, 10, True, color), 1)

        self.alerts_lay.insertWidget(self.alerts_lay.count() - 1, row)

    def _add_table_row(self, p: dict):
        """Додає рядок пакета у головну таблицю."""
        color_map = {"TCP": COLORS["primary"], "UDP": COLORS["success"], "OTHER": COLORS["warning"]}
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)

        vals = [
            p["time"], p["src_ip"], p["dst_ip"],
            p["protocol"], str(p["src_port"]), f'{p["dst_port"]} / {p["length"]}B'
        ]

        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setFont(QFont(DATA_FONT, 10))
            if col == 3:
                item.setForeground(QColor(color_map.get(val, COLORS["text_primary"])))
                item.setFont(QFont(DATA_FONT, 10, QFont.Bold))
            self.tbl.setItem(row, col, item)

        if row > 300:
            self.tbl.scrollToBottom()

    def _inspect_packet(self, row: int, _=0):
        """Відображає деталі пакета у інспекторі."""
        if row >= len(self.packets):
            return
        p = self.packets[row]

        html = f"""
        <div style="font-family:Consolas, monospace; font-size:11pt; line-height:1.6; color:{COLORS['text_primary']}; padding: 4px;">
          <span style="color:{COLORS['primary']}; font-weight:bold;">=== Frame #{row+1} ======================================</span><br><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Arrival Time:</span>    <span style="color:{COLORS['success']}; font-weight:bold;">{p['time']}</span><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Protocol:</span>        <span style="color:{COLORS['purple']}; font-weight:bold;">{p['protocol']}</span><br><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Source IP:</span>       <span style="color:{COLORS['text_primary']}; font-weight:bold;">{p['src_ip']}</span><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Destination IP:</span>  <span style="color:{COLORS['text_primary']}; font-weight:bold;">{p['dst_ip']}</span><br><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Source Port:</span>     <span style="color:{COLORS['text_primary']}; font-weight:bold;">{p['src_port']}</span><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Dest Port:</span>       <span style="color:{COLORS['text_primary']}; font-weight:bold;">{p['dst_port']}</span><br><br>
          <span style="color:{COLORS['text_muted']}; display:inline-block; width:140px;">Frame Length:</span>    <span style="color:{COLORS['success']}; font-weight:bold;">{p['length']} bytes</span>
        </div>"""
        self.inspector.setHtml(html)

    # --- Analysis & Charts ---

    def _refresh_analysis_tables(self):
        self.tbl_ips.setRowCount(0)
        for ip, cnt in self.analyzer.get_top_ips():
            r = self.tbl_ips.rowCount()
            self.tbl_ips.insertRow(r)
            self.tbl_ips.setItem(r, 0, QTableWidgetItem(ip))
            self.tbl_ips.setItem(r, 1, QTableWidgetItem(str(cnt)))

        self.tbl_ports.setRowCount(0)
        for port, cnt in self.analyzer.get_top_ports():
            r = self.tbl_ports.rowCount()
            self.tbl_ports.insertRow(r)
            self.tbl_ports.setItem(r, 0, QTableWidgetItem(str(port)))
            self.tbl_ports.setItem(r, 1, QTableWidgetItem(str(cnt)))

    def _show_chart_ips(self): plot_top_ips(self.analyzer.get_top_ips())
    def _show_chart_ports(self): plot_top_ports(self.analyzer.get_top_ports())
    def _show_chart_proto(self):
        tcp = sum(1 for p in self.packets if p["protocol"] == "TCP")
        udp = sum(1 for p in self.packets if p["protocol"] == "UDP")
        plot_protocol_pie({"TCP": tcp, "UDP": udp, "OTHER": len(self.packets) - tcp - udp})
    def _show_chart_time(self): plot_traffic_timeline(self.packets)

    # --- Endpoints / Apps ---

    def _refresh_apps(self):
        summary = self.app_analyzer.get_summary()
        self.tbl_apps.setRowCount(0)

        for row_data in summary:
            row = self.tbl_apps.rowCount()
            self.tbl_apps.insertRow(row)

            mb = row_data["mb"]
            b = row_data["bytes"]

            if b >= 1_048_576:
                traffic_str = f"{b / 1_048_576:.2f} MB"
            elif b >= 1024:
                traffic_str = f"{b / 1024:.1f} KB"
            else:
                traffic_str = f"{b} B"

            if mb > 1:
                bg_color = QColor("#FEE2E2")
                txt_color = COLORS["danger"]
            elif mb > 0.1:
                bg_color = QColor("#FEF3C7")
                txt_color = COLORS["warning"]
            else:
                bg_color = QColor("#D1FAE5")
                txt_color = COLORS["success"]

            values = [
                row_data["application"], str(row_data["packets"]),
                traffic_str, str(row_data["connections"]), row_data["protocols"]
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFont(QFont(DATA_FONT, 10))

                # Apply background only to traffic column for cleaner UI
                if col == 2:
                    item.setBackground(bg_color)
                    item.setForeground(QColor(txt_color))
                    item.setFont(QFont(DATA_FONT, 10, QFont.Bold))
                elif col == 0:
                    item.setFont(QFont(DATA_FONT, 10, QFont.Bold))

                self.tbl_apps.setItem(row, col, item)

    def _sort_apps(self, col: int):
        if self._apps_sort_col == col:
            self._apps_sort_asc = not self._apps_sort_asc
        else:
            self._apps_sort_col = col
            self._apps_sort_asc = False

        order = Qt.AscendingOrder if self._apps_sort_asc else Qt.DescendingOrder
        self.tbl_apps.sortItems(col, order)

    # --- Other Actions ---

    def _clear_alerts(self):
        self.alerts.clear()
        while self.alerts_lay.count() > 1:
            widget = self.alerts_lay.takeAt(0).widget()
            if widget:
                widget.deleteLater()
        self.c_alerts.set_value(0)

    def _apply_threshold(self):
        try:
            self.detector.threshold = int(self.thr_input.text())
        except ValueError:
            pass

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "packets.csv", "CSV (*.csv)")
        if path:
            DataExporter(self.packets).export_csv(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] Success: Exported packets to {path}")

    def _export_excel(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Excel", "packets.xlsx", "Excel (*.xlsx)")
        if path:
            DataExporter(self.packets).export_excel(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] Success: Exported packets to {path}")

    def _export_stats(self):
        import pandas as pd
        path, _ = QFileDialog.getSaveFileName(self, "Save Stats", "stats.csv", "CSV (*.csv)")
        if path:
            rows = [{"ip": ip, "packets": c} for ip, c in self.analyzer.ip_counter.items()]
            pd.DataFrame(rows).to_csv(path, index=False)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] Success: Exported statistics to {path}")

    def _clear_all(self):
        self.packets.clear()
        self.tbl.setRowCount(0)
        self.inspector.clear()
        self.c_total.set_value(0)
        self.c_tcp.set_value(0)
        self.c_udp.set_value(0)
        self.app_analyzer.reset()

    def _tick(self):
        """Щосекундне оновлення метрик."""
        self._clock_lbl.setText(time.strftime("%H:%M:%S"))
        elapsed = time.time() - self._start_ts if self._start_ts else 1
        bw = self._bytes / max(elapsed, 1)

        if bw >= 1_000_000:
            bw_str = f"{bw/1_000_000:.1f} MB/s"
        elif bw >= 1000:
            bw_str = f"{bw/1000:.1f} KB/s"
        else:
            bw_str = f"{int(bw)} B/s"
        self.c_bw.set_value(bw_str)

        now = time.time()
        n = len(self.packets)
        dt = now - self._pkt_t
        if dt >= 1.0:
            self.rate_lbl.setText(f"{(n - self._pkt_last)/dt:.0f} pkt/s")
            self._pkt_last = n
            self._pkt_t = now

    def _show_error(self, msg: str):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Capture Error")
        dlg.setText(msg)
        dlg.setIcon(QMessageBox.Warning)
        dlg.setStyleSheet(f"""
            QMessageBox {{ background: {COLORS['bg_panel']}; }}
            QLabel {{ color: {COLORS['text_primary']}; font-size: 11px; }}
            QPushButton {{
                background: {COLORS['bg_main']}; color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']}; border-radius: 4px; padding: 6px 16px;
            }}
        """)
        dlg.exec_()