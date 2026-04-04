import threading
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QLineEdit, QFrame, QStackedWidget,
    QHeaderView, QSizePolicy, QScrollArea, QComboBox,
    QProgressBar, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon

from capture.packet_capture import PacketCapture
from analysis.traffic_analyzer import TrafficAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from storage.data_export import DataExporter
from visualization.charts import plot_top_ips, plot_top_ports, plot_protocol_pie, plot_traffic_timeline


# ─────────────────────────────────────────────
#  Signal bridge (cross-thread UI updates)
# ─────────────────────────────────────────────
class SignalBridge(QObject):
    packet_received = pyqtSignal(dict)
    alert_received  = pyqtSignal(str)


# ─────────────────────────────────────────────
#  Reusable styled widgets
# ─────────────────────────────────────────────
def _label(text, size=13, bold=False, color="#c9d1d9"):
    lbl = QLabel(text)
    font = QFont("Consolas", size)
    font.setBold(bold)
    lbl.setFont(font)
    lbl.setStyleSheet(f"color: {color}; background: transparent;")
    return lbl


def _separator():
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet("color: #30363d;")
    return line


class StatCard(QFrame):
    """Small metric card for the dashboard strip."""

    def __init__(self, title: str, value: str = "0", accent: str = "#00ff88"):
        super().__init__()
        self._accent = accent
        self.setFixedHeight(88)
        self.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid #30363d;
                border-top: 3px solid {accent};
                border-radius: 6px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        self.value_lbl = _label(value, size=22, bold=True, color=accent)
        self.title_lbl = _label(title, size=9, color="#8b949e")
        layout.addWidget(self.value_lbl)
        layout.addWidget(self.title_lbl)

    def update_value(self, val: str):
        self.value_lbl.setText(val)


class NavButton(QPushButton):
    """Sidebar navigation button."""

    def __init__(self, text: str, icon_char: str = "▶"):
        super().__init__(f"  {icon_char}  {text}")
        self.setCheckable(True)
        self.setFont(QFont("Consolas", 10))
        self.setFixedHeight(42)
        self.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #8b949e;
                border: none;
                text-align: left;
                padding-left: 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #21262d;
                color: #c9d1d9;
            }
            QPushButton:checked {
                background: #0d1117;
                color: #00ff88;
                border-left: 3px solid #00ff88;
            }
        """)


class AlertRow(QFrame):
    """Single alert entry in the alert log."""

    COLORS = {
        "⚠": "#ffa500",
        "🔴": "#ff4444",
        "ℹ": "#4d9eff",
    }

    def __init__(self, message: str):
        super().__init__()
        icon = message[0] if message[0] in self.COLORS else "⚠"
        color = self.COLORS.get(icon, "#ffa500")
        ts = datetime.now().strftime("%H:%M:%S")

        self.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border-left: 3px solid {color};
                border-radius: 3px;
                margin: 2px 0;
            }}
        """)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 6, 10, 6)

        row.addWidget(_label(ts, size=9, color="#8b949e"))
        row.addWidget(_label(message, size=9, color=color), stretch=1)


# ─────────────────────────────────────────────
#  Main Window
# ─────────────────────────────────────────────
class MainWindow(QMainWindow):

    BASE_STYLE = """
        QMainWindow, QWidget {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: Consolas, 'Courier New', monospace;
        }
        QTableWidget {
            background-color: #161b22;
            alternate-background-color: #1c2128;
            color: #c9d1d9;
            gridline-color: #30363d;
            border: 1px solid #30363d;
            border-radius: 6px;
            selection-background-color: #1f6feb33;
            selection-color: #4d9eff;
        }
        QHeaderView::section {
            background-color: #21262d;
            color: #8b949e;
            border: none;
            border-bottom: 1px solid #30363d;
            padding: 6px 10px;
            font-size: 10px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        QScrollBar:vertical {
            background: #161b22;
            width: 8px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #30363d;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background: #4d9eff;
        }
        QScrollBar:horizontal { height: 8px; background: #161b22; }
        QScrollBar::handle:horizontal { background: #30363d; border-radius: 4px; }
        QTextEdit {
            background-color: #161b22;
            color: #7ee787;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 8px;
        }
        QLineEdit {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 5px;
            padding: 6px 10px;
        }
        QLineEdit:focus {
            border: 1px solid #4d9eff;
        }
        QComboBox {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 5px;
            padding: 5px 10px;
        }
        QComboBox::drop-down { border: none; }
        QComboBox QAbstractItemView {
            background: #161b22;
            color: #c9d1d9;
            selection-background-color: #1f6feb;
        }
        QToolTip {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 4px 8px;
        }
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel  ·  Traffic Analyzer")
        self.resize(1400, 860)
        self.setMinimumSize(1100, 680)
        self.setStyleSheet(self.BASE_STYLE)

        self.packets   = []
        self.alerts    = []
        self._start_ts = None
        self._bytes    = 0

        self.analyzer = TrafficAnalyzer()
        self.detector = AnomalyDetector()
        self.capture  = PacketCapture(self._on_packet_raw)

        self.bridge = SignalBridge()
        self.bridge.packet_received.connect(self._on_packet_ui)
        self.bridge.alert_received.connect(self._on_alert_ui)

        self._build_ui()

        # Live clock / bandwidth timer
        self._timer = QTimer()
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    # ──────────────────────────────────────────
    #  UI construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        root_layout.addWidget(self._build_sidebar())

        # Main area
        main_area = QWidget()
        main_area.setStyleSheet("background: #0d1117;")
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self._build_topbar())
        main_layout.addWidget(self._build_stat_strip())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_capture_page())   # 0
        self.stack.addWidget(self._build_analysis_page())  # 1
        self.stack.addWidget(self._build_alerts_page())    # 2
        self.stack.addWidget(self._build_export_page())    # 3
        main_layout.addWidget(self.stack, stretch=1)

        main_layout.addWidget(self._build_statusbar())

        root_layout.addWidget(main_area, stretch=1)

    # ── Sidebar ──────────────────────────────
    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet("""
            QFrame {
                background: #010409;
                border-right: 1px solid #21262d;
            }
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 20, 10, 20)
        layout.setSpacing(4)

        # Logo
        logo = _label("⬡ NetSentinel", size=13, bold=True, color="#00ff88")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("color: #00ff88; background: transparent; letter-spacing: 2px;")
        layout.addWidget(logo)
        layout.addWidget(_label("v1.0  ·  Traffic Analyzer", size=8, color="#3d444d"))
        layout.addSpacing(20)
        layout.addWidget(_separator())
        layout.addSpacing(10)

        self._nav_btns = []
        pages = [
            ("Capture",  "◉", 0),
            ("Analysis", "◈", 1),
            ("Alerts",   "⚑", 2),
            ("Export",   "⤓", 3),
        ]
        for name, icon, idx in pages:
            btn = NavButton(name, icon)
            btn.clicked.connect(lambda _, i=idx: self._nav(i))
            self._nav_btns.append(btn)
            layout.addWidget(btn)

        self._nav_btns[0].setChecked(True)
        layout.addStretch()

        # Bottom info
        layout.addWidget(_separator())
        self.clock_lbl = _label("--:--:--", size=9, color="#3d444d")
        self.clock_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.clock_lbl)

        return sidebar

    def _nav(self, idx: int):
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_btns):
            btn.setChecked(i == idx)

    # ── Top bar ──────────────────────────────
    def _build_topbar(self):
        bar = QFrame()
        bar.setFixedHeight(56)
        bar.setStyleSheet("""
            QFrame {
                background: #010409;
                border-bottom: 1px solid #21262d;
            }
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(10)

        layout.addWidget(_label("LIVE CAPTURE", size=10, bold=True, color="#4d9eff"))
        layout.addStretch()

        # Interface selector
        layout.addWidget(_label("Interface:", size=9, color="#8b949e"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(["eth0", "wlan0", "lo", "any"])
        self.iface_combo.setFixedWidth(110)
        layout.addWidget(self.iface_combo)

        layout.addSpacing(10)

        # Filter preset dropdown
        layout.addWidget(_label("Filter:", size=9, color="#8b949e"))
        from capture.packet_capture import FILTER_PRESETS
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(list(FILTER_PRESETS.keys()))
        self.filter_combo.setFixedWidth(130)
        self.filter_combo.currentTextChanged.connect(self._on_filter_preset)
        layout.addWidget(self.filter_combo)

        # Custom BPF input (shown only when "Custom…" is selected)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF: tcp or udp  /  port 80 …")
        self.filter_input.setFixedWidth(220)
        self.filter_input.setVisible(False)
        layout.addWidget(self.filter_input)

        layout.addSpacing(10)

        self.start_btn = self._action_btn("▶  Start", "#00ff88", "#003322")
        self.stop_btn = self._action_btn("■  Stop", "#ff4444", "#330000")
        self.stop_btn.setEnabled(False)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)

        return bar

    def _on_filter_preset(self, text):
        """Show the custom text box only when 'Custom…' is chosen."""
        self.filter_input.setVisible(text == "Custom…")




    def _action_btn(self, text, fg, bg):
        btn = QPushButton(text)
        btn.setFont(QFont("Consolas", 10, QFont.Bold))
        btn.setFixedSize(110, 34)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: 1px solid {fg}55;
                border-radius: 5px;
            }}
            QPushButton:hover {{
                background: {fg}22;
                border: 1px solid {fg};
            }}
            QPushButton:disabled {{
                background: #161b22;
                color: #3d444d;
                border: 1px solid #21262d;
            }}
        """)
        return btn

    # ── Stat strip ───────────────────────────
    def _build_stat_strip(self):
        strip = QFrame()
        strip.setFixedHeight(104)
        strip.setStyleSheet("QFrame { background: #0d1117; border-bottom: 1px solid #21262d; }")
        layout = QHBoxLayout(strip)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(12)

        self.card_total   = StatCard("TOTAL PACKETS",     "0",        "#00ff88")
        self.card_ips     = StatCard("UNIQUE IPs",        "0",        "#4d9eff")
        self.card_alerts  = StatCard("ALERTS",            "0",        "#ff4444")
        self.card_bw      = StatCard("AVG BANDWIDTH",     "0 B/s",    "#ffa500")
        self.card_tcp     = StatCard("TCP",               "0",        "#a371f7")
        self.card_udp     = StatCard("UDP",               "0",        "#39d353")

        for card in [self.card_total, self.card_ips, self.card_alerts,
                     self.card_bw, self.card_tcp, self.card_udp]:
            layout.addWidget(card)

        return strip

    # ── Capture page ─────────────────────────
    def _build_capture_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        layout.addWidget(_label("Packet Stream", size=11, bold=True, color="#8b949e"))

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(
            ["TIME", "SOURCE IP", "DESTINATION IP", "PROTOCOL", "SRC PORT", "DST PORT  /  LENGTH"]
        )
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setShowGrid(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(26)
        self.packet_table.cellClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table, stretch=3)

        # Details panel
        detail_header = QHBoxLayout()
        detail_header.addWidget(_label("Packet Inspector", size=10, bold=True, color="#4d9eff"))
        clear_btn = QPushButton("Clear all")
        clear_btn.setFont(QFont("Consolas", 8))
        clear_btn.setFixedSize(80, 24)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 4px;
            }
            QPushButton:hover { color: #ff4444; border-color: #ff4444; }
        """)
        clear_btn.clicked.connect(self._clear_packets)
        detail_header.addStretch()
        detail_header.addWidget(clear_btn)
        layout.addLayout(detail_header)

        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setFont(QFont("Consolas", 10))
        self.packet_details.setFixedHeight(140)
        self.packet_details.setPlaceholderText("Click a packet row to inspect…")
        layout.addWidget(self.packet_details)

        return page

    # ── Analysis page ────────────────────────
    def _build_analysis_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)

        layout.addWidget(_label("Traffic Analysis", size=11, bold=True, color="#8b949e"))

        btn_row = QHBoxLayout()
        charts = [
            ("Top 10 IPs",     self._chart_ips),
            ("Top Ports",      self._chart_ports),
            ("Protocol Split", self._chart_proto),
            ("Timeline",       self._chart_timeline),
        ]
        for txt, fn in charts:
            b = QPushButton(txt)
            b.setFont(QFont("Consolas", 10))
            b.setFixedHeight(34)
            b.setStyleSheet("""
                QPushButton {
                    background: #161b22;
                    color: #4d9eff;
                    border: 1px solid #30363d;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background: #1f6feb22;
                    border-color: #4d9eff;
                }
            """)
            b.clicked.connect(fn)
            btn_row.addWidget(b)
        layout.addLayout(btn_row)

        # Top IPs table
        split = QHBoxLayout()
        split.setSpacing(16)

        left = QVBoxLayout()
        left.addWidget(_label("Top Source IPs", size=10, color="#4d9eff"))
        self.top_ips_table = self._mini_table(["IP Address", "Packets"])
        left.addWidget(self.top_ips_table)
        split.addLayout(left)

        right = QVBoxLayout()
        right.addWidget(_label("Top Ports", size=10, color="#a371f7"))
        self.top_ports_table = self._mini_table(["Port", "Packets"])
        right.addWidget(self.top_ports_table)
        split.addLayout(right)

        layout.addLayout(split, stretch=1)

        refresh = QPushButton("⟳  Refresh Tables")
        refresh.setFont(QFont("Consolas", 9))
        refresh.setFixedHeight(30)
        refresh.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #39d353;
                border: 1px solid #39d35344;
                border-radius: 4px;
            }
            QPushButton:hover { border-color: #39d353; background: #39d35311; }
        """)
        refresh.clicked.connect(self._refresh_analysis)
        layout.addWidget(refresh)

        return page

    def _mini_table(self, headers):
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.verticalHeader().setDefaultSectionSize(24)
        return t

    # ── Alerts page ──────────────────────────
    def _build_alerts_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_label("Security Alerts", size=11, bold=True, color="#8b949e"))
        hdr.addStretch()
        clr = QPushButton("Clear Alerts")
        clr.setFont(QFont("Consolas", 9))
        clr.setFixedSize(100, 28)
        clr.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #ff4444;
                border: 1px solid #ff444444;
                border-radius: 4px;
            }
            QPushButton:hover { border-color: #ff4444; background: #ff444411; }
        """)
        clr.clicked.connect(self._clear_alerts)
        hdr.addWidget(clr)
        layout.addLayout(hdr)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: 1px solid #30363d; border-radius: 6px; }")

        self.alerts_container = QWidget()
        self.alerts_layout = QVBoxLayout(self.alerts_container)
        self.alerts_layout.setContentsMargins(8, 8, 8, 8)
        self.alerts_layout.setSpacing(4)
        self.alerts_layout.addStretch()

        scroll.setWidget(self.alerts_container)
        layout.addWidget(scroll)

        # Threshold control
        thr_row = QHBoxLayout()
        thr_row.addWidget(_label("Anomaly threshold (packets/IP):", size=9, color="#8b949e"))
        self.threshold_input = QLineEdit("300")
        self.threshold_input.setFixedWidth(80)
        apply_btn = QPushButton("Apply")
        apply_btn.setFont(QFont("Consolas", 9))
        apply_btn.setFixedSize(70, 26)
        apply_btn.setStyleSheet("""
            QPushButton {
                background: #003322;
                color: #00ff88;
                border: 1px solid #00ff8844;
                border-radius: 4px;
            }
            QPushButton:hover { border-color: #00ff88; }
        """)
        apply_btn.clicked.connect(self._apply_threshold)
        thr_row.addWidget(self.threshold_input)
        thr_row.addWidget(apply_btn)
        thr_row.addStretch()
        layout.addLayout(thr_row)

        return page

    # ── Export page ──────────────────────────
    def _build_export_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(16)

        layout.addWidget(_label("Data Export", size=11, bold=True, color="#8b949e"))
        layout.addWidget(_label(
            "Export captured packets and statistics to CSV or Excel format.",
            size=9, color="#4d9eff"))
        layout.addWidget(_separator())

        for label, fn, color in [
            ("⤓  Export Packets → CSV",   self._export_csv,   "#00ff88"),
            ("⤓  Export Packets → Excel", self._export_excel, "#39d353"),
            ("⤓  Export Stats → CSV",     self._export_stats, "#4d9eff"),
        ]:
            btn = QPushButton(label)
            btn.setFont(QFont("Consolas", 11))
            btn.setFixedHeight(44)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {color}11;
                    color: {color};
                    border: 1px solid {color}44;
                    border-radius: 6px;
                    text-align: left;
                    padding-left: 20px;
                }}
                QPushButton:hover {{
                    background: {color}22;
                    border: 1px solid {color};
                }}
            """)
            btn.clicked.connect(fn)
            layout.addWidget(btn)

        layout.addStretch()

        self.export_log = QTextEdit()
        self.export_log.setReadOnly(True)
        self.export_log.setFixedHeight(100)
        self.export_log.setFont(QFont("Consolas", 9))
        self.export_log.setPlaceholderText("Export log…")
        layout.addWidget(self.export_log)

        return page

    # ── Status bar ───────────────────────────
    def _build_statusbar(self):
        bar = QFrame()
        bar.setFixedHeight(30)
        bar.setStyleSheet("QFrame { background: #010409; border-top: 1px solid #21262d; }")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)

        self.status_lbl = _label("●  Idle", size=9, color="#4d9eff")
        layout.addWidget(self.status_lbl)
        layout.addStretch()

        self.pkt_rate_lbl = _label("0 pkt/s", size=9, color="#8b949e")
        layout.addWidget(self.pkt_rate_lbl)
        layout.addSpacing(20)
        self.total_lbl = _label("0 packets total", size=9, color="#8b949e")
        layout.addWidget(self.total_lbl)

        return bar

    # ──────────────────────────────────────────
    #  Capture control
    # ──────────────────────────────────────────
    def start_capture(self):
        from capture.packet_capture import FILTER_PRESETS

        preset = self.filter_combo.currentText()
        if preset == "Custom…":
            bpf = self.filter_input.text().strip()
        else:
            bpf = FILTER_PRESETS.get(preset, "")

        self.capture.set_filter(bpf)
        self._start_ts = time.time()
        self._bytes = 0
        self._pkt_last = 0
        self._pkt_last_time = time.time()

        thread = threading.Thread(target=self.capture.start, daemon=True)
        thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("●  Capturing…")
        self.status_lbl.setStyleSheet(
            "color: #00ff88; background: transparent; font-size: 9pt;")

    def _show_capture_error(self, message: str):
        from PyQt5.QtWidgets import QMessageBox
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Capture Error")
        dlg.setText(message)
        dlg.setIcon(QMessageBox.Warning)
        dlg.setStyleSheet("""
            QMessageBox {
                background: #161b22;
                color: #c9d1d9;
                font-family: Consolas;
            }
            QLabel { color: #c9d1d9; font-family: Consolas; font-size: 10pt; }
            QPushButton {
                background: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 6px 16px;
                font-family: Consolas;
            }
        """)
        dlg.exec_()

    def stop_capture(self):
        self.capture.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("●  Stopped")
        self.status_lbl.setStyleSheet("color: #ff4444; background: transparent; font-size: 9pt;")

    # ──────────────────────────────────────────
    #  Packet processing (worker thread → UI)
    # ──────────────────────────────────────────
    def _on_packet_raw(self, packet):
        """Called from capture thread — emit signal to UI thread."""
        packet["time"] = time.strftime("%H:%M:%S")
        self.analyzer.analyze(packet)
        alert = self.detector.check(packet)
        self._bytes += packet.get("length", 0)
        self.bridge.packet_received.emit(packet)
        if alert:
            self.bridge.alert_received.emit(alert)

    # ── Updated _on_packet_ui — handles errors ───────────────
    def _on_packet_ui(self, packet):
        # Error packet from capture thread
        if packet.get("__error__"):
            self._show_capture_error(packet["message"])
            self.stop_capture()
            return

        self.packets.append(packet)
        self._add_table_row(packet)
        n = len(self.packets)
        self.card_total.update_value(str(n))
        self.card_ips.update_value(str(len(self.analyzer.ip_counter)))
        tcp = sum(1 for p in self.packets if p["protocol"] == "TCP")
        udp = sum(1 for p in self.packets if p["protocol"] == "UDP")
        self.card_tcp.update_value(str(tcp))
        self.card_udp.update_value(str(udp))
        self.total_lbl.setText(f"{n} packets total")

    def _on_alert_ui(self, msg):
        self.alerts.append(msg)
        self.card_alerts.update_value(str(len(self.alerts)))
        row = AlertRow(msg)
        self.alerts_layout.insertWidget(self.alerts_layout.count() - 1, row)

    def _add_table_row(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        proto_colors = {"TCP": "#a371f7", "UDP": "#39d353", "OTHER": "#ffa500"}
        color = proto_colors.get(packet["protocol"], "#c9d1d9")
        vals = [
            packet["time"],
            packet["src_ip"],
            packet["dst_ip"],
            packet["protocol"],
            str(packet["src_port"]),
            f'{packet["dst_port"]}  ·  {packet["length"]}B',
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setFont(QFont("Consolas", 9))
            if col == 3:
                item.setForeground(QColor(color))
            self.packet_table.setItem(row, col, item)

        # Auto-scroll
        if row > 200:
            self.packet_table.scrollToBottom()

    # ──────────────────────────────────────────
    #  Packet inspector
    # ──────────────────────────────────────────
    def show_packet_details(self, row, _col=0):
        if row >= len(self.packets):
            return
        p = self.packets[row]
        self.packet_details.setHtml(f"""
<pre style="color:#c9d1d9; font-family:Consolas; font-size:10pt; line-height:1.6;">
<span style="color:#4d9eff">═══ PACKET #{row+1} ═══════════════════════════════</span>

  <span style="color:#8b949e">Time:</span>             <span style="color:#00ff88">{p['time']}</span>
  <span style="color:#8b949e">Protocol:</span>         <span style="color:#a371f7">{p['protocol']}</span>

  <span style="color:#8b949e">Source IP:</span>        <span style="color:#ffa500">{p['src_ip']}</span>
  <span style="color:#8b949e">Destination IP:</span>   <span style="color:#ffa500">{p['dst_ip']}</span>

  <span style="color:#8b949e">Source Port:</span>      <span style="color:#c9d1d9">{p['src_port']}</span>
  <span style="color:#8b949e">Destination Port:</span> <span style="color:#c9d1d9">{p['dst_port']}</span>

  <span style="color:#8b949e">Length:</span>           <span style="color:#39d353">{p['length']} bytes</span>
</pre>""")

    # ──────────────────────────────────────────
    #  Analysis
    # ──────────────────────────────────────────
    def _refresh_analysis(self):
        top_ips = self.analyzer.get_top_ips()
        self.top_ips_table.setRowCount(0)
        for ip, cnt in top_ips:
            r = self.top_ips_table.rowCount()
            self.top_ips_table.insertRow(r)
            self.top_ips_table.setItem(r, 0, QTableWidgetItem(ip))
            self.top_ips_table.setItem(r, 1, QTableWidgetItem(str(cnt)))

        top_ports = self.analyzer.get_top_ports()
        self.top_ports_table.setRowCount(0)
        for port, cnt in top_ports:
            r = self.top_ports_table.rowCount()
            self.top_ports_table.insertRow(r)
            self.top_ports_table.setItem(r, 0, QTableWidgetItem(str(port)))
            self.top_ports_table.setItem(r, 1, QTableWidgetItem(str(cnt)))

    def _chart_ips(self):
        plot_top_ips(self.analyzer.get_top_ips())

    def _chart_ports(self):
        plot_top_ports(self.analyzer.get_top_ports())

    def _chart_proto(self):
        tcp = sum(1 for p in self.packets if p["protocol"] == "TCP")
        udp = sum(1 for p in self.packets if p["protocol"] == "UDP")
        oth = len(self.packets) - tcp - udp
        plot_protocol_pie({"TCP": tcp, "UDP": udp, "OTHER": oth})

    def _chart_timeline(self):
        plot_traffic_timeline(self.packets)

    # ──────────────────────────────────────────
    #  Alerts
    # ──────────────────────────────────────────
    def _clear_alerts(self):
        self.alerts.clear()
        while self.alerts_layout.count() > 1:
            item = self.alerts_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.card_alerts.update_value("0")

    def _apply_threshold(self):
        try:
            val = int(self.threshold_input.text())
            self.detector.threshold = val
        except ValueError:
            pass

    # ──────────────────────────────────────────
    #  Export
    # ──────────────────────────────────────────
    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "packets.csv",
                                              "CSV Files (*.csv)")
        if path:
            DataExporter(self.packets).export_csv(path)
            self.export_log.append(f"[{time.strftime('%H:%M:%S')}] CSV saved → {path}")

    def _export_excel(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Excel", "packets.xlsx",
                                              "Excel Files (*.xlsx)")
        if path:
            DataExporter(self.packets).export_excel(path)
            self.export_log.append(f"[{time.strftime('%H:%M:%S')}] Excel saved → {path}")

    def _export_stats(self):
        import pandas as pd
        path, _ = QFileDialog.getSaveFileName(self, "Save Stats CSV", "stats.csv",
                                              "CSV Files (*.csv)")
        if path:
            rows = [{"ip": ip, "packets": cnt}
                    for ip, cnt in self.analyzer.ip_counter.items()]
            pd.DataFrame(rows).to_csv(path, index=False)
            self.export_log.append(f"[{time.strftime('%H:%M:%S')}] Stats saved → {path}")

    # ──────────────────────────────────────────
    #  Misc
    # ──────────────────────────────────────────
    def _clear_packets(self):
        self.packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.card_total.update_value("0")
        self.card_tcp.update_value("0")
        self.card_udp.update_value("0")

    def _tick(self):
        self.clock_lbl.setText(time.strftime("%H:%M:%S"))
        elapsed = time.time() - self._start_ts if self._start_ts else 1
        bw = self._bytes / max(elapsed, 1)
        if bw >= 1_000_000:
            bw_str = f"{bw/1_000_000:.1f} MB/s"
        elif bw >= 1000:
            bw_str = f"{bw/1000:.1f} KB/s"
        else:
            bw_str = f"{int(bw)} B/s"
        self.card_bw.update_value(bw_str)

        # Packets per second (last second)
        now = time.time()
        n = len(self.packets)
        if hasattr(self, "_pkt_last_time"):
            dt = now - self._pkt_last_time
            if dt >= 1.0:
                rate = (n - self._pkt_last) / dt
                self.pkt_rate_lbl.setText(f"{rate:.0f} pkt/s")
                self._pkt_last = n
                self._pkt_last_time = now