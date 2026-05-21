"""
Головний модуль графічного інтерфейсу програми NetSentinel.
Реалізує сучасний світлий дизайн, багатопотоковість та взаємодію з модулями аналізу.

Threading model
---------------
  CaptureWorker (QThread)  — scapy sniff(), emits packet_ready + error_occurred
  DPIWorker     (QThread)  — DPI queue consumer, emits result_ready
  GUI thread               — all Qt widget updates (slots _pipeline, _on_dpi_result, _tick …)

No threading.Thread, no SignalBridge needed — Qt queued connections handle
cross-thread signal delivery automatically.
"""

import time
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QLineEdit, QFrame, QStackedWidget,
    QHeaderView, QScrollArea, QComboBox, QFileDialog, QMessageBox
)

from analysis.anomaly_detector import AnomalyDetector
from analysis.app_analyzer import AppAnalyzer
from analysis.dpi_worker import DPIWorker
from analysis.traffic_analyzer import TrafficAnalyzer
from capture.capture_worker import CaptureWorker
from capture.packet_capture import FILTER_PRESETS
from storage.data_export import DataExporter
from visualization.charts import (
    plot_top_ips, plot_top_ports, plot_protocol_pie, plot_traffic_timeline
)

# ── Typography ────────────────────────────────────────────────────────────────
UI_FONT   = "Segoe UI"
DATA_FONT = "Consolas"

# ── Colour palette ────────────────────────────────────────────────────────────
COLORS = {
    "bg_main":       "#F3F4F6",
    "bg_panel":      "#FFFFFF",
    "border":        "#E5E7EB",
    "text_primary":  "#111827",
    "text_muted":    "#6B7280",
    "primary":       "#3B82F6",
    "success":       "#10B981",
    "danger":        "#EF4444",
    "warning":       "#F59E0B",
    "purple":        "#8B5CF6",
    "sidebar_bg":    "#111827",
    "sidebar_text":  "#9CA3AF",
    "sidebar_active":"#F9FAFB",
}

# DPI mode labels
DPI_OFF        = "DPI: Off"
DPI_ANOMALOUS  = "DPI: Anomalous"
DPI_ALL        = "DPI: All Packets"

# DPI severity → UI colour
_DPI_SEVERITY_COLOR = {
    "info":    COLORS["primary"],
    "warning": COLORS["warning"],
    "danger":  COLORS["danger"],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _lbl(text: str, size: int = 12, bold: bool = False,
         color: str = COLORS["text_primary"]) -> QLabel:
    label = QLabel(text)
    f = QFont(UI_FONT, size)
    f.setBold(bold)
    label.setFont(f)
    label.setStyleSheet(f"color:{color}; background:transparent; border:none;")
    return label


# ── Widgets ───────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", accent: str = COLORS["primary"]):
        super().__init__()
        self.setObjectName("StatCardBox")
        self.setFixedHeight(80)
        self.setStyleSheet(f"""
            #StatCardBox {{
                background:{COLORS['bg_panel']};
                border:1px solid {COLORS['border']};
                border-top:4px solid {accent};
                border-radius:6px;
            }}
        """)
        ly = QVBoxLayout(self)
        ly.setContentsMargins(16, 8, 16, 8)
        ly.setSpacing(2)
        self.val = _lbl(value, 20, True, accent)
        self.ttl = QLabel(title)
        self.ttl.setFont(QFont(UI_FONT, 9, QFont.Bold))
        self.ttl.setStyleSheet(
            f"color:{COLORS['text_muted']}; background:transparent; border:none; letter-spacing:1px;"
        )
        ly.addWidget(self.val)
        ly.addWidget(self.ttl)

    def set_value(self, value):
        self.val.setText(str(value))


class NavBtn(QPushButton):
    def __init__(self, icon: str, text: str):
        super().__init__()
        self.setCheckable(True)
        self.setFixedHeight(44)
        self.lay = QHBoxLayout(self)
        self.lay.setContentsMargins(16, 0, 0, 0)
        self.lay.setSpacing(14)
        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.text_lbl = QLabel(text)
        self.text_lbl.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.lay.addWidget(self.icon_lbl)
        self.lay.addWidget(self.text_lbl)
        self.lay.addStretch()
        self.setStyleSheet(f"""
            QPushButton {{ background:transparent; border:none; border-radius:6px; }}
            QPushButton:hover {{ background:#1F2937; }}
            QPushButton:checked {{
                background:#1F2937;
                border-left:4px solid {COLORS['primary']};
                border-radius:4px;
            }}
        """)
        self.update_colors()
        self.toggled.connect(self.update_colors)

    def enterEvent(self, e):
        super().enterEvent(e)
        self.update_colors(hovered=True)

    def leaveEvent(self, e):
        super().leaveEvent(e)
        self.update_colors(hovered=False)

    def update_colors(self, hovered=False):
        color = (COLORS['primary'] if self.isChecked()
                 else COLORS['sidebar_active'] if hovered
                 else COLORS['sidebar_text'])
        self.icon_lbl.setStyleSheet(
            f"color:{color}; font-size:36px; background:transparent; border:none;"
        )
        self.text_lbl.setStyleSheet(
            f"color:{color}; font-size:13px; font-weight:bold; background:transparent; border:none;"
        )


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    STYLE = f"""
    QMainWindow, QStackedWidget {{ background:{COLORS['bg_main']}; font-family:'Segoe UI',Arial,sans-serif; font-size:12px; }}
    QTableWidget {{
        background:{COLORS['bg_panel']}; alternate-background-color:#F9FAFB;
        color:{COLORS['text_primary']}; gridline-color:{COLORS['border']};
        border:1px solid {COLORS['border']}; border-radius:6px;
        selection-background-color:#DBEAFE; selection-color:{COLORS['text_primary']};
    }}
    QHeaderView::section {{
        background:#F3F4F6; color:{COLORS['text_muted']};
        border:none; border-bottom:1px solid {COLORS['border']};
        padding:8px 10px; font-size:11px; font-weight:bold; letter-spacing:1px;
    }}
    QScrollBar:vertical {{ background:#F3F4F6; width:10px; }}
    QScrollBar::handle:vertical {{ background:#D1D5DB; border-radius:5px; }}
    QScrollBar::handle:vertical:hover {{ background:#9CA3AF; }}
    QTextEdit {{
        background:{COLORS['bg_panel']}; color:{COLORS['text_primary']};
        border:1px solid {COLORS['border']}; border-radius:6px;
        padding:8px; font-family:Consolas,monospace; line-height:1.5;
    }}
    QLineEdit, QComboBox {{
        background:{COLORS['bg_panel']}; color:{COLORS['text_primary']};
        border:1px solid {COLORS['border']}; border-radius:5px; padding:6px 12px;
    }}
    QLineEdit:focus, QComboBox:focus {{ border:1px solid {COLORS['primary']}; }}
    QComboBox::drop-down {{ border:none; }}
    QComboBox QAbstractItemView {{
        background:{COLORS['bg_panel']}; color:{COLORS['text_primary']};
        selection-background-color:{COLORS['primary']}; selection-color:white;
    }}
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel · Traffic Analyzer")
        self.resize(1380, 840)
        self.setMinimumSize(1080, 660)
        self.setStyleSheet(self.STYLE)

        # ── App state ──────────────────────────────────────────
        self.packets: list[dict]      = []
        self.alerts:  list[str]       = []
        self.dpi_results: dict[int, dict] = {}   # pkt_index → DPIResult.to_dict()

        self._start_ts     = None
        self._bytes        = 0
        self._pkt_last     = 0
        self._pkt_t        = time.time()
        self._is_sidebar_expanded = True

        # ── Analysis modules (lightweight, run in GUI thread) ──
        self.analyzer     = TrafficAnalyzer()
        self.app_analyzer = AppAnalyzer()
        self.detector     = AnomalyDetector()

        # ── Worker threads (created fresh on each capture start)
        self._capture_worker: CaptureWorker | None = None
        self._dpi_worker:     DPIWorker     | None = None

        self._build_ui()

        # ── 1-second stats ticker ──────────────────────────────
        self._clock = QTimer()
        self._clock.timeout.connect(self._tick)
        self._clock.start(1000)

    # ═══════════════════════════════════════════════════════════
    # UI Construction
    # ═══════════════════════════════════════════════════════════

    def _build_ui(self):
        root = QWidget()
        root.setStyleSheet(f"background:{COLORS['bg_main']};")
        root_lay = QHBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)
        self.setCentralWidget(root)

        self.sidebar = self._build_sidebar()
        root_lay.addWidget(self.sidebar)

        main = QWidget()
        main_lay = QVBoxLayout(main)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)
        main_lay.addWidget(self._build_topbar())
        main_lay.addWidget(self._build_statstrip())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_capture())      # 0
        self.stack.addWidget(self._page_analysis())     # 1
        self.stack.addWidget(self._page_alerts())       # 2
        self.stack.addWidget(self._page_export())       # 3
        self.stack.addWidget(self._page_apps())         # 4
        main_lay.addWidget(self.stack, 1)
        main_lay.addWidget(self._build_statusbar())

        root_lay.addWidget(main, 1)

    # ── Sidebar ───────────────────────────────────────────────

    def _build_sidebar(self) -> QFrame:
        sb = QFrame()
        sb.setFixedWidth(240)
        sb.setStyleSheet(f"QFrame {{ background:{COLORS['sidebar_bg']}; border-right:1px solid #000; }}")
        ly = QVBoxLayout(sb)
        ly.setContentsMargins(12, 16, 12, 20)
        ly.setSpacing(6)

        hdr = QHBoxLayout()
        self.menu_toggle_btn = QPushButton("≡")
        self.menu_toggle_btn.setFont(QFont(UI_FONT, 16))
        self.menu_toggle_btn.setFixedSize(36, 36)
        self.menu_toggle_btn.setStyleSheet(f"""
            QPushButton {{ color:{COLORS['sidebar_text']}; border:none; background:transparent; border-radius:6px; }}
            QPushButton:hover {{ background:#1F2937; color:#FFFFFF; }}
        """)
        self.menu_toggle_btn.clicked.connect(self.toggle_sidebar)

        self.logo_label = QLabel()
        self.logo_label.setText(
            f'<span style="color:#FFFFFF;font-weight:bold;font-size:15px;">Net</span>'
            f'<span style="color:{COLORS["primary"]};font-weight:bold;font-size:15px;">Sentinel</span>'
        )
        self.logo_label.setStyleSheet("background:transparent; border:none; padding-left:4px;")
        hdr.addWidget(self.menu_toggle_btn)
        hdr.addWidget(self.logo_label, 1)
        ly.addLayout(hdr)
        ly.addSpacing(24)

        self._navs = []
        for icon, text, idx in [
            ("◉", "Capture",      0),
            ("◈", "Analysis",     1),
            ("⚑", "Alerts",       2),
            ("⤓", "Export",       3),
            ("◫", "Applications", 4),
        ]:
            btn = NavBtn(icon, text)
            btn.clicked.connect(lambda _, i=idx: self._navigate(i))
            self._navs.append(btn)
            ly.addWidget(btn)

        self._navs[0].setChecked(True)
        ly.addStretch()

        self._clock_lbl = _lbl("--:--:--", 11, True, COLORS["sidebar_text"])
        self._clock_lbl.setAlignment(Qt.AlignCenter)
        ly.addWidget(self._clock_lbl)
        return sb

    def toggle_sidebar(self):
        width  = self.sidebar.width()
        target = 60 if self._is_sidebar_expanded else 240
        self._is_sidebar_expanded = not self._is_sidebar_expanded
        self.logo_label.setVisible(self._is_sidebar_expanded)
        for btn in self._navs:
            btn.text_lbl.setVisible(self._is_sidebar_expanded)
            btn.lay.setContentsMargins(16 if self._is_sidebar_expanded else 8, 0, 0, 0)

        for attr, prop in [("anim", b"minimumWidth"), ("anim2", b"maximumWidth")]:
            a = QPropertyAnimation(self.sidebar, prop)
            a.setDuration(250)
            a.setStartValue(width)
            a.setEndValue(target)
            a.setEasingCurve(QEasingCurve.InOutQuart)
            a.start()
            setattr(self, attr, a)

    def _navigate(self, idx: int):
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._navs):
            btn.setChecked(i == idx)
        if idx == 4:
            self._refresh_apps()

    # ── Top bar ───────────────────────────────────────────────

    def _build_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setFixedHeight(64)
        bar.setStyleSheet(f"QFrame {{ background:{COLORS['bg_panel']}; border-bottom:1px solid {COLORS['border']}; }}")
        ly = QHBoxLayout(bar)
        ly.setContentsMargins(24, 0, 24, 0)
        ly.setSpacing(12)

        ly.addWidget(_lbl("Live Packet Capture", 13, True))
        ly.addStretch()

        # BPF filter
        ly.addWidget(_lbl("Filter:", 10, False, COLORS["text_muted"]))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(list(FILTER_PRESETS.keys()))
        self.filter_combo.setFixedWidth(160)
        self.filter_combo.currentTextChanged.connect(self._on_preset_changed)
        ly.addWidget(self.filter_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp port 80 or udp")
        self.filter_input.setFixedWidth(200)
        self.filter_input.setVisible(False)
        ly.addWidget(self.filter_input)

        # ── DPI mode selector ─────────────────────────────────
        ly.addSpacing(8)
        ly.addWidget(_lbl("DPI:", 10, False, COLORS["text_muted"]))
        self.dpi_combo = QComboBox()
        self.dpi_combo.addItems([DPI_OFF, DPI_ANOMALOUS, DPI_ALL])
        self.dpi_combo.setFixedWidth(150)
        self.dpi_combo.setToolTip(
            "Deep Packet Inspection mode:\n"
            "  Off          — disabled\n"
            "  Anomalous — inspect only flagged packets\n"
            "  All Packets — inspect every packet (CPU-intensive)"
        )
        self.dpi_combo.currentTextChanged.connect(self._on_dpi_mode_changed)
        self._style_dpi_combo(DPI_OFF)
        ly.addWidget(self.dpi_combo)

        # ── Capture control buttons ───────────────────────────
        ly.addSpacing(10)
        self.start_btn = self._action_btn("▶ Start", COLORS["success"], "#059669")
        self.stop_btn  = self._action_btn("■ Stop",  COLORS["danger"],  "#DC2626")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        ly.addWidget(self.start_btn)
        ly.addWidget(self.stop_btn)
        return bar

    def _action_btn(self, text: str, color: str, hover: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        btn.setFixedSize(110, 36)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:transparent; color:{color};
                border:2px solid {color}; border-radius:18px;
            }}
            QPushButton:hover {{ background:{hover}; color:#FFF; border:2px solid {hover}; }}
            QPushButton:disabled {{
                background:{COLORS['bg_main']}; color:{COLORS['text_muted']};
                border:2px solid {COLORS['border']};
            }}
        """)
        return btn

    def _on_preset_changed(self, text: str):
        self.filter_input.setVisible(text == "Custom…")

    def _on_dpi_mode_changed(self, mode: str):
        self._style_dpi_combo(mode)

        # Start / stop DPI worker based on mode
        if mode == DPI_OFF:
            if self._dpi_worker and self._dpi_worker.isRunning():
                self._dpi_worker.shutdown()
        else:
            # Ensure DPI worker is running if capture is active
            if self._capture_worker and self._capture_worker.isRunning():
                self._ensure_dpi_worker()

    def _style_dpi_combo(self, mode: str):
        """Colour-code the DPI combo to reflect the current mode."""
        color_map = {
            DPI_OFF:       COLORS["text_muted"],
            DPI_ANOMALOUS: COLORS["warning"],
            DPI_ALL:       COLORS["danger"],
        }
        c = color_map.get(mode, COLORS["text_muted"])
        self.dpi_combo.setStyleSheet(f"""
            QComboBox {{
                color:{c}; border:1px solid {c};
                border-radius:5px; padding:6px 12px;
                background:{COLORS['bg_panel']};
                font-weight:bold;
            }}
            QComboBox::drop-down {{ border:none; }}
            QComboBox QAbstractItemView {{
                background:{COLORS['bg_panel']}; color:{COLORS['text_primary']};
                selection-background-color:{COLORS['primary']}; selection-color:white;
            }}
        """)

    # ── Stat strip ────────────────────────────────────────────

    def _build_statstrip(self) -> QFrame:
        strip = QFrame()
        strip.setFixedHeight(116)
        strip.setStyleSheet(f"background:transparent; border-bottom:1px solid {COLORS['border']};")
        ly = QHBoxLayout(strip)
        ly.setContentsMargins(24, 14, 24, 14)
        ly.setSpacing(16)

        self.c_total  = StatCard("TOTAL PACKETS",   "0",    COLORS["primary"])
        self.c_ips    = StatCard("UNIQUE IPs",       "0",    COLORS["purple"])
        self.c_alerts = StatCard("ALERTS",           "0",    COLORS["danger"])
        self.c_bw     = StatCard("AVG BANDWIDTH",   "0 B/s", COLORS["warning"])
        self.c_tcp    = StatCard("TCP PACKETS",      "0",    COLORS["success"])
        self.c_dpi    = StatCard("DPI INSPECTED",    "0",    COLORS["primary"])

        for card in [self.c_total, self.c_ips, self.c_alerts, self.c_bw, self.c_tcp, self.c_dpi]:
            ly.addWidget(card)
        return strip

    # ═══════════════════════════════════════════════════════════
    # Pages
    # ═══════════════════════════════════════════════════════════

    def _page_capture(self) -> QWidget:
        page = QWidget()
        ly = QVBoxLayout(page)
        ly.setContentsMargins(24, 16, 24, 16)
        ly.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Packet Stream", 12, True))
        hdr.addStretch()
        clear_btn = QPushButton("Clear Stream")
        clear_btn.setFont(QFont(UI_FONT, 9, QFont.Bold))
        clear_btn.setFixedSize(100, 28)
        clear_btn.setStyleSheet(f"""
            QPushButton {{ background:{COLORS['bg_panel']}; color:{COLORS['text_muted']};
                border:1px solid {COLORS['border']}; border-radius:5px; }}
            QPushButton:hover {{ color:{COLORS['danger']}; border-color:{COLORS['danger']}; background:#FEE2E2; }}
        """)
        clear_btn.clicked.connect(self._clear_all)
        hdr.addWidget(clear_btn)
        ly.addLayout(hdr)

        # Packet table — 7 columns (DPI column added)
        self.tbl = QTableWidget()
        self.tbl.setColumnCount(7)
        self.tbl.setHorizontalHeaderLabels(
            ["TIME", "SOURCE IP", "DESTINATION IP", "PROTOCOL", "SRC PORT", "DST PORT / LEN", "DPI"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setShowGrid(False)
        self.tbl.verticalHeader().setDefaultSectionSize(30)
        self.tbl.cellClicked.connect(self._inspect_packet)
        ly.addWidget(self.tbl, 3)

        # Packet inspector
        ly.addWidget(_lbl("Packet Inspector", 11, True, COLORS["primary"]))
        self.inspector = QTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setFont(QFont(DATA_FONT, 11))
        self.inspector.setFixedHeight(200)
        self.inspector.setPlaceholderText("Select a row to inspect packet details and DPI analysis…")
        ly.addWidget(self.inspector)
        return page

    def _page_analysis(self) -> QWidget:
        page = QWidget()
        ly = QVBoxLayout(page)
        ly.setContentsMargins(24, 16, 24, 16)
        ly.setSpacing(16)
        ly.addWidget(_lbl("Traffic Analytics", 13, True))

        btn_row = QHBoxLayout()
        for text, func in [
            ("Bar: Top 10 IPs",   self._show_chart_ips),
            ("Bar: Top Ports",    self._show_chart_ports),
            ("Pie: Protocols",    self._show_chart_proto),
            ("Line: Timeline",    self._show_chart_time),
        ]:
            btn = QPushButton(text)
            btn.setFont(QFont(UI_FONT, 11))
            btn.setFixedHeight(38)
            btn.setStyleSheet(f"""
                QPushButton {{ background:{COLORS['bg_panel']}; color:{COLORS['primary']};
                    border:1px solid {COLORS['border']}; border-radius:6px; }}
                QPushButton:hover {{ background:#EFF6FF; border-color:{COLORS['primary']}; }}
            """)
            btn.clicked.connect(func)
            btn_row.addWidget(btn)
        ly.addLayout(btn_row)

        split = QHBoxLayout()
        split.setSpacing(20)

        lv = QVBoxLayout()
        lv.addWidget(_lbl("Top Active Sources", 11, True))
        self.tbl_ips = self._create_mini_table(["IP Address", "Packets"])
        lv.addWidget(self.tbl_ips)

        rv = QVBoxLayout()
        rv.addWidget(_lbl("Top Targeted Ports", 11, True))
        self.tbl_ports = self._create_mini_table(["Port", "Packets"])
        rv.addWidget(self.tbl_ports)

        split.addLayout(lv)
        split.addLayout(rv)
        ly.addLayout(split, 1)

        ref_btn = QPushButton("⟳ Refresh Tables")
        ref_btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        ref_btn.setFixedHeight(34)
        ref_btn.setStyleSheet(f"""
            QPushButton {{ background:{COLORS['bg_panel']}; color:{COLORS['success']};
                border:1px solid {COLORS['border']}; border-radius:6px; }}
            QPushButton:hover {{ border-color:{COLORS['success']}; background:#ECFDF5; }}
        """)
        ref_btn.clicked.connect(self._refresh_analysis_tables)
        ly.addWidget(ref_btn)
        return page

    def _create_mini_table(self, headers: list) -> QTableWidget:
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
        page = QWidget()
        ly = QVBoxLayout(page)
        ly.setContentsMargins(24, 16, 24, 16)
        ly.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Security Anomalies & DPI Alerts", 13, True))
        hdr.addStretch()
        clr = QPushButton("Clear Alerts")
        clr.setFont(QFont(UI_FONT, 10))
        clr.setFixedSize(110, 30)
        clr.setStyleSheet(f"""
            QPushButton {{ background:{COLORS['bg_panel']}; color:{COLORS['danger']};
                border:1px solid {COLORS['border']}; border-radius:5px; }}
            QPushButton:hover {{ background:#FEE2E2; border-color:{COLORS['danger']}; }}
        """)
        clr.clicked.connect(self._clear_alerts)
        hdr.addWidget(clr)
        ly.addLayout(hdr)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea {{ border:1px solid {COLORS['border']}; border-radius:6px; "
            f"background:{COLORS['bg_panel']}; }}"
        )
        self.alerts_box = QWidget()
        self.alerts_box.setStyleSheet("background:transparent;")
        self.alerts_lay = QVBoxLayout(self.alerts_box)
        self.alerts_lay.setContentsMargins(12, 12, 12, 12)
        self.alerts_lay.setSpacing(8)
        self.alerts_lay.addStretch()
        scroll.setWidget(self.alerts_box)
        ly.addWidget(scroll)

        thr_row = QHBoxLayout()
        thr_row.addWidget(_lbl("Alert Threshold (pkts/IP):", 11, False, COLORS["text_muted"]))
        self.thr_input = QLineEdit("300")
        self.thr_input.setFixedWidth(80)
        appl = QPushButton("Apply")
        appl.setFont(QFont(UI_FONT, 10))
        appl.setFixedSize(80, 30)
        appl.setStyleSheet(f"""
            QPushButton {{ background:{COLORS['success']}; color:white; border:none; border-radius:5px; }}
            QPushButton:hover {{ background:#059669; }}
        """)
        appl.clicked.connect(self._apply_threshold)
        thr_row.addWidget(self.thr_input)
        thr_row.addWidget(appl)
        thr_row.addStretch()
        ly.addLayout(thr_row)
        return page

    def _page_export(self) -> QWidget:
        page = QWidget()
        ly = QVBoxLayout(page)
        ly.setContentsMargins(24, 16, 24, 16)
        ly.setSpacing(16)
        ly.addWidget(_lbl("Data Export", 13, True))
        ly.addWidget(_lbl("Save captured packets and statistics to CSV or Excel format.", 11, False, COLORS["text_muted"]))

        for text, func, color in [
            ("⤓ Export Packets to CSV",   self._export_csv,   COLORS["primary"]),
            ("⤓ Export Packets to Excel", self._export_excel, COLORS["success"]),
            ("⤓ Export IP Statistics",    self._export_stats, COLORS["purple"]),
            ("⤓ Export DPI Results",      self._export_dpi,   COLORS["warning"]),
        ]:
            btn = QPushButton(text)
            btn.setFont(QFont(UI_FONT, 12, QFont.Bold))
            btn.setFixedHeight(50)
            btn.setStyleSheet(f"""
                QPushButton {{ background:{COLORS['bg_panel']}; color:{color};
                    border:1px solid {COLORS['border']}; border-radius:6px;
                    text-align:left; padding-left:24px; }}
                QPushButton:hover {{ background:#F9FAFB; border:1px solid {color}; }}
            """)
            btn.clicked.connect(func)
            ly.addWidget(btn)

        ly.addStretch()
        ly.addWidget(_lbl("Export Log:", 11, True))
        self.exp_log = QTextEdit()
        self.exp_log.setReadOnly(True)
        self.exp_log.setFixedHeight(120)
        self.exp_log.setFont(QFont(DATA_FONT, 10))
        self.exp_log.setPlaceholderText("Export actions will appear here…")
        ly.addWidget(self.exp_log)
        return page

    def _page_apps(self) -> QWidget:
        page = QWidget()
        ly = QVBoxLayout(page)
        ly.setContentsMargins(24, 16, 24, 16)
        ly.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Application Endpoints", 13, True))
        hdr.addStretch()
        ref = QPushButton("⟳ Refresh")
        ref.setFont(QFont(UI_FONT, 10, QFont.Bold))
        ref.setFixedSize(100, 30)
        ref.setStyleSheet(f"""
            QPushButton {{ background:{COLORS['bg_panel']}; color:{COLORS['primary']};
                border:1px solid {COLORS['border']}; border-radius:5px; }}
            QPushButton:hover {{ border-color:{COLORS['primary']}; background:#EFF6FF; }}
        """)
        ref.clicked.connect(self._refresh_apps)
        hdr.addWidget(ref)
        ly.addLayout(hdr)

        ly.addWidget(_lbl("Traffic breakdown by identified application (auto-refreshes every 2 s)",
                          10, False, COLORS["text_muted"]))

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
        ly.addWidget(self.tbl_apps, 1)

        leg = QHBoxLayout()
        for c, lbl in [(COLORS["danger"],  "High > 1 MB"),
                       (COLORS["warning"], "Medium > 100 KB"),
                       (COLORS["success"], "Low ≤ 100 KB")]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{c}; background:transparent; font-size:16px; border:none;")
            leg.addWidget(dot)
            leg.addWidget(_lbl(lbl, 10, False, COLORS["text_muted"]))
            leg.addSpacing(16)
        leg.addStretch()
        ly.addLayout(leg)

        self._app_timer = QTimer()
        self._app_timer.timeout.connect(self._refresh_apps)
        self._app_timer.start(2000)
        return page

    def _build_statusbar(self) -> QFrame:
        bar = QFrame()
        bar.setFixedHeight(34)
        bar.setStyleSheet(f"QFrame {{ background:{COLORS['bg_panel']}; border-top:1px solid {COLORS['border']}; }}")
        ly = QHBoxLayout(bar)
        ly.setContentsMargins(16, 0, 16, 0)
        self.st_lbl = _lbl("● Idle", 10, True, COLORS["text_muted"])
        ly.addWidget(self.st_lbl)
        ly.addStretch()
        self.dpi_queue_lbl = _lbl("DPI queue: 0", 9, False, COLORS["text_muted"])
        ly.addWidget(self.dpi_queue_lbl)
        ly.addSpacing(16)
        self.rate_lbl  = _lbl("0 pkt/s", 10, False, COLORS["text_primary"])
        ly.addWidget(self.rate_lbl)
        ly.addSpacing(24)
        self.total_lbl = _lbl("0 packets total", 10, False, COLORS["text_primary"])
        ly.addWidget(self.total_lbl)
        return bar

    # ═══════════════════════════════════════════════════════════
    # Capture Control
    # ═══════════════════════════════════════════════════════════

    def start_capture(self):
        """Create fresh workers and begin capturing."""
        preset = self.filter_combo.currentText()
        bpf    = (self.filter_input.text().strip()
                  if preset == "Custom…"
                  else FILTER_PRESETS.get(preset, ""))

        # Tear down any previous workers
        self._teardown_workers()

        # ── Capture worker ────────────────────────────────────
        self._capture_worker = CaptureWorker(bpf_filter=bpf)
        self._capture_worker.packet_ready.connect(self._pipeline)
        self._capture_worker.error_occurred.connect(self._on_capture_error)
        self._capture_worker.start()

        # ── DPI worker (if mode is not Off) ───────────────────
        if self.dpi_combo.currentText() != DPI_OFF:
            self._ensure_dpi_worker()

        self._start_ts = time.time()
        self._bytes    = self._pkt_last = 0
        self._pkt_t    = time.time()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.st_lbl.setText("● Capturing…")
        self.st_lbl.setStyleSheet(f"color:{COLORS['success']}; font-weight:bold; border:none;")

    def stop_capture(self):
        """Stop capture and DPI workers gracefully."""
        if self._capture_worker:
            self._capture_worker.stop()

        # DPI worker drains its queue then stops
        if self._dpi_worker and self._dpi_worker.isRunning():
            self._dpi_worker.shutdown(timeout_ms=1500)

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.st_lbl.setText("● Stopped")
        self.st_lbl.setStyleSheet(f"color:{COLORS['danger']}; font-weight:bold; border:none;")

    def _teardown_workers(self):
        if self._capture_worker and self._capture_worker.isRunning():
            self._capture_worker.stop()
            self._capture_worker.wait(1000)
        if self._dpi_worker and self._dpi_worker.isRunning():
            self._dpi_worker.shutdown(timeout_ms=1000)
        self._capture_worker = None
        self._dpi_worker     = None

    def _ensure_dpi_worker(self):
        """Start the DPI worker if it is not already running."""
        if self._dpi_worker and self._dpi_worker.isRunning():
            return
        self._dpi_worker = DPIWorker(max_queue=1000)
        self._dpi_worker.result_ready.connect(self._on_dpi_result)
        self._dpi_worker.start()

    def closeEvent(self, event):
        self._teardown_workers()
        super().closeEvent(event)

    # ═══════════════════════════════════════════════════════════
    # Packet Pipeline  (GUI thread — called via queued connection)
    # ═══════════════════════════════════════════════════════════

    def _pipeline(self, packet: dict):
        """
        Central handler for each captured packet.
        Runs in the GUI thread (queued connection from CaptureWorker).
        """
        packet["time"] = time.strftime("%H:%M:%S")
        self._bytes   += packet.get("length", 0)

        # Lightweight analysis (Counter ops — fast enough for GUI thread)
        self.analyzer.analyze(packet)
        self.app_analyzer.process_packet(packet)
        alert      = self.detector.check(packet)
        is_anomaly = alert is not None

        # ── DPI submission ────────────────────────────────────
        dpi_mode = self.dpi_combo.currentText()
        if dpi_mode != DPI_OFF:
            if dpi_mode == DPI_ALL or (dpi_mode == DPI_ANOMALOUS and is_anomaly):
                pkt_index = len(self.packets)          # index BEFORE appending
                if self._dpi_worker and self._dpi_worker.isRunning():
                    # Send a shallow copy so the original can be stored cleanly
                    pkt_copy = dict(packet)
                    self._dpi_worker.enqueue(pkt_copy, pkt_index)

        # Store and display
        self.packets.append(packet)
        self._add_table_row(packet)

        n = len(self.packets)
        self.c_total.set_value(n)
        self.c_ips.set_value(len(self.analyzer.ip_counter))
        self.c_tcp.set_value(sum(1 for p in self.packets if p["protocol"] == "TCP"))
        self.total_lbl.setText(f"{n} packets total")

        if alert:
            self.alerts.append(alert)
            self.c_alerts.set_value(len(self.alerts))
            self._add_alert_row(alert)

        if self.stack.currentIndex() == 4 and n % 30 == 0:
            self._refresh_apps()

    # ═══════════════════════════════════════════════════════════
    # DPI result handler  (GUI thread)
    # ═══════════════════════════════════════════════════════════

    def _on_dpi_result(self, pkt_index: int, result: dict):
        """
        Called in GUI thread when DPIWorker emits a result.
        Updates the DPI cell in the stream table and (if danger) fires an alert.
        """
        self.dpi_results[pkt_index] = result
        self.c_dpi.set_value(len(self.dpi_results))

        # Update the DPI column in the stream table (col 6)
        if pkt_index < self.tbl.rowCount():
            severity = result.get("severity", "info")
            color    = _DPI_SEVERITY_COLOR.get(severity, COLORS["text_muted"])
            proto    = result.get("protocol", "?")
            threats  = result.get("threats", [])
            cell_txt = f"⚠ {proto}" if threats else proto

            item = QTableWidgetItem(cell_txt)
            item.setForeground(QColor(color))
            item.setFont(QFont(DATA_FONT, 9, QFont.Bold if threats else QFont.Normal))
            self.tbl.setItem(pkt_index, 6, item)

        # Escalate DPI threats to the Alerts page
        if result.get("threats"):
            threat_str = ", ".join(result["threats"])
            src = self.packets[pkt_index].get("src_ip", "?") if pkt_index < len(self.packets) else "?"
            msg = f"🔴 DPI Threat [{proto}] from {src} — {threat_str}"
            self.alerts.append(msg)
            self.c_alerts.set_value(len(self.alerts))
            self._add_alert_row(msg, color=COLORS["danger"])

    # ═══════════════════════════════════════════════════════════
    # Error handler
    # ═══════════════════════════════════════════════════════════

    def _on_capture_error(self, msg: str):
        self._show_error(msg)
        self.stop_capture()

    # ═══════════════════════════════════════════════════════════
    # Table helpers
    # ═══════════════════════════════════════════════════════════

    def _add_table_row(self, p: dict):
        proto_color = {"TCP": COLORS["primary"], "UDP": COLORS["success"], "OTHER": COLORS["warning"]}
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)

        vals = [
            p["time"], p["src_ip"], p["dst_ip"],
            p["protocol"], str(p["src_port"]),
            f'{p["dst_port"]} / {p["length"]}B',
            "…",   # DPI placeholder
        ]

        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setFont(QFont(DATA_FONT, 10))
            if col == 3:
                item.setForeground(QColor(proto_color.get(val, COLORS["text_primary"])))
                item.setFont(QFont(DATA_FONT, 10, QFont.Bold))
            elif col == 6:
                item.setForeground(QColor(COLORS["text_muted"]))
                item.setFont(QFont(DATA_FONT, 9))
            self.tbl.setItem(row, col, item)

        if row > 300:
            self.tbl.scrollToBottom()

    def _inspect_packet(self, row: int, _=0):
        """Show full packet details + DPI result in the inspector panel."""
        if row >= len(self.packets):
            return
        p   = self.packets[row]
        dpi = self.dpi_results.get(row)

        # ── Packet section ────────────────────────────────────
        html = f"""
        <div style="font-family:Consolas,monospace; font-size:11pt; line-height:1.6;
                    color:{COLORS['text_primary']}; padding:4px;">
          <span style="color:{COLORS['primary']};font-weight:bold;">
            === Frame #{row+1} ===================================
          </span><br><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Arrival Time:</span>
            <span style="color:{COLORS['success']};font-weight:bold;">{p['time']}</span><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Protocol:</span>
            <span style="color:{COLORS['purple']};font-weight:bold;">{p['protocol']}</span><br><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Source IP:</span>
            <b>{p['src_ip']}</b><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Destination IP:</span>
            <b>{p['dst_ip']}</b><br><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Source Port:</span>
            <b>{p['src_port']}</b><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Dest Port:</span>
            <b>{p['dst_port']}</b><br><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">Frame Length:</span>
            <span style="color:{COLORS['success']};font-weight:bold;">{p['length']} bytes</span>
        """

        # ── DPI section (only when available) ────────────────
        if dpi:
            sev   = dpi.get("severity", "info")
            color = _DPI_SEVERITY_COLOR.get(sev, COLORS["text_muted"])
            proto = dpi.get("protocol", "?")
            detail  = dpi.get("detail", "")
            threats = dpi.get("threats", [])
            notes   = dpi.get("notes", [])

            html += f"""
          <br>
          <span style="color:{COLORS['primary']};font-weight:bold;">
            --- DPI Analysis ─────────────────────────────────
          </span><br>
          <span style="color:{COLORS['text_muted']};display:inline-block;width:150px;">App Layer:</span>
            <span style="color:{color};font-weight:bold;">{proto}</span><br>
            """
            if detail:
                html += (
                    f'<span style="color:{COLORS["text_muted"]};display:inline-block;width:150px;">'
                    f'Detail:</span> {detail[:120]}<br>'
                )
            if threats:
                html += (
                    f'<span style="color:{COLORS["danger"]};font-weight:bold;">'
                    f'⚠ Threats: {", ".join(threats)}</span><br>'
                )
            for note in notes:
                html += (
                    f'<span style="color:{COLORS["warning"]};">ℹ {note}</span><br>'
                )
            if not threats and not notes:
                html += f'<span style="color:{COLORS["success"]};">✔ No threats detected</span><br>'

        elif self.dpi_combo.currentText() != DPI_OFF:
            html += (
                f'<br><span style="color:{COLORS["text_muted"]}; font-style:italic;">'
                f'DPI result pending…</span>'
            )

        html += "</div>"
        self.inspector.setHtml(html)

    def _add_alert_row(self, msg: str, color: str | None = None):
        if color is None:
            color = COLORS["danger"] if "🔴" in msg else COLORS["warning"]
        ts  = datetime.now().strftime("%H:%M:%S")
        row = QFrame()
        row.setStyleSheet(f"""
            QFrame {{
                background:{COLORS['bg_panel']}; border:1px solid {COLORS['border']};
                border-left:4px solid {color}; border-radius:4px; margin:2px 0;
            }}
        """)
        row_ly = QHBoxLayout(row)
        row_ly.setContentsMargins(12, 10, 12, 10)
        row_ly.addWidget(_lbl(ts, 10, False, COLORS["text_muted"]))
        row_ly.addWidget(_lbl(msg, 10, True, color), 1)
        self.alerts_lay.insertWidget(self.alerts_lay.count() - 1, row)

    # ═══════════════════════════════════════════════════════════
    # Analysis & Charts
    # ═══════════════════════════════════════════════════════════

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

    def _show_chart_ips(self):   plot_top_ips(self.analyzer.get_top_ips())
    def _show_chart_ports(self): plot_top_ports(self.analyzer.get_top_ports())
    def _show_chart_proto(self):
        tcp = sum(1 for p in self.packets if p["protocol"] == "TCP")
        udp = sum(1 for p in self.packets if p["protocol"] == "UDP")
        plot_protocol_pie({"TCP": tcp, "UDP": udp, "OTHER": len(self.packets) - tcp - udp})
    def _show_chart_time(self): plot_traffic_timeline(self.packets)

    # ═══════════════════════════════════════════════════════════
    # Application Endpoints tab
    # ═══════════════════════════════════════════════════════════

    def _refresh_apps(self):
        summary = self.app_analyzer.get_summary()
        self.tbl_apps.setRowCount(0)
        for row_data in summary:
            row = self.tbl_apps.rowCount()
            self.tbl_apps.insertRow(row)
            b  = row_data["bytes"]
            mb = row_data["mb"]
            traffic_str = (
                f"{b/1_048_576:.2f} MB" if b >= 1_048_576 else
                f"{b/1024:.1f} KB"      if b >= 1024       else
                f"{b} B"
            )
            bg  = QColor("#FEE2E2" if mb > 1 else "#FEF3C7" if mb > 0.1 else "#D1FAE5")
            clr = (COLORS["danger"] if mb > 1 else COLORS["warning"] if mb > 0.1 else COLORS["success"])

            for col, val in enumerate([
                row_data["application"], str(row_data["packets"]),
                traffic_str, str(row_data["connections"]), row_data["protocols"]
            ]):
                item = QTableWidgetItem(val)
                item.setFont(QFont(DATA_FONT, 10, QFont.Bold if col == 0 else QFont.Normal))
                if col == 2:
                    item.setBackground(bg)
                    item.setForeground(QColor(clr))
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

    # ═══════════════════════════════════════════════════════════
    # Export
    # ═══════════════════════════════════════════════════════════

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "packets.csv", "CSV (*.csv)")
        if path:
            DataExporter(self.packets).export_csv(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] ✔ Exported packets → {path}")

    def _export_excel(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Excel", "packets.xlsx", "Excel (*.xlsx)")
        if path:
            DataExporter(self.packets).export_excel(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] ✔ Exported packets → {path}")

    def _export_stats(self):
        import pandas as pd
        path, _ = QFileDialog.getSaveFileName(self, "Save Stats", "stats.csv", "CSV (*.csv)")
        if path:
            rows = [{"ip": ip, "packets": c} for ip, c in self.analyzer.ip_counter.items()]
            pd.DataFrame(rows).to_csv(path, index=False)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] ✔ Exported IP stats → {path}")

    def _export_dpi(self):
        """Export all DPI results to CSV."""
        import pandas as pd
        if not self.dpi_results:
            QMessageBox.information(self, "DPI Export", "No DPI results yet.\nEnable DPI and capture some traffic first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save DPI Results", "dpi_results.csv", "CSV (*.csv)")
        if path:
            rows = []
            for idx, r in sorted(self.dpi_results.items()):
                p = self.packets[idx] if idx < len(self.packets) else {}
                rows.append({
                    "pkt_index": idx,
                    "time":      p.get("time", ""),
                    "src_ip":    p.get("src_ip", ""),
                    "dst_ip":    p.get("dst_ip", ""),
                    "dst_port":  p.get("dst_port", ""),
                    "protocol":  r.get("protocol", ""),
                    "detail":    r.get("detail", ""),
                    "threats":   "; ".join(r.get("threats", [])),
                    "notes":     "; ".join(r.get("notes", [])),
                    "severity":  r.get("severity", ""),
                })
            pd.DataFrame(rows).to_csv(path, index=False)
            self.exp_log.append(
                f"[{time.strftime('%H:%M:%S')}] ✔ Exported {len(rows)} DPI results → {path}"
            )

    # ═══════════════════════════════════════════════════════════
    # Misc actions
    # ═══════════════════════════════════════════════════════════

    def _clear_alerts(self):
        self.alerts.clear()
        while self.alerts_lay.count() > 1:
            w = self.alerts_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.c_alerts.set_value(0)

    def _apply_threshold(self):
        try:
            self.detector.threshold = int(self.thr_input.text())
        except ValueError:
            pass

    def _clear_all(self):
        self.packets.clear()
        self.dpi_results.clear()
        self.tbl.setRowCount(0)
        self.inspector.clear()
        self.c_total.set_value(0)
        self.c_tcp.set_value(0)
        self.c_dpi.set_value(0)
        self.app_analyzer.reset()
        if self._dpi_worker:
            self._dpi_worker.reset_engine()

    # ═══════════════════════════════════════════════════════════
    # 1-second ticker
    # ═══════════════════════════════════════════════════════════

    def _tick(self):
        self._clock_lbl.setText(time.strftime("%H:%M:%S"))

        elapsed = time.time() - self._start_ts if self._start_ts else 1
        bw = self._bytes / max(elapsed, 1)
        bw_str = (f"{bw/1_000_000:.1f} MB/s" if bw >= 1_000_000 else
                  f"{bw/1000:.1f} KB/s"       if bw >= 1000      else
                  f"{int(bw)} B/s")
        self.c_bw.set_value(bw_str)

        now = time.time()
        n   = len(self.packets)
        dt  = now - self._pkt_t
        if dt >= 1.0:
            self.rate_lbl.setText(f"{(n - self._pkt_last)/dt:.0f} pkt/s")
            self._pkt_last = n
            self._pkt_t    = now

        # DPI queue depth
        if self._dpi_worker and self._dpi_worker.isRunning():
            q = self._dpi_worker.queue_depth
            d = self._dpi_worker.dropped
            self.dpi_queue_lbl.setText(
                f"DPI queue: {q}" + (f"  dropped: {d}" if d else "")
            )
        else:
            self.dpi_queue_lbl.setText("")

    # ═══════════════════════════════════════════════════════════
    # Error dialog
    # ═══════════════════════════════════════════════════════════

    def _show_error(self, msg: str):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Capture Error")
        dlg.setText(msg)
        dlg.setIcon(QMessageBox.Warning)
        dlg.setStyleSheet(f"""
            QMessageBox {{ background:{COLORS['bg_panel']}; }}
            QLabel {{ color:{COLORS['text_primary']}; font-size:11px; }}
            QPushButton {{
                background:{COLORS['bg_main']}; color:{COLORS['text_primary']};
                border:1px solid {COLORS['border']}; border-radius:4px; padding:6px 16px;
            }}
        """)
        dlg.exec_()