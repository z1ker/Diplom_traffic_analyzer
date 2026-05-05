import threading
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QLineEdit, QFrame, QStackedWidget,
    QHeaderView, QScrollArea, QComboBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor

from capture.packet_capture import PacketCapture, FILTER_PRESETS
from analysis.traffic_analyzer import TrafficAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from storage.data_export import DataExporter
from visualization.charts import plot_top_ips, plot_top_ports, plot_protocol_pie, plot_traffic_timeline
from analysis.app_analyzer import AppAnalyzer

# ── Signal bridge (safe cross-thread UI updates) ─────────────
class SignalBridge(QObject):
    packet_received = pyqtSignal(dict)
    alert_received  = pyqtSignal(str)


# ── Font constants ───────────────────────────────────────────
UI_FONT   = "Segoe UI"      # labels, buttons, nav, cards
DATA_FONT = "Consolas"      # IPs, ports, packet inspector, export log


# ── Helper widgets ───────────────────────────────────────────
def _lbl(text, size=12, bold=False, color="#e6edf3"):
    w = QLabel(text)
    f = QFont(UI_FONT, size)
    f.setBold(bold)
    w.setFont(f)
    w.setStyleSheet(f"color:{color};background:transparent;")
    return w


def _sep():
    l = QFrame(); l.setFrameShape(QFrame.HLine)
    l.setStyleSheet("color:#3d444d;"); return l


class StatCard(QFrame):
    def __init__(self, title, value="0", accent="#2ea043"):
        super().__init__()
        self._accent = accent
        self.setFixedHeight(86)
        self.setStyleSheet(f"""
            QFrame{{background:#161b22;border:1px solid #3d444d;
                    border-top:3px solid {accent};border-radius:6px;}}""")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8); lay.setSpacing(3)
        self.val = _lbl(value, 22, True, accent)
        self.ttl = QLabel(title)
        self.ttl.setFont(QFont(UI_FONT, 10, QFont.Bold))
        self.ttl.setStyleSheet("color:#a1abb5;background:transparent;letter-spacing:1px;")
        lay.addWidget(self.val)
        lay.addWidget(self.ttl)

    def set(self, v): self.val.setText(str(v))


class NavBtn(QPushButton):
    def __init__(self, icon, text):
        super().__init__(f"  {icon}  {text}")
        self.setCheckable(True)
        self.setFont(QFont(UI_FONT, 11))
        self.setFixedHeight(42)
        self.setStyleSheet("""
            QPushButton{background:transparent;color:#a1abb5;border:none;
                        text-align:left;padding-left:10px;border-radius:6px;}
            QPushButton:hover{background:#21262d;color:#e6edf3;}
            QPushButton:checked{background:#0d1117;color:#58a6ff;
                                border-left:4px solid #58a6ff;}""")


# ── Main Window ──────────────────────────────────────────────
class MainWindow(QMainWindow):

    STYLE = """
    QMainWindow,QWidget{background:#0d1117;color:#e6edf3;
                        font-family:'Segoe UI', Arial, sans-serif;font-size:12px;}
    QTableWidget{background:#161b22;alternate-background-color:#1e2329;
                 color:#e6edf3;gridline-color:#3d444d;border:1px solid #3d444d;
                 border-radius:6px;selection-background-color:#224b7a;
                 selection-color:#ffffff;}
    QHeaderView::section{background:#21262d;color:#e6edf3;border:none;
                         border-bottom:2px solid #3d444d;padding:6px 10px;
                         font-family:'Segoe UI';font-size:11px;font-weight:bold;letter-spacing:1px;}
    QScrollBar:vertical{background:#161b22;width:9px;border-radius:4px;}
    QScrollBar::handle:vertical{background:#484f58;border-radius:4px;}
    QScrollBar::handle:vertical:hover{background:#58a6ff;}
    QScrollBar:horizontal{background:#161b22;height:9px;}
    QScrollBar::handle:horizontal{background:#484f58;border-radius:4px;}
    QTextEdit{background:#0d1117;color:#3fb950;border:1px solid #3d444d;
              border-radius:6px;padding:8px;font-family:Consolas, monospace; line-height: 1.5;}
    QLineEdit{background:#0d1117;color:#e6edf3;border:1px solid #3d444d;
              border-radius:5px;padding:6px 12px;font-family:'Segoe UI';}
    QLineEdit:focus{border:1px solid #58a6ff;}
    QComboBox{background:#0d1117;color:#e6edf3;border:1px solid #3d444d;
              border-radius:5px;padding:5px 12px;font-family:'Segoe UI';}
    QComboBox::drop-down{border:none;}
    QComboBox QAbstractItemView{background:#161b22;color:#e6edf3;
                                selection-background-color:#1f6feb;
                                font-family:'Segoe UI';}
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel  ·  Traffic Analyzer")
        self.resize(1380, 840)
        self.setMinimumSize(1080, 660)
        self.setStyleSheet(self.STYLE)

        self.packets    = []
        self.alerts     = []
        self._start_ts  = None
        self._bytes     = 0
        self._pkt_last  = 0
        self._pkt_t     = time.time()

        self.analyzer = TrafficAnalyzer()
        self.app_analyzer = AppAnalyzer()
        self.detector = AnomalyDetector()
        self.capture  = PacketCapture(self._raw_callback)

        self.bridge = SignalBridge()
        self.bridge.packet_received.connect(self._on_packet)
        self.bridge.alert_received.connect(self._on_alert)

        self._build_ui()

        self._clock = QTimer()
        self._clock.timeout.connect(self._tick)
        self._clock.start(1000)

    # ── UI ───────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        rl = QHBoxLayout(root)
        rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(0)
        self.setCentralWidget(root)

        rl.addWidget(self._sidebar())

        main = QWidget()
        main.setStyleSheet("background:#0d1117;")
        ml = QVBoxLayout(main)
        ml.setContentsMargins(0, 0, 0, 0); ml.setSpacing(0)
        ml.addWidget(self._topbar())
        ml.addWidget(self._statstrip())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_capture())   # 0
        self.stack.addWidget(self._page_analysis())  # 1
        self.stack.addWidget(self._page_alerts())    # 2
        self.stack.addWidget(self._page_export())    # 3
        self.stack.addWidget(self._page_apps())      # 4
        ml.addWidget(self.stack, 1)
        ml.addWidget(self._statusbar())
        rl.addWidget(main, 1)

    # sidebar
    def _sidebar(self):
        sb = QFrame()
        sb.setFixedWidth(210)
        sb.setStyleSheet("QFrame{background:#010409;border-right:1px solid #21262d;}")
        l = QVBoxLayout(sb)
        l.setContentsMargins(12, 20, 12, 20); l.setSpacing(6)

        logo = _lbl("⬡  NetSentinel", 13, True, "#58a6ff")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("color:#58a6ff;background:transparent;letter-spacing:2px;")
        l.addWidget(logo)
        l.addWidget(_lbl("Traffic Analyzer  v1.0", 9, False, "#6e7681"))
        l.addSpacing(18); l.addWidget(_sep()); l.addSpacing(10)

        self._navs = []
        for icon, text, idx in [("◉", "Capture", 0), ("◈", "Analysis", 1),
                                ("⚑", "Alerts", 2), ("⤓", "Export", 3),
                                ("◫", "Applications", 4)]:
            b = NavBtn(icon, text)
            b.clicked.connect(lambda _, i=idx: self._nav(i))
            self._navs.append(b); l.addWidget(b)

        self._navs[0].setChecked(True)
        l.addStretch()
        l.addWidget(_sep())
        self._clock_lbl = _lbl("--:--:--", 10, True, "#6e7681")
        self._clock_lbl.setAlignment(Qt.AlignCenter)
        l.addWidget(self._clock_lbl)
        return sb

    def _nav(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self._navs): b.setChecked(i == idx)


        if idx == 4:
            self._refresh_apps()

    # topbar
    def _topbar(self):
        bar = QFrame()
        bar.setFixedHeight(58)
        bar.setStyleSheet("QFrame{background:#010409;border-bottom:1px solid #21262d;}")
        l = QHBoxLayout(bar)
        l.setContentsMargins(20, 0, 20, 0); l.setSpacing(12)

        l.addWidget(_lbl("LIVE CAPTURE", 11, True, "#58a6ff"))
        l.addStretch()

        l.addWidget(_lbl("Filter:", 10, False, "#a1abb5"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([k for k in FILTER_PRESETS])
        self.filter_combo.setFixedWidth(140)
        self.filter_combo.currentTextChanged.connect(self._on_preset)
        l.addWidget(self.filter_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF:  tcp or udp  /  port 80 …")
        self.filter_input.setFixedWidth(240)
        self.filter_input.setVisible(False)
        l.addWidget(self.filter_input)

        l.addSpacing(10)
        self.start_btn = self._abtn("▶  Start",  "#3fb950", "#0b2a14")
        self.stop_btn  = self._abtn("■  Stop",   "#f85149", "#2e0f0f")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        l.addWidget(self.start_btn); l.addWidget(self.stop_btn)
        return bar

    def _abtn(self, text, fg, bg):
        b = QPushButton(text)
        b.setFont(QFont(UI_FONT, 10, QFont.Bold))
        b.setFixedSize(110, 34)
        b.setStyleSheet(f"""
            QPushButton{{background:{bg};color:{fg};
                         border:1px solid {fg}66;border-radius:6px;}}
            QPushButton:hover{{background:{fg}22;border:1px solid {fg};}}
            QPushButton:disabled{{background:#161b22;color:#6e7681;
                                  border:1px solid #21262d;}}""")
        return b

    def _on_preset(self, text):
        self.filter_input.setVisible(text == "Custom…")

    # stat strip
    def _statstrip(self):
        strip = QFrame()
        strip.setFixedHeight(106)
        strip.setStyleSheet("QFrame{background:#0d1117;border-bottom:1px solid #21262d;}")
        l = QHBoxLayout(strip)
        l.setContentsMargins(20, 10, 20, 10); l.setSpacing(12)
        self.c_total  = StatCard("TOTAL PACKETS",  "0",      "#3fb950")
        self.c_ips    = StatCard("UNIQUE IPs",      "0",      "#58a6ff")
        self.c_alerts = StatCard("ALERTS",          "0",      "#f85149")
        self.c_bw     = StatCard("AVG BANDWIDTH",   "0 B/s",  "#d29922")
        self.c_tcp    = StatCard("TCP",             "0",      "#8957e5")
        self.c_udp    = StatCard("UDP",             "0",      "#2ea043")
        for c in [self.c_total,self.c_ips,self.c_alerts,
                  self.c_bw,self.c_tcp,self.c_udp]: l.addWidget(c)
        return strip

    # capture page
    def _page_capture(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(20, 16, 20, 16); l.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Packet Stream", 12, True, "#a1abb5"))
        hdr.addStretch()
        clr = QPushButton("Clear")
        clr.setFont(QFont(UI_FONT, 9, QFont.Bold))
        clr.setFixedSize(68, 26)
        clr.setStyleSheet("QPushButton{background:transparent;color:#a1abb5;"
                          "border:1px solid #3d444d;border-radius:5px;}"
                          "QPushButton:hover{color:#f85149;border-color:#f85149;background:#f8514911;}")
        clr.clicked.connect(self._clear)
        hdr.addWidget(clr)
        l.addLayout(hdr)

        self.tbl = QTableWidget()
        self.tbl.setColumnCount(6)
        self.tbl.setHorizontalHeaderLabels(
            ["TIME", "SOURCE IP", "DESTINATION IP", "PROTOCOL", "SRC PORT", "DST PORT / LEN"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setShowGrid(False)
        self.tbl.verticalHeader().setDefaultSectionSize(28)
        self.tbl.cellClicked.connect(self._inspect)
        l.addWidget(self.tbl, 3)

        l.addWidget(_lbl("Packet Inspector", 11, True, "#58a6ff"))
        self.inspector = QTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setFont(QFont(DATA_FONT, 11))
        self.inspector.setFixedHeight(150)
        self.inspector.setPlaceholderText("Click a row to inspect packet…")
        l.addWidget(self.inspector)
        return p

    # analysis page
    def _page_analysis(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(20, 16, 20, 16); l.setSpacing(14)
        l.addWidget(_lbl("Traffic Analysis", 12, True, "#a1abb5"))

        btn_row = QHBoxLayout()
        for txt, fn in [("Top 10 IPs",self._ch_ips),("Top Ports",self._ch_ports),
                         ("Protocol Pie",self._ch_proto),("Timeline",self._ch_time)]:
            b = QPushButton(txt)
            b.setFont(QFont(UI_FONT, 11)); b.setFixedHeight(34)
            b.setStyleSheet("QPushButton{background:#161b22;color:#58a6ff;"
                            "border:1px solid #3d444d;border-radius:5px;}"
                            "QPushButton:hover{background:#1f6feb22;border-color:#58a6ff;}")
            b.clicked.connect(fn); btn_row.addWidget(b)
        l.addLayout(btn_row)

        split = QHBoxLayout(); split.setSpacing(16)
        lv = QVBoxLayout()
        lv.addWidget(_lbl("Top Source IPs", 11, False, "#58a6ff"))
        self.tbl_ips = self._mini(["IP Address","Packets"])
        lv.addWidget(self.tbl_ips)
        rv = QVBoxLayout()
        rv.addWidget(_lbl("Top Ports", 11, False, "#8957e5"))
        self.tbl_ports = self._mini(["Port","Packets"])
        rv.addWidget(self.tbl_ports)
        split.addLayout(lv); split.addLayout(rv)
        l.addLayout(split, 1)

        ref = QPushButton("⟳  Refresh Tables")
        ref.setFont(QFont(UI_FONT, 10, QFont.Bold)); ref.setFixedHeight(30)
        ref.setStyleSheet("QPushButton{background:transparent;color:#3fb950;"
                          "border:1px solid #3fb95055;border-radius:5px;}"
                          "QPushButton:hover{border-color:#3fb950;background:#3fb95011;}")
        ref.clicked.connect(self._refresh)
        l.addWidget(ref)
        return p

    def _mini(self, headers):
        t = QTableWidget(); t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.verticalHeader().setDefaultSectionSize(26)
        return t

    # alerts page
    def _page_alerts(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(20, 16, 20, 16); l.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Security Alerts", 12, True, "#a1abb5"))
        hdr.addStretch()
        clr = QPushButton("Clear Alerts")
        clr.setFont(QFont(UI_FONT, 10)); clr.setFixedSize(106, 28)
        clr.setStyleSheet("QPushButton{background:transparent;color:#f85149;"
                          "border:1px solid #f8514955;border-radius:5px;}"
                          "QPushButton:hover{border-color:#f85149;background:#f8514911;}")
        clr.clicked.connect(self._clear_alerts)
        hdr.addWidget(clr); l.addLayout(hdr)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:1px solid #3d444d;border-radius:6px; background:#161b22;}")
        self.alerts_box = QWidget()
        self.alerts_box.setStyleSheet("background:transparent;")
        self.alerts_lay = QVBoxLayout(self.alerts_box)
        self.alerts_lay.setContentsMargins(10,10,10,10); self.alerts_lay.setSpacing(6)
        self.alerts_lay.addStretch()
        scroll.setWidget(self.alerts_box); l.addWidget(scroll)

        thr = QHBoxLayout()
        thr.addWidget(_lbl("Anomaly threshold (pkts/IP):", 10, False, "#a1abb5"))
        self.thr_input = QLineEdit("300"); self.thr_input.setFixedWidth(80)
        ok = QPushButton("Apply"); ok.setFont(QFont(UI_FONT,10)); ok.setFixedSize(70,28)
        ok.setStyleSheet("QPushButton{background:#0b2a14;color:#3fb950;"
                         "border:1px solid #3fb95055;border-radius:5px;}"
                         "QPushButton:hover{border-color:#3fb950;}")
        ok.clicked.connect(self._apply_thr)
        thr.addWidget(self.thr_input); thr.addWidget(ok); thr.addStretch()
        l.addLayout(thr)
        return p

    # export page
    def _page_export(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(20, 16, 20, 16); l.setSpacing(16)
        l.addWidget(_lbl("Data Export", 12, True, "#a1abb5"))
        l.addWidget(_lbl("Save captured packets and statistics to CSV or Excel.", 10, False, "#58a6ff"))
        l.addWidget(_sep())

        for txt, fn, col in [
            ("⤓  Export Packets → CSV",    self._exp_csv,   "#3fb950"),
            ("⤓  Export Packets → Excel",  self._exp_excel, "#2ea043"),
            ("⤓  Export Statistics → CSV", self._exp_stats, "#58a6ff"),
        ]:
            b = QPushButton(txt); b.setFont(QFont(UI_FONT,12, QFont.Bold)); b.setFixedHeight(46)
            b.setStyleSheet(f"QPushButton{{background:{col}11;color:{col};"
                            f"border:1px solid {col}55;border-radius:6px;"
                            f"text-align:left;padding-left:20px;}}"
                            f"QPushButton:hover{{background:{col}22;border:1px solid {col};}}")
            b.clicked.connect(fn); l.addWidget(b)

        l.addStretch()
        self.exp_log = QTextEdit(); self.exp_log.setReadOnly(True)
        self.exp_log.setFixedHeight(100); self.exp_log.setFont(QFont(DATA_FONT,10))
        self.exp_log.setPlaceholderText("Export log…")
        l.addWidget(self.exp_log)
        return p

    # statusbar
    def _statusbar(self):
        bar = QFrame(); bar.setFixedHeight(30)
        bar.setStyleSheet("QFrame{background:#010409;border-top:1px solid #21262d;}")
        l = QHBoxLayout(bar); l.setContentsMargins(16,0,16,0)
        self.st_lbl = _lbl("●  Idle", 10, False, "#58a6ff"); l.addWidget(self.st_lbl)
        l.addStretch()
        self.rate_lbl  = _lbl("0 pkt/s",         10, False, "#a1abb5"); l.addWidget(self.rate_lbl)
        l.addSpacing(18)
        self.total_lbl = _lbl("0 packets total", 10, False, "#a1abb5"); l.addWidget(self.total_lbl)
        return bar

    # ── Capture control ──────────────────────────────────────
    def start_capture(self):
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
        self.st_lbl.setText("●  Capturing…")
        self.st_lbl.setStyleSheet("color:#3fb950;background:transparent;font-size:10pt;")

    def stop_capture(self):
        self.capture.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.st_lbl.setText("●  Stopped")
        self.st_lbl.setStyleSheet("color:#f85149;background:transparent;font-size:10pt;")

    # ── Packet pipeline ──────────────────────────────────────
    def _raw_callback(self, packet):
        """Called from capture thread — just emit signals, no UI work here."""
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

    def _on_packet(self, packet):
        """Called on UI thread via Qt signal."""
        if packet.get("__error__"):
            self._show_error(packet.get("message", "Unknown error"))
            self.stop_capture()
            return

        self.packets.append(packet)
        self._add_row(packet)

        n = len(self.packets)
        self.c_total.set(n)
        self.c_ips.set(len(self.analyzer.ip_counter))
        self.c_tcp.set(sum(1 for p in self.packets if p["protocol"] == "TCP"))
        self.c_udp.set(sum(1 for p in self.packets if p["protocol"] == "UDP"))
        self.total_lbl.setText(f"{n} packets total")
        if self.stack.currentIndex() == 4 and n % 30 == 0:
            self._refresh_apps()

    def _on_alert(self, msg):
        self.alerts.append(msg)
        self.c_alerts.set(len(self.alerts))
        colors = {"⚠": "#d29922", "🔴": "#f85149"}
        color  = colors.get(msg[0], "#d29922")
        ts     = datetime.now().strftime("%H:%M:%S")
        row    = QFrame()
        row.setStyleSheet(f"QFrame{{background:#0d1117;border-left:4px solid {color};"
                          "border-radius:4px;margin:2px 0; border: 1px solid #21262d; border-left-width: 4px;}}")
        rl = QHBoxLayout(row); rl.setContentsMargins(10,8,10,8)
        rl.addWidget(_lbl(ts,  10, False, "#a1abb5"))
        rl.addWidget(_lbl(msg, 10, True, color), 1)
        self.alerts_lay.insertWidget(self.alerts_lay.count()-1, row)

    def _add_row(self, p):
        PC = {"TCP": "#58a6ff", "UDP": "#3fb950", "OTHER": "#f0883e"}
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)
        vals = [p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                str(p["src_port"]), f'{p["dst_port"]} / {p["length"]}B']
        for col, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setFont(QFont(DATA_FONT, 11))
            if col == 3:
                item.setForeground(QColor(PC.get(v, "#e6edf3")))
                item.setFont(QFont(DATA_FONT, 11, QFont.Bold))
            self.tbl.setItem(row, col, item)
        if row > 300:
            self.tbl.scrollToBottom()

    # ── Packet inspector ─────────────────────────────────────
    def _inspect(self, row, _=0):
        if row >= len(self.packets): return
        p = self.packets[row]
        self.inspector.setHtml(f"""
<div style="font-family:Consolas, monospace; font-size:11pt; line-height:1.8; color:#e6edf3; padding: 4px;">
  <span style="color:#58a6ff; font-weight:bold;">═══ PACKET #{row+1} ═══════════════════════════════</span><br><br>

  <span style="color:#a1abb5; display:inline-block; width:150px;">Time:</span>              <span style="color:#3fb950; font-weight:bold;">{p['time']}</span><br>
  <span style="color:#a1abb5; display:inline-block; width:150px;">Protocol:</span>          <span style="color:#8957e5; font-weight:bold;">{p['protocol']}</span><br><br>

  <span style="color:#a1abb5; display:inline-block; width:150px;">Source IP:</span>         <span style="color:#f0883e; font-weight:bold;">{p['src_ip']}</span><br>
  <span style="color:#a1abb5; display:inline-block; width:150px;">Destination IP:</span>    <span style="color:#f0883e; font-weight:bold;">{p['dst_ip']}</span><br><br>

  <span style="color:#a1abb5; display:inline-block; width:150px;">Source Port:</span>       <span style="color:#e6edf3; font-weight:bold;">{p['src_port']}</span><br>
  <span style="color:#a1abb5; display:inline-block; width:150px;">Destination Port:</span>  <span style="color:#e6edf3; font-weight:bold;">{p['dst_port']}</span><br><br>

  <span style="color:#a1abb5; display:inline-block; width:150px;">Length:</span>            <span style="color:#3fb950; font-weight:bold;">{p['length']} bytes</span>
</div>""")

    # ── Analysis ─────────────────────────────────────────────
    def _refresh(self):
        self.tbl_ips.setRowCount(0)
        for ip, cnt in self.analyzer.get_top_ips():
            r = self.tbl_ips.rowCount(); self.tbl_ips.insertRow(r)
            self.tbl_ips.setItem(r,0,QTableWidgetItem(ip))
            self.tbl_ips.setItem(r,1,QTableWidgetItem(str(cnt)))
        self.tbl_ports.setRowCount(0)
        for port, cnt in self.analyzer.get_top_ports():
            r = self.tbl_ports.rowCount(); self.tbl_ports.insertRow(r)
            self.tbl_ports.setItem(r,0,QTableWidgetItem(str(port)))
            self.tbl_ports.setItem(r,1,QTableWidgetItem(str(cnt)))

    def _ch_ips(self):   plot_top_ips(self.analyzer.get_top_ips())
    def _ch_ports(self): plot_top_ports(self.analyzer.get_top_ports())
    def _ch_proto(self):
        tcp = sum(1 for p in self.packets if p["protocol"]=="TCP")
        udp = sum(1 for p in self.packets if p["protocol"]=="UDP")
        plot_protocol_pie({"TCP":tcp,"UDP":udp,"OTHER":len(self.packets)-tcp-udp})
    def _ch_time(self):  plot_traffic_timeline(self.packets)

    # ── Alerts ───────────────────────────────────────────────
    def _clear_alerts(self):
        self.alerts.clear()
        while self.alerts_lay.count() > 1:
            w = self.alerts_lay.takeAt(0).widget()
            if w: w.deleteLater()
        self.c_alerts.set(0)

    def _apply_thr(self):
        try: self.detector.threshold = int(self.thr_input.text())
        except ValueError: pass

    # ── Export ───────────────────────────────────────────────
    def _exp_csv(self):
        path, _ = QFileDialog.getSaveFileName(self,"Save CSV","packets.csv","CSV (*.csv)")
        if path:
            DataExporter(self.packets).export_csv(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] CSV → {path}")

    def _exp_excel(self):
        path, _ = QFileDialog.getSaveFileName(self,"Save Excel","packets.xlsx","Excel (*.xlsx)")
        if path:
            DataExporter(self.packets).export_excel(path)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] Excel → {path}")

    def _exp_stats(self):
        import pandas as pd
        path, _ = QFileDialog.getSaveFileName(self,"Save Stats","stats.csv","CSV (*.csv)")
        if path:
            rows = [{"ip":ip,"packets":c} for ip,c in self.analyzer.ip_counter.items()]
            pd.DataFrame(rows).to_csv(path,index=False)
            self.exp_log.append(f"[{time.strftime('%H:%M:%S')}] Stats → {path}")

    # ── Misc ─────────────────────────────────────────────────
    def _clear(self):
        self.packets.clear(); self.tbl.setRowCount(0); self.inspector.clear()
        self.c_total.set(0); self.c_tcp.set(0); self.c_udp.set(0)
        self.app_analyzer.reset()

    def _tick(self):
        self._clock_lbl.setText(time.strftime("%H:%M:%S"))
        elapsed = time.time() - self._start_ts if self._start_ts else 1
        bw = self._bytes / max(elapsed, 1)
        if bw >= 1_000_000: s = f"{bw/1_000_000:.1f} MB/s"
        elif bw >= 1000:     s = f"{bw/1000:.1f} KB/s"
        else:                s = f"{int(bw)} B/s"
        self.c_bw.set(s)

        now = time.time(); n = len(self.packets)
        dt = now - self._pkt_t
        if dt >= 1.0:
            self.rate_lbl.setText(f"{(n - self._pkt_last)/dt:.0f} pkt/s")
            self._pkt_last = n; self._pkt_t = now

    def _show_error(self, msg):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Capture Error"); dlg.setText(msg)
        dlg.setIcon(QMessageBox.Warning)
        dlg.setStyleSheet("""
            QMessageBox{background:#161b22;}
            QLabel{color:#e6edf3;font-family:Consolas, monospace;font-size:11pt;}
            QPushButton{background:#21262d;color:#e6edf3;
                        border:1px solid #3d444d;border-radius:5px;padding:6px 16px;}""")
        dlg.exec_()

        # ------------------------- App analyze
    def _page_apps(self):
        """Applications page — like Wireshark's 'Statistics → Endpoints'."""
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(20, 16, 20, 16)
        l.setSpacing(12)

        # ── Header ───────────────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Applications", 12, True, "#a1abb5"))
        hdr.addStretch()

        ref_btn = QPushButton("⟳  Refresh")
        ref_btn.setFont(QFont(UI_FONT, 10, QFont.Bold))
        ref_btn.setFixedSize(100, 28)
        ref_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#3fb950;"
            "border:1px solid #3fb95055;border-radius:5px;}"
            "QPushButton:hover{border-color:#3fb950;background:#3fb95011;}"
        )
        ref_btn.clicked.connect(self._refresh_apps)
        hdr.addWidget(ref_btn)
        l.addLayout(hdr)

        l.addWidget(_lbl(
            "Traffic breakdown by application / process  (auto-refreshes every 2 s while capturing)",
            10, False, "#58a6ff"
        ))

        # ── Table ────────────────────────────────────────────────
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
        self.tbl_apps.verticalHeader().setDefaultSectionSize(30)

        # Сортировка по клику на заголовок
        self.tbl_apps.horizontalHeader().sectionClicked.connect(
            self._sort_apps
        )
        self._apps_sort_col = 1  # по умолчанию — по пакетам
        self._apps_sort_asc = False

        l.addWidget(self.tbl_apps, 1)

        # ── Legend ───────────────────────────────────────────────
        leg = QHBoxLayout()
        for color, label in [
            ("#f85149", "High  > 1 MB"),
            ("#d29922", "Medium  > 100 KB"),
            ("#3fb950", "Low  ≤ 100 KB"),
        ]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{color};background:transparent;font-size:14px;")
            leg.addWidget(dot)
            leg.addWidget(_lbl(label, 9, False, "#a1abb5"))
            leg.addSpacing(16)
        leg.addStretch()
        l.addLayout(leg)

        # ── Auto-refresh timer ───────────────────────────────────
        self._app_timer = QTimer()
        self._app_timer.timeout.connect(self._refresh_apps)
        self._app_timer.start(2000)  # каждые 2 секунды

        return p

    # ── Apps helpers ─────────────────────────────────────────────

    def _refresh_apps(self):
        """Populate / update the applications table."""
        summary = self.app_analyzer.get_summary()
        self.tbl_apps.setRowCount(0)

        for row_data in summary:
            row = self.tbl_apps.rowCount()
            self.tbl_apps.insertRow(row)

            mb = row_data["mb"]
            pkts = row_data["packets"]
            conns = row_data["connections"]
            proto = row_data["protocols"]
            app = row_data["application"]

            # Форматируем трафик
            b = row_data["bytes"]
            if b >= 1_048_576:
                traffic_str = f"{b / 1_048_576:.2f} MB"
            elif b >= 1024:
                traffic_str = f"{b / 1024:.1f} KB"
            else:
                traffic_str = f"{b} B"

            if mb > 1:
                row_color = QColor("#3a1a1a")  # red
                txt_color = "#f85149"
            elif mb > 0.1:
                row_color = QColor("#2a2200")  # yellow
                txt_color = "#d29922"
            else:
                row_color = QColor("#0d1f12")  # green
                txt_color = "#3fb950"

            values = [app, str(pkts), traffic_str, str(conns), proto]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFont(QFont(DATA_FONT, 11))
                item.setBackground(row_color)

                # Имя приложения — выделяем ярче
                if col == 0:
                    item.setForeground(QColor("#e6edf3"))
                    item.setFont(QFont(DATA_FONT, 11, QFont.Bold))
                elif col == 2:
                    item.setForeground(QColor(txt_color))
                    item.setFont(QFont(DATA_FONT, 11, QFont.Bold))
                else:
                    item.setForeground(QColor("#a1abb5"))

                self.tbl_apps.setItem(row, col, item)

    def _sort_apps(self, col: int):
        """Toggle sort direction when header clicked."""
        if self._apps_sort_col == col:
            self._apps_sort_asc = not self._apps_sort_asc
        else:
            self._apps_sort_col = col
            self._apps_sort_asc = False

        order = Qt.AscendingOrder if self._apps_sort_asc else Qt.DescendingOrder
        self.tbl_apps.sortItems(col, order)
