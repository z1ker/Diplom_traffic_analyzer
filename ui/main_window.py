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


# ── Signal bridge (safe cross-thread UI updates) ─────────────
class SignalBridge(QObject):
    packet_received = pyqtSignal(dict)
    alert_received  = pyqtSignal(str)


# ── Font constants ───────────────────────────────────────────
UI_FONT   = "Segoe UI"      # labels, buttons, nav, cards
DATA_FONT = "Consolas"      # IPs, ports, packet inspector, export log


# ── Helper widgets ───────────────────────────────────────────
def _lbl(text, size=11, bold=False, color="#c9d1d9"):
    w = QLabel(text)
    f = QFont(UI_FONT, size)
    f.setBold(bold)
    w.setFont(f)
    w.setStyleSheet(f"color:{color};background:transparent;")
    return w


def _sep():
    l = QFrame(); l.setFrameShape(QFrame.HLine)
    l.setStyleSheet("color:#30363d;"); return l


class StatCard(QFrame):
    def __init__(self, title, value="0", accent="#00ff88"):
        super().__init__()
        self._accent = accent
        self.setFixedHeight(86)
        self.setStyleSheet(f"""
            QFrame{{background:#161b22;border:1px solid #30363d;
                    border-top:3px solid {accent};border-radius:6px;}}""")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8); lay.setSpacing(3)
        self.val = _lbl(value, 20, True, accent)
        self.ttl = QLabel(title)
        self.ttl.setFont(QFont(UI_FONT, 9))
        self.ttl.setStyleSheet("color:#8b949e;background:transparent;letter-spacing:1px;")
        lay.addWidget(self.val)
        lay.addWidget(self.ttl)

    def set(self, v): self.val.setText(str(v))


class NavBtn(QPushButton):
    def __init__(self, icon, text):
        super().__init__(f"  {icon}  {text}")
        self.setCheckable(True)
        self.setFont(QFont(UI_FONT, 10))
        self.setFixedHeight(40)
        self.setStyleSheet("""
            QPushButton{background:transparent;color:#8b949e;border:none;
                        text-align:left;padding-left:10px;border-radius:4px;}
            QPushButton:hover{background:#21262d;color:#c9d1d9;}
            QPushButton:checked{background:#0d1117;color:#00ff88;
                                border-left:3px solid #00ff88;}""")


# ── Main Window ──────────────────────────────────────────────
class MainWindow(QMainWindow):

    STYLE = """
    QMainWindow,QWidget{background:#0d1117;color:#c9d1d9;
                        font-family:'Segoe UI',Arial,sans-serif;font-size:11px;}
    QTableWidget{background:#161b22;alternate-background-color:#1c2128;
                 color:#c9d1d9;gridline-color:#30363d;border:1px solid #30363d;
                 border-radius:5px;selection-background-color:#1f6feb33;
                 selection-color:#4d9eff;}
    QHeaderView::section{background:#21262d;color:#8b949e;border:none;
                         border-bottom:1px solid #30363d;padding:5px 10px;
                         font-family:'Segoe UI';font-size:10px;letter-spacing:1px;}
    QScrollBar:vertical{background:#161b22;width:7px;border-radius:3px;}
    QScrollBar::handle:vertical{background:#30363d;border-radius:3px;}
    QScrollBar::handle:vertical:hover{background:#4d9eff;}
    QScrollBar:horizontal{background:#161b22;height:7px;}
    QScrollBar::handle:horizontal{background:#30363d;border-radius:3px;}
    QTextEdit{background:#161b22;color:#7ee787;border:1px solid #30363d;
              border-radius:5px;padding:6px;font-family:Consolas;}
    QLineEdit{background:#161b22;color:#c9d1d9;border:1px solid #30363d;
              border-radius:4px;padding:5px 10px;font-family:'Segoe UI';}
    QLineEdit:focus{border:1px solid #4d9eff;}
    QComboBox{background:#161b22;color:#c9d1d9;border:1px solid #30363d;
              border-radius:4px;padding:4px 10px;font-family:'Segoe UI';}
    QComboBox::drop-down{border:none;}
    QComboBox QAbstractItemView{background:#161b22;color:#c9d1d9;
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
        ml.addWidget(self.stack, 1)
        ml.addWidget(self._statusbar())
        rl.addWidget(main, 1)

    # sidebar
    def _sidebar(self):
        sb = QFrame()
        sb.setFixedWidth(200)
        sb.setStyleSheet("QFrame{background:#010409;border-right:1px solid #21262d;}")
        l = QVBoxLayout(sb)
        l.setContentsMargins(10, 18, 10, 18); l.setSpacing(4)

        logo = _lbl("⬡  NetSentinel", 12, True, "#00ff88")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("color:#00ff88;background:transparent;letter-spacing:2px;")
        l.addWidget(logo)
        l.addWidget(_lbl("Traffic Analyzer  v1.0", 8, False, "#3d444d"))
        l.addSpacing(16); l.addWidget(_sep()); l.addSpacing(8)

        self._navs = []
        for icon, text, idx in [("◉","Capture",0),("◈","Analysis",1),
                                  ("⚑","Alerts",2),("⤓","Export",3)]:
            b = NavBtn(icon, text)
            b.clicked.connect(lambda _, i=idx: self._nav(i))
            self._navs.append(b); l.addWidget(b)

        self._navs[0].setChecked(True)
        l.addStretch()
        l.addWidget(_sep())
        self._clock_lbl = _lbl("--:--:--", 9, False, "#3d444d")
        self._clock_lbl.setAlignment(Qt.AlignCenter)
        l.addWidget(self._clock_lbl)
        return sb

    def _nav(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self._navs): b.setChecked(i == idx)

    # topbar
    def _topbar(self):
        bar = QFrame()
        bar.setFixedHeight(54)
        bar.setStyleSheet("QFrame{background:#010409;border-bottom:1px solid #21262d;}")
        l = QHBoxLayout(bar)
        l.setContentsMargins(18, 0, 18, 0); l.setSpacing(10)

        l.addWidget(_lbl("LIVE CAPTURE", 10, True, "#4d9eff"))
        l.addStretch()

        l.addWidget(_lbl("Filter:", 9, False, "#8b949e"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([k for k in FILTER_PRESETS])
        self.filter_combo.setFixedWidth(130)
        self.filter_combo.currentTextChanged.connect(self._on_preset)
        l.addWidget(self.filter_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF:  tcp or udp  /  port 80 …")
        self.filter_input.setFixedWidth(220)
        self.filter_input.setVisible(False)
        l.addWidget(self.filter_input)

        l.addSpacing(8)
        self.start_btn = self._abtn("▶  Start",  "#00ff88", "#003322")
        self.stop_btn  = self._abtn("■  Stop",   "#ff4444", "#330000")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        l.addWidget(self.start_btn); l.addWidget(self.stop_btn)
        return bar

    def _abtn(self, text, fg, bg):
        b = QPushButton(text)
        b.setFont(QFont(UI_FONT, 10, QFont.Bold))
        b.setFixedSize(106, 32)
        b.setStyleSheet(f"""
            QPushButton{{background:{bg};color:{fg};
                         border:1px solid {fg}55;border-radius:5px;}}
            QPushButton:hover{{background:{fg}22;border:1px solid {fg};}}
            QPushButton:disabled{{background:#161b22;color:#3d444d;
                                  border:1px solid #21262d;}}""")
        return b

    def _on_preset(self, text):
        self.filter_input.setVisible(text == "Custom…")

    # stat strip
    def _statstrip(self):
        strip = QFrame()
        strip.setFixedHeight(100)
        strip.setStyleSheet("QFrame{background:#0d1117;border-bottom:1px solid #21262d;}")
        l = QHBoxLayout(strip)
        l.setContentsMargins(18, 8, 18, 8); l.setSpacing(10)
        self.c_total  = StatCard("TOTAL PACKETS",  "0",      "#00ff88")
        self.c_ips    = StatCard("UNIQUE IPs",      "0",      "#4d9eff")
        self.c_alerts = StatCard("ALERTS",          "0",      "#ff4444")
        self.c_bw     = StatCard("AVG BANDWIDTH",   "0 B/s",  "#ffa500")
        self.c_tcp    = StatCard("TCP",             "0",      "#a371f7")
        self.c_udp    = StatCard("UDP",             "0",      "#39d353")
        for c in [self.c_total,self.c_ips,self.c_alerts,
                  self.c_bw,self.c_tcp,self.c_udp]: l.addWidget(c)
        return strip

    # capture page
    def _page_capture(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(18, 14, 18, 14); l.setSpacing(10)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Packet Stream", 11, True, "#8b949e"))
        hdr.addStretch()
        clr = QPushButton("Clear")
        clr.setFont(QFont(UI_FONT, 8))
        clr.setFixedSize(60, 24)
        clr.setStyleSheet("QPushButton{background:transparent;color:#8b949e;"
                          "border:1px solid #30363d;border-radius:4px;}"
                          "QPushButton:hover{color:#ff4444;border-color:#ff4444;}")
        clr.clicked.connect(self._clear)
        hdr.addWidget(clr)
        l.addLayout(hdr)

        self.tbl = QTableWidget()
        self.tbl.setColumnCount(6)
        self.tbl.setHorizontalHeaderLabels(
            ["TIME","SOURCE IP","DESTINATION IP","PROTOCOL","SRC PORT","DST PORT / LEN"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setShowGrid(False)
        self.tbl.verticalHeader().setDefaultSectionSize(26)
        self.tbl.cellClicked.connect(self._inspect)
        l.addWidget(self.tbl, 3)

        l.addWidget(_lbl("Packet Inspector", 10, True, "#4d9eff"))
        self.inspector = QTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setFont(QFont("Consolas", 10))
        self.inspector.setFixedHeight(130)
        self.inspector.setPlaceholderText("Click a row to inspect packet…")
        l.addWidget(self.inspector)
        return p

    # analysis page
    def _page_analysis(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(18, 14, 18, 14); l.setSpacing(12)
        l.addWidget(_lbl("Traffic Analysis", 11, True, "#8b949e"))

        btn_row = QHBoxLayout()
        for txt, fn in [("Top 10 IPs",self._ch_ips),("Top Ports",self._ch_ports),
                         ("Protocol Pie",self._ch_proto),("Timeline",self._ch_time)]:
            b = QPushButton(txt)
            b.setFont(QFont(UI_FONT, 10)); b.setFixedHeight(32)
            b.setStyleSheet("QPushButton{background:#161b22;color:#4d9eff;"
                            "border:1px solid #30363d;border-radius:4px;}"
                            "QPushButton:hover{background:#1f6feb22;border-color:#4d9eff;}")
            b.clicked.connect(fn); btn_row.addWidget(b)
        l.addLayout(btn_row)

        split = QHBoxLayout(); split.setSpacing(14)
        lv = QVBoxLayout()
        lv.addWidget(_lbl("Top Source IPs", 10, False, "#4d9eff"))
        self.tbl_ips = self._mini(["IP Address","Packets"])
        lv.addWidget(self.tbl_ips)
        rv = QVBoxLayout()
        rv.addWidget(_lbl("Top Ports", 10, False, "#a371f7"))
        self.tbl_ports = self._mini(["Port","Packets"])
        rv.addWidget(self.tbl_ports)
        split.addLayout(lv); split.addLayout(rv)
        l.addLayout(split, 1)

        ref = QPushButton("⟳  Refresh Tables")
        ref.setFont(QFont(UI_FONT, 9)); ref.setFixedHeight(28)
        ref.setStyleSheet("QPushButton{background:transparent;color:#39d353;"
                          "border:1px solid #39d35344;border-radius:4px;}"
                          "QPushButton:hover{border-color:#39d353;background:#39d35311;}")
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
        t.verticalHeader().setDefaultSectionSize(22)
        return t

    # alerts page
    def _page_alerts(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(18, 14, 18, 14); l.setSpacing(10)

        hdr = QHBoxLayout()
        hdr.addWidget(_lbl("Security Alerts", 11, True, "#8b949e"))
        hdr.addStretch()
        clr = QPushButton("Clear Alerts")
        clr.setFont(QFont(UI_FONT, 9)); clr.setFixedSize(96, 26)
        clr.setStyleSheet("QPushButton{background:transparent;color:#ff4444;"
                          "border:1px solid #ff444444;border-radius:4px;}"
                          "QPushButton:hover{border-color:#ff4444;background:#ff444411;}")
        clr.clicked.connect(self._clear_alerts)
        hdr.addWidget(clr); l.addLayout(hdr)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:1px solid #30363d;border-radius:5px;}")
        self.alerts_box = QWidget()
        self.alerts_lay = QVBoxLayout(self.alerts_box)
        self.alerts_lay.setContentsMargins(8,8,8,8); self.alerts_lay.setSpacing(4)
        self.alerts_lay.addStretch()
        scroll.setWidget(self.alerts_box); l.addWidget(scroll)

        thr = QHBoxLayout()
        thr.addWidget(_lbl("Anomaly threshold (pkts/IP):", 9, False, "#8b949e"))
        self.thr_input = QLineEdit("300"); self.thr_input.setFixedWidth(72)
        ok = QPushButton("Apply"); ok.setFont(QFont(UI_FONT,9)); ok.setFixedSize(64,24)
        ok.setStyleSheet("QPushButton{background:#003322;color:#00ff88;"
                         "border:1px solid #00ff8844;border-radius:4px;}"
                         "QPushButton:hover{border-color:#00ff88;}")
        ok.clicked.connect(self._apply_thr)
        thr.addWidget(self.thr_input); thr.addWidget(ok); thr.addStretch()
        l.addLayout(thr)
        return p

    # export page
    def _page_export(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(18, 14, 18, 14); l.setSpacing(14)
        l.addWidget(_lbl("Data Export", 11, True, "#8b949e"))
        l.addWidget(_lbl("Save captured packets and statistics to CSV or Excel.", 9, False, "#4d9eff"))
        l.addWidget(_sep())

        for txt, fn, col in [
            ("⤓  Export Packets → CSV",    self._exp_csv,   "#00ff88"),
            ("⤓  Export Packets → Excel",  self._exp_excel, "#39d353"),
            ("⤓  Export Statistics → CSV", self._exp_stats, "#4d9eff"),
        ]:
            b = QPushButton(txt); b.setFont(QFont(UI_FONT,11)); b.setFixedHeight(42)
            b.setStyleSheet(f"QPushButton{{background:{col}11;color:{col};"
                            f"border:1px solid {col}44;border-radius:5px;"
                            f"text-align:left;padding-left:18px;}}"
                            f"QPushButton:hover{{background:{col}22;border:1px solid {col};}}")
            b.clicked.connect(fn); l.addWidget(b)

        l.addStretch()
        self.exp_log = QTextEdit(); self.exp_log.setReadOnly(True)
        self.exp_log.setFixedHeight(90); self.exp_log.setFont(QFont("Consolas",9))
        self.exp_log.setPlaceholderText("Export log…")
        l.addWidget(self.exp_log)
        return p

    # statusbar
    def _statusbar(self):
        bar = QFrame(); bar.setFixedHeight(28)
        bar.setStyleSheet("QFrame{background:#010409;border-top:1px solid #21262d;}")
        l = QHBoxLayout(bar); l.setContentsMargins(14,0,14,0)
        self.st_lbl = _lbl("●  Idle", 9, False, "#4d9eff"); l.addWidget(self.st_lbl)
        l.addStretch()
        self.rate_lbl  = _lbl("0 pkt/s",         9, False, "#8b949e"); l.addWidget(self.rate_lbl)
        l.addSpacing(16)
        self.total_lbl = _lbl("0 packets total", 9, False, "#8b949e"); l.addWidget(self.total_lbl)
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
        self.st_lbl.setStyleSheet("color:#00ff88;background:transparent;font-size:9pt;")

    def stop_capture(self):
        self.capture.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.st_lbl.setText("●  Stopped")
        self.st_lbl.setStyleSheet("color:#ff4444;background:transparent;font-size:9pt;")

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

    def _on_alert(self, msg):
        self.alerts.append(msg)
        self.c_alerts.set(len(self.alerts))
        colors = {"⚠": "#ffa500", "🔴": "#ff4444"}
        color  = colors.get(msg[0], "#ffa500")
        ts     = datetime.now().strftime("%H:%M:%S")
        row    = QFrame()
        row.setStyleSheet(f"QFrame{{background:#161b22;border-left:3px solid {color};"
                          "border-radius:3px;margin:1px 0;}}")
        rl = QHBoxLayout(row); rl.setContentsMargins(8,5,8,5)
        rl.addWidget(_lbl(ts,  8, False, "#8b949e"))
        rl.addWidget(_lbl(msg, 8, False, color), 1)
        self.alerts_lay.insertWidget(self.alerts_lay.count()-1, row)

    def _add_row(self, p):
        PC = {"TCP": "#a371f7", "UDP": "#39d353", "OTHER": "#ffa500"}
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)
        vals = [p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                str(p["src_port"]), f'{p["dst_port"]} / {p["length"]}B']
        for col, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setFont(QFont("Consolas", 10))
            if col == 3:
                item.setForeground(QColor(PC.get(v, "#c9d1d9")))
            self.tbl.setItem(row, col, item)
        if row > 300:
            self.tbl.scrollToBottom()

    # ── Packet inspector ─────────────────────────────────────
    def _inspect(self, row, _=0):
        if row >= len(self.packets): return
        p = self.packets[row]
        self.inspector.setHtml(f"""
<pre style="color:#c9d1d9;font-family:Consolas;font-size:10pt;line-height:1.7;">
<span style="color:#4d9eff">═══ PACKET #{row+1} ══════════════════════</span>

  <span style="color:#8b949e">Time:</span>              <span style="color:#00ff88">{p['time']}</span>
  <span style="color:#8b949e">Protocol:</span>          <span style="color:#a371f7">{p['protocol']}</span>

  <span style="color:#8b949e">Source IP:</span>         <span style="color:#ffa500">{p['src_ip']}</span>
  <span style="color:#8b949e">Destination IP:</span>    <span style="color:#ffa500">{p['dst_ip']}</span>

  <span style="color:#8b949e">Source Port:</span>       <span style="color:#c9d1d9">{p['src_port']}</span>
  <span style="color:#8b949e">Destination Port:</span>  <span style="color:#c9d1d9">{p['dst_port']}</span>

  <span style="color:#8b949e">Length:</span>            <span style="color:#39d353">{p['length']} bytes</span>
</pre>""")

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
            QLabel{color:#c9d1d9;font-family:Consolas;font-size:10pt;}
            QPushButton{background:#21262d;color:#c9d1d9;
                        border:1px solid #30363d;border-radius:4px;padding:5px 14px;}""")
        dlg.exec_()