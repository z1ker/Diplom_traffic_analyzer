import threading
import time

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QLineEdit
)

from capture.packet_capture import PacketCapture
from analysis.traffic_analyzer import TrafficAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from visualization.charts import plot_top_ips


class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("Network Traffic Analyzer")

        self.resize(1200, 800)

        main_widget = QWidget()

        main_layout = QVBoxLayout()

        toolbar = QHBoxLayout()

        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.stats_btn = QPushButton("Statistics")

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter (tcp / udp / port 80)")

        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.stats_btn)
        toolbar.addWidget(self.filter_input)

        main_layout.addLayout(toolbar)

        self.packet_table = QTableWidget()

        self.packet_table.setColumnCount(5)

        self.packet_table.setHorizontalHeaderLabels([
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length"
        ])

        main_layout.addWidget(self.packet_table)

        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)

        main_layout.addWidget(self.packet_details)

        self.status = QLabel("Packets captured: 0")

        main_layout.addWidget(self.status)

        main_widget.setLayout(main_layout)

        self.setCentralWidget(main_widget)

        self.packets = []

        self.analyzer = TrafficAnalyzer()
        self.detector = AnomalyDetector()

        self.capture = PacketCapture(self.process_packet)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stats_btn.clicked.connect(self.show_stats)

        self.packet_table.cellClicked.connect(self.show_packet_details)

    def start_capture(self):

        filter_value = self.filter_input.text()

        if filter_value:
            self.capture.set_filter(filter_value)

        thread = threading.Thread(target=self.capture.start)

        thread.start()

    def stop_capture(self):

        self.capture.stop()

    def process_packet(self, packet):

        packet["time"] = time.strftime("%H:%M:%S")

        self.packets.append(packet)

        self.analyzer.analyze(packet)

        alert = self.detector.check(packet)

        if alert:
            print(alert)

        self.update_table(packet)

    def update_table(self, packet):

        row = self.packet_table.rowCount()

        self.packet_table.insertRow(row)

        self.packet_table.setItem(row, 0, QTableWidgetItem(packet["time"]))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet["src_ip"]))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet["dst_ip"]))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet["protocol"]))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(packet["length"])))

        self.status.setText(f"Packets captured: {len(self.packets)}")

    def show_packet_details(self, row):

        packet = self.packets[row]

        text = f"""
Time: {packet['time']}

Source IP: {packet['src_ip']}
Destination IP: {packet['dst_ip']}

Protocol: {packet['protocol']}

Source Port: {packet['src_port']}
Destination Port: {packet['dst_port']}

Packet Length: {packet['length']}
"""

        self.packet_details.setText(text)

    def show_stats(self):

        data = self.analyzer.get_top_ips()

        plot_top_ips(data)