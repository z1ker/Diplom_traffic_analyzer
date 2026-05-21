"""
CaptureWorker — QThread-based packet capture.

Replaces the old `threading.Thread + PacketCapture` pattern:
  - Signals are properly queued between threads by Qt
  - Lifecycle (start / stop / isRunning) is managed by QThread
  - Raw payload bytes are extracted here so Scapy objects never leave the thread
"""

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.error import Scapy_Exception


class CaptureWorker(QThread):
    """
    Runs scapy's blocking sniff() in a dedicated QThread.

    Signals
    -------
    packet_ready(dict)
        Emitted for every captured IP packet.  Dict keys:
        src_ip, dst_ip, protocol, src_port, dst_port, length, payload (bytes).
    error_occurred(str)
        Emitted on PermissionError / bad BPF filter / any other exception.
    """

    packet_ready  = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, bpf_filter: str = "", parent=None):
        super().__init__(parent)
        self._filter  = bpf_filter.strip()
        self._running = False

    # ── public API ────────────────────────────────────────────

    def set_filter(self, bpf_filter: str):
        self._filter = bpf_filter.strip()

    def stop(self):
        """Request the capture loop to exit on the next packet."""
        self._running = False

    # ── QThread entry point ───────────────────────────────────

    def run(self):
        self._running = True
        try:
            sniff(
                prn=self._on_raw_packet,
                filter=self._filter or None,   # None = capture everything
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Scapy_Exception as exc:
            self.error_occurred.emit(
                f"Filter error: {exc}\n\n"
                "Use BPF syntax, e.g.  tcp or udp  /  port 80"
            )
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied.\nRun the application as Administrator / root."
            )
        except Exception as exc:
            self.error_occurred.emit(f"Capture error: {exc}")
        finally:
            self._running = False

    # ── internal ─────────────────────────────────────────────

    def _on_raw_packet(self, pkt):
        """Called by scapy in THIS thread for every captured frame."""
        if not self._running or IP not in pkt:
            return

        data: dict = {
            "src_ip":   pkt[IP].src,
            "dst_ip":   pkt[IP].dst,
            "protocol": "OTHER",
            "src_port": "",
            "dst_port": "",
            "length":   len(pkt),
            "payload":  b"",          # raw application-layer bytes for DPI
        }

        if TCP in pkt:
            data["protocol"] = "TCP"
            data["src_port"] = pkt[TCP].sport
            data["dst_port"] = pkt[TCP].dport
            try:
                if pkt[TCP].payload:
                    data["payload"] = bytes(pkt[TCP].payload)
            except Exception:
                pass

        elif UDP in pkt:
            data["protocol"] = "UDP"
            data["src_port"] = pkt[UDP].sport
            data["dst_port"] = pkt[UDP].dport
            try:
                if pkt[UDP].payload:
                    data["payload"] = bytes(pkt[UDP].payload)
            except Exception:
                pass

        # Signal is emitted from worker thread → Qt queues it to GUI thread
        self.packet_ready.emit(data)