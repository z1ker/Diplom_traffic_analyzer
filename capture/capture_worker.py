"""
capture/capture_worker.py
==========================
QThread-based packet capture з батчингом і розумним вибором інтерфейсу.

Архітектура (виправлена):
  sniff() у capture thread
    → _on_raw_packet() складає пакети у list-буфер (_batch)
    → кожні BATCH_INTERVAL_MS мс emit batch_ready(list[dict])
    → GUI thread отримує ПАЧКУ пакетів за один виклик _pipeline_batch()
    → _pipeline_batch() вставляє всі рядки за один pass з setUpdatesEnabled(False)

Чому попередній підхід лагав:
  packet_ready emit() на кожен пакет → Qt event loop накопичував тисячі
  queued signal calls → GUI thread не встигав малювати між ними → підвисання.

Батчинг вирішує це: GUI отримує 20-50 пакетів раз на 50 мс замість
50 окремих сигналів, і таблиця оновлюється одним repaint.
"""

import socket
import threading
import time
import psutil

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.error import Scapy_Exception

# ── BPF presets ───────────────────────────────────────────────────────────────
FILTER_PRESETS = {
    "All traffic": "",
    "TCP only":    "tcp",
    "UDP only":    "udp",
    "TCP + UDP":   "tcp or udp",
    "HTTP (80)":   "tcp port 80",
    "HTTPS (443)": "tcp port 443",
    "DNS (53)":    "port 53",
    "SSH (22)":    "tcp port 22",
    "Custom…":     None,
}

# Як часто скидати накопичені пакети в GUI (мс)
BATCH_INTERVAL_MS = 50   # 20 fps оновлення таблиці

# ── Interface keywords ────────────────────────────────────────────────────────
_SKIP_KW   = ("loopback", "vmware", "virtualbox", "vbox", "pseudo",
               "npcap loopback", "bluetooth pan")
_MOBILE_KW = ("usb", "rndis", "remote ndis", "mobile", "tether",
               "android", "iphone", "pdp", "phone")
_WIFI_KW   = ("wi-fi", "wifi", "wlan", "wireless")
_ETH_KW    = ("ethernet", "eth", "en0", "en1", "local area connection")


# ════════════════════════════════════════════════════════════════
#  Interface discovery
# ════════════════════════════════════════════════════════════════

def get_active_interfaces() -> list[dict]:
    """Повертає активні IPv4-інтерфейси, відсортовані за пріоритетом."""
    stats  = psutil.net_if_stats()
    addrs  = psutil.net_if_addrs()
    io     = psutil.net_io_counters(pernic=True)
    result = []

    for name, stat in stats.items():
        if not stat.isup:
            continue
        nl = name.lower()
        if any(kw in nl for kw in _SKIP_KW):
            continue
        if not any(a.family == socket.AF_INET for a in addrs.get(name, [])):
            continue

        nic_io     = io.get(name)
        bytes_recv = nic_io.bytes_recv if nic_io else 0

        priority = 10
        if any(kw in nl for kw in _MOBILE_KW):
            priority = 100
        elif any(kw in nl for kw in _WIFI_KW):
            priority = 60
        elif any(kw in nl for kw in _ETH_KW):
            priority = 50
        if bytes_recv > 0:
            priority += 20

        if any(kw in nl for kw in _MOBILE_KW):
            label = f"[Mobile]   {name}"
        elif any(kw in nl for kw in _WIFI_KW):
            label = f"[Wi-Fi]    {name}"
        elif any(kw in nl for kw in _ETH_KW):
            label = f"[Ethernet] {name}"
        else:
            label = f"[Other]    {name}"

        result.append({"name": name, "label": label, "priority": priority})

    result.sort(key=lambda x: x["priority"], reverse=True)
    return result


def pick_best_interface() -> str | None:
    ifaces = get_active_interfaces()
    return ifaces[0]["name"] if ifaces else None


# ════════════════════════════════════════════════════════════════
#  CaptureWorker  (з батчингом)
# ════════════════════════════════════════════════════════════════

class CaptureWorker(QThread):
    """
    Захоплює пакети та відправляє їх у GUI ПАЧКАМИ (batch_ready),
    а не по одному — це усуває лаги при великому трафіку.

    Сигнали:
      batch_ready(list[dict])  — пачка розібраних пакетів (кожні ~50 мс)
      error_occurred(str)      — помилка захоплення
      iface_detected(str)      — який інтерфейс реально обрано
    """

    batch_ready    = pyqtSignal(list)   # list[dict]
    error_occurred = pyqtSignal(str)
    iface_detected = pyqtSignal(str)

    def __init__(self, bpf_filter: str = "", iface: str = "auto", parent=None):
        super().__init__(parent)
        self._filter   = bpf_filter.strip()
        self._iface    = iface
        self._running  = False

        # Внутрішній буфер — заповнюється в capture thread
        self._batch: list[dict] = []
        self._batch_lock        = threading.Lock()
        self._last_flush        = 0.0

    def set_filter(self, f: str): self._filter = f.strip()
    def set_iface(self,  i: str): self._iface  = i

    def stop(self):
        self._running = False
        self._flush()   # скидаємо залишок буфера

    # ── QThread.run ───────────────────────────────────────────

    def run(self):
        self._running     = True
        self._last_flush  = time.monotonic()
        iface_arg         = self._resolve_iface()

        try:
            sniff(
                iface      = iface_arg,
                prn        = self._on_raw_packet,
                filter     = self._filter or None,
                store      = False,
                stop_filter= lambda _: not self._running,
            )
        except Scapy_Exception as e:
            self.error_occurred.emit(
                f"Filter error: {e}\n\nUse BPF syntax, e.g.  tcp or udp  /  port 80")
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied.\nRun the application as Administrator / root.")
        except OSError as e:
            self.error_occurred.emit(
                f"Interface error: {e}\n\n"
                "Try 'All interfaces' or reconnect your device.")
        except Exception as e:
            self.error_occurred.emit(f"Capture error: {e}")
        finally:
            self._running = False
            self._flush()

    # ── Interface resolution ──────────────────────────────────

    def _resolve_iface(self):
        if self._iface == "all":
            active = [i["name"] for i in get_active_interfaces()]
            label  = f"All interfaces ({len(active)}): {', '.join(active)}" if active \
                     else "All interfaces (system default)"
            self.iface_detected.emit(label)
            return active or None

        if self._iface == "auto":
            best = pick_best_interface()
            self.iface_detected.emit(best or "All interfaces (fallback)")
            return best or None

        self.iface_detected.emit(self._iface)
        return self._iface

    # ── Packet handler ────────────────────────────────────────

    def _on_raw_packet(self, pkt):
        """Викликається Scapy в capture thread для кожного фрейму."""
        if not self._running or IP not in pkt:
            return

        data: dict = {
            "src_ip":   pkt[IP].src,
            "dst_ip":   pkt[IP].dst,
            "protocol": "OTHER",
            "src_port": "",
            "dst_port": "",
            "length":   len(pkt),
            "payload":  b"",
        }

        if TCP in pkt:
            data["protocol"] = "TCP"
            data["src_port"] = pkt[TCP].sport
            data["dst_port"] = pkt[TCP].dport
            try:
                if pkt[TCP].payload:
                    data["payload"] = bytes(pkt[TCP].payload)[:512]
            except Exception:
                pass
        elif UDP in pkt:
            data["protocol"] = "UDP"
            data["src_port"] = pkt[UDP].sport
            data["dst_port"] = pkt[UDP].dport
            try:
                if pkt[UDP].payload:
                    data["payload"] = bytes(pkt[UDP].payload)[:512]
            except Exception:
                pass

        with self._batch_lock:
            self._batch.append(data)

        # Скидаємо буфер якщо минув BATCH_INTERVAL або накопичилось > 100 пакетів
        now = time.monotonic()
        with self._batch_lock:
            size = len(self._batch)
        if (now - self._last_flush) * 1000 >= BATCH_INTERVAL_MS or size >= 100:
            self._flush()

    def _flush(self):
        """Атомарно знімає буфер і emits batch_ready у GUI thread."""
        with self._batch_lock:
            if not self._batch:
                return
            batch           = self._batch
            self._batch     = []
            self._last_flush = time.monotonic()

        self.batch_ready.emit(batch)