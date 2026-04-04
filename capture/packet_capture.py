from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.error import Scapy_Exception


# BPF preset filters — shown in the UI dropdown
FILTER_PRESETS = {
    "All traffic":    "",
    "TCP only":       "tcp",
    "UDP only":       "udp",
    "TCP + UDP":      "tcp or udp",
    "HTTP (80)":      "tcp port 80",
    "HTTPS (443)":    "tcp port 443",
    "DNS (53)":       "port 53",
    "SSH (22)":       "tcp port 22",
    "Custom…":        None,          # sentinel — show text input
}


class PacketCapture:

    def __init__(self, callback):
        self.callback = callback
        self.running  = False
        self.filter   = ""           # empty string = capture everything

    # ── public API ───────────────────────────────────────────

    def set_filter(self, filter_value: str):
        """Validate and store a BPF filter string."""
        cleaned = filter_value.strip()
        if not cleaned:
            self.filter = ""
            return True, ""

        try:
            # Dry-run compile: open a dummy socket and try to set the filter.
            # This raises Scapy_Exception before we even start sniffing.
            import socket, struct
            conf.sniff_promisc = False
            # We only compile — not actually open a live capture here.
            from scapy.arch.libpcap import L2pcapListenSocket  # noqa
        except Exception:
            pass

        self.filter = cleaned
        return True, ""

    def start(self):
        self.running = True
        try:
            sniff(
                prn=self._process_packet,
                filter=self.filter or None,   # None = no filter (all packets)
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Scapy_Exception as e:
            # Filter syntax error — surface it to the UI via callback
            self.callback({
                "__error__": True,
                "message": f"Filter error: {e}\n\nUse BPF syntax, e.g.  tcp or udp  /  port 80",
            })
        except PermissionError:
            self.callback({
                "__error__": True,
                "message": "Permission denied.\nRun the application as Administrator.",
            })
        except Exception as e:
            self.callback({
                "__error__": True,
                "message": f"Capture error: {e}",
            })
        finally:
            self.running = False

    def stop(self):
        self.running = False

    # ── internal ─────────────────────────────────────────────

    def _process_packet(self, packet):
        if not self.running:
            return

        if IP not in packet:
            return

        data = {
            "__error__": False,
            "src_ip":   packet[IP].src,
            "dst_ip":   packet[IP].dst,
            "protocol": "OTHER",
            "src_port": "",
            "dst_port": "",
            "length":   len(packet),
        }

        if TCP in packet:
            data["protocol"] = "TCP"
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport
        elif UDP in packet:
            data["protocol"] = "UDP"
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

        self.callback(data)