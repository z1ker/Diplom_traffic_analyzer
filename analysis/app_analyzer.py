import psutil
from collections import defaultdict


# Известные порты → названия приложений
KNOWN_PORTS = {
    80:    "HTTP (Browser)",
    443:   "HTTPS (Browser)",
    53:    "DNS",
    22:    "SSH",
    21:    "FTP",
    25:    "SMTP (Mail)",
    110:   "POP3 (Mail)",
    143:   "IMAP (Mail)",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    3389:  "RDP",
    1194:  "OpenVPN",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    5222:  "XMPP (Telegram/Jabber)",
    1935:  "RTMP (Streaming)",
    6881:  "BitTorrent",
    5353:  "mDNS",
    123:   "NTP",
    161:   "SNMP",
    67:    "DHCP",
    68:    "DHCP Client",
    5060:  "SIP (VoIP)",
    5061:  "SIP-TLS (VoIP)",
}


class AppAnalyzer:

    def __init__(self):
        # app_name -> { packets, bytes, connections, protocols }
        self.app_stats = defaultdict(lambda: {
            "packets":     0,
            "bytes":       0,
            "connections": set(),
            "protocols":   set(),
        })
        self._port_map = {}          # port -> process name
        self._refresh_counter = 0

    # ── public API ───────────────────────────────────────────

    def process_packet(self, packet: dict):
        """Feed one parsed packet dict (same format as the rest of the app)."""

        # Обновляем карту портов каждые 50 пакетов
        self._refresh_counter += 1
        if self._refresh_counter % 50 == 0:
            self._refresh_port_map()

        app = self._identify(packet)

        stats = self.app_stats[app]
        stats["packets"] += 1
        stats["bytes"]   += packet.get("length", 0)
        stats["protocols"].add(packet.get("protocol", "?"))

        src = packet.get("src_ip", "")
        dst = packet.get("dst_ip", "")
        sp  = packet.get("src_port", "")
        dp  = packet.get("dst_port", "")
        if src and dst:
            stats["connections"].add(f"{src}:{sp} → {dst}:{dp}")

    def get_summary(self) -> list[dict]:
        """Return list of dicts sorted by bytes descending."""
        result = []
        for app, s in self.app_stats.items():
            mb = s["bytes"] / 1_048_576
            result.append({
                "application": app,
                "packets":     s["packets"],
                "bytes":       s["bytes"],
                "mb":          round(mb, 3),
                "connections": len(s["connections"]),
                "protocols":   ", ".join(sorted(s["protocols"])),
            })
        result.sort(key=lambda x: x["bytes"], reverse=True)
        return result

    def reset(self):
        self.app_stats.clear()
        self._port_map.clear()
        self._refresh_counter = 0

    # ── internal ─────────────────────────────────────────────

    def _refresh_port_map(self):
        """Build port → process-name map from live connections."""
        pm = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid and conn.laddr:
                    try:
                        name = psutil.Process(conn.pid).name()
                        pm[conn.laddr.port] = name
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass
        self._port_map = pm

    def _identify(self, packet: dict) -> str:
        sp = packet.get("src_port")
        dp = packet.get("dst_port")

        # 1. Попробуем найти живой процесс
        for port in (sp, dp):
            if port and port in self._port_map:
                return self._port_map[port]

        # 2. Известные порты
        for port in (dp, sp):
            if port and port in KNOWN_PORTS:
                return KNOWN_PORTS[port]

        # 3. Fallback
        proto = packet.get("protocol", "OTHER")
        if dp:
            return f"{proto}:{dp}"
        return "Unknown"