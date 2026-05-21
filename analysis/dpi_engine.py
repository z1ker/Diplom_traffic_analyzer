"""
DPI Engine — Deep Packet Inspection
=====================================
Stateless, thread-safe class that identifies application-layer protocols
and scans payload bytes for known attack signatures.

Design choices
--------------
* Pure Python — no external libs beyond stdlib `re`.
* All public methods are re-entrant; instances are safe to share across threads
  if `_counters` accuracy is not critical (Counter updates are not atomic).
  The DPIWorker creates one engine per thread, so there is no sharing.
* Only the first 8 KB of payload is scanned for threats (performance cap).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Severity constants ────────────────────────────────────────────────────────

SEVERITY_NONE    = "none"
SEVERITY_INFO    = "info"
SEVERITY_WARNING = "warning"
SEVERITY_DANGER  = "danger"


# ── Protocol signatures ───────────────────────────────────────────────────────

_HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ",
    b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
)

_TLS_CONTENT_TYPE_HANDSHAKE = 0x16   # first byte of TLS record
_TLS_VERSION_PREFIX         = 0x03   # second byte  (0x03 0x01/0x03/0x04)

# SMTP client commands that appear at start of payload
_SMTP_CMDS = (b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:", b"DATA\r\n", b"QUIT\r\n")

# FTP client commands
_FTP_CMDS = (b"USER ", b"PASS ", b"LIST\r\n", b"RETR ", b"STOR ", b"QUIT\r\n")

# Well-known port → protocol name  (used as fallback and for mismatch detection)
PORT_PROTOCOL_MAP: dict[int, str] = {
    20:    "FTP-Data",  21:    "FTP",      22:  "SSH",
    23:    "Telnet",    25:    "SMTP",     53:  "DNS",
    67:    "DHCP",      68:    "DHCP-Cli", 80:  "HTTP",
    110:   "POP3",      143:   "IMAP",     443: "HTTPS",
    465:   "SMTPS",     993:   "IMAPS",    995: "POP3S",
    3306:  "MySQL",     5432:  "PostgreSQL",
    6379:  "Redis",     27017: "MongoDB",
    3389:  "RDP",       1194:  "OpenVPN",
    8080:  "HTTP-Alt",  8443:  "HTTPS-Alt",
    5222:  "XMPP",      1935:  "RTMP",
    6881:  "BitTorrent",5353:  "mDNS",
    123:   "NTP",       161:   "SNMP",
    5060:  "SIP",       5061:  "SIP-TLS",
}

# Threat signatures: (compiled regex, human-readable label)
_THREAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"(\.\./){2,}",                                      re.I), "Path Traversal"),
    (re.compile(rb"<script[\s>]",                                      re.I), "XSS Attempt"),
    (re.compile(rb"(union[\s+]select|drop[\s+]table|insert[\s+]into)", re.I), "SQL Injection"),
    (re.compile(rb"cmd\.exe|powershell(?:\.exe)?|/bin/(?:sh|bash|zsh)",re.I), "Shell Command"),
    (re.compile(rb"eval\s*\(|base64_decode\s*\(|exec\s*\(",            re.I), "Code Injection"),
    (re.compile(rb"(?:password|passwd|pwd)\s*=\s*\S{3,}",             re.I), "Credential Exposure"),
    (re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^",                         0),    "EICAR Test Signature"),
    (re.compile(rb"\x00{20,}",                                         0),    "NOP-Sled / Overflow"),
    (re.compile(rb"(?:wget|curl)\s+https?://",                         re.I), "Download Attempt"),
    (re.compile(rb"nc\s+-[el]",                                        re.I), "Netcat Shell"),
]

_DPI_SCAN_LIMIT = 8192   # bytes — max payload to scan for threats


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class DPIResult:
    pkt_index: int          = -1
    protocol:  str          = "UNKNOWN"
    detail:    str          = ""         # e.g. "HTTP | GET /path | Host: example.com"
    threats:   list[str]    = field(default_factory=list)
    notes:     list[str]    = field(default_factory=list)   # non-threat observations
    severity:  str          = SEVERITY_NONE

    def to_dict(self) -> dict:
        return {
            "pkt_index": self.pkt_index,
            "protocol":  self.protocol,
            "detail":    self.detail,
            "threats":   self.threats,
            "notes":     self.notes,
            "severity":  self.severity,
        }


# ── Engine ────────────────────────────────────────────────────────────────────

class DPIEngine:
    """
    Stateless Deep Packet Inspection engine.

    Usage (per-packet)::

        engine = DPIEngine()
        result = engine.inspect(packet_dict, payload_bytes, pkt_index)
    """

    def __init__(self):
        self._stats = {
            "inspected": 0, "http": 0, "tls": 0,
            "dns": 0, "threats": 0, "unknown": 0,
        }

    # ── Public API ────────────────────────────────────────────

    def inspect(self, packet: dict, payload: bytes, pkt_index: int = -1) -> DPIResult:
        self._stats["inspected"] += 1

        result = DPIResult(pkt_index=pkt_index)

        # 1. Protocol identification (payload → port fallback)
        proto, detail = self._identify(packet, payload)
        result.protocol = proto
        result.detail   = detail

        # 2. Threat scanning (only when payload exists)
        if payload:
            result.threats = self._scan_threats(payload[:_DPI_SCAN_LIMIT])
            if result.threats:
                self._stats["threats"] += 1

        # 3. Port / protocol mismatch check
        dst_port = packet.get("dst_port") or 0
        expected = PORT_PROTOCOL_MAP.get(int(dst_port) if dst_port else 0)
        if expected and proto not in ("UNKNOWN", expected) and not proto.startswith(expected):
            result.notes.append(
                f"Protocol mismatch: port {dst_port} → expected {expected}, got {proto}"
            )

        # 4. Assign severity
        if result.threats:
            result.severity = SEVERITY_DANGER
        elif result.notes:
            result.severity = SEVERITY_WARNING
        elif proto != "UNKNOWN":
            result.severity = SEVERITY_INFO

        return result

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset(self):
        for k in self._stats:
            self._stats[k] = 0

    # ── Protocol Identification ───────────────────────────────

    def _identify(self, packet: dict, payload: bytes) -> tuple[str, str]:
        """Return (protocol_name, human-readable detail string)."""

        dst_port = int(packet.get("dst_port") or 0)
        src_port = int(packet.get("src_port") or 0)

        if not payload:
            port  = dst_port or src_port
            proto = PORT_PROTOCOL_MAP.get(port, "UNKNOWN")
            if proto == "UNKNOWN":
                self._stats["unknown"] += 1
            return proto, ""

        # ── TLS ──────────────────────────────────────────────
        if (len(payload) >= 3
                and payload[0] == _TLS_CONTENT_TYPE_HANDSHAKE
                and payload[1] == _TLS_VERSION_PREFIX):
            self._stats["tls"] += 1
            sni    = self._extract_sni(payload)
            detail = f"SNI: {sni}" if sni else ""
            return "TLS", detail

        # ── HTTP Request ─────────────────────────────────────
        if any(payload.startswith(m) for m in _HTTP_METHODS):
            self._stats["http"] += 1
            parts  = payload.split(b" ", 2)
            method = parts[0].decode("ascii", errors="ignore")
            uri    = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else "?"
            host   = self._extract_header(payload, b"Host") or ""
            detail = f"{method} {uri[:80]}"
            if host:
                detail += f"  ·  Host: {host}"
            return "HTTP", detail

        # ── HTTP Response ────────────────────────────────────
        if payload.startswith(b"HTTP/"):
            self._stats["http"] += 1
            status = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            return "HTTP-Response", status[:60]

        # ── SSH banner ───────────────────────────────────────
        if payload.startswith(b"SSH-"):
            banner = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            return "SSH", banner[:60]

        # ── SMTP ─────────────────────────────────────────────
        if any(payload.upper().startswith(c.upper()) for c in _SMTP_CMDS):
            line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            return "SMTP", line[:60]

        # ── FTP ──────────────────────────────────────────────
        if any(payload.upper().startswith(c.upper()) for c in _FTP_CMDS):
            line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            return "FTP", line[:60]

        # ── DNS (port-gated) ─────────────────────────────────
        if dst_port == 53 or src_port == 53:
            self._stats["dns"] += 1
            domain = self._parse_dns_name(payload)
            return "DNS", f"Query: {domain}" if domain else "DNS"

        # ── Port-based fallback ──────────────────────────────
        self._stats["unknown"] += 1
        port  = dst_port or src_port
        return PORT_PROTOCOL_MAP.get(port, "UNKNOWN"), ""

    # ── Threat Detection ─────────────────────────────────────

    def _scan_threats(self, data: bytes) -> list[str]:
        return [name for pattern, name in _THREAT_PATTERNS if pattern.search(data)]

    # ── Parsers ───────────────────────────────────────────────

    @staticmethod
    def _extract_header(payload: bytes, name: bytes) -> Optional[str]:
        try:
            m = re.search(name + rb":\s*([^\r\n]+)", payload, re.IGNORECASE)
            return m.group(1).decode("utf-8", errors="ignore").strip() if m else None
        except Exception:
            return None

    @staticmethod
    def _extract_sni(payload: bytes) -> Optional[str]:
        """Parse SNI extension from TLS ClientHello (RFC 6066)."""
        try:
            # TLS record layout: [type 1B][ver 2B][len 2B] → handshake starts at byte 5
            # Handshake: [type=0x01 1B][len 3B][ver 2B][random 32B] → byte 43 in record
            if len(payload) < 44 or payload[5] != 0x01:
                return None
            idx = 43
            if idx >= len(payload): return None

            idx += 1 + payload[idx]                                   # session ID
            if idx + 2 > len(payload): return None
            idx += 2 + int.from_bytes(payload[idx:idx+2], "big")      # cipher suites
            if idx + 1 > len(payload): return None
            idx += 1 + payload[idx]                                   # compression

            if idx + 2 > len(payload): return None
            ext_end = idx + 2 + int.from_bytes(payload[idx:idx+2], "big")
            idx += 2

            while idx + 4 <= min(ext_end, len(payload)):
                ext_type = int.from_bytes(payload[idx:idx+2], "big")
                ext_len  = int.from_bytes(payload[idx+2:idx+4], "big")
                idx += 4
                if ext_type == 0x0000:       # SNI extension
                    if idx + 5 <= len(payload):
                        name_len = int.from_bytes(payload[idx+3:idx+5], "big")
                        return payload[idx+5: idx+5+name_len].decode("utf-8", errors="ignore")
                idx += ext_len
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_dns_name(payload: bytes) -> Optional[str]:
        """Naively extract the first question-section domain name from a DNS datagram."""
        try:
            if len(payload) < 13:
                return None
            idx    = 12          # skip 12-byte DNS header
            labels = []
            while idx < len(payload):
                length = payload[idx]
                if length == 0:
                    break
                if length >= 0xC0:   # pointer — stop
                    break
                idx += 1
                labels.append(payload[idx: idx+length].decode("ascii", errors="ignore"))
                idx += length
            return ".".join(labels) if labels else None
        except Exception:
            return None