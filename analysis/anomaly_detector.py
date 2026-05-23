"""
analysis/anomaly_detector.py
=============================
Детектор аномалій із двома незалежними механізмами:

1. Volume detector  — спрацьовує коли кількість пакетів від одного IP
                      перевищує поріг (threshold). Алерт — рівно один раз
                      на кожен кратний поріг (300, 600, 900…).

2. Shannon entropy   — аналізує останні window_size пакетів.
                       Якщо ентропія падає нижче entropy_threshold —
                       трафік домінується 1-2 IP → підозра на flood.
                       Cooldown між ентропійними алертами = cooldown_pkts,
                       щоб не спамити UI.

Виправлення відносно попередньої версії:
  - _packet_counter починався з 0, тому 0 % 50 == 0 спрацьовував одразу
    до заповнення вікна → алерт ніколи не видавався коректно.
  - Cooldown тепер відраховується від останнього ВИДАНОГО алерту,
    а не від глобального лічильника пакетів.
  - Вікно зменшено до 50 пакетів (швидше реагує на короткі флади).
  - Додано reset() для скидання стану при очищенні стріму.
"""

import math
from collections import deque, Counter


class AnomalyDetector:

    def __init__(self):
        # ── Volume detector ───────────────────────────────────
        self.ip_activity: Counter = Counter()
        self.threshold: int       = 300   # пакетів від одного IP

        # ── Shannon entropy detector ──────────────────────────
        self.window_size:        int   = 50    # розмір ковзного вікна
        self.entropy_threshold:  float = 1.5   # нижче = підозрілий трафік
        self.cooldown_pkts:      int   = 25    # мін. пакетів між ентропійними алертами

        self._packet_window: deque = deque(maxlen=self.window_size)
        self._total_packets: int   = 0         # загальний лічильник (без reset-багу)
        self._last_entropy_alert_at: int = -999  # пакет, на якому був останній алерт

    # ── Public API ────────────────────────────────────────────

    def check(self, packet: dict) -> str | None:
        """
        Перевіряє пакет на аномалії.
        Повертає рядок-попередження або None.
        """
        ip = packet.get("src_ip")
        if not ip:
            return None

        self._total_packets += 1
        alerts = []

        # ── 1. Volume check ───────────────────────────────────
        self.ip_activity[ip] += 1
        cnt = self.ip_activity[ip]

        # Алерт на кожен кратний поріг: 300, 600, 900…
        if cnt % self.threshold == 0:
            alerts.append(
                f"🔴 High volume from {ip}  ({cnt} packets)"
            )

        # ── 2. Entropy check ──────────────────────────────────
        self._packet_window.append(ip)

        # Рахуємо ентропію тільки коли вікно повністю заповнене
        if len(self._packet_window) == self.window_size:
            entropy = self._shannon_entropy(self._packet_window)

            # Cooldown: видаємо алерт не частіше ніж раз на cooldown_pkts пакетів
            pkts_since_last = self._total_packets - self._last_entropy_alert_at
            if entropy < self.entropy_threshold and pkts_since_last >= self.cooldown_pkts:
                self._last_entropy_alert_at = self._total_packets
                # Визначаємо домінуючий IP для детального повідомлення
                top_ip, top_cnt = Counter(self._packet_window).most_common(1)[0]
                pct = round(top_cnt / self.window_size * 100)
                alerts.append(
                    f"⚠ Low entropy ({entropy:.2f}) — "
                    f"{top_ip} = {pct}% of last {self.window_size} packets "
                    f"(possible flood)"
                )

        if not alerts:
            return None
        return "  |  ".join(alerts)

    def reset(self):
        """Скидає весь стан (викликається при Clear Stream)."""
        self.ip_activity.clear()
        self._packet_window.clear()
        self._total_packets          = 0
        self._last_entropy_alert_at  = -999

    # ── Internal ──────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(window: deque) -> float:
        """H(X) = -Σ p(x) * log2(p(x))"""
        n      = len(window)
        counts = Counter(window)
        h      = 0.0
        for c in counts.values():
            p  = c / n
            h -= p * math.log2(p)
        return h