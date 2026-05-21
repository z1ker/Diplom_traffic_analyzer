import math
from collections import deque, Counter


class AnomalyDetector:
    def __init__(self):
        # 1. Классический детектор по объему
        self.ip_activity = Counter()
        self.threshold = 300

        # 2. Детектор на основе энтропии Шеннона
        self.window_size = 100  # Анализируем скользящее окно из 100 последних пакетов
        self.packet_window = deque(maxlen=self.window_size)
        self.entropy_threshold = 1.0  # Порог аномалии (ниже 1.0 = доминация 1-2 IP)
        self._packet_counter = 0  # Для ограничения спама алертами

    def calculate_entropy(self):
        """Вычисляет энтропию Шеннона для IP-адресов в текущем окне."""
        # Если окно еще не заполнилось - статистику считать рано
        if len(self.packet_window) < self.window_size:
            return None

        ip_counts = Counter(self.packet_window)
        entropy = 0.0

        # Формула Шеннона: H(X) = - Σ ( P(x) * log2(P(x)) )
        for count in ip_counts.values():
            probability = count / self.window_size
            entropy -= probability * math.log2(probability)

        return entropy

    def check(self, packet):
        """Проверяет пакет на аномалии и возвращает строку с предупреждением."""
        ip = packet.get("src_ip")
        if not ip:
            return None

        self._packet_counter += 1
        alert = None

        # --- Логика 1: Проверка по количеству пакетов ---
        self.ip_activity[ip] += 1

        # Срабатываем ровно тогда, когда достигнут порог (чтобы не спамить UI каждый раз)
        if self.ip_activity[ip] == self.threshold:
            alert = f"🔴 High traffic volume from {ip} (reached {self.threshold} pkts)"

        # --- Логика 2: Вычисление энтропии ---
        self.packet_window.append(ip)
        entropy = self.calculate_entropy()

        if entropy is not None:
            # Если энтропия упала ниже 1.0, значит ~90% трафика идет от 1-2 IP
            if entropy < self.entropy_threshold:
                # Выдаем предупреждение раз в половину окна, чтобы интерфейс не завис от спама
                if self._packet_counter % (self.window_size // 2) == 0:
                    entropy_msg = f"⚠ Low Entropy ({entropy:.2f}): Possible Network Flood"
                    return f"{alert} | {entropy_msg}" if alert else entropy_msg

        return alert

    def reset(self):
        """Очистка истории (полезно при сбросе стрима захвата)."""
        self.ip_activity.clear()
        self.packet_window.clear()
        self._packet_counter = 0