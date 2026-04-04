class AnomalyDetector:

    def __init__(self):

        self.ip_activity = {}

        self.threshold = 300

    def check(self, packet):

        ip = packet["src_ip"]

        self.ip_activity[ip] = self.ip_activity.get(ip, 0) + 1

        if self.ip_activity[ip] > self.threshold:

            return f"⚠ Suspicious traffic from {ip}"

        return None