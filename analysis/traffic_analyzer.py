from collections import Counter

class TrafficAnalyzer:

    def __init__(self):

        self.ip_counter = Counter()
        self.port_counter = Counter()

    def analyze(self, packet):

        self.ip_counter[packet["src_ip"]] += 1

        if packet["dst_port"]:
            self.port_counter[packet["dst_port"]] += 1

    def get_top_ips(self):

        return self.ip_counter.most_common(10)

    def get_top_ports(self):

        return self.port_counter.most_common(10)