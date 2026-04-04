from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

class PacketCapture:

    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.filter = None

    def start(self):

        self.running = True

        sniff(
            prn=self.process_packet,
            filter=self.filter,
            store=False
        )

    def stop(self):

        self.running = False

    def set_filter(self, filter_value):

        self.filter = filter_value

    def process_packet(self, packet):

        if not self.running:
            return

        if IP in packet:

            data = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": "OTHER",
                "src_port": "",
                "dst_port": "",
                "length": len(packet)
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