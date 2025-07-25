from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime

# Load allow/block rules from rules.json
def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

rules = load_rules()

# Logging function
def log_packet(packet, reason):
    with open("log.txt", "a") as log:
        log.write(f"[{datetime.now()}] {reason}: {packet.summary()}\n")

# Packet filtering logic
def packet_filter(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto
        sport = packet.sport if TCP in packet or UDP in packet else None

        # Convert proto number to name
        protocol = {6: "TCP", 17: "UDP"}.get(proto, "OTHER")

        # Check block rules first
        if src_ip in rules["block"]["ip"]:
            log_packet(packet, "Blocked IP")
            return
        if sport in rules["block"]["port"]:
            log_packet(packet, "Blocked Port")
            return
        if protocol in rules["block"]["protocol"]:
            log_packet(packet, "Blocked Protocol")
            return

        
        # if src_ip not in rules["allow"]["ip"]:
        #     log_packet(packet, "Not in allowed IPs")
        #     return

        print(f"Allowed: {packet.summary()}")

# Start sniffing
print("Firewall is running... Press Ctrl+C to stop.")
sniff(prn=packet_filter, store=0)
