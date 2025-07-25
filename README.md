# 🔥 Elevate Labs Personal Firewall (Python)

A **cross-platform, Python-based personal firewall** that leverages **Scapy** to actively monitor, filter, and log network traffic in real-time. Set your own rules for IP, port, and protocol to take charge of your system's security!

---

## ✨ Features

- **Real-Time Packet Sniffing**  
  Captures and inspects *all* incoming and outgoing packets.

- **Customizable Allow/Block Rules**  
  Filter traffic by:
  - IP address
  - Port number
  - Protocol (TCP/UDP)

- **Comprehensive Traffic Logging**  
  Logs all suspicious or blocked packets (with timestamps) in `log.txt` for easy auditing.

- **Cross-Platform Support**  
  Runs on **Windows**, **Linux**, and **macOS** (administrator/root privileges required).

---

## 📁 Project Structure

    personal-firewall-python/
    ├── firewall.py # Main firewall script
    ├── rules.json # User-defined allow/block rules
    ├── log.txt # Log of blocked/suspicious packets
    └── requirements.txt # Python dependencies


---

## ⚙️ Tools & Technologies

- **Python 3.8+**
- **Scapy** – For packet sniffing and filtering
- **JSON** – For storing rules

---

## 🚀 How to Run

### 1. Clone this Repository

    git clone https://github.com/ShubhamAdsule/Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python.git
    
    cd Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python


### 2. Install Dependencies

      pip install -r requirements.txt


### 3. Run the Firewall

- **Windows**: Run your terminal as **Administrator**
- **Linux/macOS**: Use **sudo** if necessary

## python firewall.py
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
      
              
              #     return
      
              print(f"Allowed: {packet.summary()}")
      
      # Start sniffing
      print("Firewall is running... Press Ctrl+C to stop.")
      sniff(prn=packet_filter, store=0)


---

## 📝 Configuring Rules (`rules.json`)

Control how the firewall allows or blocks traffic by editing `rules.json`.

**Example configuration:**

      {
      "allow": {
      "ip": ["127.0.0.1"],
      "port": [80, "protocol": ["TCP"]
      },
      "block": {
      "ip": ["192.168.1.5"],
      "port": ,
      "protocol": ["UDP"]
      }
      }


- **allow**: Only traffic from the listed IPs, ports, or protocols is allowed.
- **block**: Blocks all traffic matching these parameters.

---

## 📄 Logs

All blocked or suspicious packets are recorded in `log.txt` with timestamps.

**Example:**

    [2025-07-25 10:15:34] Blocked IP: IP src=192.168.1.5 TCP dport=80


---

## 🛡️ Notes

- **Root/administrator access** is required to sniff and filter packets at the network interface.
- For best results, **customize your rules** to match your threat model and network environment.

---
 ## Screenshot
 
   <img width="1906" height="1058" alt="image" src="https://github.com/user-attachments/assets/709bd5d8-8b52-43e5-bba8-dea2e8d9e080" />
   
## log.txt

<img width="1805" height="937" alt="image" src="https://github.com/user-attachments/assets/8b5c373a-5f16-4267-9db4-4b0b23409f8e" />



