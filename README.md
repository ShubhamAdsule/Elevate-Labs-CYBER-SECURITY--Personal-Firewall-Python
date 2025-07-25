# Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python
A Python-based personal firewall that captures and filters network traffic using Scapy. Supports custom block/allow rules for IPs, ports, and protocols, and logs suspicious packets for auditing.

# 🔥 Personal Firewall using Python

A simple yet effective **personal firewall** built using **Python** and **Scapy**.  
This firewall monitors and filters network traffic based on custom **rules** (IP, Port, and Protocol) and logs suspicious packets for auditing.  
Created as part of a cybersecurity internship project, it demonstrates the core concepts of **packet sniffing, filtering, and logging**.

---

## ✨ Features
- **Real-Time Packet Sniffing**: Captures and inspects all incoming/outgoing packets.
- **Customizable Rules**: Allows blocking or allowing traffic based on:
  - IP addresses
  - Port numbers
  - Protocols (TCP/UDP)
- **Traffic Logging**: Suspicious or blocked packets are recorded with timestamps in `log.txt`.
- **Cross-Platform Support**: Works on Windows, Linux, and macOS (admin/root access required).

---

## 📂 Project Structure
``` personal-firewall-python/
    ├── firewall.py # Main firewall script
    ├── rules.json # User-defined allow/block rules
    ├── log.txt # Logs of blocked packets
    └── requirements.txt # Dependencies  ```


## ⚙️ Tools & Technologies
- **Python 3.8+**
- **Scapy** – For packet sniffing and filtering.
- **JSON** – For storing rules.

---

## 🚀 How to Run

### 1. Clone this Repository
```bash
git clone https://github.com/ShubhamAdsule/Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python.git
cd Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python


### 2. Install Dependencies
    pip install -r requirements.txt

### 3. Run the Firewall
Windows (Run as Administrator):
python firewall.py


###📝 Sample Rules (rules.json)
      {
        "allow": {
          "ip": ["127.0.0.1"],
          "port": [80, 443],
          "protocol": ["TCP"]
        },
        "block": {
          "ip": ["192.168.1.5"],
          "port": [23],
          "protocol": ["UDP"]
        }
      }

###📄 Logs
All blocked or suspicious packets are recorded in log.txt.
Example:
      [2025-07-25 10:15:34] Blocked IP: IP src=192.168.1.5 TCP dport=80
