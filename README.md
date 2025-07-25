# 🔥 Elevate Labs Personal Firewall (Python)

A **cross-platform, Python-based personal firewall** that leverages **Scapy**. This tool actively monitors, filters, and logs network traffic in real-time according to user-defined rules for IP, port, and protocol—empowering you to take control of your system's security!

---

## ✨ Features

- **Real-Time Packet Sniffing**  
  Captures and inspects *all* incoming and outgoing packets.

- **Customizable Allow/Block Rules**  
  Filter traffic based on:
  - IP address
  - Port number
  - Protocol (TCP/UDP)

- **Comprehensive Traffic Logging**  
  Records all suspicious or blocked packets (with timestamps) in `log.txt` for easy auditing.

- **Cross-Platform Support**  
  Works on **Windows**, **Linux**, and **macOS** (requires administrator/root privileges).

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
- **Scapy** – For packet sniffing and filtering.
- **JSON** – For storing rules.

---

## 🚀 How to Run

### 1. Clone this Repository
```bash
    git clone https://github.com/ShubhamAdsule/Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python.git
    cd Elevate-Labs-CYBER-SECURITY--Personal-Firewall-Python

---
    2. Install Dependencies
    
    pip install -r requirements.txt
    
    3. Run the Firewall
    Windows: Run your terminal as Administrator
    Linux/macOS: Use sudo if necessary
    
    python firewall.py


📝 Configuring Rules (rules.json)
Rules control how the firewall allows or blocks traffic.
Example configuration:

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

allow: Only traffic from listed IPs, ports, or protocols is allowed.

block: Blocks traffic matching these parameters.

Ex:
[2025-07-25 10:15:34] Blocked IP: IP src=192.168.1.5 TCP dport=80
