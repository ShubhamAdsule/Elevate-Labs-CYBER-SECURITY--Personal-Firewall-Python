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
