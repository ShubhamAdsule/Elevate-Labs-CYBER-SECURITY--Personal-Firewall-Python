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

