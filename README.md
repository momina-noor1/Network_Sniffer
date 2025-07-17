# Network_Sniffer
This project is a basic network sniffer written in Python using the Scapy library.  
It captures and analyzes network packets (IP, TCP, UDP, ICMP) from a live network interface within a short duration.

Features:
- Captures live network packets
- Analyzes IP, TCP, UDP, and ICMP layers
- Displays source/destination IP and ports
- Automatically stops after a specified timeout (default: 10 seconds)

Requirements:
- Python 3.x
- Scapy (Install via pip)

```bash
pip install scapy
