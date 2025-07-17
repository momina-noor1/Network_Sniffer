from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_capture(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] Source IP: {ip_layer.src}")
        print(f"[+] Destination IP: {ip_layer.dst}")
        print(f"[+] Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"  TCP Packet | Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"  UDP Packet | Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            print("  ICMP Packet Detected")

    else:
        print("Non-IP Packet Captured")

try:
    print("[*] Starting Packet Sniffer... Press Ctrl+C to stop")
    sniff(prn=packet_capture)

except KeyboardInterrupt:
    print("\n[!] Stopped by user.")
