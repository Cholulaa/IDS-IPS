from scapy.all import ARP, DNS, IP, TCP, ICMP
from collections import Counter

# Define thresholds for detection
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets in a short time
PING_FLOOD_THRESHOLD = 100  # Number of ICMP echo requests in a short time
SSH_BRUTEFORCE_THRESHOLD = 10  # Number of failed SSH login attempts per IP
PORT_SCAN_THRESHOLD = 20  # Number of SYN packets to different ports from the same IP

# Counters for detection
syn_sources = Counter()
port_scan_sources = Counter()
ssh_sources = Counter()

def analyze_packet(packet):
    """Analyze a single packet and detect potential attacks."""
    alerts = []

    # Detect ARP Spoofing
    if ARP in packet and packet[ARP].op == 2:
        if packet[ARP].psrc != packet[ARP].hwsrc:
            alerts.append(f"ARP Spoofing detected: {packet[ARP].psrc} claims to be {packet[ARP].hwsrc}")

    # Detect DNS Spoofing
    if DNS in packet and packet[DNS].qr == 1:  # DNS response packet
        dns_query = packet[DNS].qd.qname.decode()
        dns_response = packet[DNS].an.rdata
        if dns_response not in ["8.8.8.8", "1.1.1.1"]:  # Example IPs of known DNS servers
            alerts.append(f"DNS Spoofing detected for query {dns_query}: responded with {dns_response}")

    # Detect TCP SYN Flooding
    if TCP in packet and packet[TCP].flags == "S":  # SYN packet
        syn_sources[packet[IP].src] += 1
        if syn_sources[packet[IP].src] > SYN_FLOOD_THRESHOLD:
            alerts.append(f"SYN Flooding detected from {packet[IP].src}")

    # Detect Ping Flooding (ICMP echo request flood)
    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request (Ping)
        syn_sources[packet[IP].src] += 1
        if syn_sources[packet[IP].src] > PING_FLOOD_THRESHOLD:
            alerts.append(f"Ping Flooding detected from {packet[IP].src}")

    # Detect SSH Bruteforce (Repeated failed login attempts)
    if TCP in packet and packet[TCP].dport == 22 and packet[TCP].flags == "S":  # SYN to port 22 (SSH)
        ssh_sources[packet[IP].src] += 1
        if ssh_sources[packet[IP].src] > SSH_BRUTEFORCE_THRESHOLD:
            alerts.append(f"SSH Brute-force attack detected from {packet[IP].src}")

    # Detect Port Scanning (Multiple SYN requests to different ports)
    if TCP in packet and packet[TCP].flags == "S":
        port_scan_sources[packet[IP].src] += 1
        if port_scan_sources[packet[IP].src] > PORT_SCAN_THRESHOLD:
            alerts.append(f"Port Scanning detected from {packet[IP].src}")

    # Print the alerts (if any) in real-time
    if alerts:
        for alert in alerts:
            print(alert)
