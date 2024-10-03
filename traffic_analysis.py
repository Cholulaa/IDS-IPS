from scapy.all import ARP

def analyze_traffic(packets):
    """Analyze captured traffic and detect potential attacks."""
    alerts = []
    
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:  # ARP Spoofing detection
            if pkt[ARP].psrc != pkt[ARP].hwsrc:
                alerts.append(f"ARP Spoofing detected: {pkt[ARP].psrc} claims to be {pkt[ARP].hwsrc}")
    
    if alerts:
        for alert in alerts:
            print(alert)
        return alerts
    else:
        print("No threats detected.")
        return None
