from scapy.all import sniff, IP  # Ajoute l'import de IP
from collections import Counter
import psutil

def capture_traffic(interface, duration):
    """Capture traffic from the specified network interface for the given duration."""
    print(f"Capturing on interface: {interface} for {duration} seconds...")
    packets = sniff(iface=interface, timeout=duration)
    return packets

def list_protocols(packets):
    """List all protocols captured during the traffic sniffing."""
    protocols = Counter([pkt.summary().split()[1] for pkt in packets if IP in pkt])
    return protocols

def list_network_interfaces():
    """List all available network interfaces with their descriptions."""
    interfaces = []
    for interface_name, interface_info in psutil.net_if_addrs().items():
        description = interface_info[0].address  # Assuming the first one is the main address (IPv4 or MAC)
        interfaces.append((interface_name, description))
    print("Available network interfaces with descriptions:")
    for idx, (iface, desc) in enumerate(interfaces):
        print(f"{idx + 1}. {iface} - {desc}")
    
    return interfaces

def choose_interface():
    """Prompt the user to choose a network interface by its description."""
    interfaces = list_network_interfaces()
    choice = input(f"Select the interface number (1-{len(interfaces)}): ")
    
    try:
        interface_index = int(choice) - 1
        if 0 <= interface_index < len(interfaces):
            return interfaces[interface_index][0]  # Return the interface name (not description)
        else:
            print("Invalid selection. Please try again.")
            return choose_interface()
    except ValueError:
        print("Please enter a valid number.")
        return choose_interface()
