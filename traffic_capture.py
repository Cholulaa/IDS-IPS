from scapy.all import sniff, IP
from collections import Counter
import psutil
import platform

def capture_traffic(interface, duration, os_type):
    """Capture traffic from the specified network interface for the given duration."""
    print(f"Capturing on interface: {interface} for {duration} seconds...")

    # Windows requires Npcap/WinPcap installed for Scapy to capture packets
    if 'windows' in os_type:
        print("Ensure WinPcap or Npcap is installed on Windows.")

    # Capture packets using Scapy
    packets = sniff(iface=interface, timeout=duration)
    return packets

def list_protocols(packets):
    """List all protocols captured during the traffic sniffing."""
    protocols = Counter([pkt.summary().split()[1] for pkt in packets if IP in pkt])
    return protocols

def list_network_interfaces(os_type):
    """List all available network interfaces with their descriptions, adapting to OS."""
    interfaces = []

    if 'windows' in os_type:
        # On Windows, use psutil to list network interfaces
        for interface_name, interface_info in psutil.net_if_addrs().items():
            description = interface_info[0].address  # Assuming the first is main (IPv4 or MAC)
            interfaces.append((interface_name, description))
    elif 'linux' in os_type:
        # On Linux, also use psutil to list network interfaces
        for interface_name, interface_info in psutil.net_if_addrs().items():
            description = interface_info[0].address
            interfaces.append((interface_name, description))
    else:
        print("Unsupported OS")

    print("Available network interfaces with descriptions:")
    for idx, (iface, desc) in enumerate(interfaces):
        print(f"{idx + 1}. {iface} - {desc}")

    return interfaces

def choose_interface(os_type):
    """Prompt the user to choose a network interface based on the OS."""
    interfaces = list_network_interfaces(os_type)
    choice = input(f"Select the interface number (1-{len(interfaces)}): ")

    try:
        interface_index = int(choice) - 1
        if 0 <= interface_index < len(interfaces):
            return interfaces[interface_index][0]  # Return the interface name
        else:
            print("Invalid selection. Please try again.")
            return choose_interface(os_type)
    except ValueError:
        print("Please enter a valid number.")
        return choose_interface(os_type)
