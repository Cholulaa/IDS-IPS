import platform
from traffic_capture import capture_traffic, choose_interface
from traffic_analysis import analyze_packet
from report_generator import generate_graph, generate_pdf
from collections import Counter
import threading
import keyboard  # For detecting keyboard events
import time

# Flag to stop continuous capture
stop_capture = False

def main():
    # Detect the operating system
    os_type = platform.system().lower()
    print(f"Detected operating system: {os_type}")

    # Allow the user to choose a network interface
    interface = choose_interface(os_type)

    # Ask the user if they want continuous detection
    detection_mode = input("Do you want continuous detection? (yes/no): ").strip().lower()

    if detection_mode == "yes":
        # Continuous mode: Capture and analyze traffic in real-time
        print("Starting continuous detection mode. Press 'S' to stop.")
        global stop_capture

        # Start the packet capturing in a separate thread
        capture_thread = threading.Thread(target=continuous_capture, args=(interface, os_type))
        capture_thread.start()

        # Wait for the user to press 'S' to stop the capture
        while not stop_capture:
            if keyboard.is_pressed('s'):
                stop_capture = True
            time.sleep(0.1)  # Short delay to prevent high CPU usage

        # Wait for the capture thread to stop
        capture_thread.join()
        print("Continuous detection stopped.")

        # Optionally generate a report with the protocols captured
        print(f"Generating final report for interface: {interface}")
        generate_final_report()

    else:
        # Time-limited mode: Ask for the duration
        duration = int(input("Enter the capture duration in seconds: "))
        capture_traffic(interface, duration, os_type)

def continuous_capture(interface, os_type):
    """Continuously capture and analyze packets in real-time."""
    from scapy.all import sniff

    global stop_capture
    protocols = Counter()

    # Continuous capture with a timeout to allow checking for the stop condition
    while not stop_capture:
        # Capture packets for 1 second at a time, then check the stop condition
        packets = sniff(iface=interface, timeout=1, store=False)
        for pkt in packets:
            process_packet(pkt, protocols)

def process_packet(packet, protocols):
    """Process each packet and detect threats, updating protocols."""
    # Update protocol stats
    if packet.haslayer("IP"):
        proto = packet.summary().split()[1]
        protocols[proto] += 1

    # Analyze packet for threats
    analyze_packet(packet)

def generate_final_report():
    """Generate a final report after continuous capture is stopped."""
    print("Generating final report...")
    # Example: generate graph and pdf (this would depend on how you accumulate the data)
    # graph_path = generate_graph(protocols, interface)
    # pdf_path = generate_pdf(protocols, alerts, interface)
    # print(f"Report saved: {pdf_path}, Graph saved: {graph_path}")

if __name__ == "__main__":
    main()
