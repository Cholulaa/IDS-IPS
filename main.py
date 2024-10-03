import platform
from traffic_capture import capture_traffic, list_protocols, choose_interface
from traffic_analysis import analyze_traffic
from report_generator import generate_graph, generate_pdf

def main():
    # Detect the operating system
    os_type = platform.system().lower()
    print(f"Detected operating system: {os_type}")

    # Allow the user to choose a network interface
    interface = choose_interface(os_type)

    # Ask the user for the duration of the capture
    duration = int(input("Enter the capture duration in seconds: "))

    # Capture traffic on the selected interface
    packets = capture_traffic(interface, duration, os_type)
    protocols = list_protocols(packets)

    if protocols:
        print("Protocols captured:", protocols)

        # Analyze the traffic and detect attacks
        alerts = analyze_traffic(packets)
        if alerts:
            print(f"Threats detected: {alerts}")

        # Generate a graph and a PDF report with the interface and timestamp
        graph_path = generate_graph(protocols, interface)
        pdf_path = generate_pdf(protocols, alerts, interface)

        print(f"Report and graph saved: {pdf_path}, {graph_path}")
    else:
        print("No traffic captured.")

if __name__ == "__main__":
    main()
