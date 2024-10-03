from traffic_capture import capture_traffic, list_protocols, choose_interface
from traffic_analysis import analyze_traffic
from report_generator import generate_graph, generate_pdf

def main():
    # Permettre à l'utilisateur de choisir une interface réseau
    interface = choose_interface()
    
    # Demander à l'utilisateur la durée de la capture
    duration = int(input("Enter the capture duration in seconds: "))
    
    packets = capture_traffic(interface, duration)
    protocols = list_protocols(packets)
    
    if protocols:
        print("Protocols captured:", protocols)
        
        # Analyser le trafic et détecter les attaques
        alerts = analyze_traffic(packets)
        if alerts:
            print(f"Threats detected: {alerts}")
        
        # Générer un graphique et un rapport PDF avec le nom de l'interface et l'heure
        graph_path = generate_graph(protocols, interface)
        pdf_path = generate_pdf(protocols, alerts, interface)

        print(f"Report and graph saved: {pdf_path}, {graph_path}")
    else:
        print("No traffic captured.")

if __name__ == "__main__":
    main()
