import os  # Import de la bibliothèque os pour gérer les répertoires
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

# Créer le dossier 'Reports' s'il n'existe pas déjà
if not os.path.exists('Reports'):
    os.makedirs('Reports')

def generate_graph(protocols, interface_name):
    """Generate a bar chart for the captured network protocols and save it to the Reports folder."""
    plt.figure(figsize=(10, 6))
    plt.bar(protocols.keys(), protocols.values(), color='skyblue')
    plt.xlabel('Protocols')
    plt.ylabel('Packet Count')
    plt.title('Captured Network Protocols Statistics')

    # Formater l'heure pour éviter des caractères spéciaux dans les noms de fichiers
    current_time = datetime.now().strftime('%H-%M')

    # Sauvegarder le graphique avec l'interface et l'heure dans le dossier Reports
    graph_filename = f'protocol_stats_{interface_name}_{current_time}.png'
    graph_path = os.path.join('Reports', graph_filename)
    plt.savefig(graph_path)
    plt.close()

    return graph_path  # Retourner le chemin complet du fichier graphique

def generate_pdf(protocols, alerts, interface_name):
    """Generate a PDF report including protocol statistics and detected threats, saved to the Reports folder."""
    
    # Formater l'heure pour éviter des caractères spéciaux dans les noms de fichiers
    current_time = datetime.now().strftime('%H-%M')
    
    # Chemin complet pour le fichier PDF dans le dossier Reports avec l'interface et l'heure
    pdf_filename = f'rapport_ids_ips_{interface_name}_{current_time}.pdf'
    pdf_path = os.path.join('Reports', pdf_filename)

    # Créer le fichier PDF
    pdf = canvas.Canvas(pdf_path, pagesize=letter)
    pdf.setTitle(f"IDS/IPS Report for {interface_name}")
    
    # Add date and time
    pdf.drawString(50, 750, f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Add protocol statistics table
    pdf.drawString(50, 730, f"Captured Protocol Statistics for {interface_name}:")
    y = 700
    for protocol, count in protocols.items():
        pdf.drawString(50, y, f"{protocol}: {count} packets")
        y -= 20
    
    # Add detected alerts
    if alerts:
        pdf.drawString(50, y, "Detected Threats:")
        y -= 20
        for alert in alerts:
            pdf.drawString(50, y, alert)
            y -= 20
    else:
        pdf.drawString(50, y, "No threats detected.")
        y -= 20
    
    # Add protocol graph
    graph_path = f'protocol_stats_{interface_name}_{current_time}.png'
    graph_full_path = os.path.join('Reports', graph_path)
    if os.path.exists(graph_full_path):
        pdf.drawImage(graph_full_path, 50, y - 200, width=500, height=300)
    
    # Enregistrer le fichier PDF
    pdf.save()

    return pdf_path  # Retourner le chemin complet du fichier PDF
