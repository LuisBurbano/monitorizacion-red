from scapy.all import sniff, Packet
from src.filters import analyze_packet

def packet_callback(packet: Packet):
    """Callback que se ejecuta por cada paquete capturado."""
    try:
        analyze_packet(packet)
    except Exception as e:
        print(f"Error al analizar paquete: {e}")

def start_sniffer(interface: str):
    """Inicia el sniffer en una interfaz de red específica."""
    print(f"Escuchando tráfico en la interfaz: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)
