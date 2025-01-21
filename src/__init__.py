import pandas as pd
from datetime import datetime

LOG_FILE = "data/logs/traffic_log.csv"

def log_packet(data):
    """Guarda información del paquete en un archivo CSV."""
    df = pd.DataFrame([data])
    df.to_csv(LOG_FILE, mode='a', header=False, index=False)

def analyze_packet(packet):
    """Analiza y registra paquetes sospechosos."""
    if packet.haslayer("IP"):
        data = {
            "timestamp": datetime.now(),
            "src_ip": packet["IP"].src,
            "dst_ip": packet["IP"].dst,
            "protocol": packet["IP"].proto,
        }
        # Ejemplo: Almacenar todos los paquetes
        log_packet(data)
        print(data)
