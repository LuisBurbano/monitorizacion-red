def analyze_packet(packet):
    """Analiza un paquete en busca de patrones sospechosos."""
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto

        # Ejemplo: Detección de escaneo de puertos
        if packet.haslayer("TCP") or packet.haslayer("UDP"):
            port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport
            print(f"Posible escaneo de puertos: {src_ip} -> {dst_ip}:{port}")

        # Imprimir información básica del paquete
        print(f"[INFO] {src_ip} -> {dst_ip} (Protocolo: {protocol})")
