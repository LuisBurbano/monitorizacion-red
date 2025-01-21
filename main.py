from src.packet_sniffer import start_sniffer

def main():
    print("Iniciando monitoreo de tráfico...")
    interface = "eth0"  # Cambia a la interfaz de red que usarás
    start_sniffer(interface)

if __name__ == "__main__":
    main()
