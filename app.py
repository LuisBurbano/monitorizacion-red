import subprocess, sqlite3, os, json, socket, time
from flask import Flask, render_template, jsonify, request
from threading import Thread, Event
from scapy.all import sniff

app = Flask(__name__)

scan_active = False
detected_packets = []
alerts = []  
stop_event = Event()

DB_PATH = "datos.db"

# 🔹 Inicializar la base de datos si no existe
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo_ataque TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                paquetes INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ips_bloqueadas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ips_excluidas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                scan_active INTEGER DEFAULT 0
            )
        """)

        cursor.execute("INSERT OR IGNORE INTO config (id, scan_active) VALUES (1, 0)")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

init_db()

# 🔹 Variables Globales
packet_timestamps = {}  
port_scanning_attempts = {}  
brute_force_attempts = {}  
spoofed_ips = set()  
LOCAL_IP = socket.gethostbyname(socket.gethostname())  

# 🔹 Parámetros de detección
TIME_WINDOW = 10  
BLOCK_THRESHOLD = 50  
PORT_SCAN_THRESHOLD = 10  
BRUTE_FORCE_THRESHOLD = 5  
SUSPICIOUS_PORTS = {22, 3389, 80, 443}  

def save_event(tipo_ataque, ip_origen, paquetes):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO eventos (tipo_ataque, ip_origen, paquetes)
            VALUES (?, ?, ?)
        """, (tipo_ataque, ip_origen, paquetes))
        conn.commit()
        conn.close()

def get_scan_status():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_active FROM config WHERE id = 1")
    result = cursor.fetchone()
    conn.close()
    return bool(result[0]) if result else False

def set_scan_status(status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE config SET scan_active = ? WHERE id = 1", (1 if status else 0,))
    conn.commit()
    conn.close()

def capture_traffic():
    global detected_packets, packet_timestamps, port_scanning_attempts, brute_force_attempts, spoofed_ips

    def process_packet(packet):
        if not scan_active or stop_event.is_set():
            return

        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst

            # 🚫 Ignorar la IP de la máquina local
            if ip_src == LOCAL_IP:
                return  

            # 🚫 Ignorar IPs excluidas
            excluded_ips = get_excluded_ips()
            if ip_src in excluded_ips or ip_dst in excluded_ips:
                return  

            detected_packets.append({
                "origen": ip_src,
                "destino": ip_dst,
                "protocolo": packet.summary()
            })

            # 📌 Detección de DDoS
            now = time.time()
            if ip_src not in packet_timestamps:
                packet_timestamps[ip_src] = []
            packet_timestamps[ip_src].append(now)
            packet_timestamps[ip_src] = [t for t in packet_timestamps[ip_src] if now - t <= TIME_WINDOW]

            if len(packet_timestamps[ip_src]) > BLOCK_THRESHOLD:
                save_event("Ataque DDoS Detectado", ip_src, len(packet_timestamps[ip_src]))
                block_ip(ip_src)
                packet_timestamps[ip_src] = []

            # 📌 Detección de Escaneo de Puertos
            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport
                if ip_src not in port_scanning_attempts:
                    port_scanning_attempts[ip_src] = set()
                port_scanning_attempts[ip_src].add(port)

                if len(port_scanning_attempts[ip_src]) > PORT_SCAN_THRESHOLD:
                    save_event("Escaneo de Puertos Detectado", ip_src, len(port_scanning_attempts[ip_src]))
                    block_ip(ip_src)
                    port_scanning_attempts[ip_src] = set()

            # 📌 Detección de Fuerza Bruta
            if packet.haslayer("TCP") and packet["TCP"].dport in SUSPICIOUS_PORTS:
                if ip_src not in brute_force_attempts:
                    brute_force_attempts[ip_src] = 0
                brute_force_attempts[ip_src] += 1

                if brute_force_attempts[ip_src] > BRUTE_FORCE_THRESHOLD:
                    save_event("Ataque de Fuerza Bruta Detectado", ip_src, brute_force_attempts[ip_src])
                    block_ip(ip_src)
                    brute_force_attempts[ip_src] = 0

            # 📌 Detección de IP Spoofing
            if ip_src in spoofed_ips:
                save_event("Ataque de IP Spoofing Detectado", ip_src, 1)
                block_ip(ip_src)
            else:
                spoofed_ips.add(ip_src)

    while scan_active and not stop_event.is_set():
        sniff(prn=process_packet, store=False, timeout=5)

@app.route('/toggle_scan', methods=['POST'])
def toggle_scan():
    global scan_active, stop_event

    scan_active = not get_scan_status()  
    set_scan_status(scan_active)  

    if scan_active:
        stop_event.clear()
        thread = Thread(target=capture_traffic, daemon=True)
        thread.start()
    else:
        stop_event.set()

    return jsonify({"status": scan_active})

@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    global alerts
    return jsonify(alerts)  

@app.route('/get_packets', methods=['GET'])
def get_packets():
    return jsonify(detected_packets)

@app.route('/get_ip_stats', methods=['GET'])
def get_ip_stats():
    ip_stats = {ip: len(timestamps) for ip, timestamps in packet_timestamps.items()}
    return jsonify(ip_stats)

@app.route('/configuracion_ips')
def configuracion_ips():
    return render_template("configuracion_ips.html", 
                           blocked_ips=get_blocked_ips(), 
                           excluded_ips=get_excluded_ips())

@app.route('/ver_eventos')
def ver_eventos():
    eventos = get_events()
    return render_template("ver_eventos.html", eventos=eventos)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
