import subprocess, sqlite3, os, json, socket, time, pytz
from flask import Flask, render_template, jsonify, request
from threading import Thread, Event
from scapy.all import sniff, conf
from datetime import datetime

app = Flask(__name__)

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
        # 🔹 Nueva tabla para almacenar el estado del escaneo
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                scan_active INTEGER DEFAULT 0
            )
        """)

        # 🔹 Asegurar que siempre hay un valor en config
        cursor.execute("INSERT OR IGNORE INTO config (id, scan_active) VALUES (1, 0)")
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

init_db()

# 🔹 Variables Globales
scan_active = False
detected_packets = []
alerts = []
stop_event = Event()
packet_timestamps = {}  # Rastreo de paquetes por IP para detección de DDoS
port_scanning_attempts = {}  # Rastreo de escaneo de puertos
brute_force_attempts = {}  # Rastreo de intentos de fuerza bruta
spoofed_ips = set()  # Rastreo de IPs sospechosas de Spoofing
mac_tracking = {}  # Última MAC detectada por cada IP

# 🔹 Obtener IP local y la IP del router (gateway predeterminado)
LOCAL_IP = socket.gethostbyname(socket.gethostname())  
ROUTER_IP = conf.route.route("0.0.0.0")[2]

# 🔹 Parámetros de detección
TIME_WINDOW = 15  # Segundos para detectar DDoS y escaneo de puertos
BLOCK_THRESHOLD = 100  # Máximo de paquetes antes de bloquear una IP (DDoS)
PORT_SCAN_THRESHOLD = 10  # Máximo de puertos escaneados antes de bloqueo
BRUTE_FORCE_THRESHOLD = 5  # Intentos de acceso a puertos sensibles antes de bloqueo
SUSPICIOUS_PORTS = {22, 3389, 80, 443, 3306, 5432}  # Puertos críticos que podrían ser atacados

# 🔹 Función para capturar paquetes cuando el escaneo está activo
# Diccionario para contar paquetes por IP
packet_count = {}

# Obtener zona horaria local de la máquina
LOCAL_TZ = pytz.timezone("America/Mexico_City")  # Cambia según tu ubicación

def get_local_timestamp():
    """ Devuelve la hora actual en la zona horaria local """
    return datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")


def save_event(tipo_ataque, ip_origen, paquetes):
    """
    Guarda un evento sospechoso en la base de datos con hora local.
    """
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO eventos (tipo_ataque, ip_origen, paquetes, timestamp)
            VALUES (?, ?, ?, ?)
        """, (tipo_ataque, ip_origen, paquetes, get_local_timestamp()))
        conn.commit()
        conn.close()

def get_scan_status():
    """
    Obtiene el estado actual del escaneo desde la base de datos.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_active FROM config WHERE id = 1")
    result = cursor.fetchone()
    conn.close()
    return bool(result[0]) if result else False

# 🔹 Actualiza el estado del escaneo en la base de datos
def set_scan_status(status):
    """
    Actualiza el estado del escaneo en la base de datos.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE config SET scan_active = ? WHERE id = 1", (1 if status else 0,))
    conn.commit()
    conn.close()


# 🔹 Función para capturar y analizar tráfico en tiempo real
def capture_traffic():
    global detected_packets, packet_timestamps, port_scanning_attempts, brute_force_attempts, spoofed_ips

    def process_packet(packet):
        if not scan_active or stop_event.is_set():
            return

        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst

            # 🚫 Ignorar la IP local y la IP del router
            if ip_src == LOCAL_IP or ip_src == ROUTER_IP:
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

            # Limpiar registros viejos y verificar si excede el umbral
            packet_timestamps[ip_src] = [t for t in packet_timestamps[ip_src] if now - t <= TIME_WINDOW]
            if len(packet_timestamps[ip_src]) > BLOCK_THRESHOLD:
                save_event("Ataque DDoS Detectado", ip_src, len(packet_timestamps[ip_src]))
                block_ip(ip_src)
                packet_timestamps[ip_src] = []  # Resetear contador

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
            #if ip_src in spoofed_ips:
            #    save_event("Ataque de IP Spoofing Detectado", ip_src, 1)
            #    block_ip(ip_src)
            #else:
            #    spoofed_ips.add(ip_src)

    while scan_active and not stop_event.is_set():
        sniff(prn=process_packet, store=False, timeout=5)

# 🔹 API para controlar el escaneo de tráfico
@app.route('/toggle_scan', methods=['POST'])
def toggle_scan():
    global scan_active, stop_event

    scan_active = not get_scan_status()  # 🔹 Alternar estado real de la BD
    set_scan_status(scan_active)  # 🔹 Guardar nuevo estado en la BD

    if scan_active:
        stop_event.clear()
        thread = Thread(target=capture_traffic, daemon=True)
        thread.start()
    else:
        stop_event.set()

    return jsonify({"status": scan_active})

@app.route('/get_ip_stats', methods=['GET'])
def get_ip_stats():
    """
    Retorna la cantidad de paquetes enviados por cada IP en el escaneo.
    """
    ip_stats = {ip: len(timestamps) for ip, timestamps in packet_timestamps.items()}
    return jsonify(ip_stats)


@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    global alerts
    return jsonify(alerts)  # Enviar las alertas acumuladas al frontend

# 🔹 API para obtener paquetes en tiempo real
@app.route('/get_packets', methods=['GET'])
def get_packets():
    return jsonify(detected_packets)

# 🔹 Funciones de base de datos con manejo de errores
def get_db_connection():
    try:
        return sqlite3.connect(DB_PATH)
    except sqlite3.Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None

def get_blocked_ips():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM ips_bloqueadas")
    blocked_ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return blocked_ips

def get_excluded_ips():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM ips_excluidas")
    excluded_ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return excluded_ips

def add_excluded_ip(ip):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        if ip not in get_excluded_ips():
            cursor.execute("INSERT INTO ips_excluidas (ip) VALUES (?)", (ip,))
            conn.commit()
        conn.close()

def remove_excluded_ip(ip):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ips_excluidas WHERE ip=?", (ip,))
        conn.commit()
        conn.close()

def unblock_ip(ip):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ips_bloqueadas WHERE ip=?", (ip,))
        command = f'netsh advfirewall firewall delete rule name="Bloqueo {ip}"'
        subprocess.run(command, shell=True)
        conn.commit()
        conn.close()

def block_ip(ip):
    global alerts
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        if ip not in get_blocked_ips():
            cursor.execute("INSERT INTO ips_bloqueadas (ip) VALUES (?)", (ip,))
            command = f'netsh advfirewall firewall add rule name="Bloqueo {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(command, shell=True)
            conn.commit()

            # Registrar alerta
            alerts.append(f"¡IP {ip} ha sido bloqueada automáticamente por actividad sospechosa!")

        conn.close()


def get_events():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor()
    cursor.execute("SELECT id, tipo_ataque, ip_origen, paquetes, timestamp FROM eventos ORDER BY timestamp DESC")
    eventos = [{"id": row[0], "tipo_ataque": row[1], "ip_origen": row[2], "paquetes": row[3], "timestamp": row[4]} for row in cursor.fetchall()]
    conn.close()
    return eventos

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan_status', methods=['GET'])
def scan_status():
    return jsonify({"status": get_scan_status()})  # Obtener el estado real desde la BD

@app.route('/ver_eventos')
def ver_eventos():
    eventos = get_events()
    return render_template("ver_eventos.html", eventos=eventos)

@app.route('/configuracion_ips')
def configuracion_ips():
    return render_template("configuracion_ips.html", 
                           blocked_ips=get_blocked_ips(), 
                           excluded_ips=get_excluded_ips())

@app.route('/block_ip', methods=['POST'])
def block_ip_route():
    try:
        data = request.json
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": "No se proporcionó una IP válida."}), 400
        block_ip(ip)
        return jsonify({"status": f"IP {ip} bloqueada."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip_route():
    data = request.json
    ip = data.get("ip")
    if ip:
        unblock_ip(ip)
        return jsonify({"status": f"IP {ip} desbloqueada."})
    return jsonify({"error": "No se proporcionó una IP válida."}), 400

@app.route('/add_excluded_ip', methods=['POST'])
def add_excluded_ip_route():
    data = request.json
    ip = data.get("ip")
    if ip:
        add_excluded_ip(ip)
        return jsonify({"status": f"IP {ip} excluida."})
    return jsonify({"error": "No se proporcionó una IP válida."}), 400

@app.route('/remove_excluded_ip', methods=['POST'])
def remove_excluded_ip_route():
    data = request.json
    ip = data.get("ip")
    if ip:
        remove_excluded_ip(ip)
        return jsonify({"status": f"IP {ip} eliminada de la exclusión."})
    return jsonify({"error": "No se proporcionó una IP válida."}), 400

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
