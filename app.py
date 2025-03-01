import subprocess, sqlite3, os, json
from flask import Flask, render_template, jsonify, request
from threading import Thread, Event
from scapy.all import sniff

app = Flask(__name__)

scan_active = False
detected_packets = []
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
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

init_db()

# 🔹 Función para capturar paquetes cuando el escaneo está activo
def capture_traffic():
    global detected_packets

    def process_packet(packet):
        if not scan_active or stop_event.is_set():
            return

        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            detected_packets.append({
                "origen": ip_src,
                "destino": ip_dst,
                "protocolo": packet.summary()
            })
        if len(detected_packets) > 50:  # Evita que la lista crezca indefinidamente
            detected_packets.pop(0)

    while scan_active and not stop_event.is_set():
        sniff(prn=process_packet, store=False, timeout=5)

# 🔹 API para controlar el escaneo de tráfico
@app.route('/toggle_scan', methods=['POST', 'GET'])
def toggle_scan():
    global scan_active, stop_event

    if request.method == 'GET':
        return jsonify({"status": scan_active})

    scan_active = not scan_active

    if scan_active:
        stop_event.clear()
        thread = Thread(target=capture_traffic, daemon=True)
        thread.start()
    else:
        stop_event.set()

    return jsonify({"status": scan_active}), 200

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
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        if ip not in get_blocked_ips():
            cursor.execute("INSERT INTO ips_bloqueadas (ip) VALUES (?)", (ip,))
            command = f'netsh advfirewall firewall add rule name="Bloqueo {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(command, shell=True)
            conn.commit()
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
    return jsonify({"status": scan_active})

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
