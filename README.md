# 🛡️ Monitorización de Red y Detección de Ataques

Este proyecto enfocado en Windows 11 es un **sistema de monitorización de red** basado en **Flask y Scapy**, diseñado para detectar actividades sospechosas en la red en tiempo real, incluyendo ataques **DDoS, escaneo de puertos, ataques de fuerza bruta e IP Spoofing**. El sistema permite bloquear automáticamente direcciones IP sospechosas y muestra alertas en una interfaz web.

## 📌 Características Principales
- 📡 **Captura de tráfico en tiempo real** utilizando `Scapy`.
- 🛑 **Bloqueo automático de IPs sospechosas** mediante reglas de firewall.
- 🚨 **Detección de múltiples tipos de ataques**, incluyendo:
  - **DDoS (Denegación de servicio distribuida)**
  - **Escaneo de Puertos**
  - **Ataques de Fuerza Bruta**
  - **IP Spoofing**
- 🖥 **Interfaz web dinámica** para visualizar eventos de seguridad.
- 📝 **Registro de eventos en una base de datos SQLite**.
- 🔍 **Búsqueda y filtrado de eventos**.
- 🌐 **Interfaz amigable en Bootstrap con actualización en tiempo real**.

## 🚀 Requisitos

Asegúrate de tener instalados los siguientes componentes:

- Python 3.8+
- Npcap: Packet capture library for Windows

Puedes instalar Npcap desde: 
```bash
https://npcap.com/#download
```

## 📥 Instalación

1. **Clona el repositorio:**
```bash
git clone https://github.com/LuisBurbano/monitorizacion-red.git
cd monitorizacion-red
```
2. **Configura un entorno virtual (opcional pero recomendado):**
```bash
python -m venv venv
source venv/bin/activate  # En Linux/macOS
venv\Scripts\activate  # En Windows
```
3. **Instala las dependencias:**
```bash
pip install -r requirements.txt
```
4. **Ejecuta la aplicación:**
```bash
python app.py
```

La aplicación se ejecutará en `http://127.0.0.1:5000` o `http://localhost:5000`.

## 🖥 Uso
### 🔹 1. Iniciar el escaneo de tráfico
- Accede a `http://localhost:5000`.
- Haz clic en **Iniciar Escaneo**.
- Verás los paquetes en tiempo real en la tabla.

### 🔹 2. Ver eventos detectados
- Haz clic en **"Ver Eventos Detallados"** para acceder a la página de incidentes.
- Podrás ordenar y buscar eventos por IP.

### 🔹 3. Configurar IPs bloqueadas/excluidas
- Desde la opción **"Configuración de IPs"**, puedes:
  - **Bloquear manualmente una IP**.
  - **Excluir IPs del escaneo** (por ejemplo, dispositivos seguros).
  - **Desbloquear IPs previamente bloqueadas**.

## 🛠 Detección de Ataques
El sistema analiza el tráfico y detecta diferentes ataques con base en umbrales predefinidos:

| Ataque | Descripción | Acción |
|--------|------------|--------|
| **DDoS** | Más de `100` paquetes en `15s` desde una misma IP | Bloqueo automático |
| **Escaneo de Puertos** | Más de `10` intentos de conexión a diferentes puertos | Bloqueo automático |
| **Fuerza Bruta** | Más de `5` intentos en puertos sensibles (22, 3389, 80, 443) | Bloqueo automático |

## 📄 Base de Datos
El sistema usa **SQLite** para almacenar los eventos de seguridad. La base de datos `datos.db` contiene las siguientes tablas:
- **`eventos`**: Registra los incidentes detectados.
- **`ips_bloqueadas`**: Almacena IPs bloqueadas manual o automáticamente.
- **`ips_excluidas`**: Contiene IPs que serán ignoradas en el escaneo.
- **`config`**: Guarda el estado del escaneo (activo/inactivo).

## 📌 Notas Adicionales
- Asegúrate de ejecutar la aplicación con permisos de administrador para capturar tráfico de red correctamente.
- Puedes cambiar los umbrales de detección editando las constantes en `app.py`.
- Para verificar las reglas de firewall en Windows, usa:
```bash
netsh advfirewall firewall show rule name=all
```

## 👥 Contribuciones
¡Las contribuciones son bienvenidas! Si deseas mejorar la detección de ataques o añadir nuevas características, envía un Pull Request.

## 📜 Licencia
Este proyecto está bajo la licencia **MIT**. Puedes usarlo y modificarlo libremente.

