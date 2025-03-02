document.addEventListener("DOMContentLoaded", function () {
    let toggleScanBtn = document.getElementById("toggleScan");
    let packetTableBody = document.querySelector("#packetTable tbody");

    // Función para actualizar el estado del botón de escaneo
    function updateScanButton() {
        fetch('/scan_status')
            .then(response => response.json())
            .then(data => {
                let isActive = data.status;
                toggleScanBtn.textContent = isActive ? "Detener Escaneo" : "Iniciar Escaneo";
                toggleScanBtn.classList.toggle("btn-danger", isActive);
                toggleScanBtn.classList.toggle("btn-success", !isActive);
            })
            .catch(error => console.error("Error al obtener estado de escaneo:", error));
    }
    

    // Función para obtener paquetes escaneados y mostrarlos en la tabla
    function fetchPackets() {
        fetch('/get_packets')
            .then(response => response.json())
            .then(packetData => {
                fetch('/get_ip_stats') // Obtener estadísticas de paquetes por IP
                    .then(response => response.json())
                    .then(ipStats => {
                        packetTableBody.innerHTML = ""; // Limpiar la tabla

                        let packetCountByIp = {}; // Almacenar paquetes por IP

                        packetData.forEach(packet => {
                            let ip = packet.origen;
                            let count = ipStats[ip] || 0;  // Obtener cantidad de paquetes de esa IP

                            // Agregar al objeto para evitar duplicados
                            if (!packetCountByIp[ip]) {
                                packetCountByIp[ip] = {
                                    ip_origen: ip,
                                    ip_destino: packet.destino,
                                    protocolo: packet.protocolo,
                                    paquetes: count
                                };
                            }
                        });

                        // Actualizar la cantidad de IPs activas en la interfaz
                        document.getElementById("totalIPs").textContent = Object.keys(packetCountByIp).length;


                        // Insertar los datos en la tabla
                        Object.values(packetCountByIp).forEach((packet, index) => {
                            let row = `<tr>
                                <td>${index + 1}</td>  
                                <td>${packet.ip_origen}</td>
                                <td>${packet.ip_destino}</td>
                                <td>${packet.protocolo}</td>
                                <td>${packet.paquetes}</td>  <!-- Agregamos cantidad de paquetes enviados -->
                            </tr>`;
                            packetTableBody.innerHTML += row;
                        });
                    });
            });
    }

    // Alternar el estado del escaneo
    toggleScanBtn.addEventListener("click", () => {
        fetch('/toggle_scan', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                toggleScanBtn.textContent = data.status ? "Detener Escaneo" : "Iniciar Escaneo";
                toggleScanBtn.classList.toggle("btn-danger", data.status);
                toggleScanBtn.classList.toggle("btn-success", !data.status);
            });
    });

    // Llamar a las funciones para actualizar datos en tiempo real
    updateScanButton();
    setInterval(fetchPackets, 5000); // Cada 5 segundos obtener paquetes
});

function fetchAlerts() {
    fetch('/get_alerts')
        .then(response => response.json())
        .then(alerts => {
            let alertBox = document.getElementById("alerts");
            if (alerts.length > 0) {
                alertBox.innerHTML = alerts.join("<br>");  // Mostrar alertas
                alertBox.style.display = "block";
            } else {
                alertBox.style.display = "none";  // Ocultar si no hay alertas
            }
        });
}

// 🔹 Consultar alertas cada 5 segundos
setInterval(fetchAlerts, 5000);
