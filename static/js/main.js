document.addEventListener("DOMContentLoaded", function () {
    let toggleScanBtn = document.getElementById("toggleScan");
    let packetTableBody = document.querySelector("#packetTable tbody");

    // Función para actualizar el estado del botón de escaneo
    function updateScanButton() {
        fetch('/scan_status')
            .then(response => response.json())
            .then(data => {
                toggleScanBtn.textContent = data.status ? "Detener Escaneo" : "Iniciar Escaneo";
                toggleScanBtn.classList.toggle("btn-danger", data.status);
                toggleScanBtn.classList.toggle("btn-success", !data.status);
            });
    }

    // Función para obtener paquetes escaneados y mostrarlos en la tabla
    function fetchPackets() {
        fetch('/get_packets')
            .then(response => response.json())
            .then(data => {
                packetTableBody.innerHTML = ""; // Limpiar la tabla
                data.forEach(packet => {
                    let row = `<tr>
                        <td>${packet.origen}</td>
                        <td>${packet.destino}</td>
                        <td>${packet.protocolo}</td>
                    </tr>`;
                    packetTableBody.innerHTML += row;
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
