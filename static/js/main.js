document.addEventListener("DOMContentLoaded", function () {
    let toggleScanBtn = document.getElementById("toggleScan");
    
    toggleScanBtn.addEventListener("click", () => {
        fetch('/toggle_scan', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                toggleScanBtn.textContent = data.status.includes("activated") ? "Detener Escaneo" : "Iniciar Escaneo";
                toggleScanBtn.classList.toggle("btn-danger");
                toggleScanBtn.classList.toggle("btn-success");
            });
    });
});
