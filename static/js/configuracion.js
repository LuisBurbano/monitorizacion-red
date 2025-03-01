function addExcludedIp() {
    let ip = document.getElementById("excludeIpInput").value.trim();
    if (!ip) {
        alert("Por favor, ingrese una IP válida.");
        return;
    }

    fetch('/add_excluded_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
        location.reload();
    })
    .catch(error => console.error("Error al excluir la IP:", error));
}

function removeExcludedIp(ip) {
    if (!confirm(`¿Estás seguro de eliminar la IP ${ip} de la exclusión?`)) return;

    fetch('/remove_excluded_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
        location.reload();
    })
    .catch(error => console.error("Error al eliminar la IP:", error));
}

function addBlockedIp() {
    let ip = document.getElementById("blockIpInput").value.trim();
    if (!ip) {
        alert("Por favor, ingrese una IP válida.");
        return;
    }

    fetch('/block_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
        location.reload();
    })
    .catch(error => console.error("Error al bloquear la IP:", error));
}


function unblockIp(ip) {
    if (!confirm(`¿Estás seguro de desbloquear la IP ${ip}?`)) return;

    fetch('/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
        location.reload();
    })
    .catch(error => console.error("Error al desbloquear la IP:", error));
}
