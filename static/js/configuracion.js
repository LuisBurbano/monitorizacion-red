function addExcludedIp() {
    let ip = document.getElementById("excludeIpInput").value;
    fetch('/add_excluded_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    }).then(() => location.reload());
}

function removeExcludedIp(ip) {
    fetch('/remove_excluded_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    }).then(() => location.reload());
}

function unblockIp(ip) {
    fetch('/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    }).then(() => location.reload());
}
