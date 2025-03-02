document.addEventListener("DOMContentLoaded", function () {
    let searchInput = document.getElementById("searchInput");
    let eventTable = document.getElementById("eventTable");
    let headers = document.querySelectorAll("th");

    function sortTableBy(columnIndex, ascending = true) {
        let rows = Array.from(eventTable.getElementsByTagName("tr"));
        rows.shift(); // Omitir encabezados si están presentes

        rows.sort((a, b) => {
            let aValue = a.cells[columnIndex].textContent.trim();
            let bValue = b.cells[columnIndex].textContent.trim();

            if (columnIndex === 0) { // Ordenar por ID (número)
                aValue = parseInt(aValue);
                bValue = parseInt(bValue);
            } else if (columnIndex === 4) { // Ordenar por fecha
                aValue = new Date(aValue).getTime();
                bValue = new Date(bValue).getTime();
            }

            return ascending ? aValue - bValue : bValue - aValue;
        });

        eventTable.innerHTML = ""; // Limpiar tabla y volver a insertar filas ordenadas
        rows.forEach(row => eventTable.appendChild(row));
    }

    // Agregar evento de ordenación en encabezados
    headers.forEach((header, index) => {
        header.addEventListener("click", () => {
            let ascending = header.getAttribute("data-asc") === "true"; // Alternar orden
            sortTableBy(index, !ascending);
            header.setAttribute("data-asc", !ascending); // Guardar estado
        });
    });

    // Filtrado por IP
    searchInput.addEventListener("keyup", function () {
        let filter = searchInput.value.toLowerCase();
        let rows = eventTable.getElementsByTagName("tr");

        if (rows.length === 0) {
            return;
        }

        for (let row of rows) {
            let ipCell = row.cells.length > 2 ? row.cells[2].textContent.toLowerCase() : "";
            row.style.display = ipCell.includes(filter) ? "" : "none";
        }
    });

    searchInput.addEventListener("search", function () {
        if (!searchInput.value.trim()) {
            let rows = eventTable.getElementsByTagName("tr");
            for (let row of rows) {
                row.style.display = "";
            }
        }
    });
});
