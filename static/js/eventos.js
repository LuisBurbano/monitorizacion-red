document.addEventListener("DOMContentLoaded", function () {
    let searchInput = document.getElementById("searchInput");
    let eventTable = document.getElementById("eventTable");
    let headers = document.querySelectorAll("th");
    let sortButtons = document.querySelectorAll(".sort-btn");

    // 🔹 Función para ordenar la tabla
    function sortTableBy(columnIndex, columnType, order, button) {
        let rows = Array.from(eventTable.getElementsByTagName("tr"));

        rows.sort((a, b) => {
            let aValue = a.cells[columnIndex].textContent.trim();
            let bValue = b.cells[columnIndex].textContent.trim();

            if (columnType === "number") {
                aValue = parseInt(aValue);
                bValue = parseInt(bValue);
            } else if (columnType === "date") {
                aValue = new Date(aValue).getTime();
                bValue = new Date(bValue).getTime();
            }

            return order === "asc" ? aValue - bValue : bValue - aValue;
        });

        eventTable.innerHTML = "";
        rows.forEach(row => eventTable.appendChild(row));

        // 🔹 Cambiar el icono de ordenación
        sortButtons.forEach(btn => btn.querySelector("i").className = "fas fa-sort"); // Reset icons
        button.querySelector("i").className = order === "asc" ? "fas fa-sort-up" : "fas fa-sort-down";
    }

    // 🔹 Agregar evento de ordenación en encabezados
    sortButtons.forEach((button, index) => {
        button.addEventListener("click", function () {
            let columnType = headers[index].getAttribute("data-type");
            let currentOrder = headers[index].getAttribute("data-order") || "desc";
            let newOrder = currentOrder === "asc" ? "desc" : "asc";

            sortTableBy(index, columnType, newOrder, button);
            headers[index].setAttribute("data-order", newOrder); // Guardar estado
        });
    });

    // 🔹 Filtrado por IP y Tipo de Ataque
    searchInput.addEventListener("keyup", function () {
        let filter = searchInput.value.toLowerCase();
        let rows = eventTable.getElementsByTagName("tr");

        if (rows.length === 0) {
            return;
        }

        for (let row of rows) {
            let ipCell = row.cells.length > 2 ? row.cells[2].textContent.toLowerCase() : "";
            let attackCell = row.cells.length > 1 ? row.cells[1].textContent.toLowerCase() : "";
            row.style.display = ipCell.includes(filter) || attackCell.includes(filter) ? "" : "none";
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
