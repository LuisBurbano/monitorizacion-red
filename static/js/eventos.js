document.addEventListener("DOMContentLoaded", function () {
    let searchInput = document.getElementById("searchInput");
    let eventTable = document.getElementById("eventTable");

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
