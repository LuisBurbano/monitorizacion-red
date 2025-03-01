document.addEventListener("DOMContentLoaded", function () {
    let searchInput = document.getElementById("searchInput");

    searchInput.addEventListener("keyup", function () {
        let filter = searchInput.value.toLowerCase();
        let rows = document.getElementById("eventTable").getElementsByTagName("tr");

        for (let row of rows) {
            let ip = row.cells[2].textContent.toLowerCase();
            row.style.display = ip.includes(filter) ? "" : "none";
        }
    });
});
