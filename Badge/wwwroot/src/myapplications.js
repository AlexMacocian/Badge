import badge from "./badge.js"

document.addEventListener("DOMContentLoaded", async () => {
    const errorMessage = document.getElementById("errorMessage");
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    const myApplicationsTable = document.getElementById("applicationsTable");
    const tbody = myApplicationsTable.querySelector("tbody");
    var applicationsResponse = await badge.getApplications();
    if (!applicationsResponse.success) {
        errorMessage.textContent = applicationsResponse.message;
        return;
    }

    applicationsResponse.applications.forEach(entry => {
        const app = entry.application;
        const row = document.createElement("tr");

        const idCell = document.createElement("td");
        idCell.textContent = app.id;
        row.appendChild(idCell);

        const nameCell = document.createElement("td");
        nameCell.textContent = app.name;
        row.appendChild(nameCell);

        const creationDateCell = document.createElement("td");
        creationDateCell.textContent = app.creationDate;
        row.appendChild(creationDateCell);

        const ownedCell = document.createElement("td");
        ownedCell.textContent = entry.owned;
        row.appendChild(ownedCell);

        tbody.append(row);
    });
});
