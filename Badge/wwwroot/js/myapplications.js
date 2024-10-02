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
        const row = document.createElement("tr");

        const idCell = document.createElement("td");
        const idLink = document.createElement("a");
        idLink.href = `application?id=${entry.id}`;
        idLink.textContent = entry.id;
        idCell.appendChild(idLink);
        row.appendChild(idCell);

        const nameCell = document.createElement("td");
        nameCell.textContent = entry.name;
        row.appendChild(nameCell);

        const creationDateCell = document.createElement("td");
        creationDateCell.textContent = entry.creationDate;
        row.appendChild(creationDateCell);

        const ownedCell = document.createElement("td");
        ownedCell.textContent = entry.owned;
        row.appendChild(ownedCell);

        tbody.append(row);
    });
});
