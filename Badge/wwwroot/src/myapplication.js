import badge from "./badge.js"

document.addEventListener("DOMContentLoaded", async () => {
    const errorMessage = document.getElementById("errorMessage");
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    const urlParams = new URLSearchParams(window.location.search);
    const applicationId = urlParams.get('id');
    if (!applicationId) {
        document.location.href = "/applications/me";
        return;
    }

    const secretsTable = document.getElementById("secretsTable");
    const tbody = secretsTable.querySelector("tbody");
    var secretsResponse = await badge.getClientSecrets(applicationId);
    if (!secretsResponse.success) {
        errorMessage.textContent = secretsResponse.message;
        return;
    }

    document.getElementById("createSecretButton").addEventListener("click", async () => {
        var createSecretResponse = await badge.createClientSecret(applicationId);
        if (!createSecretResponse.success) {
            errorMessage.textContent = createSecretResponse.message;
            return;
        }

        const newRow = document.createElement("tr");

        const newIdCell = document.createElement("td");
        newIdCell.textContent = createSecretResponse.clientSecret.id;
        newRow.appendChild(newIdCell);

        const newCreationDateCell = document.createElement("td");
        newCreationDateCell.textContent = createSecretResponse.clientSecret.creationDate;
        newRow.appendChild(newCreationDateCell);

        const newExpirationDateCell = document.createElement("td");
        newExpirationDateCell.textContent = createSecretResponse.clientSecret.expirationDate;
        newRow.appendChild(newExpirationDateCell);

        const newSecretCell = document.createElement("td");
        newSecretCell.textContent = createSecretResponse.clientSecret.password;
        newRow.appendChild(newSecretCell);

        tbody.append(newRow);
    });

    secretsResponse.secrets.forEach(entry => {
        const row = document.createElement("tr");

        const idCell = document.createElement("td");
        idCell.textContent = entry.id;
        row.appendChild(idCell);

        const creationDateCell = document.createElement("td");
        creationDateCell.textContent = entry.creationDate;
        row.appendChild(creationDateCell);

        const expirationDateCell = document.createElement("td");
        expirationDateCell.textContent = entry.expirationDate;
        row.appendChild(expirationDateCell);

        const secretCell = document.createElement("td");
        secretCell.textContent = "***";
        row.appendChild(secretCell);

        tbody.append(row);
    });
});
