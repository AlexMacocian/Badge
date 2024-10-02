import badge from "./badge.js"

function hideError() {
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";
}

function showError(message) {
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.textContent = message;
    errorMessage.style.display = "block";
}

function getApplicationId() {
    const urlParams = new URLSearchParams(window.location.search);
    const applicationId = urlParams.get('id');
    if (!applicationId) {
        document.location.href = "/applications/me";
        return null;
    }

    return applicationId;
}

function getAllRedirectUris() {
    const table = document.getElementById("redirectUrisTable");
    const tbody = table.querySelector("tbody");
    const redirectUris = [];
    tbody.querySelectorAll('td.uri').forEach(cell => {
        redirectUris.push(cell.textContent.trim());
    });

    return redirectUris;
}

async function postRedirectUris() {
    const uris = getAllRedirectUris();
    const applicationId = getApplicationId();
    const response = await badge.postRedirectUris(applicationId, uris);
    if (!response.success) {
        showError(response.message);
    }
    else {
        hideError();
    }
}

function addClientSecretRow(clientSecret, tbody) {
    const row = document.createElement("tr");

    const idCell = document.createElement("td");
    idCell.textContent = clientSecret.id;
    idCell.classList.add("id");
    row.appendChild(idCell);

    const creationDateCell = document.createElement("td");
    creationDateCell.textContent = clientSecret.creationDate;
    creationDateCell.classList.add("creationDate");
    row.appendChild(creationDateCell);

    const expirationDateCell = document.createElement("td");
    expirationDateCell.textContent = clientSecret.expirationDate;
    expirationDateCell.classList.add("expirationDate");
    row.appendChild(expirationDateCell);

    const secretCell = document.createElement("td");
    secretCell.textContent = clientSecret.password;
    secretCell.classList.add("secret");
    row.appendChild(secretCell);

    const deleteCell = document.createElement("td");
    const deleteButton = document.createElement("button");
    deleteButton.textContent = "🗑";
    deleteButton.addEventListener("click", async function () {
        row.remove();
        const applicationId = getApplicationId();
        const result = await badge.deleteClientSecret(applicationId, clientSecret.id);
        if (!result.success) {
            showError(result.message);
        }
        else {
            hideError();
        }
    });

    deleteCell.appendChild(deleteButton);
    row.appendChild(deleteCell);

    tbody.append(row);
}

function addRedirectUriRow(redirectUri, tbody) {
    const row = document.createElement("tr");

    const uriCell = document.createElement("td");
    uriCell.textContent = redirectUri;
    uriCell.contentEditable = true;
    uriCell.style.minWidth = "200px";
    uriCell.classList.add("uri");
    uriCell.addEventListener("blur", function () {
        postRedirectUris();
    });

    row.appendChild(uriCell);

    const deleteCell = document.createElement("td");
    const deleteButton = document.createElement("button");
    deleteButton.textContent = "🗑";
    deleteButton.addEventListener("click", function () {
        row.remove();
        postRedirectUris();
    });

    deleteCell.appendChild(deleteButton);
    row.appendChild(deleteCell);

    tbody.append(row);
}

async function createClientSecretButtonClicked(applicationId) {
    var createSecretResponse = await badge.createClientSecret(applicationId);
    if (!createSecretResponse.success) {
        errorMessage.textContent = createSecretResponse.message;
        return;
    }

    const table = document.getElementById("secretsTable");
    const tbody = table.querySelector("tbody");
    addClientSecretRow(createSecretResponse.clientSecret, tbody);
}

async function createRedirectUriButtonClicked() {
    const templateUri = "http://localhost";
    const redirectUrisTable = document.getElementById("redirectUrisTable");
    const redirectUrisTableBody = redirectUrisTable.querySelector("tbody");
    addRedirectUriRow(templateUri, redirectUrisTableBody);
}

document.addEventListener("DOMContentLoaded", async () => {
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    const applicationId = getApplicationId();
    const applicationResponse = await badge.getApplication(applicationId)
    if (!applicationResponse.success) {
        showError(applicationResponse.message);
        return;
    }

    document.getElementById("applicationNameCell").textContent = applicationResponse.application.name;
    document.getElementById("applicationIdCell").textContent = applicationResponse.application.id;

    const secretsTable = document.getElementById("secretsTable");
    const secretsTableBody = secretsTable.querySelector("tbody");
    const redirectUrisTable = document.getElementById("redirectUrisTable");
    const redirectUrisTableBody = redirectUrisTable.querySelector("tbody");

    document.getElementById("createSecretButton").addEventListener("click", async () => {
        await createClientSecretButtonClicked(applicationId);
    });

    document.getElementById("createRedirectUriButton").addEventListener("click", async () => {
        await createRedirectUriButtonClicked(applicationId);
    });

    var secretsResponse = await badge.getClientSecrets(applicationId);
    if (!secretsResponse.success) {
        showError(secretsResponse.message);
        return;
    }

    secretsResponse.secrets.forEach(entry => {
        entry.password = "***";
        addClientSecretRow(entry, secretsTableBody);
    });

    var redirectsResponse = await badge.getRedirectUris(applicationId);
    if (!redirectsResponse.success) {
        showError(redirectsResponse.message);
        return;
    }

    hideError();
    redirectsResponse.redirectUris.forEach(redirectUri => {
        addRedirectUriRow(redirectUri, redirectUrisTableBody)
    });
});
