import badge from "./badge.js"

async function showConfirmationModal() {
    const landingModal = document.getElementById("landingModal");
    const confirmationModal = document.getElementById("confirmationModal");

    landingModal.classList.add("hidden");
    confirmationModal.classList.remove("hidden");
    const applicationNamePlaceholder = confirmationModal.querySelector("#applicationNamePlaceholder");
    const scopesList = confirmationModal.querySelector("#scopesList");

    const urlSearchParams = new URLSearchParams(window.location.search);
    const clientId = urlSearchParams.get("client_id");
    const scopes = urlSearchParams.get("scope").split(' ');
    const applicationInfo = await badge.getApplicationInfo(clientId);
    if (!applicationInfo.success) {
        return;
    }

    const supportedScopes = await badge.getScopes();
    const requestedSupportedScopes = supportedScopes.scopes.filter(supportedScope =>
        scopes.includes(supportedScope.name)
    );

    scopesList.textContent = "";
    requestedSupportedScopes.forEach(scope => {
        scopesList.innerHTML += "<li>" + scope.description + "</li>";
    });

    applicationNamePlaceholder.textContent = applicationInfo.application.name;
}

async function performOAuthFlow() {
    const urlSearchParams = new URLSearchParams(window.location.search);
    const clientId = urlSearchParams.get("client_id");
    const clientSecret = urlSearchParams.get("client_secret");
    const scope = urlSearchParams.get("scope");
    const state = urlSearchParams.get("state");
    const redirectUri = urlSearchParams.get("redirect_uri");
    const nonce = urlSearchParams.get("nonce");
    const codeChallenge = urlSearchParams.get("code_challenge");
    const codeChallengeMethod = urlSearchParams.get("code_challenge_method");
    var responseType = urlSearchParams.get("response_type");
    if (!responseType) {
        responseType = "code";
    }

    const result = await badge.authorize(clientId, clientSecret, scope, state, redirectUri, responseType, nonce, codeChallenge, codeChallengeMethod);
    const url = new URL(redirectUri);
    if (result.success) {
        const authResult = result.result;
        if (authResult.response_type == "code") {
            url.searchParams.append("state", authResult.state);
            url.searchParams.append("code", authResult.code);
            url.searchParams.append("expires_in", authResult.expires_in);
        }
        else if (authResult.response_type == "token") {
            const fragmentParams = new URLSearchParams();
            fragmentParams.append("access_token", authResult.access_token);
            fragmentParams.append("token_type", authResult.token_type);
            fragmentParams.append("expires_in", authResult.expires_in);
            fragmentParams.append("state", authResult.state);
            if (authResult.refresh_token) {
                fragmentParams.append("refresh_token", authResult.refresh_token);
            }
            url.hash = fragmentParams.toString();
        }
        else if (authResult.response_type == "token id_token") {
            const fragmentParams = new URLSearchParams();
            fragmentParams.append("id_token", authResult.id_token);
            fragmentParams.append("access_token", authResult.access_token);
            fragmentParams.append("token_type", authResult.token_type);
            fragmentParams.append("expires_in", authResult.expires_in);
            fragmentParams.append("state", authResult.state);
            if (authResult.refresh_token) {
                fragmentParams.append("refresh_token", authResult.refresh_token);
            }
            url.hash = fragmentParams.toString();
        }
    }
    else {
        url.searchParams.append("state", state);
        url.searchParams.append("result", "failed");
        url.searchParams.append("reason", result.message);
    }

    window.location.href = url.toString();
}

async function yesButtonClicked() {
    await performOAuthFlow();
}

async function noButtonClicked() {
    const urlSearchParams = new URLSearchParams(window.location.search);
    const redirectUri = urlSearchParams.get("redirect_uri");
    const url = new URL(redirectUri);
    const state = urlSearchParams.get("state");
    url.searchParams.append("state", state);
    url.searchParams.append("result", "failed");
    url.searchParams.append("reason", "User rejected access");
    window.location.href = url.toString();
}

document.addEventListener("DOMContentLoaded", async () => {
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    document.getElementById("yesButton").addEventListener("click", async () => {
        await yesButtonClicked();
    });

    document.getElementById("noButton").addEventListener("click", async () => {
        await noButtonClicked();
    });

    showConfirmationModal();
});
