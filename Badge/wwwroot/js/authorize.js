import badge from "./badge.js"

document.addEventListener("DOMContentLoaded", async () => {
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    const urlSearchParams = new URLSearchParams(window.location.search);
    const clientId = urlSearchParams.get("client_id");
    const clientSecret = urlSearchParams.get("client_secret");
    const scope = urlSearchParams.get("scope");
    const state = urlSearchParams.get("state");
    const redirectUri = urlSearchParams.get("redirect_uri");
    const result = await badge.authorize(clientId, clientSecret, scope, state, redirectUri);
    const url = new URL(redirectUri);
    if (result.success) {
        const authResult = result.result;
        url.searchParams.append("code", authResult.code);
        url.searchParams.append("state", authResult.state);
    }
    else {
        url.searchParams.append("state", state);
        url.searchParams.append("result", "failed");
        url.searchParams.append("reason", result.message);
    }

    window.location.href = url.toString();
});
