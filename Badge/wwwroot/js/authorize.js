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
    if (result.success) {
        const authResult = result.result;
        const url = new URL(redirectUri);
        url.searchParams.append("code", authResult.code);
        url.searchParams.append("state", authResult.state);
        window.location.href = url.toString();
        return;
    }
});
