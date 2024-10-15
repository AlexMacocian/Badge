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
    const nonce = urlSearchParams.get("nonce");
    var responseType = urlSearchParams.get("response_type");
    if (!responseType) {
        responseType = "code";
    }

    const result = await badge.authorize(clientId, clientSecret, scope, state, redirectUri, responseType, nonce);
    const url = new URL(redirectUri);
    if (result.success) {
        const authResult = result.result;
        if (authResult.responseType == "code") {
            url.searchParams.append("state", authResult.state);
            url.searchParams.append("code", authResult.code);
        }
        else if (authResult.responseType == "token") {
            const fragmentParams = new URLSearchParams();
            fragmentParams.append("access_token", authResult.token);
            fragmentParams.append("token_type", authResult.tokenType);
            fragmentParams.append("expires_in", authResult.expiresIn);
            fragmentParams.append("state", authResult.state);
            url.hash = fragmentParams.toString();
        }
        else if (authResult.responseType == "id_token token") {
            const fragmentParams = new URLSearchParams();
            fragmentParams.append("id_token", authResult.idToken);
            fragmentParams.append("access_token", authResult.token);
            fragmentParams.append("token_type", authResult.tokenType);
            fragmentParams.append("expires_in", authResult.expiresIn);
            fragmentParams.append("state", authResult.state);
            url.hash = fragmentParams.toString();
        }
    }
    else {
        url.searchParams.append("state", state);
        url.searchParams.append("result", "failed");
        url.searchParams.append("reason", result.message);
    }

    window.location.href = url.toString();
});
