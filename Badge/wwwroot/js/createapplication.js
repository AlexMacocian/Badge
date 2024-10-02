import badge from "./badge.js"

document.addEventListener("DOMContentLoaded", async () => {
    const creationForm = document.getElementById("creationForm");
    const errorMessage = document.getElementById("errorMessage");
    if (!await badge.isAuthenticated()) {
        const redirectUri = encodeURIComponent(document.location.href);
        document.location.href = "/login?redirect_uri=" + redirectUri;
        return;
    }

    creationForm.addEventListener("submit", async (event) => {
        event.preventDefault();  // Prevent the form from submitting the default way

        const applicationName = document.getElementById("applicationName").value;
        const createResult = await badge.createApplication(applicationName);
        if (createResult.success) {
            window.location.href = "/applications/me";
        }
        else {
            errorMessage.textContent = createResult.message;
            errorMessage.style.display = "block";
        }
    });
});
