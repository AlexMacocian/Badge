import badge from './badge.js';

document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const errorMessage = document.getElementById("errorMessage");

    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();  // Prevent the form from submitting the default way

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const continueUri = new URLSearchParams(window.location.search).get("redirect_uri");

        const loginResult = await badge.login(username, password);
        if (loginResult.success) {
            const redirectUri = continueUri || "/";
            window.location.href = redirectUri;
        }
        else {
            errorMessage.textContent = loginResult.message;
            errorMessage.style.display = "block";
        }
    });
});
