import badge from './badge.js';

document.addEventListener("DOMContentLoaded", async () => {
  let usernamePlaceholder = document.getElementById("usernamePlaceholder");
  if (!usernamePlaceholder) {
    return;
  }

  const result = await badge.getUserDetails();
  if (!result.success) {
    window.location.href = "/login";
  } else {
    usernamePlaceholder.textContent = result.user.username;
  }
});
