"use strict";
let csrf = "";
const status = document.getElementById("result");
document.getElementById("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.fromEntries(new FormData(event.target)))
    });
    const data = await response.json();
    event.target.password.value = "";
    if (!response.ok) { status.textContent = data.message; return; }
    csrf = data.csrf_token;
    if (data.password_reset_required) {
      event.target.hidden = true;
      document.getElementById("reset").hidden = false;
    } else { location.assign("/"); }
  } catch { status.textContent = document.body.dataset.connectionError; }
});
document.getElementById("reset").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/api/v1/auth/password", {
    method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: JSON.stringify(Object.fromEntries(new FormData(event.target)))
  });
  if (response.ok) { location.reload(); }
  else { status.textContent = (await response.json()).message; }
});
