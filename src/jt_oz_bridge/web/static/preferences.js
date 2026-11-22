"use strict";
const csrf = document.cookie.split("; ").find(item => item.startsWith("jtoz_csrf="))?.slice("jtoz_csrf=".length) || "";
const headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf};
document.getElementById("save").addEventListener("click", async () => {
  const response = await fetch("/api/v1/preferences/me", {method: "PATCH", headers,
    body: JSON.stringify({locale: document.getElementById("locale").value})});
  if (response.ok) location.reload();
  else document.getElementById("result").textContent = (await response.json()).message;
});
document.getElementById("logout").addEventListener("click", async () => {
  const response = await fetch("/api/v1/auth/logout", {method: "POST", headers});
  if (response.ok) { location.reload(); }
});
