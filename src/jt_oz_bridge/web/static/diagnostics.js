"use strict";
const diagnosticButton = document.getElementById("diagnostics");
diagnosticButton.addEventListener("click", async () => {
  const status = document.getElementById("result");
  diagnosticButton.disabled = true;
  status.textContent = diagnosticButton.dataset.busy;
  let url;
  try {
    const csrfToken = document.cookie.split("; ").find(item => item.startsWith("jtoz_csrf="))?.slice("jtoz_csrf=".length) || "";
    const response = await fetch("/api/v1/admin/diagnostics/export", {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
      body: "{}"
    });
    if (!response.ok || !response.headers.get("content-type")?.startsWith("application/json") || !response.body) {
      throw new Error("unavailable");
    }
    const reader = response.body.getReader();
    const parts = [];
    let size = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 32768) {
          await reader.cancel();
          throw new Error("capacity");
        }
        parts.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    url = URL.createObjectURL(new Blob(parts, {type: "application/json"}));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "jt-oz-bridge-diagnostics.json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    status.textContent = diagnosticButton.dataset.ready;
  } catch (_) {
    status.textContent = diagnosticButton.dataset.error;
  } finally {
    if (url) setTimeout(() => URL.revokeObjectURL(url), 1000);
    diagnosticButton.disabled = false;
  }
});
