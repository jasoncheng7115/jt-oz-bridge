"use strict";
const theme = document.getElementById("theme");
function applyTheme(value) {
  if (!["light", "dark", "system"].includes(value)) value = "system";
  document.documentElement.dataset.theme = value;
  if (theme) theme.value = value;
}
try { applyTheme(localStorage.getItem("jtoz-theme") || "system"); } catch { applyTheme("system"); }
theme?.addEventListener("change", () => {
  applyTheme(theme.value);
  try { localStorage.setItem("jtoz-theme", theme.value); } catch { /* System theme still works. */ }
});
