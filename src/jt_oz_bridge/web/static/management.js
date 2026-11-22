"use strict";
const panel = document.getElementById("management-dialog");
if (panel) {
  const status = document.getElementById("management-status");
  const result = document.getElementById("management-result");
  const confirm = document.getElementById("management-confirm");
  const cancel = document.getElementById("management-cancel");
  const close = document.getElementById("management-close");
  let draft = null;
  let previewRequest = null;
  let busy = false;
  let returnToLogin = false;
  function setBusy(value) {
    busy = value;
    confirm.disabled = cancel.disabled = value;
    document.querySelectorAll(".management").forEach(button => { button.disabled = value; });
  }
  async function request(url, body) {
    const csrf = document.cookie.split("; ").find(item => item.startsWith("jtoz_csrf="))?.slice(10) || "";
    const response = await fetch(url, {method: "POST", headers: {
      "Content-Type": "application/json", "X-CSRF-Token": csrf
    }, body: JSON.stringify(body)});
    const data = await response.json();
    if (!response.ok) { const error = new Error("request_failed"); error.authRejected = response.status === 403; throw error; }
    return data;
  }
  function terminal(data) {
    returnToLogin = false;
    close.textContent = panel.dataset.close;
    draft = null;
    confirm.hidden = cancel.hidden = true;
    close.hidden = false;
    result.textContent = data.state === "confirmed" ? panel.dataset.confirmed : panel.dataset.cancelled;
    if (panel.open) close.focus();
  }
  function showPreview(data) {
    returnToLogin = false;
    draft = data;
    confirm.hidden = cancel.hidden = false;
    close.hidden = true;
    result.textContent = "";
    const preview = data.preview;
    const scope = preview.scope;
    const reference = scope.reference;
    panel.querySelector("#management-warning").textContent = panel.dataset[preview.operation];
    const fields = {project:reference.project_id, backend:reference.backend_id, installation:reference.backend_identity, owner:scope.owner_id, audience:scope.audience_user_ids.join(", "), realm:scope.realm_id,
      channel:scope.channel_id, topic:scope.topic, session:reference.upstream_session_id,
      directory:reference.canonical_directory, revision:scope.revision, queue:preview.queue_revision};
    Object.entries(fields).forEach(([key, value]) => {
      document.getElementById("scope-" + key).textContent = String(value);
    });
    const effects = document.getElementById("scope-effects");
    effects.replaceChildren();
    Object.entries(preview.affected).forEach(([key, values]) => {
      const item = document.createElement("li");
      const counts = Object.entries(values).map(([state, count]) => state + ": " + count).join(", ");
      item.textContent = effects.dataset[key] + " — " + (counts || effects.dataset.empty);
      effects.append(item);
    });
  }
  document.querySelectorAll(".management").forEach(button => {
    button.addEventListener("click", async () => {
      if (busy) return;
      setBusy(true);
      status.textContent = "";
      const key = [button.dataset.binding, button.dataset.operation, button.dataset.revision, button.dataset.queue].join(":");
      if (previewRequest?.key !== key) previewRequest = {key, client:crypto.randomUUID()};
      try {
        const data = await request("/api/v1/admin/bindings/" + encodeURIComponent(button.dataset.binding) + "/preview", {
          client_action_id:previewRequest.client, operation:button.dataset.operation,
          binding_revision:Number(button.dataset.revision), queue_revision:Number(button.dataset.queue)
        });
        if (data.state === "pending") showPreview(data);
        else terminal(data);
        panel.showModal();
        document.getElementById("management-scroll").scrollTop = 0;
        document.getElementById("management-title").focus({preventScroll:true});
      } catch (error) { status.textContent = error.authRejected === true ? status.dataset.auth : status.dataset.error; }
      finally { setBusy(false); }
    });
  });
  async function finish(cancelled) {
    if (busy || !draft) return;
    setBusy(true);
    result.textContent = "";
    try {
      const data = await request("/api/v1/admin/decisions/" + encodeURIComponent(draft.decision_id) + (cancelled ? "/cancel" : "/confirm"), {
        confirmation_token:draft.confirmation_token, version:draft.version
      });
      terminal(data);
    } catch (error) {
      const expired = error.authRejected === true;
      result.textContent = expired ? status.dataset.auth : status.dataset.error;
      if (expired) {
        draft = previewRequest = null;
        returnToLogin = true;
        confirm.hidden = cancel.hidden = true;
        close.hidden = false;
        close.textContent = panel.dataset.login;
        close.focus();
      }
    }
    finally { setBusy(false); }
  }
  confirm.addEventListener("click", () => finish(false));
  cancel.addEventListener("click", () => finish(true));
  close.addEventListener("click", () => returnToLogin ? location.assign("/") : location.reload());
  panel.addEventListener("cancel", event => {
    event.preventDefault();
    if (draft) finish(true);
    else if (!busy) returnToLogin ? location.assign("/") : location.reload();
  });
}
