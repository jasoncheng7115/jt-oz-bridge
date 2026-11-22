"use strict";
for (const runtimeEditor of document.querySelectorAll("[data-runtime-editor]")) {
  const prefix=runtimeEditor.dataset.prefix;
  const element = suffix => document.getElementById(prefix+"-"+suffix);
  const panel = element("dialog");
  const status = element("status");
  const result = element("result");
  const confirm = element("confirm");
  const cancel = element("cancel");
  const close = element("close");
  const preview = element("preview");
  const clear = element("clear");
  let draft = null, requestKey = null, busy = false, returnToLogin = false;
  function setBusy(value) { busy=value; confirm.disabled=cancel.disabled=preview.disabled=clear.disabled=value; }
  async function request(url,body) {
    const csrf=document.cookie.split("; ").find(item=>item.startsWith("jtoz_csrf="))?.slice(10)||"";
    const response=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});
    const data=await response.json();
    if (!response.ok) { const error=new Error("request_failed"); error.authRejected=response.status===403; throw error; }
    return data;
  }
  function terminal(data) { draft=null; confirm.hidden=cancel.hidden=true; close.hidden=false; close.textContent=panel.dataset.close; result.textContent=data.state==="confirmed"?panel.dataset.confirmed:panel.dataset.cancelled; if(panel.open)close.focus(); }
  async function begin(value) {
    if(busy)return;setBusy(true);status.textContent="";
    const key=JSON.stringify([value,runtimeEditor.dataset.revision,runtimeEditor.dataset.baseline]);
    if(requestKey?.key!==key)requestKey={key,client:crypto.randomUUID()};
    try{
      const data=await request("/api/v1/admin/settings/preview",{client_action_id:requestKey.client,key:runtimeEditor.dataset.key,value,configuration_revision:Number(runtimeEditor.dataset.revision),baseline_hash:runtimeEditor.dataset.baseline});
      returnToLogin=false;result.textContent="";
      if(data.state!=="pending")terminal(data);
      else {
        draft=data;confirm.hidden=cancel.hidden=false;close.hidden=true;
        const before=data.preview.before;
        element("before").textContent=before.value;
        element("origin").textContent=panel.getAttribute("data-origin-"+before.origin.replaceAll("_","-"));
        element("previous").textContent=before.stored_override??panel.dataset.empty;
        element("requested").textContent=data.preview.requested_value??panel.dataset.empty;
        element("before-revision").textContent=String(before.configuration_revision);
        element("shadow").hidden=before.baseline_origin!=="environment";
      }
      panel.showModal();panel.querySelector(".dialog-scroll").scrollTop=0;element("title").focus({preventScroll:true});
    }catch(error){status.textContent=error.authRejected===true?status.dataset.auth:status.dataset.error;}
    finally{setBusy(false);}
  }
  async function finish(cancelled) {
    if(busy||!draft)return;setBusy(true);result.textContent="";
    try{terminal(await request("/api/v1/admin/settings/decisions/"+encodeURIComponent(draft.decision_id)+(cancelled?"/cancel":"/confirm"),{confirmation_token:draft.confirmation_token,version:draft.version}));}
    catch(error){const expired=error.authRejected===true;result.textContent=expired?status.dataset.auth:status.dataset.error;if(expired){draft=requestKey=null;returnToLogin=true;confirm.hidden=cancel.hidden=true;close.hidden=false;close.textContent=panel.dataset.login;close.focus();}}
    finally{setBusy(false);}
  }
  function leave(){returnToLogin?location.assign("/"):location.reload();}
  preview.addEventListener("click",()=>{
    const input=element("value");
    if(!input.reportValidity())return;
    begin(input.type==="number"?Number(input.value):input.value);
  });
  clear.addEventListener("click",()=>begin(null));confirm.addEventListener("click",()=>finish(false));cancel.addEventListener("click",()=>finish(true));close.addEventListener("click",leave);
  panel.addEventListener("cancel",event=>{event.preventDefault();if(draft)finish(true);else if(!busy)leave();});
}
