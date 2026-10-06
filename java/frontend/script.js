const API="http://127.0.0.1:5000/api";

// ---- Auth guard: no token, no dashboard ----
const authToken = localStorage.getItem("pg_token");
if (!authToken) {
  window.location.href = "login.html";
}

let state={rules:[],logs:[],stats:{total:0,allowed:0,blocked:0}};

const $=id=>document.getElementById(id);

// Escape text before putting it into innerHTML (rule names are user-typed)
function esc(v){
 return String(v==null?"":v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

document.querySelectorAll(".nav-item").forEach(b=>b.onclick=()=>showPage(b.dataset.page));

function showPage(page){
 document.querySelectorAll(".page").forEach(x=>x.classList.remove("active-page"));
 $(page).classList.add("active-page");
 document.querySelectorAll(".nav-item").forEach(x=>x.classList.toggle("active",x.dataset.page===page));
 const t={dashboard:["Dashboard","Network traffic and firewall activity"],rules:["Firewall Rules","Create and manage packet filtering rules"],simulator:["Packet Simulator","Test packets against your firewall rules"],traffic:["Traffic Log","Review all simulated network traffic"],settings:["Settings","Configure the simulator"]};
 $("pageTitle").textContent=t[page][0]; $("pageSubtitle").textContent=t[page][1];
}

function initUserChip(){
 const username=localStorage.getItem("pg_username")||"Account";
 $("usernameDisplay").textContent=username;
 $("userAvatar").textContent=username.charAt(0).toUpperCase();
}

async function api(path,options={}){
 const r=await fetch(API+path,{
  headers:{
   "Content-Type":"application/json",
   "Authorization":"Bearer "+localStorage.getItem("pg_token")
  },
  ...options
 });
 if(r.status===401){
  localStorage.removeItem("pg_token");
  localStorage.removeItem("pg_username");
  window.location.href="login.html";
  return new Promise(()=>{});
 }
 const data=await r.json();
 if(!r.ok) throw new Error(data.error||"Server error");
 return data;
}

async function logout(){
 try{await api("/auth/logout",{method:"POST"})}catch(e){/* proceed with client-side logout regardless */}
 localStorage.removeItem("pg_token");
 localStorage.removeItem("pg_username");
 window.location.href="login.html";
}

async function loadAll(){
 try{
  const d=await api("/dashboard");
  state=d;
  render();
 }catch(e){
  document.querySelector(".sidebar-bottom small").textContent="Backend offline";
  console.error(e);
 }
}

function render(){
 $("totalPackets").textContent=state.stats.total;
 $("allowedPackets").textContent=state.stats.allowed;
 $("blockedPackets").textContent=state.stats.blocked;
 $("ruleCount").textContent=state.rules.length;
 $("rulesTotal").textContent=state.rules.length+" rule"+(state.rules.length===1?"":"s");

 $("rulesTable").innerHTML=state.rules.map((r,i)=>`<tr>
 <td>${i+1}</td><td>${r.priority}</td><td><span class="badge ${r.action==="ALLOW"?"allow":"deny"}">${r.action}</span></td>
 <td>${r.protocol}</td><td>${r.sourceIP}:${r.sourcePort}</td><td>${r.destinationIP}:${r.destinationPort}</td>
 <td>${r.description}</td><td><button class="delete-btn" onclick="deleteRule(${r.id})">Delete</button></td></tr>`).join("");

 $("dashboardRules").innerHTML=state.rules.slice(0,5).map(r=>`<tr><td>${r.priority}</td><td><span class="badge ${r.action==="ALLOW"?"allow":"deny"}">${r.action}</span></td><td>${r.protocol}</td><td>${r.sourceIP}:${r.sourcePort}</td><td>${r.destinationIP}:${r.destinationPort}</td><td>${r.description}</td></tr>`).join("");

 displayRecent(); displayLogs(); drawChart(); renderCaptureStatus();
}

function renderCaptureStatus(){
 const badge=$("captureStatus"), startBtn=$("startCaptureBtn"), stopBtn=$("stopCaptureBtn");
 if(!badge) return;
 const cap=state.capture||{active:false,available:true,error:null};
 if(cap.active){
  badge.textContent="● Capturing"; badge.className="capture-badge on";
  startBtn.classList.add("hidden"); stopBtn.classList.remove("hidden");
 }else{
  badge.textContent="Off"; badge.className="capture-badge off";
  startBtn.classList.remove("hidden"); stopBtn.classList.add("hidden");
 }
 if(cap.error){
  const box=$("captureMessage");
  box.className="packet-result blocked";
  box.textContent="Capture stopped with an error: "+cap.error;
 }
}

async function startCapture(){
 const iface=$("captureIface").value.trim();
 const box=$("captureMessage");
 try{
  const result=await api("/capture/start",{method:"POST",body:JSON.stringify({interface:iface||null})});
  box.className="packet-result allowed"; box.textContent=result.message+(result.interface?` (interface: ${result.interface})`:"");
  await loadAll();
 }catch(e){
  box.className="packet-result blocked"; box.textContent=e.message;
 }
}

async function stopCapture(){
 const box=$("captureMessage");
 try{
  const result=await api("/capture/stop",{method:"POST"});
  box.className="packet-result allowed"; box.textContent=result.message;
  await loadAll();
 }catch(e){
  box.className="packet-result blocked"; box.textContent=e.message;
 }
}

async function addRule(){
 const body={action:$("action").value,protocol:$("protocol").value,sourceIP:$("sourceIP").value.trim()||"any",sourcePort:$("sourcePort").value.trim()||"any",destinationIP:$("destinationIP").value.trim()||"any",destinationPort:$("destinationPort").value.trim()||"any",description:$("description").value.trim()||"No description",priority:Number($("priority").value)||100};
 try{await api("/rules",{method:"POST",body:JSON.stringify(body)});await loadAll();alert("Firewall rule added successfully.");}
 catch(e){alert(e.message)}
}

async function deleteRule(id){
 if(!confirm("Delete this firewall rule?")) return;
 try{await api("/rules/"+id,{method:"DELETE"});await loadAll()}catch(e){alert(e.message)}
}

async function sendPacket(){
 const p={protocol:$("packetProtocol").value,direction:$("direction").value,sourceIP:$("packetSourceIP").value.trim(),sourcePort:$("packetSourcePort").value.trim(),destinationIP:$("packetDestinationIP").value.trim(),destinationPort:$("packetDestinationPort").value.trim()};
 try{
  const result=await api("/packets",{method:"POST",body:JSON.stringify(p)});
  const box=$("packetResult");
  box.className="packet-result "+(result.action==="ALLOW"?"allowed":"blocked");
  box.innerHTML=`<b>${result.action==="ALLOW"?"✓ PACKET ALLOWED":"✕ PACKET BLOCKED"}</b><br>${esc(result.message)}<br><small>${p.protocol} | ${p.sourceIP}:${p.sourcePort} → ${p.destinationIP}:${p.destinationPort}</small>`;
  await loadAll();
 }catch(e){alert(e.message)}
}

function displayRecent(){
 const c=$("recentActivity");
 if(!state.logs.length){c.innerHTML=`<div class="activity"><small>No traffic simulated yet.</small></div>`;return}
 c.innerHTML=state.logs.slice(0,5).map(l=>`<div class="activity"><div class="activity-top"><span class="${l.action==="ALLOW"?"allow-text":"deny-text"}">${l.action==="ALLOW"?"✓ ALLOW":"✕ DENY"}</span><small>${l.time}</small></div><code>${l.protocol} ${l.sourceIP}:${l.sourcePort} → ${l.destinationIP}:${l.destinationPort}</code></div>`).join("");
}

function displayLogs(){
 const c=$("trafficTable");
 if(!state.logs.length){c.innerHTML=`<div style="padding:35px;text-align:center;color:#8a95a5">No traffic has been simulated yet.</div>`;return}
 c.innerHTML=`<div class="traffic-row head"><span>Time</span><span>Action</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Rule</span></div>`+
 state.logs.map(l=>`<div class="traffic-row"><span>${l.time}</span><span class="${l.action==="ALLOW"?"action-allow":"action-deny"}">${l.action}</span><span><code>${l.sourceIP}:${l.sourcePort}</code></span><span><code>${l.destinationIP}:${l.destinationPort}</code></span><span>${l.protocol}</span><span title="${esc(l.message||"")}">${esc(l.rule)}</span></div>`).join("");
}

async function clearLogs(){try{await api("/logs",{method:"DELETE"});await loadAll()}catch(e){alert(e.message)}}
async function resetSimulator(){if(!confirm("Reset rules and traffic?"))return;try{await api("/reset",{method:"POST"});await loadAll();$("packetResult").className="packet-result hidden";alert("Simulator reset successfully.")}catch(e){alert(e.message)}}

// ---- Export traffic log as CSV ----
function csvCell(v){
 let s=v==null?"":String(v);
 if(/^[=+\-@\t\r]/.test(s)) s="'"+s; // stop spreadsheet apps treating text as a formula
 return '"'+s.replace(/"/g,'""')+'"';
}

function exportLogsCSV(){
 if(!state.logs.length){alert("There are no log entries to export.");return}
 const header=["Time","Action","Protocol","Source IP","Source Port","Destination IP","Destination Port","State","Rule ID","Rule Name","Message"];
 const rows=state.logs.map(l=>[
  l.time,l.action,l.protocol,l.sourceIP,l.sourcePort,l.destinationIP,l.destinationPort,
  l.state||"",l.ruleId==null?"":l.ruleId,l.ruleName||l.rule||"",l.message||""
 ]);
 const csv="\uFEFF"+[header,...rows].map(r=>r.map(csvCell).join(",")).join("\r\n");
 const blob=new Blob([csv],{type:"text/csv;charset=utf-8;"});
 const now=new Date(),p=n=>String(n).padStart(2,"0");
 const stamp=`${now.getFullYear()}${p(now.getMonth()+1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
 const a=document.createElement("a");
 a.href=URL.createObjectURL(blob);
 a.download=`packetgate-traffic-log-${stamp}.csv`;
 document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}

// Adds an "Export CSV" button next to "Clear Log" (no HTML changes needed)
function initExportButton(){
 if($("exportCsvBtn")) return;
 const btn=document.createElement("button");
 btn.id="exportCsvBtn";
 btn.type="button";
 btn.textContent="Export CSV";
 btn.style.cssText="padding:10px 18px;border:1px solid #cbd5e1;background:#fff;color:#1e293b;border-radius:6px;font-size:15px;cursor:pointer;";
 btn.onclick=exportLogsCSV;
 const clearBtn=document.querySelector('button[onclick*="clearLogs"]');
 if(clearBtn&&clearBtn.parentNode){
  const wrap=document.createElement("div");
  wrap.style.cssText="display:flex;gap:10px;align-items:center;";
  clearBtn.parentNode.insertBefore(wrap,clearBtn);
  wrap.appendChild(btn);wrap.appendChild(clearBtn);
 }else if($("trafficTable")){
  $("trafficTable").parentNode.insertBefore(btn,$("trafficTable"));
 }
}

function drawChart(){
 const canvas=$("trafficChart"); if(!canvas)return;
 const ctx=canvas.getContext("2d"),dpr=devicePixelRatio||1,w=canvas.clientWidth,h=canvas.clientHeight;
 canvas.width=w*dpr;canvas.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
 ctx.strokeStyle="#e5e7eb";ctx.lineWidth=1;
 for(let y=30;y<h;y+=50){ctx.beginPath();ctx.moveTo(30,y);ctx.lineTo(w-10,y);ctx.stroke()}
 const vals=Array(10).fill(0);state.logs.slice(0,10).reverse().forEach((l,i)=>vals[i]=l.action==="ALLOW"?2:1);
 ctx.beginPath();ctx.strokeStyle="#2563eb";ctx.lineWidth=2;
 vals.forEach((v,i)=>{const x=35+i*((w-55)/9),y=h-35-v*45;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke();
 vals.forEach((v,i)=>{const x=35+i*((w-55)/9),y=h-35-v*45;ctx.beginPath();ctx.fillStyle=v===1?"#dc2626":"#2563eb";ctx.arc(x,y,4,0,Math.PI*2);ctx.fill()});
 ctx.fillStyle="#8a95a5";ctx.font="11px Arial";ctx.fillText("Packets",10,17);ctx.fillText("Older",30,h-10);ctx.fillText("Recent",w-55,h-10);
}

function clock(){$("clock").textContent=new Date().toLocaleTimeString()}
if ($("logoutBtn")) $("logoutBtn").addEventListener("click",logout);
setInterval(clock,1000);clock();initUserChip();initExportButton();addEventListener("resize",drawChart);loadAll();
setInterval(loadAll,3000); // keep dashboard/traffic log live while a capture is running