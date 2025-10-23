// dashboard.js
const token = localStorage.getItem('token');
if (!token) window.location.href = '/login.html';

const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(`${proto}://${location.host}/?token=${token}`);
let currentUser = null;

document.getElementById('logoutBtn').addEventListener('click', () => {
  localStorage.removeItem('token'); window.location.href = '/login.html';
});

// theme
const body = document.getElementById('bodyRoot');
let dark = localStorage.getItem('theme') === 'dark';
applyTheme();
document.getElementById('themeToggle').addEventListener('click', () => {
  dark = !dark; localStorage.setItem('theme', dark ? 'dark' : 'light'); applyTheme();
});
function applyTheme() {
  document.body.className = dark ? 'dark' : '';
}

// background
document.getElementById('applyBg').addEventListener('click', ()=> {
  const url = document.getElementById('bgUrl').value.trim();
  if(url) { document.body.style.backgroundImage = `url('${url}')`; localStorage.setItem('bg', url); }
});
document.getElementById('clearBg').addEventListener('click', ()=> { document.body.style.backgroundImage = ''; localStorage.removeItem('bg'); });

const savedBg = localStorage.getItem('bg'); if(savedBg) document.body.style.backgroundImage = `url('${savedBg}')`;

// WebSocket events
ws.onopen = ()=> {
  console.log('ws open');
  fetch('/api/dashboard-data', { headers: { Authorization: token } }).then(r=>r.json()).then(j=>{
    currentUser = j;
    document.getElementById('userInfo').textContent = `${j.username} (${j.role})`;
    if (j.role === 'owner') {
      document.getElementById('ownerPanel').classList.remove('hide');
      getOwnerCreds();
    } else {
      document.getElementById('notOwnerMsg').textContent = 'Owner-only settings hidden';
    }
  });
  refreshFiles();
};
ws.onmessage = (evt) => {
  const d = JSON.parse(evt.data);
  if (d.type === 'file_list') populateFiles(d.files);
  if (d.type === 'file_content') loadFileContent(d.filename, d.content);
  if (d.type === 'console_output') appendConsole(d.output);
  if (d.type === 'chat_message') appendChat(d.message);
  if (d.type === 'file_saved' || d.type === 'upload_success') {
    appendConsole(`[Info] File saved: ${d.filename}`);
    refreshFiles();
  }
  if (d.type === 'backup_list') populateBackups(d.backups);
  if (d.type === 'backup_content') showBackupDiff(d.content);
  if (d.type === 'skript_errors') showSkriptErrors(d.errors);
  if (d.type === 'error') appendConsole(`[Error] ${d.message}`);
};

function appendConsole(msg) {
  const out = document.getElementById('consoleOut');
  const el = document.createElement('div'); el.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`; out.appendChild(el); out.scrollTop = out.scrollHeight;
}
function sendConsole() {
  const cmd = document.getElementById('consoleInput').value.trim();
  if(!cmd) return;
  ws.send(JSON.stringify({ type:'server_command', command: cmd }));
  document.getElementById('consoleInput').value = '';
}
function sendChat(){
  const txt = document.getElementById('chatInput').value.trim(); if(!txt) return;
  ws.send(JSON.stringify({ type: 'chat_message', content: txt })); document.getElementById('chatInput').value = '';
}
function appendChat(message) {
  const out = document.getElementById('chatOut');
  const el = document.createElement('div'); el.textContent = `[${new Date(message.timestamp).toLocaleTimeString()}] ${message.sender}: ${message.content}`; out.appendChild(el); out.scrollTop = out.scrollHeight;
}

// files
function refreshFiles(){ ws.send(JSON.stringify({ type:'list_files' })); }
function populateFiles(files) {
  const div = document.getElementById('fileList'); div.innerHTML = '';
  files.forEach(f => {
    const el = document.createElement('div'); el.textContent = f;
    el.onclick = ()=> { window.location.href = '/skript.html?file=' + encodeURIComponent(f); };
    div.appendChild(el);
  });
}
function uploadFile(){
  const inp = document.getElementById('fileUpload');
  if(!inp.files || inp.files.length===0) return alert('Select file');
  const f = inp.files[0];
  const reader = new FileReader();
  reader.onload = ()=> {
    ws.send(JSON.stringify({ type:'upload_file', filename: f.name, content: reader.result }));
  };
  reader.readAsText(f);
}

// backups (handled by skript page)
// owner creds
async function saveOwnerCreds(){
  const hostIP = document.getElementById('hostIP').value;
  const hostUser = document.getElementById('hostUser').value;
  const hostPass = document.getElementById('hostPass').value;
  const rconPort = document.getElementById('rconPort').value;
  const reloadCmd = document.getElementById('reloadCmd').value || 'sk reload {file}';
  const res = await fetch('/api/owner/creds', { method:'POST', headers:{ 'Content-Type':'application/json', Authorization: token }, body: JSON.stringify({ hostIP, hostUser, hostPass, rconPort, fileReloadCommand: reloadCmd }) });
  const j = await res.json();
  document.getElementById('ownerMsg').textContent = j.success ? 'Saved' : (j.error || 'Error');
}
async function getOwnerCreds(){
  const res = await fetch('/api/owner/creds', { headers: { Authorization: token } });
  if(!res.ok) return;
  const j = await res.json();
  document.getElementById('hostIP').value = j.hostIP || '';
  document.getElementById('hostUser').value = j.hostUser || '';
  document.getElementById('hostPass').value = j.hostPass || '';
  document.getElementById('rconPort').value = j.rconPort || 25575;
  document.getElementById('reloadCmd').value = j.fileReloadCommand || 'sk reload {file}';
}

// skript-related UI will be on skript.html
