// dashboard.js
const token = localStorage.getItem('token');
if(!token) location.href = '/login.html';

let ws;
let editor;
let currentFile = '';
let currentBackupContent = '';
let currentBackupName = '';
let currentErrors = [];

async function init(){
  const res = await fetch('/dashboard-data', { headers: { 'Authorization': token }});
  if(res.status !== 200) return location.href = '/login.html';
  const data = await res.json();
  document.getElementById('topInfo').textContent = `Logged in as: ${data.username} (${data.role})`;
  if(data.role === 'owner') document.getElementById('ownerSection').style.display = 'block';
  initEditor();
  initWebSocket();
}
function initEditor(){
  editor = CodeMirror(document.getElementById('codeMirrorEditor'), {
    value: '',
    lineNumbers: true,
    mode: 'javascript',
    tabSize: 2
  });
  editor.on('change', debounce(()=> {
    checkSkriptSyntax();
  }, 400));
}
function initWebSocket(){
  // connect with token as query param
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/?token=${token}`);

  ws.onopen = ()=> {
    console.log('WS open');
    refreshFiles();
    refreshBackups();
  };
  ws.onmessage = (evt) => {
    const d = JSON.parse(evt.data);
    if(d.type === 'file_list'){
      populateFileList(d.files);
    }
    if(d.type === 'file_content'){
      loadFileIntoEditor(d.filename, d.content);
    }
    if(d.type === 'file_saved' || d.type === 'upload_success'){
      alert('Saved: ' + d.filename);
      refreshFiles();
      refreshBackups();
    }
    if(d.type === 'backup_list'){
      populateBackups(d.backups);
    }
    if(d.type === 'backup_content'){
      currentBackupContent = d.content;
      currentBackupName = d.backupFile;
      compareWithCurrent(d.content);
    }
    if(d.type === 'chat_message'){
      appendChat(d.message);
    }
    if(d.type === 'error'){
      console.error('Server error:', d.message);
    }
    if(d.type === 'skript_errors'){
      currentErrors = d.errors || [];
      displaySkriptErrors(currentErrors);
    }
    if(d.type === 'player_action_log'){
      appendConsole(`[${new Date(d.log.timestamp).toLocaleTimeString()}] ${d.log.by} ${d.log.action} ${d.log.playerName} ${d.log.reason||''}`);
    }
    if(d.type === 'server_status'){
      appendConsole('[Server] ' + (d.status || 'status update'));
    }
  };
}

function refreshFiles(){ ws.send(JSON.stringify({ type:'list_files' })); }
function populateFileList(files){
  const sel = document.getElementById('editFileSelect');
  sel.innerHTML = '';
  files.forEach(f => {
    const opt = document.createElement('option');
    opt.value = f;
    opt.textContent = f;
    sel.appendChild(opt);
  });
  // fill owner file list too
  const fileListDiv = document.getElementById('fileList');
  fileListDiv.innerHTML = '';
  files.forEach(f => {
    const d = document.createElement('div');
    d.textContent = f;
    d.style.cursor = 'pointer';
    d.onclick = ()=> { document.getElementById('editFileSelect').value = f; loadFileContent(); };
    fileListDiv.appendChild(d);
  });
}

function loadFileContent(){
  const filename = document.getElementById('editFileSelect').value;
  if(!filename) return;
  ws.send(JSON.stringify({ type:'download_file', filename }));
}

function loadFileIntoEditor(filename, content){
  currentFile = filename;
  editor.setValue(content);
  setEditorModeByFilename(filename);
  checkSkriptSyntax();
}

function setEditorModeByFilename(fn){
  if (fn.endsWith('.yml') || fn.endsWith('.yaml')) editor.setOption('mode','yaml');
  else if (fn.endsWith('.js')) editor.setOption('mode','javascript');
  else if (fn.endsWith('.sk')) editor.setOption('mode','clike'); // Skript-ish
  else editor.setOption('mode','javascript');
}

function saveFileContent(){
  if(!currentFile) { alert('Select a file first'); return; }
  const content = editor.getValue();
  ws.send(JSON.stringify({ type:'save_file', filename: currentFile, content }));
}

function uploadNewFile(){
  const name = prompt('Enter new filename (relative to server files root):');
  if(!name) return;
  const content = prompt('Paste file content:');
  if(content == null) return;
  ws.send(JSON.stringify({ type:'upload_file', filename: name, content }));
}

// Backups
function refreshBackups(){
  if(!currentFile) return;
  ws.send(JSON.stringify({ type:'list_backups', filename: currentFile }));
}
function populateBackups(list){
  const ul = document.getElementById('backupList');
  ul.innerHTML = '';
  list.forEach(b => {
    const li = document.createElement('li');
    li.innerHTML = `${b} <button onclick="viewBackup('${b}')">View</button> <button onclick="restoreBackup('${b}')">Restore</button>`;
    ul.appendChild(li);
  });
}
function viewBackup(b){ ws.send(JSON.stringify({ type:'get_backup_content', backupFile: b })); }
function restoreBackup(b){
  if(!currentFile) return alert('No file selected');
  if(!confirm('Restore backup? This overwrites current file.')) return;
  ws.send(JSON.stringify({ type:'restore_backup', backupFile: b, filename: currentFile }));
}

// Compare with current: line & word-level diff with clickable revert
function compareWithCurrent(backupContent){
  const cur = editor.getValue();
  const backupLines = backupContent.split('\n');
  const curLines = cur.split('\n');
  const max = Math.max(backupLines.length, curLines.length);
  const container = document.getElementById('backupDiff');
  container.innerHTML = '';

  for(let i=0;i<max;i++){
    const b = backupLines[i] || '';
    const c = curLines[i] || '';
    const lineDiv = document.createElement('div');
    if(b === c){
      lineDiv.textContent = c;
    } else {
      lineDiv.innerHTML = wordDiffClickable(b, c, i);
    }
    container.appendChild(lineDiv);
  }
}

// generate clickable word-level diff HTML; revertWord will be called on click
function wordDiffClickable(oldLine, newLine, lineIndex){
  const oldWords = oldLine.split(/(\s+)/);
  const newWords = newLine.split(/(\s+)/);
  const len = Math.max(oldWords.length, newWords.length);
  let html = '';
  for(let i=0;i<len;i++){
    const o = oldWords[i] || '';
    const n = newWords[i] || '';
    if(o !== n){
      const safeOld = o.replace(/'/g,"\\'");
      html += `<span style="background:red;color:white;cursor:pointer" onclick="revertWord(${lineIndex},${i},'${safeOld}')">${o}</span> → <span style="background:green;color:white">${n}</span> `;
    } else {
      html += o;
    }
  }
  return html;
}

function revertWord(lineIndex, wordIndex, oldWord){
  const lines = editor.getValue().split('\n');
  const words = lines[lineIndex].split(/(\s+)/);
  words[wordIndex] = oldWord;
  lines[lineIndex] = words.join('');
  editor.setValue(lines.join('\n'));
  // refresh diff view (if a backup is loaded)
  if(currentBackupContent) compareWithCurrent(currentBackupContent);
}

// Skript syntax check
function checkSkriptSyntax(){
  const code = editor.getValue();
  ws.send(JSON.stringify({ type:'check_skript', code }));
}
function displaySkriptErrors(errors){
  const panel = document.getElementById('errorPanel');
  panel.innerHTML = '';
  if(!errors || errors.length === 0){ panel.textContent = 'No syntax errors detected.'; return; }
  errors.forEach(err=>{
    const d = document.createElement('div');
    d.innerHTML = `Line ${err.line}: ${err.message} <button onclick="explainError(${err.line})">Explain</button>`;
    panel.appendChild(d);
  });
}
function explainError(line) {
  alert('This is a basic linter message: check line ' + line + '. (No AI in this build)');
}

// Chat
function sendChat(){
  const txt = document.getElementById('chatInput').value;
  if(!txt) return;
  ws.send(JSON.stringify({ type:'chat_message', content: txt }));
  document.getElementById('chatInput').value = '';
}
function appendChat(msg){
  const out = document.getElementById('chatOutput');
  const d = document.createElement('div');
  d.textContent = `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.sender}: ${msg.content}`;
  out.appendChild(d);
  out.scrollTop = out.scrollHeight;
}

// Console (placeholder)
function sendCommand(){
  const cmd = document.getElementById('consoleInput').value;
  if(!cmd) return;
  ws.send(JSON.stringify({ type:'server_command', command: cmd }));
  appendConsole('[You] ' + cmd);
}
function appendConsole(line){
  const out = document.getElementById('consoleOutput');
  const d = document.createElement('div');
  d.textContent = line;
  out.appendChild(d);
  out.scrollTop = out.scrollHeight;
}

// Owner credentials (save/load)
async function saveOwnerCreds(){
  const hostIP = document.getElementById('hostIP').value;
  const hostUser = document.getElementById('hostUser').value;
  const hostPass = document.getElementById('hostPass').value;
  const res = await fetch('/owner/creds', {
    method:'POST',
    headers: { 'Content-Type':'application/json', 'Authorization': token },
    body: JSON.stringify({ hostIP, hostUser, hostPass })
  });
  if(res.status === 200) document.getElementById('ownerCredsMsg').textContent = 'Saved';
  else document.getElementById('ownerCredsMsg').textContent = 'Failed';
}
async function loadOwnerCreds(){
  const res = await fetch('/owner/creds', { headers: { 'Authorization': token } });
  if(res.status !== 200) return;
  const j = await res.json();
  document.getElementById('hostIP').value = j.hostIP || '';
  document.getElementById('hostUser').value = j.hostUser || '';
  document.getElementById('hostPass').value = j.hostPass || '';
}

// file upload (owner)
function uploadFileAsOwner(){
  const inp = document.getElementById('fileUploadInput');
  if(!inp.files || inp.files.length === 0) return alert('Select file');
  const f = inp.files[0];
  const reader = new FileReader();
  reader.onload = () => {
    ws.send(JSON.stringify({ type:'upload_file', filename: f.name, content: reader.result }));
  };
  reader.readAsText(f);
}

// Help text: call loadOwnerCreds if owner
init();
setTimeout(()=> loadOwnerCreds(), 600);
function debounce(fn, ms){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }
