const token = localStorage.getItem('token');
if(!token) window.location.href='/login.html';

async function init(){
    const res = await fetch('/dashboard-data',{ headers:{ 'Authorization': token }});
    if(res.status!==200) return window.location.href='/login.html';
    const data = await res.json();
    console.log('Logged in as', data.username, 'Role:', data.role);

    initWebSocket();
    initEditor();
}

let ws;
function initWebSocket(){
    ws = new WebSocket(`ws://${window.location.host}`);
    ws.onopen = ()=>console.log('WebSocket connected');
    ws.onmessage = e=>console.log('WS Msg',e.data);
}

let editor;
function initEditor(){
    editor = CodeMirror(document.getElementById('codeMirrorEditor'),{
        value:'',
        lineNumbers:true,
        mode:'javascript'
    });
}

init();
