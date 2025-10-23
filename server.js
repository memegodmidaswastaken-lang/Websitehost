// server.js (full)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Rcon } = require('rcon-client'); // rcon-client v5

const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const SECRET = process.env.SECRET || 'please_change_secret';
const PORT = process.env.PORT || 3000;
const PERSIST_DIR = process.env.PERSIST_DIR || path.join(__dirname, 'data_storage');

if (!fs.existsSync(PERSIST_DIR)) fs.mkdirSync(PERSIST_DIR, { recursive: true });

const DATA_USERS = path.join(PERSIST_DIR, 'users.json');
const DATA_PENDING = path.join(PERSIST_DIR, 'pending.json');
const OWNER_CREDS_FILE = path.join(PERSIST_DIR, 'owner_creds.json');
const SERVER_FILES_DIR = path.join(PERSIST_DIR, 'server_files'); // skript files storage
const BACKUP_DIR = path.join(SERVER_FILES_DIR, 'backups');

if (!fs.existsSync(SERVER_FILES_DIR)) fs.mkdirSync(SERVER_FILES_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// util JSON load/save
function loadJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function saveJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }

// initialize files if missing
if (!fs.existsSync(DATA_USERS)) {
  // default owner account (change after first login)
  const defaultOwnerPassPlain = 'owner123';
  const users = {
    owner: { passwordHash: bcrypt.hashSync(defaultOwnerPassPlain, 10), role: 'owner' },
    admin: { passwordHash: bcrypt.hashSync('admin123', 10), role: 'admin' }
  };
  saveJSON(DATA_USERS, users);
}
if (!fs.existsSync(DATA_PENDING)) saveJSON(DATA_PENDING, {});
if (!fs.existsSync(OWNER_CREDS_FILE)) saveJSON(OWNER_CREDS_FILE, {});

// encryption helper for owner creds
function encrypt(text) {
  const key = crypto.createHash('sha256').update(SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}
function decrypt(enc) {
  if (!enc) return '';
  const b = Buffer.from(enc, 'base64');
  const iv = b.slice(0, 12);
  const tag = b.slice(12, 28);
  const encrypted = b.slice(28);
  const key = crypto.createHash('sha256').update(SECRET).digest();
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const out = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return out.toString('utf8');
  } catch (e) {
    return '';
  }
}

// backup helper
function backupFile(filename, content) {
  const safeName = filename.replace(/\//g, '_');
  const ts = Date.now();
  const backupName = `${safeName}.${ts}.bak`;
  const p = path.join(BACKUP_DIR, backupName);
  fs.writeFileSync(p, content, 'utf8');
  return backupName;
}

// JWT helpers
function signToken(username, role) {
  return jwt.sign({ username, role }, SECRET, { expiresIn: '8h' });
}
function verifyToken(token) {
  try { return jwt.verify(token, SECRET); } catch (e) { return null; }
}

// basic skript linter (very simple)
function checkSkriptSyntax(code) {
  const errors = [];
  const lines = (code || '').split('\n');
  lines.forEach((ln, i) => {
    const line = ln.trim();
    if ((/if$/.test(line) || /else if$/.test(line)) && !/:$/.test(line)) {
      errors.push({ line: i + 1, message: 'Possible missing colon at condition end.' });
    }
    if (line.includes('§')) errors.push({ line: i + 1, message: 'Invalid character § detected.' });
  });
  return errors;
}

// RCON helper - connects, sends command, returns output (owner creds must have rcon details)
async function runRconCommand(cmd) {
  const owner = loadJSON(OWNER_CREDS_FILE, {});
  const host = decrypt(owner.hostIP);
  const port = owner.rconPort || 25575;
  const pass = decrypt(owner.hostPass);
  if (!host || !pass) throw new Error('RCON credentials not configured by owner.');

  const rcon = new Rcon({ host, port: Number(port), password: pass });
  await rcon.connect();
  const res = await rcon.send(cmd);
  await rcon.end();
  return res;
}

/* ----- HTTP API ----- */

// login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const users = loadJSON(DATA_USERS, {});
  if (!username || !password || !users[username]) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, users[username].passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken(username, users[username].role);
  res.json({ token });
});

// register request (saved to pending)
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const users = loadJSON(DATA_USERS, {});
  const pending = loadJSON(DATA_PENDING, {});
  if (users[username] || pending[username]) return res.status(400).json({ error: 'User exists or pending' });
  pending[username] = { passwordHash: bcrypt.hashSync(password, 10), role: 'staff' };
  saveJSON(DATA_PENDING, pending);
  return res.json({ success: true, message: 'Request saved. Owner will approve.' });
});

// owner: list pending
app.get('/api/pending', (req, res) => {
  const token = req.headers.authorization;
  const info = verifyToken(token);
  if (!info || info.role !== 'owner') return res.status(403).json({ error: 'Forbidden' });
  const pending = loadJSON(DATA_PENDING, {});
  res.json(pending);
});

// owner: approve/deny
app.post('/api/approve', (req, res) => {
  const token = req.headers.authorization;
  const info = verifyToken(token);
  if (!info || info.role !== 'owner') return res.status(403).json({ error: 'Forbidden' });
  const { username, action } = req.body || {};
  const pending = loadJSON(DATA_PENDING, {});
  const users = loadJSON(DATA_USERS, {});
  if (!pending[username]) return res.status(404).json({ error: 'Not found' });
  if (action === 'approve') {
    users[username] = pending[username];
    saveJSON(DATA_USERS, users);
  }
  delete pending[username];
  saveJSON(DATA_PENDING, pending);
  return res.json({ success: true });
});

// owner credentials (save/get)
app.post('/api/owner/creds', (req, res) => {
  const token = req.headers.authorization;
  const info = verifyToken(token);
  if (!info || info.role !== 'owner') return res.status(403).json({ error: 'Forbidden' });

  const { hostIP, hostUser, hostPass, rconPort, fileReloadCommand } = req.body || {};
  const toSave = {
    hostIP: encrypt(hostIP || ''),
    hostUser: encrypt(hostUser || ''),
    hostPass: encrypt(hostPass || ''),
    rconPort: rconPort || 25575,
    fileReloadCommand: fileReloadCommand || 'sk reload' // default placeholder
  };
  saveJSON(OWNER_CREDS_FILE, toSave);
  return res.json({ success: true });
});
app.get('/api/owner/creds', (req, res) => {
  const token = req.headers.authorization;
  const info = verifyToken(token);
  if (!info || info.role !== 'owner') return res.status(403).json({ error: 'Forbidden' });
  const c = loadJSON(OWNER_CREDS_FILE, {});
  res.json({
    hostIP: decrypt(c.hostIP || ''),
    hostUser: decrypt(c.hostUser || ''),
    hostPass: decrypt(c.hostPass || ''),
    rconPort: c.rconPort || 25575,
    fileReloadCommand: c.fileReloadCommand || 'sk reload'
  });
});

// get dashboard data
app.get('/api/dashboard-data', (req, res) => {
  const token = req.headers.authorization;
  const info = verifyToken(token);
  if (!info) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ username: info.username, role: info.role });
});

/* ----- WebSocket features (console, chat, files, skript) ----- */
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const WebSocketServer = require('ws').Server;
const wss = new WebSocketServer({ server });

function listServerFiles() {
  return fs.readdirSync(SERVER_FILES_DIR).filter(f => f !== 'backups' && !f.startsWith('.'));
}

wss.on('connection', (socket, req) => {
  // token passed as query param ?token=...
  const params = new URL(req.url, `http://${req.headers.host}`).searchParams;
  const token = params.get('token');
  const info = verifyToken(token) || { username: 'anon', role: 'guest' };
  socket.user = info;

  // send initial file list
  socket.send(JSON.stringify({ type: 'file_list', files: listServerFiles() }));

  socket.on('message', async (msg) => {
    let data;
    try { data = JSON.parse(msg); } catch (e) { return; }

    // list files
    if (data.type === 'list_files') {
      socket.send(JSON.stringify({ type: 'file_list', files: listServerFiles() }));
    }

    // download file
    if (data.type === 'download_file') {
      const filePath = path.join(SERVER_FILES_DIR, data.filename);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        socket.send(JSON.stringify({ type: 'file_content', filename: data.filename, content }));
      } else {
        socket.send(JSON.stringify({ type: 'error', message: 'File not found' }));
      }
    }

    // save file (create backup first)
    if (data.type === 'save_file') {
      if (!socket.user || !['owner','admin'].includes(socket.user.role)) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const filePath = path.join(SERVER_FILES_DIR, data.filename);
      if (fs.existsSync(filePath)) {
        const old = fs.readFileSync(filePath, 'utf8');
        backupFile(data.filename, old);
      }
      fs.writeFileSync(filePath, data.content, 'utf8');
      socket.send(JSON.stringify({ type: 'file_saved', filename: data.filename }));
      // attempt to reload skript file on server via RCON using configured reload command (owner must set fileReloadCommand)
      try {
        const ownerC = loadJSON(OWNER_CREDS_FILE, {});
        const reloadCmd = ownerC.fileReloadCommand || 'sk reload';
        // attempt full reload command: if reloadCmd contains {file} replace with filename
        const cmdToSend = reloadCmd.includes('{file}') ? reloadCmd.replace('{file}', data.filename) : `${reloadCmd} ${data.filename}`;
        const out = await runRconCommand(cmdToSend);
        socket.send(JSON.stringify({ type: 'console_output', output: `[RCON] ${out}` }));
      } catch (e) {
        socket.send(JSON.stringify({ type: 'console_output', output: `[RCON Error] ${e.message}` }));
      }
      // broadcast file list
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
    }

    // upload new file (same as save)
    if (data.type === 'upload_file') {
      if (!socket.user || !['owner','admin'].includes(socket.user.role)) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const pth = path.join(SERVER_FILES_DIR, data.filename);
      if (fs.existsSync(pth)) {
        const old = fs.readFileSync(pth, 'utf8');
        backupFile(data.filename, old);
      }
      fs.writeFileSync(pth, data.content, 'utf8');
      socket.send(JSON.stringify({ type: 'upload_success', filename: data.filename }));
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
    }

    // list backups
    if (data.type === 'list_backups') {
      const safePrefix = data.filename.replace(/\//g, '_');
      const backups = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith(safePrefix)).sort((a,b) => b.localeCompare(a));
      socket.send(JSON.stringify({ type: 'backup_list', backups }));
    }

    // get backup content
    if (data.type === 'get_backup_content') {
      const p = path.join(BACKUP_DIR, data.backupFile);
      if (!fs.existsSync(p)) { socket.send(JSON.stringify({ type: 'error', message: 'Backup not found' })); return; }
      const content = fs.readFileSync(p, 'utf8');
      socket.send(JSON.stringify({ type: 'backup_content', backupFile: data.backupFile, content }));
    }

    // restore backup
    if (data.type === 'restore_backup') {
      if (!socket.user || !['owner','admin'].includes(socket.user.role)) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const p = path.join(BACKUP_DIR, data.backupFile);
      if (!fs.existsSync(p)) { socket.send(JSON.stringify({ type: 'error', message: 'Backup not found' })); return; }
      const content = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(path.join(SERVER_FILES_DIR, data.filename), content, 'utf8');
      socket.send(JSON.stringify({ type: 'backup_restored', filename: data.filename }));
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
    }

    // skript syntax check
    if (data.type === 'check_skript') {
      const errs = checkSkriptSyntax(data.code || '');
      socket.send(JSON.stringify({ type: 'skript_errors', errors: errs }));
    }

    // chat
    if (data.type === 'chat_message') {
      const message = { sender: socket.user.username || 'anon', content: data.content || '', timestamp: Date.now() };
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'chat_message', message })));
    }

    // player actions via RCON: kick/ban/unban (enforce reason)
    if (data.type === 'player_action') {
      if (!socket.user || !['owner','admin'].includes(socket.user.role)) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const { action, playerName, reason } = data;
      if ((action === 'kick' || action === 'ban') && (!reason || reason.trim() === '')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Reason required for kick/ban' }));
        return;
      }
      try {
        const cmd = action === 'kick' ? `kick ${playerName} ${reason}` : action === 'ban' ? `ban ${playerName} ${reason}` : `pardon ${playerName}`;
        const out = await runRconCommand(cmd);
        wss.clients.forEach(c => c.send(JSON.stringify({ type: 'player_action_log', log: { by: socket.user.username, action, playerName, reason, out, timestamp: Date.now() } })));
      } catch (e) {
        socket.send(JSON.stringify({ type: 'error', message: `RCON error: ${e.message}` }));
      }
    }

    // server command (owner only)
    if (data.type === 'server_command') {
      if (!socket.user || socket.user.role !== 'owner') { socket.send(JSON.stringify({ type: 'error', message: 'Only owner' })); return; }
      try {
        const out = await runRconCommand(data.command);
        wss.clients.forEach(c => c.send(JSON.stringify({ type: 'console_output', output: out })));
      } catch (e) {
        socket.send(JSON.stringify({ type: 'error', message: 'RCON error: ' + e.message }));
      }
    }

  });
});
