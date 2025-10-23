// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET = process.env.SECRET || 'please_change_secret';
const OWNER_USERNAME = process.env.OWNER_USERNAME || 'owner';
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || 'ownerpassword';

// Persistent storage (on Render use /mnt/data)
const PERSIST_DIR = process.env.PERSIST_DIR || (fs.existsSync('/mnt/data') ? '/mnt/data/server_files' : path.join(__dirname, 'server_files'));
const BACKUP_DIR = path.join(PERSIST_DIR, 'backups');

if (!fs.existsSync(PERSIST_DIR)) fs.mkdirSync(PERSIST_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// Basic in-memory user store (for demo). Replace with DB in prod.
const users = [
  { username: OWNER_USERNAME, passwordHash: bcrypt.hashSync(OWNER_PASSWORD, 10), role: 'owner' },
  { username: 'admin', passwordHash: bcrypt.hashSync('admin123', 10), role: 'admin' }
];

// Helper: encrypt/decrypt owner credentials using SECRET
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash('sha256').update(String(SECRET)).digest();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}
function decrypt(enc) {
  try {
    const b = Buffer.from(enc, 'base64');
    const iv = b.slice(0, 12);
    const tag = b.slice(12, 28);
    const encrypted = b.slice(28);
    const key = crypto.createHash('sha256').update(String(SECRET)).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (e) {
    return null;
  }
}

// Persisted owner credentials (encrypted) - stored in file for simplicity
const OWNER_CRED_FILE = path.join(PERSIST_DIR, 'owner_creds.json');
let ownerCreds = {};
if (fs.existsSync(OWNER_CRED_FILE)) {
  try { ownerCreds = JSON.parse(fs.readFileSync(OWNER_CRED_FILE, 'utf8')); } catch(e) { ownerCreds = {}; }
}

// Helper: backup function
function backupFile(filename, content) {
  const safeName = filename.replace(/\//g, '_');
  const timestamp = Date.now();
  const backupFilePath = path.join(BACKUP_DIR, `${safeName}.${timestamp}.bak`);
  fs.writeFileSync(backupFilePath, content, 'utf8');
  return path.basename(backupFilePath);
}

// Authentication endpoints
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find(u => u.username === username);
  if (!user) return res.json({ success: false, message: 'Invalid username or password' });
  if (!bcrypt.compareSync(password, user.passwordHash)) return res.json({ success: false, message: 'Invalid username or password' });
  const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: '8h' });
  res.json({ success: true, token });
});

function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET);
  } catch (e) {
    return null;
  }
}

app.get('/dashboard-data', (req, res) => {
  const token = req.headers['authorization'];
  const user = verifyToken(token);
  if (!user) return res.status(401).send('Unauthorized');
  res.json({ username: user.username, role: user.role });
});

// Save owner credentials (owner only)
app.post('/owner/creds', (req, res) => {
  const token = req.headers['authorization'];
  const user = verifyToken(token);
  if (!user || user.username !== OWNER_USERNAME) return res.status(403).send('Forbidden');
  const { hostIP, hostUser, hostPass } = req.body;
  ownerCreds = {
    hostIP: encrypt(hostIP || ''),
    hostUser: encrypt(hostUser || ''),
    hostPass: encrypt(hostPass || '')
  };
  fs.writeFileSync(OWNER_CRED_FILE, JSON.stringify(ownerCreds), 'utf8');
  res.json({ success: true });
});

app.get('/owner/creds', (req, res) => {
  const token = req.headers['authorization'];
  const user = verifyToken(token);
  if (!user || user.username !== OWNER_USERNAME) return res.status(403).send('Forbidden');
  res.json({
    hostIP: decrypt(ownerCreds.hostIP || '') || '',
    hostUser: decrypt(ownerCreds.hostUser || '') || '',
    hostPass: decrypt(ownerCreds.hostPass || '') || ''
  });
});

// WebSocket server for live operations
const server = app.listen(process.env.PORT || 3000, () => console.log('Dashboard running on port', process.env.PORT || 3000));
const wss = new WebSocket.Server({ server });

// Utility: list files in PERSIST_DIR
function listServerFiles() {
  const files = fs.readdirSync(PERSIST_DIR).filter(f => f !== 'backups' && f !== 'owner_creds.json');
  return files;
}

// Simple skript syntax checker (very basic rules — extend as needed)
function checkSkriptSyntax(code) {
  const errors = [];
  const lines = code.split('\n');
  lines.forEach((ln, idx) => {
    const line = ln.trim();
    if (line.endsWith('if') || line.endsWith('else if')) {
      errors.push({ line: idx + 1, message: 'Possible missing colon or ending after condition' });
    }
    if (line.includes('§')) {
      errors.push({ line: idx + 1, message: 'Invalid character § detected' });
    }
  });
  return errors;
}

// Manage socket connections with token auth via query string ?token=...
wss.on('connection', (socket, req) => {
  // parse token from query string
  const params = new URL(req.url, `http://${req.headers.host}`).searchParams;
  const token = params.get('token');
  const user = verifyToken(token) || { username: 'anonymous', role: 'guest' };
  socket.user = user;

  // send initial file list & backups
  socket.send(JSON.stringify({ type: 'file_list', files: listServerFiles() }));

  socket.on('message', msg => {
    let data;
    try { data = JSON.parse(msg); } catch (e) { return; }

    // Handle file list refresh
    if (data.type === 'list_files') {
      socket.send(JSON.stringify({ type: 'file_list', files: listServerFiles() }));
    }

    // Download file
    if (data.type === 'download_file') {
      const filePath = path.join(PERSIST_DIR, data.filename);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        socket.send(JSON.stringify({ type: 'file_content', filename: data.filename, content }));
      } else {
        socket.send(JSON.stringify({ type: 'error', message: 'File not found' }));
      }
    }

    // Save file with backup (owner or admin depending on permission)
    if (data.type === 'save_file') {
      if (!user || (user.role !== 'owner' && user.role !== 'admin')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const filePath = path.join(PERSIST_DIR, data.filename);
      if (fs.existsSync(filePath)) {
        const oldContent = fs.readFileSync(filePath, 'utf8');
        backupFile(data.filename, oldContent);
      }
      fs.writeFileSync(filePath, data.content, 'utf8');
      socket.send(JSON.stringify({ type: 'file_saved', filename: data.filename }));
      // broadcast updated list
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
    }

    // Upload new file (owner or admin)
    if (data.type === 'upload_file') {
      if (!user || (user.role !== 'owner' && user.role !== 'admin')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const filePath = path.join(PERSIST_DIR, data.filename);
      if (fs.existsSync(filePath)) {
        const oldContent = fs.readFileSync(filePath, 'utf8');
        backupFile(data.filename, oldContent);
      }
      fs.writeFileSync(filePath, data.content, 'utf8');
      socket.send(JSON.stringify({ type: 'upload_success', filename: data.filename }));
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
    }

    // List backups
    if (data.type === 'list_backups') {
      const safePrefix = data.filename.replace(/\//g, '_');
      const backups = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith(safePrefix)).sort((a,b) => b.localeCompare(a));
      socket.send(JSON.stringify({ type: 'backup_list', backups }));
    }

    // Get backup content
    if (data.type === 'get_backup_content') {
      const backupPath = path.join(BACKUP_DIR, data.backupFile);
      if (fs.existsSync(backupPath)) {
        const content = fs.readFileSync(backupPath, 'utf8');
        socket.send(JSON.stringify({ type: 'backup_content', backupFile: data.backupFile, content }));
      } else {
        socket.send(JSON.stringify({ type: 'error', message: 'Backup not found' }));
      }
    }

    // Restore backup (owner or admin)
    if (data.type === 'restore_backup') {
      if (!user || (user.role !== 'owner' && user.role !== 'admin')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const backupPath = path.join(BACKUP_DIR, data.backupFile);
      const filename = data.filename;
      if (fs.existsSync(backupPath)) {
        const content = fs.readFileSync(backupPath, 'utf8');
        fs.writeFileSync(path.join(PERSIST_DIR, filename), content, 'utf8');
        socket.send(JSON.stringify({ type: 'backup_restored', filename }));
        wss.clients.forEach(c => c.send(JSON.stringify({ type: 'file_list', files: listServerFiles() })));
      } else {
        socket.send(JSON.stringify({ type: 'error', message: 'Backup not found' }));
      }
    }

    // Basic skript syntax check
    if (data.type === 'check_skript') {
      const errors = checkSkriptSyntax(data.code || '');
      socket.send(JSON.stringify({ type: 'skript_errors', errors }));
    }

    // Chat message (admin chat)
    if (data.type === 'chat_message') {
      const message = { sender: user.username || 'anon', content: data.content || '', timestamp: Date.now() };
      // Broadcast to all admins
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'chat_message', message })));
    }

    // Player actions: kick/ban/unban (enforce reason)
    if (data.type === 'player_action') {
      if (!user || (user.role !== 'owner' && user.role !== 'admin')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Permission denied' }));
        return;
      }
      const { action, playerName, reason } = data;
      if ((action === 'kick' || action === 'ban') && (!reason || reason.trim() === '')) {
        socket.send(JSON.stringify({ type: 'error', message: 'Reason required for kick/ban' }));
        return;
      }
      // TODO: integrate with your RCON or proxy to actually perform kick/ban on the Minecraft server
      // For now, we just log and broadcast
      const log = { by: user.username, action, playerName, reason, timestamp: Date.now() };
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'player_action_log', log })));
    }

    // Server control placeholders (start/stop/restart)
    if (data.type === 'server_command') {
      if (!user || user.role !== 'owner') {
        socket.send(JSON.stringify({ type: 'error', message: 'Only owner can control server lifecycle' }));
        return;
      }
      // TODO: implement real server start/stop/restart logic (systemctl, docker, etc.)
      wss.clients.forEach(c => c.send(JSON.stringify({ type: 'server_status', status: `Executed ${data.command} (placeholder)` })));
    }
  });
});
