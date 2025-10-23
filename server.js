require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET = process.env.SECRET || "SUPER_SECRET_KEY";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY; // For AI integration
const SERVER_DIR = path.join(__dirname,'server_files');
const BACKUP_DIR = path.join(SERVER_DIR,'backups');

if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

// Example users
const users = [
    { username:"owner", passwordHash:bcrypt.hashSync("ownerpass",10), role:"owner" },
    { username:"admin", passwordHash:bcrypt.hashSync("admin123",10), role:"admin" }
];

// Login route
app.post('/login',(req,res)=>{
    const { username, password } = req.body;
    const user = users.find(u=>u.username===username);
    if(!user) return res.json({ success:false, message:"Invalid username" });
    if(bcrypt.compareSync(password, user.passwordHash)){
        const token = jwt.sign({ username:user.username, role:user.role }, SECRET, { expiresIn:'8h' });
        return res.json({ success:true, token });
    }
    return res.json({ success:false, message:"Invalid password" });
});

// Auth middleware
function authenticate(req,res,next){
    const token = req.headers['authorization'];
    if(!token) return res.status(401).send('Unauthorized');
    try{
        req.user = jwt.verify(token, SECRET);
        next();
    }catch(err){
        res.status(401).send('Unauthorized');
    }
}

// Protected data
app.get('/dashboard-data', authenticate, (req,res)=>{
    res.json({ username:req.user.username, role:req.user.role });
});

const server = app.listen(3000,()=>console.log("Dashboard running on port 3000"));

// WebSocket for live console, chat, file editor, AI
const wss = new WebSocket.Server({ server });

wss.on('connection', socket=>{
    // Here implement your:
    // - live server console
    // - chat messages
    // - file download/upload
    // - Skript AI error detection
    // - batch fixes
    // - backup management
    socket.on('message', msg=>{
        const data = JSON.parse(msg);
        // Example: Handle file download
        if(data.type==='download_file'){
            const filePath = path.join(SERVER_DIR,data.filename);
            if(fs.existsSync(filePath)){
                const content = fs.readFileSync(filePath,'utf8');
                socket.send(JSON.stringify({ type:'file_content', filename:data.filename, content }));
            }
        }
        // Add more handlers here: upload_file, AI suggestions, batch fixes, backups...
    });
});
