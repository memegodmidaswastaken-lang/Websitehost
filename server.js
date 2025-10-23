require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const { Configuration, OpenAIApi } = require("openai");

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET = process.env.SECRET;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

const SERVER_DIR = path.join(__dirname,'server_files');
const BACKUP_DIR = path.join(SERVER_DIR,'backups');
if(!fs.existsSync(SERVER_DIR)) fs.mkdirSync(SERVER_DIR);
if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

const openai = new OpenAIApi(new Configuration({ apiKey: OPENAI_API_KEY }));

// Example users
const users = [
    { username:"owner", passwordHash:bcrypt.hashSync("ownerpass",10), role:"owner" },
    { username:"admin", passwordHash:bcrypt.hashSync("admin123",10), role:"admin" }
];

// Login
app.post('/login',(req,res)=>{
    const { username, password } = req.body;
    const user = users.find(u=>u.username===username);
    if(!user) return res.json({ success:false, message:"Invalid username" });
    if(bcrypt.compareSync(password,user.passwordHash)){
        const token = jwt.sign({ username:user.username, role:user.role }, SECRET, { expiresIn:'8h' });
        return res.json({ success:true, token });
    }
    return res.json({ success:false, message:"Invalid password" });
});

// Middleware
function authenticate(req,res,next){
    const token = req.headers['authorization'];
    if(!token) return res.status(401).send('Unauthorized');
    try{ req.user = jwt.verify(token, SECRET); next(); }
    catch(err){ res.status(401).send('Unauthorized'); }
}

// Dashboard data
app.get('/dashboard-data', authenticate, (req,res)=>{
    res.json({ username:req.user.username, role:req.user.role });
});

// Backup helper
function backupFile(filename, content){
    const timestamp = Date.now();
    const backupFilePath = path.join(BACKUP_DIR, `${filename}.${timestamp}.bak`);
    fs.writeFileSync(backupFilePath, content);
    return backupFilePath;
}

// WebSocket
const server = app.listen(3000,()=>console.log("Dashboard running on port 3000"));
const wss = new WebSocket.Server({ server });

wss.on('connection', socket=>{
    socket.on('message', async msg=>{
        const data = JSON.parse(msg);

        // Download file
        if(data.type==='download_file'){
            const filePath = path.join(SERVER_DIR,data.filename);
            if(fs.existsSync(filePath)){
                const content = fs.readFileSync(filePath,'utf8');
                socket.send(JSON.stringify({ type:'file_content', filename:data.filename, content }));
            }
        }

        // Save file with backup
        if(data.type==='save_file'){
            const filePath = path.join(SERVER_DIR,data.filename);
            const content = data.content;
            if(fs.existsSync(filePath)){
                const oldContent = fs.readFileSync(filePath,'utf8');
                backupFile(data.filename, oldContent);
            }
            fs.writeFileSync(filePath, content,'utf8');
            socket.send(JSON.stringify({ type:'file_saved', filename:data.filename }));
        }

        // AI explanation
        if(data.type==='skript_ai_explain'){
            try{
                const prompt = `
You are an expert Skript developer. Explain the following Skript error in plain English and suggest a fix:
Skript code:
${data.code}

Error:
${data.error.message}
`;
                const response = await openai.createChatCompletion({
                    model: "gpt-4o-mini",
                    messages:[{ role:"user", content:prompt }]
                });
                socket.send(JSON.stringify({
                    type:'skript_ai_response',
                    explanation: response.data.choices[0].message.content
                }));
            }catch(err){
                socket.send(JSON.stringify({ type:'skript_ai_response', explanation:'AI failed: '+err.message }));
            }
        }

        // AI suggestion fix
        if(data.type==='skript_ai_suggest'){
            try{
                const prompt = `
You are an expert Skript developer. Analyze the following code and the reported error:
Skript code:
${data.code}

Error:
${data.error.message}

Provide a fixed snippet. Only output the snippet.
`;
                const response = await openai.createChatCompletion({
                    model:"gpt-4o-mini",
                    messages:[{ role:"user", content:prompt }]
                });
                socket.send(JSON.stringify({ type:'skript_ai_suggestion', suggestion: response.data.choices[0].message.content }));
            }catch(err){
                socket.send(JSON.stringify({ type:'skript_ai_suggestion', suggestion:'AI failed: '+err.message }));
            }
        }

        // Backups list
        if(data.type==='list_backups'){
            const backups = fs.readdirSync(BACKUP_DIR)
                .filter(f=>f.startsWith(data.filename))
                .sort((a,b)=>b.localeCompare(a));
            socket.send(JSON.stringify({ type:'backup_list', backups }));
        }

        // Restore backup
        if(data.type==='restore_backup'){
            const backupPath = path.join(BACKUP_DIR, data.backupFile);
            const filePath = path.join(SERVER_DIR, data.filename);
            const content = fs.readFileSync(backupPath,'utf8');
            fs.writeFileSync(filePath, content,'utf8');
            socket.send(JSON.stringify({ type:'backup_restored', filename:data.filename }));
        }

        // Get backup content
        if(data.type==='get_backup_content'){
            const backupPath = path.join(BACKUP_DIR, data.backupFile);
            const content = fs.readFileSync(backupPath,'utf8');
            socket.send(JSON.stringify({ type:'backup_content', backupFile:data.backupFile, content }));
        }
    });
});
