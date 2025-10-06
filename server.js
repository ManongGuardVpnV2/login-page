const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_strong_secret';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';

// Middleware to check login token
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1] || req.query.token;
  if (!token) return res.redirect('/login');
  try { jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.redirect('/login'); }
}

// Login page
app.get('/login', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>IPTV Login</title>
    <style>
      body { font-family: sans-serif; background:#121212; color:#eee; display:flex; justify-content:center; align-items:center; height:100vh;}
      .login-box { background:#1f1f1f; padding:20px; border-radius:10px; width:300px; text-align:center;}
      input { width:100%; padding:10px; margin:10px 0; border-radius:5px; border:none;}
      button { width:100%; padding:10px; border-radius:5px; background:#4caf50; color:white; border:none; cursor:pointer;}
      button:hover{background:#45a049;}
      .msg{margin-top:10px; color:#f44336;}
    </style>
  </head>
  <body>
    <div class="login-box">
      <h2>IPTV Login</h2>
      <input id="username" placeholder="Username" />
      <input id="password" type="password" placeholder="Password" />
      <button onclick="login()">Login</button>
      <div class="msg" id="msg"></div>
    </div>
    <script>
      async function login(){
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const msg = document.getElementById('msg');
        msg.textContent='';
        try{
          const res = await fetch('/api/login', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username,password})
          });
          const data = await res.json();
          if(res.ok){
            localStorage.setItem('iptv_token',data.token);
            window.location.href='/index.html';
          } else { msg.textContent=data.error; }
        } catch(e){ msg.textContent='Server error'; }
      }
    </script>
  </body>
  </html>
  `);
});

// Login API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });
  if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// Channels API
app.get('/api/channels', authMiddleware, (req, res) => {
  const channelsPath = path.join(__dirname, 'data', 'channels.json');
  let rawChannels;
  try { rawChannels = JSON.parse(fs.readFileSync(channelsPath, 'utf-8')); } catch(e) { return res.status(500).json({error:'Failed to load channels'}); }

  const channelsWithPlay = rawChannels.map((ch,i)=>{
    const playToken = jwt.sign({ channelIndex:i }, JWT_SECRET, { expiresIn:'1h' });
    return {
      id:i,
      name:ch.name,
      logo:ch.logo,
      category:ch.category || 'General',
      play_url:`/play/${playToken}`,
      manifestUri:ch.manifestUri||null,
      url:ch.url||null,
      clearKey:ch.clearKey||null
    };
  });

  res.json(channelsWithPlay);
});

// Play proxy
app.get('/play/:playToken', async (req,res)=>{
  try {
    const payload = jwt.verify(req.params.playToken, JWT_SECRET);
    const channelsPath = path.join(__dirname,'data','channels.json');
    const channels = JSON.parse(fs.readFileSync(channelsPath,'utf-8'));
    const channel = channels[payload.channelIndex];
    if(!channel) return res.status(404).send('Channel not found');
    const sourceUrl = channel.manifestUri || channel.url;
    if(!sourceUrl) return res.status(500).send('Invalid source');
    const upstream = await fetch(sourceUrl);
    res.status(upstream.status);
    if(upstream.headers.get('content-type')) res.setHeader('content-type', upstream.headers.get('content-type'));
    upstream.body.pipe(res);
  } catch(e){
    res.status(401).send('Invalid or expired play token');
  }
});

// Serve frontend
app.use(express.static(path.join(__dirname,'public')));

app.listen(PORT,()=>console.log(`IPTV server running on port ${PORT}`));
