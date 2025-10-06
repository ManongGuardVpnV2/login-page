// server.js
// IPTV server with 24h JWT login, protected static files and channels.json
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Config
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_strong_secret';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';

// Middleware to verify token
function authMiddleware(req, res, next) {
  const token = req.cookies?.iptv_token || req.headers['authorization']?.split(' ')[1] || req.query.token;
  if (!token) return res.redirect('/login');
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}

// --------------------------
// Login page
// --------------------------
app.get('/login', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>IPTV Login</title>
    <style>
      body { font-family: sans-serif; background: #121212; color: #eee; display: flex; justify-content: center; align-items: center; height: 100vh; }
      .login-box { background: #1f1f1f; padding: 20px; border-radius: 10px; width: 300px; text-align: center; }
      input { width: 100%; padding: 10px; margin: 10px 0; border-radius: 5px; border: none; }
      button { width: 100%; padding: 10px; border-radius: 5px; background: #4caf50; color: white; border: none; cursor: pointer; }
      button:hover { background: #45a049; }
      .msg { margin-top: 10px; color: #f44336; }
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
      async function login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const msg = document.getElementById('msg');
        msg.textContent = '';
        try {
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          const data = await res.json();
          if(res.ok) {
            localStorage.setItem('iptv_token', data.token);
            window.location.href = '/index.html';
          } else {
            msg.textContent = data.error;
          }
        } catch(e) {
          msg.textContent = 'Server error';
        }
      }
    </script>
  </body>
  </html>
  `);
});

// --------------------------
// Login API - returns 24h JWT
// --------------------------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });
  if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// --------------------------
// Protected channels API
// --------------------------
app.get('/api/channels', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1] || req.query.token || req.headers['x-access-token'];
  if (!token) return res.status(401).json({ error: 'Token required' });
  try {
    jwt.verify(token, JWT_SECRET);
    const channelsPath = path.join(__dirname, 'public', 'data', 'channels.json');
    const data = fs.readFileSync(channelsPath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// --------------------------
// Serve static files - protected by token
// --------------------------
app.use('/index.html', authMiddleware, express.static(path.join(__dirname, 'public', 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

// 404 fallback
app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => console.log(`IPTV server running on port ${PORT}`));
