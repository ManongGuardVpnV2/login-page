// server.js
// Secure IPTV server — encrypted channel list, login page, proxy, ready for Render

const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_jwt_secret_in_prod';
const ENC_SECRET = process.env.ENC_SECRET || 'change_this_enc_secret_32_bytes_long!';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';

if (!process.env.JWT_SECRET || !process.env.ENC_SECRET) {
  console.warn('WARNING: Set JWT_SECRET and ENC_SECRET environment variables in production.');
}

// -------------------------
// Raw embedded channel list
// -------------------------
const rawChannels = [
  {
    "name": "TV5",
    "logo": "https://logowik.com/content/uploads/images/tv5-philippines1731625551.logowik.com.webp",
    "manifestUri": "https://qp-pldt-live-bpk-02-prod.akamaized.net/bpk-tv/tv5_hd/default1/index.mpd",
    "clearKey": { "2615129ef2c846a9bbd43a641c7303ef": "07c7f996b1734ea288641a68e1cfdc4d" },
    "category": "Local"
  },
  {
    "name": "A2Z",
    "logo": "https://i.ebayimg.com/images/g/3EoAAOSwuLxjH4JN/s-l300.png",
    "manifestUri": "https://vod.nathcreqtives.com/1087/manifest.mpd",
    "clearKey": { "31363231383437383231323033353237": "583130656f6d3267777a6d7235487858" },
    "category": "Local"
  },
  {
    "name": "Kapamilya",
    "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/f/f2/Kapamilya_Channel_Logo_2020.svg/2560px-Kapamilya_Channel_Logo_2020.svg.png",
    "manifestUri": "https://vod.nathcreqtives.com/1286/manifest.mpd",
    "clearKey": { "31363331363737343637333533323837": "71347339457958556439543650426e74" },
    "category": "Local"
  },
  {
    "name": "Jeepney TV",
    "logo": "https://tse3.mm.bing.net/th/id/OIP.bnjFWbiXnqyPP8tHr9hkoAHaE0?pid=Api&P=0&h=180",
    "manifestUri": "https://abslive.akamaized.net/dash/live/2028025/jeepneytv/manifest.mpd",
    "clearKey": { "90ea4079e02f418db7b170e8763e65f0": "1bfe2d166e31d03eee86ee568bd6c272" },
    "category": "Local"
  }
  // Add the rest of your channel list here
];

// -------------------------
// AES-256-GCM encryption helpers
// -------------------------
function _deriveKey(secret) {
  return crypto.createHash('sha256').update(secret).digest();
}

function encryptJSON(obj) {
  const iv = crypto.randomBytes(12);
  const key = _deriveKey(ENC_SECRET);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptJSON(enc) {
  try {
    const data = Buffer.from(enc, 'base64');
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const encrypted = data.slice(28);
    const key = _deriveKey(ENC_SECRET);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

// -------------------------
// Build internal CHANNELS with encrypted manifest & clearKey
// -------------------------
const CHANNELS = rawChannels.map((ch, i) => {
  const item = { id: i + 1, name: ch.name, logo: ch.logo, category: ch.category || 'General' };
  if (ch.manifestUri) item.encryptedManifest = encryptJSON({ manifestUri: ch.manifestUri });
  if (ch.clearKey) item.encryptedClearKey = encryptJSON(ch.clearKey);
  if (ch.url) item.encryptedUrl = encryptJSON({ url: ch.url });
  return item;
});

// -------------------------
// JWT helpers
// -------------------------
function generateToken(payload = {}, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: opts.expiresIn || '24h' });
}

function extractToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  if (req.query && req.query.token) return req.query.token;
  return null;
}

function authMiddleware(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'token_required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'invalid_or_expired_token' });
    req.user = decoded;
    next();
  });
}

// -------------------------
// LOGIN endpoint (API)
// -------------------------
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_credentials' });
  if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(401).json({ error: 'invalid_credentials' });
  const token = generateToken({ username, admin: true }, { expiresIn: '24h' });
  return res.json({ token, expires_in: 24 * 60 * 60 });
});

// -------------------------
// LOGIN PAGE
// -------------------------
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure IPTV Login</title>
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
            const res = await fetch('/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (res.ok) {
              localStorage.setItem('iptv_token', data.token);
              window.location.href = '/index.html';
            } else {
              msg.textContent = data.error || 'Login failed';
            }
          } catch (err) {
            msg.textContent = 'Server error';
          }
        }
      </script>
    </body>
    </html>
  `);
});

// -------------------------
// CHANNEL LIST API
// -------------------------
app.get('/api/channels', authMiddleware, (req, res) => {
  const channelsSafe = CHANNELS.map(ch => {
    const playToken = jwt.sign({ channelId: ch.id, username: req.user.username || 'unknown' }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    return { id: ch.id, name: ch.name, logo: ch.logo, category: ch.category, play_url: `/play/${playToken}` };
  });
  res.json({ channels: channelsSafe });
});

// -------------------------
// PLAY proxy
// -------------------------
app.get('/play/:playToken', async (req, res) => {
  const { playToken } = req.params;
  try {
    const payload = jwt.verify(playToken, JWT_SECRET);
    const ch = CHANNELS.find(c => c.id === payload.channelId);
    if (!ch) return res.status(404).json({ error: 'channel_not_found' });

    let sourceInfo = ch.encryptedManifest ? decryptJSON(ch.encryptedManifest) : decryptJSON(ch.encryptedUrl);
    if (!sourceInfo) return res.status(500).json({ error: 'source_unavailable' });
    const sourceUrl = sourceInfo.manifestUri || sourceInfo.url;
    if (!sourceUrl) return res.status(500).json({ error: 'invalid_source' });

    const upstream = await fetch(sourceUrl, { method: 'GET', headers: { 'User-Agent': 'Mozilla/5.0 (Secure-IPTV)' }, redirect: 'follow' });
    res.status(upstream.status);
    const contentType = upstream.headers.get('content-type');
    if (contentType) res.setHeader('content-type', contentType);
    if (!upstream.body) return res.status(502).json({ error: 'empty_upstream_body' });
    upstream.body.pipe(res);
  } catch (err) {
    return res.status(401).json({ error: 'invalid_or_expired_play_token' });
  }
});

// -------------------------
// Health
// -------------------------
app.get('/health', (req, res) => res.json({ ok: true }));

// 404 fallback
app.use((req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(PORT, () => console.log(`Secure IPTV server listening on port ${PORT}`));
