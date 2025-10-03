// server.js
import express from "express";
import crypto from "crypto";
import fs from "fs";

const app = express();
app.use(express.json());

const TOKEN_DURATION = 60 * 60 * 1000; // 1 hour tokens
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours sessions
const CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 min cleanup

let tokens = {};   // token: expiry
let sessions = {}; // sessionId: expiry
let usedTokens = new Set();

// -------------------------
// Helper functions
// -------------------------
function createToken() {
  const token = crypto.randomBytes(8).toString("hex");
  const expiry = Date.now() + TOKEN_DURATION;
  tokens[token] = expiry;
  return { token, expiry };
}

function validateToken(token) {
  if (!token) return false;
  if (!tokens[token]) return false;
  if (Date.now() > tokens[token]) { delete tokens[token]; return false; }
  if (usedTokens.has(token)) return false;
  return true;
}

function useToken(token) {
  usedTokens.add(token);
  delete tokens[token];
}

function createSession(ip) {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + SESSION_DURATION;
  sessions[sessionId] = { expiry, ip };
  return { sessionId, expiry };
}

function validateSession(sessionId, ip) {
  const s = sessions[sessionId];
  if (!s) return false;
  if (Date.now() > s.expiry) { delete sessions[sessionId]; return false; }
  // if IP was bound at creation and doesn't match, reject
  if (s.ip && ip && s.ip !== ip) return false;
  return true;
}

function refreshSession(sessionId, ip) {
  if (!sessions[sessionId]) return false;
  if (sessions[sessionId].ip && ip && sessions[sessionId].ip !== ip) return false;
  sessions[sessionId].expiry = Date.now() + SESSION_DURATION;
  return true;
}

function regenSession(oldSessionId, ip) {
  if (oldSessionId && sessions[oldSessionId]) delete sessions[oldSessionId];
  return createSession(ip);
}

function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const match = cookies.split(";").find(c => c.trim().startsWith(name + "="));
  return match ? match.split("=")[1] : null;
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || null;
}

function cleanupExpired() {
  const now = Date.now();
  for (const t in tokens) if (tokens[t] < now) delete tokens[t];
  for (const s in sessions) if (sessions[s].expiry < now) delete sessions[s];
  usedTokens = new Set([...usedTokens].filter(t => t in tokens));
}
setInterval(cleanupExpired, CLEANUP_INTERVAL);

// -------------------------
// Security headers & CSP
// -------------------------
app.use((req, res, next) => {
  // Force HTTPS when behind a proxy (Render sets x-forwarded-proto to 'https')
  const proto = req.headers["x-forwarded-proto"];
  if (proto && proto !== "https" && process.env.NODE_ENV === "production") {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }

  // Security headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  // Content Security Policy: allow self only, allow tailwind CDN for the login UI (if used)
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; frame-ancestors 'none';");
  next();
});

// -------------------------
// API routes
// -------------------------
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  // We copy token to clipboard on client side; returning it over HTTPS is acceptable.
  res.json({ token, expiry });
});

app.post("/validate-token", (req, res) => {
  try {
    const { token } = req.body;
    if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    // single-use
    useToken(token);

    const ip = getClientIp(req);
    const { sessionId, expiry } = createSession(ip);

    // Strong cookie
    // Note: 'Secure' requires HTTPS (Render provides certs). For local testing, remove 'Secure'
    res.setHeader("Set-Cookie",
      `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`
    );

    res.json({ success: true, expiry });
  } catch (err) {
    console.error("validate-token error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/refresh-session", (req, res) => {
  try {
    const sessionId = getCookie(req, "sessionId");
    const ip = getClientIp(req);
    if (!sessionId || !validateSession(sessionId, ip)) return res.status(400).json({ success: false });
    const ok = refreshSession(sessionId, ip);
    if (!ok) return res.status(400).json({ success: false });
    res.json({ success: true });
  } catch (err) {
    console.error("refresh-session error:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/check-session", (req, res) => {
  try {
    const sessionId = getCookie(req, "sessionId");
    const ip = getClientIp(req);
    if (!sessionId || !validateSession(sessionId, ip)) return res.status(401).json({ success: false });
    const expiry = sessions[sessionId].expiry;
    res.json({ success: true, expiry });
  } catch (err) {
    console.error("check-session error:", err);
    res.status(500).json({ success: false });
  }
});

// -------------------------
// Protected IPTV page
// -------------------------
app.get("/iptv", (req, res) => {
  try {
    const sessionId = getCookie(req, "sessionId");
    const ip = getClientIp(req);
    if (!sessionId || !validateSession(sessionId, ip)) return res.redirect("/");

    // Regenerate session (prevent replay)
    const { sessionId: newSessionId, expiry } = regenSession(sessionId, ip);
    res.setHeader("Set-Cookie",
      `sessionId=${newSessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`
    );

    // No-cache headers
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    // Read user's IPTV HTML
    const htmlPath = new URL('./public/myiptv.html', import.meta.url);
    let html = fs.readFileSync(htmlPath, "utf8");

    // Inject countdown + anti-devtools script
    html = html.replace("</body>", `
      <div id="countdownBar" style="height:40px;background:#1E40AF;color:white;display:flex;justify-content:center;align-items:center;font-family:monospace;font-weight:bold;font-size:16px;position:fixed;bottom:0;left:0;right:0;z-index:9999;">Loading session...</div>
      <script>
        /* Anti-DevTools deterrents (not foolproof) */
        try{
          document.addEventListener("contextmenu", e => e.preventDefault());
          document.addEventListener("keydown", function(e){
            if(e.keyCode === 123) e.preventDefault(); // F12
            if(e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) e.preventDefault(); // Ctrl+Shift+I/J
            if(e.ctrlKey && e.keyCode === 85) e.preventDefault(); // Ctrl+U
          });
        }catch(e){}

        // DevTools detection using debugger timing probe
        (function(){
          var last = Date.now();
          setInterval(function(){
            var start = Date.now();
            debugger;
            var delta = Date.now() - start;
            if (delta > 200) {
              try { alert("DevTools detected. Returning to login."); } catch(e){}
              window.location.href = "/";
            }
          }, 1000);
        })();

        // Countdown (uses exact server expiry)
        let expiryTime;
        async function start() {
          try {
            const r = await fetch('/check-session', { cache: 'no-store' });
            if(!r.ok) { window.location.href = '/'; return; }
            const j = await r.json();
            if(!j.success) { window.location.href = '/'; return; }
            expiryTime = j.expiry;
            startCountdown();
            setInterval(async ()=>{ await fetch('/refresh-session', { method:'POST' }); }, 5*60*1000);
          } catch(e) { console.error(e); window.location.href='/'; }
        }
        function startCountdown(){
          const el = document.getElementById('countdownBar');
          setInterval(()=>{
            if(!expiryTime) return;
            const now = Date.now();
            const dist = expiryTime - now;
            if(dist <= 0){ alert('Session expired'); window.location.href='/'; return; }
            const h = Math.floor((dist/(1000*60*60))%24);
            const m = Math.floor((dist/(1000*60))%60);
            const s = Math.floor((dist/1000)%60);
            el.innerText = 'Session expires in: ' + h + 'h ' + m + 'm ' + s + 's';
          }, 1000);
        }
        start();
      </script>
    </body>`);

    res.send(html);
  } catch (err) {
    console.error("Error reading IPTV HTML:", err);
    res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});

// -------------------------
// Login page (root and fallback)
// -------------------------
app.get("*", (req, res) => {
  // Inline login UI with anti-devtools and token copy behavior
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure IPTV Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen flex items-center justify-center bg-gray-100">
  <div class="w-full max-w-md bg-white p-6 rounded-xl shadow">
    <h1 class="text-xl font-bold text-center mb-4">Access IPTV</h1>
    <div class="mb-4">
      <button id="generateBtn" class="w-full bg-green-600 text-white py-2 rounded">Generate Token (Copy)</button>
    </div>
    <div class="mb-2">
      <input id="tokenInput" type="password" placeholder="Paste token here" class="w-full border px-3 py-2 rounded" />
    </div>
    <div>
      <button id="loginBtn" class="w-full bg-blue-600 text-white py-2 rounded">Login</button>
    </div>
    <p id="msg" class="text-sm text-center mt-3 text-gray-600"></p>
  </div>

<script>
  /* Anti-DevTools deterrents (not foolproof) */
  try{
    document.addEventListener("contextmenu", e => e.preventDefault());
    document.addEventListener("keydown", function(e){
      if(e.keyCode === 123) e.preventDefault();
      if(e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) e.preventDefault();
      if(e.ctrlKey && e.keyCode === 85) e.preventDefault();
    });
  }catch(e){}

  // debugger probe
  setInterval(function(){
    var start = Date.now(); debugger; var delta = Date.now() - start;
    if(delta > 200){ try{ alert("DevTools detected. Reloading."); }catch(e){}; window.location.href = "/"; }
  }, 1000);

  const msgEl = document.getElementById('msg');

  document.getElementById('generateBtn').addEventListener('click', async () => {
    try {
      const r = await fetch('/generate-token', { method: 'GET', cache: 'no-store' });
      const j = await r.json();
      if (j.token) {
        // copy token to clipboard and do not display it on the page
        await navigator.clipboard.writeText(j.token);
        msgEl.innerText = "Token copied to clipboard. Paste it into the field to login.";
        // optionally wipe clipboard after 30s (best-effort)
        setTimeout(async ()=> { try{ await navigator.clipboard.writeText(''); } catch(e){} }, 30000);
      } else {
        msgEl.innerText = "Failed to generate token.";
      }
    } catch (e) {
      console.error(e);
      msgEl.innerText = "Error generating token.";
    }
  });

  document.getElementById('loginBtn').addEventListener('click', async () => {
    const token = document.getElementById('tokenInput').value?.trim();
    if(!token){ msgEl.innerText = "Paste your token to login."; return; }
    try {
      const r = await fetch('/validate-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const j = await r.json();
      if(j.success) {
        msgEl.innerText = "Login successful. Redirecting...";
        setTimeout(()=> { window.location.href = '/iptv'; }, 800);
      } else {
        msgEl.innerText = j.error || "Invalid token.";
      }
    } catch(e) {
      console.error(e);
      msgEl.innerText = "Server error.";
    }
  });
</script>
</body>
</html>`;

  // No-store cache header for login
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

// -------------------------
// Start
// -------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
