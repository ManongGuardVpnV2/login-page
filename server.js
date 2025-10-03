import express from "express";
import crypto from "crypto";
import fs from "fs";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
app.use(express.json());

// Security middleware
app.use(helmet());

// ----- CONFIG -----
const TOKEN_DURATION = 60 * 60 * 1000;       // 1 hour tokens
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hour sessions
const CLEANUP_INTERVAL = 30 * 60 * 1000;     // every 30 minutes

// ----- STORAGE (in-memory) -----
// For production replace with Redis/DB
let tokens = {};   // token => expiry
let sessions = {}; // sessionId => { expiry, ip }
let usedTokens = new Set();

// ----- HELPERS -----
function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function now() {
  return Date.now();
}

function createToken() {
  const token = randomHex(8);
  const expiry = now() + TOKEN_DURATION;
  tokens[token] = expiry;
  return { token, expiry };
}

function validateToken(token) {
  if (!token) return false;
  if (!tokens[token]) return false;
  if (now() > tokens[token]) { delete tokens[token]; return false; }
  if (usedTokens.has(token)) return false;
  return true;
}

function useToken(token) {
  usedTokens.add(token);
  delete tokens[token];
}

function createSession(ip) {
  const sessionId = randomHex(16);
  const expiry = now() + SESSION_DURATION;
  sessions[sessionId] = { expiry, ip };
  return { sessionId, expiry };
}

function validateSession(sessionId, ip) {
  if (!sessionId) return false;
  const s = sessions[sessionId];
  if (!s) return false;
  if (now() > s.expiry) { delete sessions[sessionId]; return false; }
  // If stored ip exists and doesn't match current ip, reject
  if (s.ip && ip && s.ip !== ip) return false;
  return true;
}

function refreshSession(sessionId, ip) {
  if (!sessions[sessionId]) return false;
  // optional: ensure IP matches before refreshing
  if (sessions[sessionId].ip && ip && sessions[sessionId].ip !== ip) return false;
  sessions[sessionId].expiry = now() + SESSION_DURATION;
  return true;
}

function regenSession(oldSessionId, ip) {
  // invalidate old and create new session bound to ip
  if (oldSessionId && sessions[oldSessionId]) delete sessions[oldSessionId];
  return createSession(ip);
}

function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const m = cookies.split(";").map(c => c.trim()).find(c => c.startsWith(name + "="));
  return m ? m.split("=")[1] : null;
}

function getClientIp(req) {
  // X-Forwarded-For may be a comma list; use first
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || null;
}

// ----- CLEANUP -----
function cleanupExpired() {
  const tnow = now();
  for (const t in tokens) if (tokens[t] < tnow) delete tokens[t];
  for (const s in sessions) if (sessions[s].expiry < tnow) delete sessions[s];
  // prune usedTokens if token no longer in tokens (safe memory)
  usedTokens = new Set([...usedTokens].filter(t => t in tokens));
}
setInterval(cleanupExpired, CLEANUP_INTERVAL);

// ----- RATE LIMITING -----
const generateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 6,              // limit generation to 6 per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many token requests - slow down" }
});

const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: "Too many attempts - try again later" }
});

// ----- SECURITY HEADERS & HTTPS enforce -----
app.use((req, res, next) => {
  // Force HTTPS when behind a proxy (Render sets x-forwarded-proto)
  const proto = req.headers["x-forwarded-proto"];
  if (proto && proto !== "https") {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  // Prevent embedding
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");
  next();
});

// ----- API ROUTES -----
// Generate token (rate limited)
app.get("/generate-token", generateLimiter, (req, res) => {
  const { token, expiry } = createToken();
  // Do NOT echo token in server logs. Return to caller over HTTPS.
  res.json({ token, expiry });
});

// Validate token => create session (rate limited)
app.post("/validate-token", validateLimiter, (req, res) => {
  try {
    const { token } = req.body;
    if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    // Mark token used (single-use)
    useToken(token);

    const ip = getClientIp(req);
    const { sessionId, expiry } = createSession(ip);

    // Strong cookie: HttpOnly (not accessible by JS), Secure (HTTPS), SameSite=Strict
    // Note: Secure requires HTTPS (Render provides it). For local testing remove Secure if needed.
    res.setHeader("Set-Cookie",
      `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`
    );

    res.json({ success: true, expiry });
  } catch (err) {
    console.error("validate-token error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Refresh session (AJAX from client). Validate IP too.
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

// Check session (returns remaining expiry only). Bound to IP.
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

// ----- PROTECTED IPTV PAGE -----
// Serve your own ./public/myiptv.html and inject countdown.
// Also regenerate session on access to prevent replay.
app.get("/iptv", (req, res) => {
  try {
    const sessionId = getCookie(req, "sessionId");
    const ip = getClientIp(req);
    if (!sessionId || !validateSession(sessionId, ip)) return res.redirect("/");

    // Regenerate session (invalidation of old)
    const { sessionId: newSessionId, expiry } = regenSession(sessionId, ip);
    // Set new cookie
    res.setHeader("Set-Cookie",
      `sessionId=${newSessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`
    );

    // no-cache headers
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    // Read user's myiptv.html from public folder (absolute)
    const htmlPath = new URL("./public/myiptv.html", import.meta.url);
    let html = fs.readFileSync(htmlPath, "utf8");

    // Inject a secure countdown bar and client-side deterrence code
    html = html.replace("</body>", `
      <div id="countdownBar" style="height:40px;background:#0b5fff;color:white;display:flex;justify-content:center;align-items:center;font-family:monospace;font-weight:600;font-size:15px;position:fixed;bottom:0;left:0;right:0;z-index:99999;">
        Validating session...
      </div>
      <script>
        // Basic deterrents (not foolproof)
        try {
          document.addEventListener("contextmenu", e => e.preventDefault());
          document.addEventListener("keydown", function(e){
            if(e.keyCode === 123) e.preventDefault(); // F12
            if(e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) e.preventDefault(); // Ctrl+Shift+I/J
            if(e.ctrlKey && e.keyCode === 85) e.preventDefault(); // Ctrl+U
          });
        } catch(e) {}

        // Countdown logic uses server expiry (exact)
        (function(){
          let expiryTime = null;
          function startCountdown(){
            const el = document.getElementById("countdownBar");
            const iv = setInterval(()=>{
              if(!expiryTime) return;
              const now = Date.now();
              const diff = expiryTime - now;
              if(diff <= 0) {
                clearInterval(iv);
                alert("Session expired. Returning to login.");
                window.location.href = "/";
                return;
              }
              const h = Math.floor((diff/(1000*60*60))%24);
              const m = Math.floor((diff/(1000*60))%60);
              const s = Math.floor((diff/1000)%60);
              el.innerText = "Session expires in: " + h + "h " + m + "m " + s + "s";
            }, 1000);
          }

          async function init(){
            try {
              const r = await fetch('/check-session', { cache: 'no-store' });
              if(!r.ok) { window.location.href = '/'; return; }
              const j = await r.json();
              if(!j.success) { window.location.href = '/'; return; }
              expiryTime = j.expiry;
              startCountdown();
              // auto-refresh every 5 minutes
              setInterval(async ()=>{
                await fetch('/refresh-session', { method: 'POST', cache: 'no-store' });
              }, 5*60*1000);
            } catch(e) {
              console.error("session check failed", e);
              window.location.href = '/';
            }
          }
          init();
        })();
      </script>
    </body>`);

    res.send(html);
  } catch (err) {
    console.error("Error serving /iptv:", err);
    res.status(500).send("Internal Server Error");
  }
});

// ----- LOGIN PAGE -----
// Root and fallback routes (serves login UI)
app.get("*", (req, res) => {
  // Very minimal login UI; includes client-side deterrents and avoids printing token plainly
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
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
  // client deterrents
  try {
    document.addEventListener("contextmenu", e => e.preventDefault());
    document.addEventListener("keydown", function(e){
      if(e.keyCode === 123) e.preventDefault();
      if(e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) e.preventDefault();
      if(e.ctrlKey && e.keyCode === 85) e.preventDefault();
    });
  } catch(e) {}

  const msgEl = document.getElementById('msg');

  document.getElementById('generateBtn').addEventListener('click', async () => {
    try {
      const r = await fetch('/generate-token');
      const j = await r.json();
      if (j.token) {
        // copy to clipboard but do NOT display it plainly in UI
        await navigator.clipboard.writeText(j.token);
        msgEl.innerText = "Token copied to clipboard. Paste it into the field to login.";
        // optional: auto-clear clipboard after 30s (not reliable cross-browser)
        setTimeout(async ()=> {
          try { await navigator.clipboard.writeText(''); } catch(e) {}
        }, 30000);
      } else {
        msgEl.innerText = "Failed to generate token.";
      }
    } catch(e) {
      console.error(e);
      msgEl.innerText = "Error generating token.";
    }
  });

  document.getElementById('loginBtn').addEventListener('click', async () => {
    const token = document.getElementById('tokenInput').value?.trim();
    if(!token) { msgEl.innerText = "Paste your token to login."; return; }
    try {
      const r = await fetch('/validate-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const j = await r.json();
      if(j.success) {
        msgEl.innerText = "Login successful. Redirecting...";
        // safe redirect to protected page
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
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

// ----- START -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
