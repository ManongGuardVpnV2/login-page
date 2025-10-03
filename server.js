// server.js
import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // serve static files

// --- Config ---
const TOKEN_DURATION = 60 * 60 * 1000;       // 1 hour tokens
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hour sessions
const CLEANUP_INTERVAL = 30 * 60 * 1000;     // cleanup interval

// --- In-memory stores (replace with Redis for production) ---
let tokens = {};   // token -> expiry
let sessions = {}; // sessionId -> expiry
let usedTokens = new Set();

// --- Helpers ---
function now() { return Date.now(); }

function createToken() {
  const token = crypto.randomBytes(8).toString("hex");
  tokens[token] = now() + TOKEN_DURATION;
  return { token, expiry: tokens[token] };
}

function validateToken(t) {
  if (!t) return false;
  if (!tokens[t]) return false;
  if (now() > tokens[t]) { delete tokens[t]; return false; }
  if (usedTokens.has(t)) return false;
  return true;
}

function useToken(t) { usedTokens.add(t); delete tokens[t]; }

function createSession() {
  const id = crypto.randomBytes(16).toString("hex");
  sessions[id] = now() + SESSION_DURATION;
  return { sessionId: id, expiry: sessions[id] };
}

function validateSession(id) {
  if (!id) return false;
  if (!sessions[id]) return false;
  if (now() > sessions[id]) { delete sessions[id]; return false; }
  return true;
}

function refreshSession(id) {
  if (!sessions[id]) return false;
  sessions[id] = now() + SESSION_DURATION;
  return true;
}

// robust cookie parser (handles URL-encoded cookies)
function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  const parts = raw.split(";").map(s => s.trim());
  for (const p of parts) {
    if (!p) continue;
    const [k, ...v] = p.split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

// cleanup expired periodically
setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

// ---------------- Routes ----------------

// generate-token (GET)
app.get("/generate-token", (req, res) => {
  const t = createToken();
  res.json({ token: t.token, expiry: t.expiry });
});

// validate-token (POST)
app.post("/validate-token", (req, res) => {
  try {
    const { token } = req.body || {};
    if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    useToken(token);
    const { sessionId, expiry } = createSession();

    // Determine if cookie should be Secure (only if request is secure or in production)
    const isSecureRequest = (req.secure === true) || (req.headers["x-forwarded-proto"] === "https") || (process.env.NODE_ENV === "production");
    const secureFlag = isSecureRequest ? "Secure; " : "";

    // Use SameSite=Lax so top-level navigation after POST/redirect works reliably
    // HttpOnly protects from JS reading cookie.
    const cookieValue = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; ${secureFlag}SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
    res.setHeader("Set-Cookie", cookieValue);

    // Helpful debug header (remove in production)
    // res.setHeader("X-Debug-Set-Cookie", cookieValue);

    res.json({ success: true, expiry });
  } catch (err) {
    console.error("validate-token error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// refresh-session (POST)
app.post("/refresh-session", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.status(400).json({ success: false });
  refreshSession(sid);
  res.json({ success: true });
});

// check-session (GET)
app.get("/check-session", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.status(401).json({ success: false });
  res.json({ success: true, expiry: sessions[sid] });
});

// Serve IPTV page (untouched) but inject only the countdown + deterrents
app.get("/iptv", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.redirect("/");

  try {
    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");
    const countdownId = "sessionCountdown_" + crypto.randomBytes(4).toString("hex");

    // Injection: visual bar + small script (keeps JSON inside myiptv.html intact)
    const injected = `
      <div id="${countdownId}" style="
        position:fixed;bottom:0;left:0;width:100%;height:44px;
        background:linear-gradient(90deg,#1E40AF,#3B82F6);color:white;
        display:flex;align-items:center;justify-content:center;
        font-family:monospace;font-weight:bold;z-index:2147483647;box-shadow:0 -2px 8px rgba(0,0,0,0.2);
      ">Loading session...</div>
      <script>
      (function(){
        try{
          var bar=document.getElementById("${countdownId}");
          var expiry=0;
          function goLogin(){ try{ location.href='/'; } catch(e){} }
          fetch('/check-session',{cache:'no-store'}).then(r=>r.json()).then(function(j){
            if(!j.success){ goLogin(); return; }
            expiry=j.expiry;
            start();
            setInterval(function(){ fetch('/refresh-session',{method:'POST'}).catch(()=>{}); },5*60*1000);
          }).catch(function(){ goLogin(); });

          function start(){
            setInterval(function(){
              var now=Date.now(), d=expiry-now;
              if(!expiry || d<=0){ try{ alert('Session expired'); }catch(e){} goLogin(); return; }
              var h=Math.floor((d/(1000*60*60))%24), m=Math.floor((d/(1000*60))%60), s=Math.floor((d/1000)%60);
              bar.innerText = 'Session expires in: ' + h + 'h ' + m + 'm ' + s + 's';
            },1000);
          }

          // Basic DevTools deterrents
          document.addEventListener('contextmenu', function(e){ e.preventDefault(); });
          document.addEventListener('keydown', function(e){
            if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I' || e.key==='J' || e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
          });

          // Prevent iframe embedding
          if(window.top !== window.self){ try{ window.top.location = window.self.location; } catch(e){ goLogin(); } }

          try{ Object.freeze(window); } catch(e){}
        }catch(err){
          console.error('injected script error', err);
          goLogin();
        }
      })();
      </script>
    `;

    if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
    else html = html + injected;

    // ensure no caching
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    res.send(html);
  } catch (err) {
    console.error("Error serving IPTV:", err);
    res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});

// Login / fallback page
app.get("*", (req, res) => {
  const nonce = crypto.randomBytes(6).toString("hex");
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen flex items-center justify-center bg-gray-100"><div class="w-full max-w-md bg-white p-6 rounded shadow"><h1 class="text-xl font-bold mb-4 text-center">Access IPTV</h1><div class="mb-4"><button id="gbtn" class="w-full bg-green-600 text-white py-2 rounded">Generate Token</button></div><div class="mb-3"><input id="t" type="password" placeholder="Paste token" class="w-full border px-3 py-2 rounded"/></div><div><button id="lbtn" class="w-full bg-blue-600 text-white py-2 rounded">Login</button></div><p id="m" class="text-sm mt-3 text-center text-gray-600"></p></div><script>(function(){const g=document.getElementById('gbtn'),l=document.getElementById('lbtn'),m=document.getElementById('m');g.onclick=async()=>{try{const r=await fetch('/generate-token');const j=await r.json();if(j.token){try{await navigator.clipboard.writeText(j.token);}catch(e){}m.innerText='Token copied to clipboard';}else m.innerText='Failed';}catch(e){m.innerText='Error';}};l.onclick=async()=>{const token=document.getElementById('t').value.trim();if(!token){m.innerText='Paste token';return;}try{const r=await fetch('/validate-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const j=await r.json();if(j.success){m.innerText='Logged in — redirecting';setTimeout(()=>location.href='/iptv',900);}else{m.innerText=j.error||'Invalid token';}}catch(e){m.innerText='Server error';}}})();</script></body></html>`;
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
