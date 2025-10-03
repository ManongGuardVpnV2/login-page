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

// --- Token & Session Settings ---
const TOKEN_DURATION = 60 * 60 * 1000; // 1 hour
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 min cleanup

let tokens = {};   // token: expiry
let sessions = {}; // sessionId: expiry
let usedTokens = new Set();

// --- Helpers ---
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

function useToken(token) { usedTokens.add(token); delete tokens[token]; }

function createSession() {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + SESSION_DURATION;
  sessions[sessionId] = expiry;
  return { sessionId, expiry };
}

function validateSession(sessionId) {
  if (!sessions[sessionId]) return false;
  if (Date.now() > sessions[sessionId]) { delete sessions[sessionId]; return false; }
  return true;
}

function refreshSession(sessionId) {
  if (!sessions[sessionId]) return false;
  sessions[sessionId] = Date.now() + SESSION_DURATION;
  return true;
}

function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const match = cookies.split(";").find(c => c.trim().startsWith(name + "="));
  return match ? match.split("=")[1] : null;
}

function cleanupExpired() {
  const now = Date.now();
  for (const t in tokens) if (tokens[t] < now) delete tokens[t];
  for (const s in sessions) if (sessions[s] < now) delete sessions[s];
  usedTokens = new Set([...usedTokens].filter(t => t in tokens));
}
setInterval(cleanupExpired, CLEANUP_INTERVAL);

// --- API Routes ---
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

app.post("/validate-token", (req, res) => {
  const { token } = req.body || {};
  if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

  useToken(token);
  const { sessionId, expiry } = createSession();

  // Strong cookie: HttpOnly; Secure (requires HTTPS); SameSite=Strict
  res.setHeader("Set-Cookie",
    `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`
  );

  res.json({ success: true, expiry });
});

app.post("/refresh-session", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.status(400).json({ success: false });
  refreshSession(sessionId);
  res.json({ success: true });
});

app.get("/check-session", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.status(401).json({ success: false });
  const expiry = sessions[sessionId];
  res.json({ success: true, expiry });
});

// --- Serve IPTV HTML with obfuscated countdown + DevTools deterrent injected ---
// Note: this injects only the bar + a compact obfuscated script. Your myiptv.html (and its JSON) remain untouched.
app.get("/iptv", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.redirect("/");

  try {
    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");

    // Randomized id to make targeting harder
    const countdownId = "sc_" + crypto.randomBytes(4).toString("hex");

    // Compact obfuscated script (keeps functionality but is hard to read in DevTools)
    // - fetch /check-session to get expiry
    // - start countdown
    // - refresh session periodically
    // - devtools detection (debugger timing) -> redirect
    // - disable right-click and common shortcuts
    const script = `
      (function(){
        try{
          var _0=['getElementById','check-session','then','json','success','expiry','innerText','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','freeze'];
          var B=document[_0[0]]('${countdownId}');
          var E;
          function g(){return fetch('/'+_0[1]).then(function(r){return r[_0[2]]();}).catch(function(){return {success:false};});}
          function s(){setInterval(function(){var n=Date.now(),d=E-n;if(!E||d<=0){try{alert('Session expired');}catch(e){}location.href='/';return;}var h=Math.floor((d/3600000)%24),m=Math.floor((d/60000)%60),s=Math.floor((d/1000)%60);B[_0[6]]='Session expires in: '+h+'h '+m+'m '+s+'s';},1000);}
          async function r(){await fetch('/'+_0[7],{method:_0[8]});}
          g().then(function(j){if(!j[_0[4]]){location.href='/';return;}E=j[_0[5]];s();setInterval(r,5*60*1000);});
          // devtools detection
          setInterval(function(){var t=Date.now();debugger; if(Date.now()-t>200){try{alert('DevTools detected — returning to login');}catch(e){}location.href='/';}},1500);
          document.addEventListener(_0[9],function(e){e[_0[13]]();});
          document.addEventListener(_0[10],function(e){if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U'))e[_0[13]]();});
          if(window[_0[11]]!==window[_0[12]]){try{window.top.location=window.self.location;}catch(e){location.href='/';}}
          try{Object[_0[14]](window);}catch(e){}
        }catch(err){console.error('injected err',err);location.href='/';}
      })();
    `;

    const injected = `
      <div id="${countdownId}" style="
        position:fixed;
        bottom:0;
        left:0;
        width:100%;
        height:44px;
        background:linear-gradient(90deg,#0b5fff,#3b82f6);
        color:#fff;
        display:flex;
        align-items:center;
        justify-content:center;
        font-family:monospace;
        font-weight:700;
        z-index:2147483647;
        box-shadow:0 -2px 8px rgba(0,0,0,0.2);
        transition: transform 0.35s ease;">
        Loading session...
      </div>
      <script>${script}</script>
    `;

    // inject right before closing </body> (if exists)
    if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
    else html = html + injected;

    // send untouched else injected html
    res.setHeader("Cache-Control", "no-store");
    res.send(html);
  } catch (err) {
    console.error("Error reading IPTV HTML:", err);
    res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});

// --- Login Page (root/fallback) ---
app.get("*", (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secure IPTV Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen flex items-center justify-center bg-gray-100">
  <div class="w-full max-w-md bg-white p-6 rounded shadow">
    <h1 class="text-xl font-bold mb-4 text-center">Access IPTV</h1>
    <div class="mb-4">
      <button id="gbtn" class="w-full bg-green-600 text-white py-2 rounded">Generate Token</button>
    </div>
    <div class="mb-3">
      <input id="t" type="password" placeholder="Paste token" class="w-full border px-3 py-2 rounded"/>
    </div>
    <div>
      <button id="lbtn" class="w-full bg-blue-600 text-white py-2 rounded">Login</button>
    </div>
    <p id="m" class="text-sm mt-3 text-center text-gray-600"></p>
  </div>

  <script>
  (function(){
    const g=document.getElementById('gbtn'), l=document.getElementById('lbtn'), m=document.getElementById('m');
    g.onclick=async()=>{ try { const r=await fetch('/generate-token'); const j=await r.json(); if(j.token){ try{ await navigator.clipboard.writeText(j.token);}catch(e){} m.innerText='Token copied to clipboard.'; } else m.innerText='Failed to generate'; } catch(e){ m.innerText='Error'; } };
    l.onclick=async()=>{ const token=document.getElementById('t').value.trim(); if(!token){ m.innerText='Paste token'; return; } try{ const r=await fetch('/validate-token',{ method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token}) }); const j=await r.json(); if(j.success){ m.innerText='Logged in — redirecting'; setTimeout(()=>location.href='/iptv',800); } else m.innerText = j.error || 'Invalid token'; }catch(e){ m.innerText='Server error'; } };
  })();
  </script>
</body>
</html>`;
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
