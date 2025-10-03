// server.js
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// --- Config ---
const TOKEN_DURATION = 60 * 60 * 1000;       // 1 hour token
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hour session
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // 30 min cleanup

// --- Stores ---
let tokens = {};    // token -> expiry
let sessions = {};  // sessionId -> expiry
let usedTokens = new Set();

// --- Helpers ---
function now() { return Date.now(); }

function createToken() {
  const token = crypto.randomBytes(8).toString("hex");
  tokens[token] = now() + TOKEN_DURATION;
  return { token, expiry: tokens[token] };
}

function validateToken(t) {
  return t && tokens[t] && now() <= tokens[t] && !usedTokens.has(t);
}

function useToken(t) { usedTokens.add(t); delete tokens[t]; }

function createSession() {
  const id = crypto.randomBytes(16).toString("hex");
  sessions[id] = now() + SESSION_DURATION;
  return { sessionId: id, expiry: sessions[id] };
}

function validateSession(id) {
  return id && sessions[id] && now() <= sessions[id];
}

function refreshSession(id) {
  if (!validateSession(id)) return false;
  sessions[id] = now() + SESSION_DURATION;
  return true;
}

function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  const parts = raw.split(";").map(s => s.trim());
  for (const p of parts) {
    const [k, ...v] = p.split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

// Cleanup expired
setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

// --- Server ---
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // --- API Routes ---
  if (url.pathname === "/generate-token" && req.method === "GET") {
    const t = createToken();
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ token: t.token, expiry: t.expiry }));
  }

  if (url.pathname === "/validate-token" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const { token } = JSON.parse(body || "{}");
        if (!validateToken(token)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "Invalid or expired token" }));
        }
        useToken(token);
        const { sessionId, expiry } = createSession();
        // Set cookie with HttpOnly, SameSite=Lax
        res.setHeader("Set-Cookie", `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`);
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, expiry }));
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: "Server error" }));
      }
    });
    return;
  }

  if (url.pathname === "/check-session" && req.method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ success: false }));
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: true, expiry: sessions[sid] }));
  }

  if (url.pathname === "/refresh-session" && req.method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ success: false }));
    }
    refreshSession(sid);
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: true }));
  }

  // --- Serve IPTV Page ---
  if (url.pathname === "/iptv") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      res.writeHead(302, { "Location": "/" });
      return res.end();
    }
    try {
      const htmlPath = path.join(__dirname, "public", "myiptv.html");
      let html = fs.readFileSync(htmlPath, "utf8");
      const countdownId = "sessionCountdown_" + crypto.randomBytes(4).toString("hex");

      const injected = `
        <div id="${countdownId}" style="
          position:fixed;bottom:0;left:0;width:100%;height:44px;
          background:linear-gradient(90deg,#1E40AF,#3B82F6);color:white;
          display:flex;align-items:center;justify-content:center;
          font-family:monospace;font-weight:bold;z-index:2147483647;
          box-shadow:0 -2px 8px rgba(0,0,0,0.2);
        ">Loading session...</div>
        <script>
        (function(){
          var bar=document.getElementById("${countdownId}");
          var expiry=0;
          function goLogin(){ location.href='/'; }

          fetch('/check-session',{cache:'no-store', credentials:'include'})
            .then(r=>r.json())
            .then(j=>{
              if(!j.success){ goLogin(); return; }
              expiry=j.expiry;
              setInterval(()=>{ fetch('/refresh-session',{method:'POST', credentials:'include'}).catch(()=>{}); },5*60*1000);
              setInterval(()=>{
                var d=expiry-Date.now();
                if(d<=0){ alert('Session expired'); goLogin(); return; }
                var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60);
                bar.innerText='Session expires in: '+h+'h '+m+'m '+s+'s';
              },1000);
            })
            .catch(goLogin);

          // DevTools deterrents
          document.addEventListener('contextmenu', e=>e.preventDefault());
          document.addEventListener('keydown', e=>{
            if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U')) e.preventDefault();
          });
          if(window.top!==window.self){ window.top.location=window.self.location; }
          try{ Object.freeze(window); } catch(e){}
        })();
        </script>
      `;

      html = html.replace("</body>", injected + "</body>");
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
      return res.end(html);
    } catch {
      res.writeHead(500, { "Content-Type": "text/plain" });
      return res.end("Internal Server Error: cannot load IPTV page.");
    }
  }

  // --- Login Page ---
  const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>IPTV Login</title>
<style>
body{font-family:sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh}
.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.2);width:300px;text-align:center}
input,button{width:100%;padding:10px;margin:5px 0;border-radius:8px;border:1px solid #ccc}
button{background:#007bff;color:#fff;border:none;cursor:pointer}
</style></head>
<body>
<div class="card">
<h2>Access IPTV</h2>
<button id="gen">Generate Token</button>
<input type="password" id="token" placeholder="Paste token"/>
<button id="login">Login</button>
<p id="msg" style="color:red;"></p>
</div>
<script>
(function(){
const gen=document.getElementById('gen'), loginBtn=document.getElementById('login'), msg=document.getElementById('msg'), tokenInput=document.getElementById('token');
gen.onclick=async()=>{
  try{
    const res=await fetch('/generate-token');
    const j=await res.json();
    tokenInput.value=j.token;
    msg.style.color='green'; msg.innerText='Token generated!';
  }catch(e){ msg.style.color='red'; msg.innerText='Error generating token'; }
};
loginBtn.onclick=async()=>{
  const t=tokenInput.value.trim();
  if(!t){ msg.innerText='Paste token'; return; }
  try{
    const res=await fetch('/validate-token',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:t}),
      credentials:'include'
    });
    const j=await res.json();
    if(j.success){ msg.style.color='green'; msg.innerText='Access granted! Redirecting...'; setTimeout(()=>location.href='/iptv',800); }
    else{ msg.style.color='red'; msg.innerText=j.error||'Invalid token'; }
  }catch(e){ msg.style.color='red'; msg.innerText='Server error'; }
};
})();
</script>
</body>
</html>`;

  res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
  return res.end(loginHTML);
});

server.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
