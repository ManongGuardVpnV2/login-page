// server.js — single-file, no external deps
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// Config
const TOKEN_DURATION = 60 * 60 * 1000;        // 1 hour
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // 30 minutes

// In-memory stores (single instance)
let tokens = {};    // token -> expiry
let sessions = {};  // sessionId -> expiry
let usedTokens = new Set();

// Helpers
const now = () => Date.now();

function createToken() {
  const token = crypto.randomBytes(8).toString("hex");
  tokens[token] = now() + TOKEN_DURATION;
  return { token, expiry: tokens[token] };
}

function validateToken(t) {
  return Boolean(t && tokens[t] && now() <= tokens[t] && !usedTokens.has(t));
}

function useToken(t) { usedTokens.add(t); delete tokens[t]; }

function createSession() {
  const id = crypto.randomBytes(16).toString("hex");
  sessions[id] = now() + SESSION_DURATION;
  return { sessionId: id, expiry: sessions[id] };
}

function validateSession(id) {
  return Boolean(id && sessions[id] && now() <= sessions[id]);
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
    if (!p) continue;
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx);
    const v = p.slice(idx + 1);
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

// Cleanup expired every interval
setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

// Utility: send JSON
function sendJSON(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

// Utility: serve static file (text/html or json)
function serveFile(res, filePath, contentType = "text/html") {
  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
    return;
  }
  const data = fs.readFileSync(filePath, "utf8");
  res.writeHead(200, { "Content-Type": contentType, "Cache-Control": "no-store" });
  res.end(data);
}

// Start server
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // GET /generate-token
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // POST /validate-token
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try {
        const { token } = JSON.parse(body || "{}");
        if (!validateToken(token)) return sendJSON(res, 400, { success: false, error: "Invalid or expired token" });
        useToken(token);
        const { sessionId, expiry } = createSession();
        // NOTE: no Secure flag so local http testing works. For production behind HTTPS you can add Secure flag.
        res.setHeader("Set-Cookie", `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`);
        return sendJSON(res, 200, { success: true, expiry });
      } catch (e) {
        return sendJSON(res, 500, { success: false, error: "Server error" });
      }
    });
    return;
  }

  // GET /check-session
  if (url.pathname === "/check-session" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false });
    return sendJSON(res, 200, { success: true, expiry: sessions[sid] });
  }

  // POST /refresh-session
  if (url.pathname === "/refresh-session" && method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 400, { success: false });
    refreshSession(sid);
    return sendJSON(res, 200, { success: true });
  }

  // GET /channels — protected JSON file (public/channels.json)
  if (url.pathname === "/channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Not authorized" });
    const channelsPath = path.join(__dirname, "public", "channels.json");
    if (!fs.existsSync(channelsPath)) return sendJSON(res, 404, { success: false, error: "Channels not found" });
    const raw = fs.readFileSync(channelsPath, "utf8");
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    return res.end(raw);
  }

  // GET /iptv — serve myiptv.html untouched except injected obfuscated protection script
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      // redirect to login
      res.writeHead(302, { Location: "/" });
      return res.end();
    }

    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    if (!fs.existsSync(htmlPath)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("myiptv.html not found");
    }

    let html = fs.readFileSync(htmlPath, "utf8");

    // injection: obfuscated compact script + bottom countdown bar
    // It will: verify session via /check-session, fetch /channels and call window.__onProtectedChannels(channels)
    const barId = "sbar_" + crypto.randomBytes(3).toString("hex");
    // obfuscated script (array technique) — compact and hard to read
    const obf = `
      (function(){
        try{
          var _=['getElementById','check-session','then','json','success','expiry','innerText','channels','fetch','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','replaceState','popstate'];
          try{ history[_[16]](null,'',location.pathname+location.search); window.addEventListener(_[17],function(){ location.href='/'; }); }catch(e){}
          var B=document[_[0]]('${barId}');
          var E=0;
          function v(){ return fetch('/'+_[1],{cache:'no-store'}).then(function(r){return r[_[2]]();}).catch(function(){return {success:false};}); }
          function s(){ setInterval(function(){ var n=Date.now(),d=E-n; if(!E||d<=0){ try{ alert('Session expired'); }catch(e){} location.href='/'; return; } var h=Math.floor((d/3600000)%24),m=Math.floor((d/60000)%60),ss=Math.floor((d/1000)%60); B[_[6]]='Session expires in: '+h+'h '+m+'m '+ss+'s'; },1000); }
          async function r(){ try{ await fetch('/'+_[9],{method:_[10]}); }catch(e){} }
          v().then(function(j){ if(!j[_[4]]){ location.href='/'; return; } E=j[_[5]]; s(); setInterval(r,5*60*1000);
            // fetch protected channels and hand to page
            fetch('/'+_[7],{cache:'no-store'}).then(function(r2){ return r2[_[2]](); }).then(function(ch){
              try{ if(window.__onProtectedChannels && typeof window.__onProtectedChannels==='function'){ window.__onProtectedChannels(ch); } else { window.protectedChannels = ch; } }catch(e){}
            }).catch(function(){});
          });
          // devtools detection via debugger timing
          setInterval(function(){ var t=Date.now(); debugger; if(Date.now()-t>200){ try{ alert('DevTools detected — returning to login'); }catch(e){} location.href='/'; } },1500);
          // keyboard/context blockers
          document.addEventListener(_[11],function(e){ e[_[14]](); });
          document.addEventListener(_[12],function(e){ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e[_[14]](); });
          if(window[_[13]]!==window[_[15]]){ try{ window.top.location = window.self.location; } catch(e){ location.href='/'; } }
          try{ Object.freeze(window); }catch(e){}
        }catch(err){ try{ console.error('injected err',err);}catch(e){} location.href='/'; }
      })();
    `;

    const injection = `
      <div id="${barId}" style="
        position:fixed;bottom:0;left:0;width:100%;height:44px;
        background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;
        display:flex;align-items:center;justify-content:center;
        font-family:monospace;font-weight:700;z-index:2147483647;
        box-shadow:0 -2px 8px rgba(0,0,0,0.25);
      ">Loading session...</div>
      <script>${obf}</script>
    `;

    // inject before </body>
    if (html.includes("</body>")) html = html.replace("</body>", injection + "</body>");
    else html += injection;

    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // Login page (root)
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<style>
body{font-family:sans-serif;background:#f0f0f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.15);width:340px;text-align:center}
input,button{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #ccc;box-sizing:border-box}
button{background:#007bff;color:#fff;border:none;cursor:pointer}
#msg{height:18px;margin-top:6px;font-size:0.95rem}
</style>
</head>
<body>
<div class="card">
  <h2>Access IPTV</h2>
  <button id="gen">Generate Token</button>
  <input id="token" type="password" placeholder="Paste token here">
  <button id="loginBtn">Login</button>
  <p id="msg"></p>
</div>
<script>
(async function(){
  const gen = document.getElementById('gen');
  const loginBtn = document.getElementById('loginBtn');
  const tokenInput = document.getElementById('token');
  const msg = document.getElementById('msg');

  gen.addEventListener('click', async ()=>{
    try{
      const r = await fetch('/generate-token');
      const j = await r.json();
      tokenInput.value = j.token || '';
      msg.style.color='green'; msg.textContent='Token generated';
      try{ await navigator.clipboard.writeText(j.token); }catch(e){}
    }catch(e){ msg.style.color='red'; msg.textContent='Error generating token'; }
  });

  loginBtn.addEventListener('click', async ()=>{
    const t = tokenInput.value.trim();
    if(!t){ msg.style.color='red'; msg.textContent='Paste token'; return; }
    try{
      const r = await fetch('/validate-token',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: t }) });
      const j = await r.json();
      if(j.success){ msg.style.color='green'; msg.textContent='Access granted — redirecting'; setTimeout(()=>location.href='/iptv',800); }
      else { msg.style.color='red'; msg.textContent = j.error || 'Invalid token'; }
    }catch(e){ msg.style.color='red'; msg.textContent='Server error'; }
  });

  // basic DevTools deterrents
  document.addEventListener('contextmenu', e=>e.preventDefault());
  document.addEventListener('keydown', e=>{
    if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
  });
})();
</script>
</body>
</html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(loginHtml);
  }

  // Allow static assets from /public by mapping /public/... or root-level file requests
  // For convenience, map requests that match a file under public
  const staticCandidate = path.join(__dirname, "public", url.pathname.replace(/^\/+/,''));
  if (fs.existsSync(staticCandidate) && fs.statSync(staticCandidate).isFile()) {
    const ext = path.extname(staticCandidate).toLowerCase();
    const mime = ext === ".css" ? "text/css" : ext === ".json" ? "application/json" : ext === ".js" ? "application/javascript" : "application/octet-stream";
    return serveFile(res, staticCandidate, mime);
  }

  // Not found
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
