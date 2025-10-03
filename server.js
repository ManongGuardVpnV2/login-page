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
const TOKEN_DURATION = 60 * 60 * 1000;       // 1h token
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24h session
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // 30 min cleanup

// --- Stores ---
let tokens = {};    // token -> expiry
let sessions = {};  // sessionId -> expiry
let usedTokens = new Set();

// Optional channels file (protected)
const channelsFile = path.join(__dirname, "public", "channels.json");

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

// robust cookie parser
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

// cleanup expired tokens/sessions
setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

// helpers
function sendJSON(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}
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

// --- Server ---
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // generate token
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    console.log("[token] created", t.token, "exp:", new Date(t.expiry).toISOString());
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // validate token -> create session
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const { token } = JSON.parse(body || "{}");
        if (!validateToken(token)) {
          console.log("[validate-token] invalid token attempt");
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "Invalid or expired token" }));
        }
        useToken(token);
        const { sessionId, expiry } = createSession();
        // cookie: no Secure so local HTTP testing works. Add Secure in production (HTTPS).
        const cookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
        res.setHeader("Set-Cookie", cookie);
        console.log("[validate-token] set cookie sessionId=", sessionId.slice(0,8)+"...", "expiry:", new Date(expiry).toISOString());
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, expiry }));
      } catch (e) {
        console.error("[validate-token] error", e);
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: "Server error" }));
      }
    });
    return;
  }

  // check session
  if (url.pathname === "/check-session" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    console.log("[check-session] cookie:", sid ? sid.slice(0,8)+"..." : null);
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false });
    return sendJSON(res, 200, { success: true, expiry: sessions[sid] });
  }

  // refresh session
  if (url.pathname === "/refresh-session" && method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 400, { success: false });
    refreshSession(sid);
    return sendJSON(res, 200, { success: true });
  }

  // protected channels endpoint (serves public/channels.json only if session valid)
  if (url.pathname === "/channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Unauthorized" });
    if (fs.existsSync(channelsFile)) return serveFile(res, channelsFile, "application/json");
    // if no file, return empty
    return sendJSON(res, 200, { success: true, channels: [] });
  }

  // serve iptv and inject obfuscated countdown + protections
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    console.log("[iptv] cookie:", sid ? sid.slice(0,8)+"..." : null);
    if (!validateSession(sid)) {
      res.writeHead(302, { "Location": "/" });
      return res.end();
    }

    try {
      const htmlPath = path.join(__dirname, "public", "myiptv.html");
      if (!fs.existsSync(htmlPath)) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("myiptv.html not found");
      }
      let html = fs.readFileSync(htmlPath, "utf8");
      const countdownId = "sessionCountdown_" + crypto.randomBytes(4).toString("hex");

      // Obfuscated injected script (array-key technique)
      const injected = `
<div id="${countdownId}" style="
  position:fixed;bottom:0;left:0;width:100%;height:44px;
  background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;
  display:flex;align-items:center;justify-content:center;
  font-family:monospace;font-weight:700;z-index:2147483647;
  box-shadow:0 -2px 8px rgba(0,0,0,0.25);
">Loading session...</div>
<script>
(function(){
  try{
    var _=['getElementById','check-session','then','json','success','expiry','innerText','channels','fetch','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','replaceState','popstate','credentials','include','slice','alert'];
    try{ history[_[15]](null,'',location.pathname+location.search); window.addEventListener(_[16],function(){ location.href='/'; }); }catch(e){}
    var B=document[_[0]]('${countdownId}');
    var E=0;
    function chk(){ return fetch('/'+_[1],{cache:'no-store',[_[18]]:_[19]}).then(function(r){return r[_[2]]();}).catch(function(){return {success:false};}); }
    function tick(){ setInterval(function(){ var n=Date.now(), d=E-n; if(!E||d<=0){ try{ window[_[20]]('Session expired'); }catch(e){} location.href='/'; return; } var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60); B[_[6]]='Session expires in: '+h+'h '+m+'m '+s+'s'; },1000); }
    async function keep(){ try{ await fetch('/'+_[9],{method:_[10],[_[18]]:_[19]}); }catch(e){} }
    chk().then(function(j){ if(!j[_[4]]){ location.href='/'; return; } E=j[_[5]]; tick(); setInterval(keep,5*60*1000);
      // load protected channels into page variable (if page uses it)
      fetch('/'+_[7],{cache:'no-store',[_[18]]:_[19]}).then(function(r2){ return r2[_[2]](); }).then(function(ch){ try{ if(window.__onProtectedChannels && typeof window.__onProtectedChannels==='function'){ window.__onProtectedChannels(ch); } else { window.protectedChannels = ch; } }catch(e){} }).catch(function(){});
    });
    // detect devtools via debugger timing
    setInterval(function(){ var t=Date.now(); debugger; if(Date.now()-t>200){ try{ window[_[20]]('DevTools detected — returning to login'); }catch(e){} location.href='/'; } },1500);
    // prevent common shortcuts & right-click
    document.addEventListener(_[11],function(e){ e[_[14]](); });
    document.addEventListener(_[12],function(e){ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e[_[14]](); });
    if(window[_[13]]!==window[_[14]]){ try{ window.top.location = window.self.location; }catch(e){ location.href='/'; } }
    try{ Object.freeze(window); }catch(e){}
  }catch(err){ try{ console.error('injected err',err);}catch(e){} location.href='/'; }
})();
</script>
`;

      if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
      else html += injected;

      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
      return res.end(html);
    } catch (err) {
      console.error("[iptv] error", err);
      res.writeHead(500, { "Content-Type": "text/plain" });
      return res.end("Internal Server Error: cannot load IPTV page.");
    }
  }

  // login page (serves generate + validate with credentials:'include')
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>IPTV Login</title>
<style>
body{font-family:sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh}
.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.2);width:320px;text-align:center}
input,button{width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #ccc;box-sizing:border-box}
button{background:#007bff;color:#fff;border:none;cursor:pointer}
#msg{height:18px;margin-top:6px}
</style>
</head>
<body>
<div class="card">
  <h2>Access IPTV</h2>
  <button id="genBtn">Generate Token</button>
  <input id="token" type="password" placeholder="Paste token here">
  <button id="loginBtn">Login</button>
  <p id="msg"></p>
</div>
<script>
document.getElementById('genBtn').onclick=async()=>{
  try{
    const r = await fetch('/generate-token', { method: 'GET', credentials: 'include' });
    const j = await r.json();
    if (j.token) {
      document.getElementById('token').value = j.token;
      document.getElementById('msg').innerText = 'Token generated';
      try{ await navigator.clipboard.writeText(j.token); }catch(e){}
    } else document.getElementById('msg').innerText = 'Failed';
  }catch(e){ document.getElementById('msg').innerText = 'Error'; }
};

document.getElementById('loginBtn').onclick=async()=>{
  const t = document.getElementById('token').value.trim();
  if(!t){ document.getElementById('msg').innerText = 'Enter token'; return; }
  try{
    const r = await fetch('/validate-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: t }),
      credentials: 'include'
    });
    const j = await r.json();
    if (j.success) { document.getElementById('msg').innerText = 'Access granted'; setTimeout(()=>location.href='/iptv',600); }
    else { document.getElementById('msg').innerText = j.error || 'Invalid token'; }
  }catch(e){ document.getElementById('msg').innerText = 'Server error'; }
};

// block some shortcuts
document.addEventListener('contextmenu', e=>e.preventDefault());
document.addEventListener('keydown', e=>{
  if (e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
});
</script>
</body>
</html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // static files from public
  const candidate = path.join(__dirname, "public", url.pathname.replace(/^\/+/, ""));
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const ext = path.extname(candidate).toLowerCase();
    const map = { ".css": "text/css", ".js": "application/javascript", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml" };
    const mime = map[ext] || "application/octet-stream";
    return serveFile(res, candidate, mime);
  }

  // 404
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
