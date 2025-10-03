// server.js (final — form-POST login + obfuscated injected script + protected channels)
// Drop this in project root next to /public/myiptv.html and (optionally) /public/channels.json
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
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // cleanup

// Stores (in-memory; use Redis for production)
let tokens = {};
let sessions = {};
let usedTokens = new Set();

// Optional protected channels json
const channelsFile = path.join(__dirname, "public", "channels.json");
const fallbackChannels = [{ name: "Sample", url: "http://example.com/1.m3u8" }];

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

// robust cookie parser
function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  const parts = raw.split(";").map(s => s.trim());
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx);
    const v = p.slice(idx + 1);
    if (k === name) return decodeURIComponent(v);
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

// Build obfuscated injected script as Base64 so it's hard to read in DevTools Sources
// The decoded script (client-side) does:
//  - fetch('/check-session', {credentials:'include'}) -> redirect to / if invalid
//  - refresh session periodically
//  - fetch('/channels') into window.protectedChannels
//  - show countdown bar at bottom
//  - detect devtools via debugger timing and deter common shortcuts
const clientScriptPlain = `(function(){
  try {
    var bar = document.getElementById('__SB__');
    if(!bar){ bar = document.createElement('div'); bar.id='__SB__'; bar.style.cssText='position:fixed;bottom:0;left:0;width:100%;height:40px;background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:center;font-family:monospace;font-weight:700;z-index:2147483647;box-shadow:0 -2px 8px rgba(0,0,0,0.25);'; document.body.appendChild(bar); }
    function kick(){ location.href='/'; }
    function api(u,o){ return fetch(u,o); }
    function check(){ return api('/check-session',{cache:'no-store',credentials:'include'}).then(r=>r.json()).catch(e=>({success:false})); }
    function refresh(){ return api('/refresh-session',{method:'POST',credentials:'include'}).catch(()=>{}); }
    function getChannels(){ return api('/channels',{cache:'no-store',credentials:'include'}).then(r=>r.json()).catch(()=>({})); }
    check().then(function(j){
      if(!j.success){ kick(); return; }
      var expiry=j.expiry;
      setInterval(refresh,5*60*1000);
      getChannels().then(function(ch){ if(ch) try{ window.__onProtectedChannels && typeof window.__onProtectedChannels==='function' ? window.__onProtectedChannels(ch) : window.protectedChannels = ch; }catch(e){} });
      setInterval(function(){
        var d=expiry-Date.now();
        if(d<=0){ try{ alert('Session expired'); }catch(e){} kick(); return; }
        var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60);
        bar.innerText='Session expires in: '+h+'h '+m+'m '+s+'s';
        bar.style.opacity = 0.9 + 0.1*Math.sin(Date.now()/1000);
      },1000);
    }).catch(kick);

    // DevTools deterrent: debugger timing
    setInterval(function(){
      var t=Date.now();
      debugger;
      if(Date.now()-t>200){ try{ alert('DevTools detected — returning to login'); }catch(e){} kick(); }
    },1500);

    document.addEventListener('contextmenu',function(e){ e.preventDefault(); });
    document.addEventListener('keydown',function(e){
      if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I' || e.key==='J' || e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
    });
    if(window.top !== window.self){ try{ window.top.location = window.self.location; }catch(e){ kick(); } }
    try{ Object.freeze(window); }catch(e){}
  } catch (err) { try{ console.error('injected',err); }catch(e){} location.href='/'; }
})();`;

// base64 encode clientScriptPlain and replace placeholder id when injecting
const clientScriptB64 = Buffer.from(clientScriptPlain).toString('base64');

// Server
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // generate-token
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    console.log("[token] created", t.token, "exp:", new Date(t.expiry).toISOString());
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // validate-token: accept form POST (x-www-form-urlencoded) and JSON fetch
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try {
        const ct = (req.headers['content-type'] || '').split(';')[0];
        let token = null;
        if (ct === 'application/json') {
          token = JSON.parse(body || "{}").token;
        } else if (ct === 'application/x-www-form-urlencoded') {
          const p = new URLSearchParams(body || "");
          token = p.get('token');
        } else {
          try { token = JSON.parse(body || "{}").token; } catch(e) {}
        }

        if (!validateToken(token)) {
          if (ct === 'application/x-www-form-urlencoded') {
            // Redirect back with simple error query (could be used for UI)
            res.writeHead(302, { Location: '/?error=invalid' });
            return res.end();
          }
          return sendJSON(res, 400, { success: false, error: "Invalid or expired token" });
        }

        useToken(token);
        const { sessionId, expiry } = createSession();
        // Set cookie (no Secure so local http works). Add Secure for HTTPS in prod.
        const cookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
        res.setHeader('Set-Cookie', cookie);
        console.log("[validate] session set", sessionId.slice(0,8)+"...", new Date(expiry).toISOString());

        if (ct === 'application/x-www-form-urlencoded') {
          // Redirect so browser accepts cookie and navigates to /iptv
          res.writeHead(302, { Location: '/iptv' });
          return res.end();
        }
        return sendJSON(res, 200, { success: true, expiry });
      } catch (err) {
        console.error("[validate] err", err);
        return sendJSON(res, 500, { success: false, error: "Server error" });
      }
    });
    return;
  }

  // check-session
  if (url.pathname === "/check-session" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false });
    return sendJSON(res, 200, { success: true, expiry: sessions[sid] });
  }

  // refresh-session
  if (url.pathname === "/refresh-session" && method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 400, { success: false });
    refreshSession(sid);
    return sendJSON(res, 200, { success: true });
  }

  // channels (protected)
  if (url.pathname === "/channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Unauthorized" });
    if (fs.existsSync(channelsFile)) return serveFile(res, channelsFile, "application/json");
    return sendJSON(res, 200, { success: true, channels: fallbackChannels });
  }

  // serve iptv with injected obfuscated script
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }

    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    if (!fs.existsSync(htmlPath)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("myiptv.html not found");
    }

    let html = fs.readFileSync(htmlPath, "utf8");
    // unique id for the bar so it doesn't collide
    const barId = "sbar_" + crypto.randomBytes(3).toString('hex');

    // build the client script by decoding base64 and replacing the placeholder id
    const clientScript = Buffer.from(clientScriptB64, 'base64').toString('utf8').replace(/__SB__/g, barId);
    // then base64 again so it's hard to see in Sources: we will decode in browser and eval via Function
    const finalB64 = Buffer.from(clientScript, 'utf8').toString('base64');

    const injection = `
<div id="${barId}" style="position:fixed;bottom:0;left:0;width:100%;height:40px;background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:center;font-family:monospace;font-weight:700;z-index:2147483647;box-shadow:0 -2px 8px rgba(0,0,0,0.25);">Loading session...</div>
<script>
(function(b64){
  try{
    var src = atob(b64);
    // run in isolated Function context
    (new Function(src))();
  }catch(e){
    try{ console.error('load err',e); }catch(e){}
    location.href='/';
  }
})("${finalB64}");
</script>
`;

    if (html.includes("</body>")) html = html.replace("</body>", injection + "</body>");
    else html += injection;

    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // login page (form POST + generate via fetch)
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    const loginHtml = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<style>body{font-family:sans-serif;background:#f0f0f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0} .card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.15);width:360px;text-align:center} input,button{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #ccc;box-sizing:border-box} button{background:#007bff;color:#fff;border:none;cursor:pointer} #msg{height:18px;margin-top:6px}</style></head><body>
<div class="card"><h2>Access IPTV</h2>
  <button id="genBtn" type="button">Generate Token</button>
  <form id="loginForm" method="POST" action="/validate-token">
    <input id="token" name="token" type="password" placeholder="Paste token here" />
    <button id="submitBtn" type="submit">Login</button>
  </form>
  <p id="msg"></p>
</div>
<script>
document.getElementById('genBtn').addEventListener('click', async function(){
  try{
    const r = await fetch('/generate-token', { method: 'GET', credentials: 'include' });
    const j = await r.json();
    if (j.token) {
      document.getElementById('token').value = j.token;
      document.getElementById('msg').innerText = 'Token generated';
      try{ await navigator.clipboard.writeText(j.token); }catch(e){}
    } else document.getElementById('msg').innerText = 'Failed';
  }catch(e){ document.getElementById('msg').innerText = 'Error'; }
});

// UX: pressing Enter in token submits form
document.getElementById('token').addEventListener('keydown', function(e){
  if(e.key === 'Enter'){ e.preventDefault(); document.getElementById('loginForm').submit(); }
});

// basic deterrents
document.addEventListener('contextmenu', e=>e.preventDefault());
document.addEventListener('keydown', e=>{
  if (e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
});
</script></body></html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(loginHtml);
  }

  // serve static files from public
  const candidate = path.join(__dirname, "public", url.pathname.replace(/^\/+/, ""));
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const ext = path.extname(candidate).toLowerCase();
    const map = { ".css": "text/css", ".js": "application/javascript", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml" };
    const mime = map[ext] || "application/octet-stream";
    return serveFile(res, candidate, mime);
  }

  // fallback 404
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
