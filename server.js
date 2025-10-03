// server.js (final, tested pattern)
// Single-file. No npm required. Uses form POST for login to guarantee Set-Cookie is stored.

import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// --- Config ---
const TOKEN_DURATION = 60 * 60 * 1000;       // 1 hour
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // 30 minutes

// --- In-memory stores (replace with Redis etc. for production) ---
let tokens = {};    // token -> expiry
let sessions = {};  // sessionId -> expiry
let usedTokens = new Set();

const channelsFile = path.join(__dirname, "public", "channels.json"); // optional protected file

// --- Helpers ---
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

// small helpers
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

  // ---------- generate-token (GET) ----------
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    console.log("[token] created", t.token, "exp:", new Date(t.expiry).toISOString());
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // ---------- validate-token (POST)
  // Accepts both form POST (application/x-www-form-urlencoded) and JSON fetch.
  // If form POST => redirect to /iptv (so cookie is accepted reliably).
  // If JSON fetch => return JSON (kept for compatibility).
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", (c) => body += c);
    req.on("end", () => {
      try {
        let token = null;
        const ct = (req.headers["content-type"] || "").split(";")[0];
        if (ct === "application/json") {
          const parsed = JSON.parse(body || "{}");
          token = parsed?.token;
        } else if (ct === "application/x-www-form-urlencoded") {
          const params = new URLSearchParams(body || "");
          token = params.get("token");
        } else {
          // try best-effort JSON
          try { token = JSON.parse(body || "{}").token; } catch(e) { }
        }

        if (!validateToken(token)) {
          // If form, redirect back with error message as query (simple)
          if (ct === "application/x-www-form-urlencoded") {
            res.writeHead(302, { "Location": "/?error=invalid" });
            return res.end();
          }
          return sendJSON(res, 400, { success: false, error: "Invalid or expired token" });
        }

        // consume token and create session
        useToken(token);
        const { sessionId, expiry } = createSession();

        // Set cookie. NOTE: no Secure flag so local http works. Add Secure in production with HTTPS.
        const cookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
        res.setHeader("Set-Cookie", cookie);
        console.log("[validate] set cookie:", sessionId.slice(0,8)+"...", "expiry:", new Date(expiry).toISOString());

        // If form POST, redirect to /iptv (browser will receive Set-Cookie and follow redirect)
        if (ct === "application/x-www-form-urlencoded") {
          res.writeHead(302, { "Location": "/iptv" });
          return res.end();
        }

        // Otherwise return JSON for AJAX flows (still works if client used fetch+credentials)
        return sendJSON(res, 200, { success: true, expiry });
      } catch (err) {
        console.error("[validate-token] error", err);
        return sendJSON(res, 500, { success: false, error: "Server error" });
      }
    });
    return;
  }

  // ---------- check-session (GET) ----------
  if (url.pathname === "/check-session" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    console.log("[check-session] cookie:", sid ? sid.slice(0,8)+"..." : null);
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false });
    return sendJSON(res, 200, { success: true, expiry: sessions[sid] });
  }

  // ---------- refresh-session (POST) ----------
  if (url.pathname === "/refresh-session" && method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 400, { success: false });
    refreshSession(sid);
    return sendJSON(res, 200, { success: true });
  }

  // ---------- channels (protected) ----------
  if (url.pathname === "/channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Unauthorized" });
    if (fs.existsSync(channelsFile)) return serveFile(res, channelsFile, "application/json");
    return sendJSON(res, 200, { success: true, channels: [] });
  }

  // ---------- iptv page (serves public/myiptv.html) ----------
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    console.log("[iptv] cookie:", sid ? sid.slice(0,8)+"..." : null);
    if (!validateSession(sid)) {
      res.writeHead(302, { "Location": "/" });
      return res.end();
    }

    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    if (!fs.existsSync(htmlPath)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("myiptv.html not found");
    }

    let html = fs.readFileSync(htmlPath, "utf8");
    const barId = "sbar_" + crypto.randomBytes(3).toString("hex");

    // obfuscated-ish injected script (array-key technique)
    const injected = `
<div id="${barId}" style="position:fixed;bottom:0;left:0;width:100%;height:44px;background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:center;font-family:monospace;font-weight:700;z-index:2147483647;box-shadow:0 -2px 8px rgba(0,0,0,0.25);">Loading session...</div>
<script>
(function(){
  try{
    var _=['getElementById','check-session','then','json','success','expiry','innerText','channels','fetch','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','replaceState','popstate','credentials','include'];
    var B=document[_[0]]('${barId}');
    var E=0;
    function chk(){ return fetch('/'+_[1],{cache:'no-store',[_[18]]:_[19]}).then(function(r){return r[_[2]]();}).catch(function(){return {success:false};}); }
    function tick(){ setInterval(function(){ var n=Date.now(), d=E-n; if(!E||d<=0){ try{ alert('Session expired'); }catch(e){} location.href='/'; return; } var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60); B[_[6]]='Session expires in: '+h+'h '+m+'m '+s+'s'; },1000); }
    async function keep(){ try{ await fetch('/'+_[9],{method:_[10],[_[18]]:_[19]}); }catch(e){} }
    chk().then(function(j){ if(!j[_[4]]){ location.href='/'; return; } E=j[_[5]]; tick(); setInterval(keep,5*60*1000);
      // load protected channels to window.protectedChannels (so your myiptv.html can use it)
      fetch('/'+_[7],{cache:'no-store',[_[18]]:_[19]}).then(function(r2){ return r2[_[2]](); }).then(function(ch){ try{ if(window.__onProtectedChannels && typeof window.__onProtectedChannels==='function'){ window.__onProtectedChannels(ch); } else { window.protectedChannels = ch; } }catch(e){} }).catch(function(){});
    });
    // detect devtools by debugger timing
    setInterval(function(){ var t=Date.now(); debugger; if(Date.now()-t>200){ try{ alert('DevTools detected — returning to login'); }catch(e){} location.href='/'; } },1500);
    document.addEventListener(_[11],function(e){ e[_[14]](); });
    document.addEventListener(_[12],function(e){ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e[_[14]](); });
    if(window[_[13]]!==window[_[15]]){ try{ window.top.location = window.self.location; }catch(e){ location.href='/'; } }
    try{ Object.freeze(window); }catch(e){}
  }catch(err){ try{ console.error('injected err',err);}catch(e){} location.href='/'; }
})();
</script>
`;

    if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
    else html += injected;

    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // ---------- login page ----------
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    const loginHtml = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<style>body{font-family:sans-serif;background:#f0f0f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0} .card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.15);width:360px;text-align:center} input,button{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #ccc;box-sizing:border-box} button{background:#007bff;color:#fff;border:none;cursor:pointer} #msg{height:18px;margin-top:6px}</style></head><body><div class="card"><h2>Access IPTV</h2>
  <button id="genBtn">Generate Token</button>
  <form id="loginForm" method="POST" action="/validate-token">
    <input id="token" name="token" type="password" placeholder="Paste token here" />
    <button id="submitBtn" type="submit">Login</button>
  </form>
  <p id="msg"></p>
</div>
<script>
document.getElementById('genBtn').addEventListener('click', async function(){
  try {
    const r = await fetch('/generate-token', { method: 'GET', credentials: 'include' });
    const j = await r.json();
    if (j.token) {
      document.getElementById('token').value = j.token;
      document.getElementById('msg').innerText = 'Token generated';
      try{ await navigator.clipboard.writeText(j.token); }catch(e){}
    } else document.getElementById('msg').innerText = 'Failed';
  } catch (e) { document.getElementById('msg').innerText = 'Error'; }
});
// small UX: focus input after generation
document.getElementById('token').addEventListener('keydown', function(e){
  if(e.key === 'Enter'){ e.preventDefault(); document.getElementById('loginForm').submit(); }
});
// block context menu & typical inspector shortcuts
document.addEventListener('contextmenu', e=>e.preventDefault());
document.addEventListener('keydown', e=>{
  if (e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault();
});
</script></body></html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(loginHtml);
  }

  // ---------- static files from public ----------
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
