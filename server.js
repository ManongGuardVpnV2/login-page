// server.js
// Protected channels file is stored outside /public in ./data/channels.json
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// Config
const TOKEN_DURATION = 60 * 60 * 1000;
const SESSION_DURATION = 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL = 30 * 60 * 1000;

let tokens = {};
let sessions = {};
let usedTokens = new Set();

// NOTE: channelsFile is outside public to avoid direct static serving.
const channelsFile = path.join(__dirname, "data", "channels.json");

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

setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

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

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // generate-token
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // validate-token
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try {
        const ct = (req.headers['content-type'] || "").split(";")[0];
        let token = null;
        if (ct === "application/json") token = JSON.parse(body || "{}").token;
        else if (ct === "application/x-www-form-urlencoded") token = new URLSearchParams(body || "").get("token");
        else {
          try { token = JSON.parse(body || "{}").token; } catch(e){}
        }

        if (!validateToken(token)) {
          if (ct === "application/x-www-form-urlencoded") {
            res.writeHead(302, { "Location": "/?error=invalid" });
            return res.end();
          }
          return sendJSON(res, 400, { success: false, error: "Invalid or expired token" });
        }

        useToken(token);
        const { sessionId, expiry } = createSession();
        const cookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
        res.setHeader("Set-Cookie", cookie);

        if (ct === "application/x-www-form-urlencoded") {
          res.writeHead(302, { "Location": "/iptv" });
          return res.end();
        }
        return sendJSON(res, 200, { success: true, expiry });
      } catch (err) {
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

  // protected channels endpoint (reads from data/channels.json)
  if (url.pathname === "/channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Unauthorized" });
    if (!fs.existsSync(channelsFile)) return sendJSON(res, 200, { success: true, channels: [] });
    // read and return file contents (no directory listing / direct URL exposure since file is outside public)
    try {
      const data = fs.readFileSync(channelsFile, "utf8");
      // ensure valid JSON
      const parsed = JSON.parse(data);
      return sendJSON(res, 200, { success: true, channels: parsed });
    } catch (e) {
      return sendJSON(res, 500, { success: false, error: "Channels file error" });
    }
  }

  // serve iptv page with injection (unchanged flow)
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
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
    // simple countdown injection (keeps page intact)
    const barId = "sbar_" + crypto.randomBytes(3).toString("hex");
    const injected = `
<div id="${barId}" style="position:fixed;bottom:0;left:0;width:100%;height:40px;background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:center;font-family:monospace;font-weight:700;z-index:2147483647;box-shadow:0 -2px 8px rgba(0,0,0,0.25);">Loading session...</div>
<script>
(function(){
  var bar=document.getElementById("${barId}");
  function goLogin(){ location.href='/'; }
  fetch('/check-session',{cache:'no-store',credentials:'include'}).then(r=>r.json()).then(j=>{
    if(!j.success){ goLogin(); return; }
    var expiry=j.expiry;
    setInterval(()=>{ fetch('/refresh-session',{method:'POST',credentials:'include'}).catch(()=>{}); },5*60*1000);
    setInterval(()=>{ var d=expiry-Date.now(); if(d<=0){ try{ alert('Session expired'); }catch(e){} goLogin(); return; } var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60); bar.innerText='Session expires in: '+h+'h '+m+'m '+s+'s'; },1000);
  }).catch(goLogin);
})();
</script>
`;
    if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
    else html += injected;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // serve login page (form POST)
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    const loginHtml = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title></head><body>
<div style="max-width:420px;margin:40px auto;padding:20px;border-radius:8px;background:#fff;color:#000">
<h2>Access IPTV</h2>
<button id="gen">Generate Token</button>
<form method="POST" action="/validate-token">
  <input id="token" name="token" type="password" placeholder="Paste token" />
  <button type="submit">Login</button>
</form>
<p id="msg"></p>
</div>
<script>
document.getElementById('gen').addEventListener('click', async ()=>{
  try{ const r = await fetch('/generate-token', { method:'GET', credentials:'include' }); const j = await r.json(); if(j.token){ document.getElementById('token').value=j.token; document.getElementById('msg').innerText='Token generated'; } }catch(e){ document.getElementById('msg').innerText='Err'; }
});
</script>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(loginHtml);
  }

  // static files from public
  const candidate = path.join(__dirname, "public", url.pathname.replace(/^\/+/, ""));
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const ext = path.extname(candidate).toLowerCase();
    const map = { ".css": "text/css", ".js": "application/javascript", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml" };
    const mime = map[ext] || "application/octet-stream";
    return serveFile(res, candidate, mime);
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
