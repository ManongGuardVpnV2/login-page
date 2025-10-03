// server.js
// Single-file, no external deps. Fixes bounce-back and obfuscates injected client script + channels payload.
// Put this file in project root alongside public/myiptv.html (and optional public/channels.json).
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// ---------------- CONFIG ----------------
const TOKEN_DURATION = 60 * 60 * 1000;        // 1 hour token
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hour session
const CLEAN_INTERVAL = 30 * 60 * 1000;        // cleanup interval

// ---------------- IN-MEMORY STORES ----------------
let tokens = {};    // token -> expiry
let sessions = {};  // sessionId -> expiry
let usedTokens = new Set();

// Optional: if you have a channels.json, we'll use it; otherwise a sample fallback
const channelsFile = path.join(__dirname, "public", "channels.json");
const fallbackChannels = [
  { name: "Sample Channel 1", url: "http://example.com/1.m3u8" },
  { name: "Sample Channel 2", url: "http://example.com/2.m3u8" }
];

// ---------------- HELPERS ----------------
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

// cookie parser
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
}, CLEAN_INTERVAL);

// send JSON helper
function sendJSON(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

// serve static file helper
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

// small obfuscator for channel payload (server-side) - reversible on client
function obfuscateString(s) {
  // simple obfuscation: base64 -> reverse string -> hex
  const b = Buffer.from(s, "utf8").toString("base64");
  const rev = b.split("").reverse().join("");
  return Buffer.from(rev, "utf8").toString("hex");
}
function deobfuscateHex(hex) {
  const rev = Buffer.from(hex, "hex").toString("utf8");
  const b64 = rev.split("").reverse().join("");
  return Buffer.from(b64, "base64").toString("utf8");
}

// ---------------- SERVER ----------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // --- generate-token (GET) ---
  if (url.pathname === "/generate-token" && method === "GET") {
    const t = createToken();
    return sendJSON(res, 200, { token: t.token, expiry: t.expiry });
  }

  // --- validate-token (POST) ---
  if (url.pathname === "/validate-token" && method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const token = parsed?.token;
        if (!validateToken(token)) return sendJSON(res, 400, { success: false, error: "Invalid or expired token" });

        // consume token and create session
        useToken(token);
        const { sessionId, expiry } = createSession();

        // set cookie: HttpOnly, Path=/, SameSite=Lax so top-level navigation works
        // Do NOT set Secure here so local http testing works. In production (HTTPS) set Secure.
        const secureFlag = (req.headers["x-forwarded-proto"] === "https" || req.connection.encrypted) ? "Secure; " : "";
        res.setHeader("Set-Cookie", `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; ${secureFlag}SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`);

        return sendJSON(res, 200, { success: true, expiry });
      } catch (err) {
        return sendJSON(res, 500, { success: false, error: "Server error" });
      }
    });
    return;
  }

  // --- check-session (GET) ---
  if (url.pathname === "/check-session" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false });
    return sendJSON(res, 200, { success: true, expiry: sessions[sid] });
  }

  // --- refresh-session (POST) ---
  if (url.pathname === "/refresh-session" && method === "POST") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 400, { success: false });
    refreshSession(sid);
    return sendJSON(res, 200, { success: true });
  }

  // --- fetch-channels (protected & obfuscated payload) ---
  // This returns an obfuscated hex string. Client will deobfuscate in-memory.
  if (url.pathname === "/fetch-channels" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) return sendJSON(res, 401, { success: false, error: "Unauthorized" });

    try {
      let channelsData;
      if (fs.existsSync(channelsFile)) {
        channelsData = fs.readFileSync(channelsFile, "utf8");
      } else {
        channelsData = JSON.stringify(fallbackChannels);
      }
      const ob = obfuscateString(channelsData);
      // return obfuscated hex string inside JSON, so network response contains obfuscated value
      return sendJSON(res, 200, { success: true, payload: ob });
    } catch (e) {
      return sendJSON(res, 500, { success: false, error: "Server error" });
    }
  }

  // --- serve iptv (inject obfuscated client script + bottom bar) ---
  if (url.pathname === "/iptv" && method === "GET") {
    const sid = getCookie(req, "sessionId");
    if (!validateSession(sid)) {
      res.writeHead(302, { Location: "/" });
      return res.end();
    }

    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    if (!fs.existsSync(htmlPath)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("myiptv.html not found");
    }

    let html = fs.readFileSync(htmlPath, "utf8");
    const barId = "sbar_" + crypto.randomBytes(3).toString("hex");

    // obfuscated client script: array-key technique, credentials:'include' everywhere, deobfuscate payload on client
    const clientScript = `
(function(){
  try{
    var _=['getElementById','check-session','then','json','success','expiry','innerText','fetch-channels','fetch','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','replaceState','popstate','credentials','include','payload'];
    try{ history[_[16]](null,'',location.pathname+location.search); window.addEventListener(_[17],function(){ location.href='/'; }); }catch(e){}
    var B=document[_[0]]('${barId}');
    var E=0;
    function check(){ return fetch('/'+_[1],{cache:'no-store', [_[18]]:_[19]}).then(function(r){return r[_[2]]();}).catch(function(){return {success:false};});}
    function tick(){ setInterval(function(){ var n=Date.now(), d=E-n; if(!E||d<=0){ try{ alert('Session expired'); }catch(e){} location.href='/'; return; } var h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60); B[_[6]]='Session expires in: '+h+'h '+m+'m '+s+'s'; },1000); }
    async function keepalive(){ try{ await fetch('/'+_[9],{method:_[10],[_[18]]:_[19]}); }catch(e){} }
    check().then(function(j){ if(!j[_[4]]){ location.href='/'; return; } E=j[_[5]]; tick(); setInterval(keepalive,5*60*1000);
      // fetch obfuscated channels payload
      fetch('/'+_[7],{cache:'no-store',[_[18]]:_[19]}).then(function(r2){ return r2[_[2]](); }).then(function(obj){
        try{
          if(!obj.success) return;
          // deobfuscate: server used base64->reverse->hex; reverse steps
          var hex = obj[_[20]];
          var rev = hexToUtf8(hex);
          var b64 = rev.split('').reverse().join('');
          var jsonText = atob(b64);
          try {
            var ch = JSON.parse(jsonText);
            if(window.__onProtectedChannels && typeof window.__onProtectedChannels==='function'){
              window.__onProtectedChannels(ch);
            } else {
              window.protectedChannels = ch;
            }
          } catch(e) {
            // parsing failed
            window.protectedChannels = null;
          }
        }catch(e){}
      }).catch(function(){});
    });
    // devtools detection
    setInterval(function(){ var t=Date.now(); debugger; if(Date.now()-t>200){ try{ alert('DevTools detected — returning to login'); }catch(e){} location.href='/'; } },1500);
    // keyboard/context blockers
    document.addEventListener(_[11],function(e){ e[_[15]](); });
    document.addEventListener(_[12],function(e){ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e[_[15]](); });
    if(window[_[13]] !== window[_[14]]){ try{ window.top.location = window.self.location; } catch(e){ location.href='/'; } }
    try{ Object.freeze(window); }catch(e){}
    // helper to convert hex to utf8 string
    function hexToUtf8(h){
      var bytes = [];
      for(var i=0;i<h.length;i+=2) bytes.push(parseInt(h.substr(i,2),16));
      return String.fromCharCode.apply(null, bytes);
    }
  }catch(err){ try{ console.error('injected err',err);}catch(e){} location.href='/'; }
})();
`.trim();

    const injection = `
<div id="${barId}" style="
  position:fixed;bottom:0;left:0;width:100%;height:44px;
  background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;
  display:flex;align-items:center;justify-content:center;
  font-family:monospace;font-weight:700;z-index:2147483647;
  box-shadow:0 -2px 8px rgba(0,0,0,0.25);
">Loading session...</div>
<script>${clientScript}</script>
`;

    if (html.includes("</body>")) html = html.replace("</body>", injection + "</body>");
    else html += injection;

    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(html);
  }

  // --- root / login page ---
  if ((url.pathname === "/" || url.pathname === "/login") && method === "GET") {
    // small login page with credentials:'include' set on fetch
    const loginHtml = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<style>body{font-family:sans-serif;background:#f0f0f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0} .card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.15);width:340px;text-align:center} input,button{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #ccc;box-sizing:border-box} button{background:#007bff;color:#fff;border:none;cursor:pointer} #msg{height:18px;margin-top:6px;font-size:0.95rem}</style>
</head><body><div class="card"><h2>Access IPTV</h2><button id="gen">Generate Token</button><input id="token" type="password" placeholder="Paste token here"><button id="loginBtn">Login</button><p id="msg"></p></div>
<script>
(async function(){
  const gen=document.getElementById('gen'), loginBtn=document.getElementById('loginBtn'), tokenInput=document.getElementById('token'), msg=document.getElementById('msg');
  gen.addEventListener('click', async ()=>{ try{ const r=await fetch('/generate-token'); const j=await r.json(); tokenInput.value=j.token||''; msg.style.color='green'; msg.textContent='Token generated'; try{ await navigator.clipboard.writeText(j.token);}catch(e){} }catch(e){ msg.style.color='red'; msg.textContent='Err'; }});
  loginBtn.addEventListener('click', async ()=>{ const t=tokenInput.value.trim(); if(!t){ msg.style.color='red'; msg.textContent='Paste token'; return;} try{ const r=await fetch('/validate-token',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: t }), credentials:'include' }); const j=await r.json(); if(j.success){ msg.style.color='green'; msg.textContent='Access granted — redirecting'; setTimeout(()=>location.href='/iptv',800); } else { msg.style.color='red'; msg.textContent=j.error||'Invalid'; } }catch(e){ msg.style.color='red'; msg.textContent='Server error'; }});
  document.addEventListener('contextmenu',e=>e.preventDefault());
  document.addEventListener('keydown',e=>{ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e.preventDefault(); });
})();
</script></body></html>`;
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    return res.end(loginHtml);
  }

  // --- serve static files (public) ---
  const candidate = path.join(__dirname, "public", url.pathname.replace(/^\/+/, ""));
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const ext = path.extname(candidate).toLowerCase();
    const m = { ".css": "text/css", ".js": "application/javascript", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml" }[ext] || "application/octet-stream";
    return serveFile(res, candidate, m);
  }

  // fallback 404
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
