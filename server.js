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
app.use(express.static(path.join(__dirname, "public"))); // keep myiptv.html as-is

/* ---------- CONFIG ---------- */
const TOKEN_DURATION = 60 * 60 * 1000;         // 1 hour
const SESSION_DURATION = 24 * 60 * 60 * 1000;  // 24 hours
const CLEANUP_INTERVAL = 30 * 60 * 1000;       // 30 minutes
const RATE_LIMIT_WINDOW = 60 * 1000;           // 1 minute window for token generation
const RATE_LIMIT_MAX = 10;                     // max tokens per IP per window

// AES key & iv — for production set env vars AES_KEY (64 hex) and AES_IV (32 hex)
const AES_KEY = process.env.AES_KEY ? Buffer.from(process.env.AES_KEY, "hex") : crypto.randomBytes(32);
const AES_IV  = process.env.AES_IV  ? Buffer.from(process.env.AES_IV, "hex")  : crypto.randomBytes(16);

function aesEncrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let enc = cipher.update(String(text), "utf8", "hex");
  enc += cipher.final("hex");
  return enc;
}
function aesDecrypt(hex) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let dec = decipher.update(String(hex), "hex", "utf8");
    dec += decipher.final("utf8");
    return dec;
  } catch (e) {
    return null;
  }
}

/* ---------- In-memory stores (single-instance) ---------- */
let tokens = {};   // token => expiry
let sessions = {}; // sessionId => expiry
let usedTokens = new Set();
let rateMap = new Map(); // ip -> {count, windowStart}

/* ---------- Helpers ---------- */
const now = () => Date.now();

function createToken() {
  const t = crypto.randomBytes(8).toString("hex");
  tokens[t] = now() + TOKEN_DURATION;
  return { token: t, expiry: tokens[t] };
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

// robust cookie parser
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

// cleanup expired
setInterval(() => {
  const t = now();
  for (const k in tokens) if (tokens[k] < t) delete tokens[k];
  for (const k in sessions) if (sessions[k] < t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

/* ---------- Per-request security headers + nonce ---------- */
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(12).toString("base64");
  res.locals.nonce = nonce;

  // basic headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "interest-cohort=()");

  // caching
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  // CSP: only allow scripts from self + nonce + tailwind CDN
  res.setHeader("Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; frame-ancestors 'none';`
  );

  // HSTS if request seems secure / production
  const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https" || process.env.NODE_ENV === "production";
  if (isSecure) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");

  next();
});

/* ---------- Rate limiter for token generation (per IP) ---------- */
function rateLimitIP(ip) {
  const nowTs = Date.now();
  const rec = rateMap.get(ip);
  if (!rec || nowTs - rec.windowStart > RATE_LIMIT_WINDOW) {
    rateMap.set(ip, { count: 1, windowStart: nowTs });
    return true;
  }
  if (rec.count >= RATE_LIMIT_MAX) return false;
  rec.count++;
  return true;
}

/* ---------- Routes ---------- */

// generate-token (GET)
app.get("/generate-token", (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  if (!rateLimitIP(ip)) return res.status(429).json({ error: "Too many requests" });
  const t = createToken();
  res.json({ token: t.token, expiry: t.expiry });
});

// validate-token (POST) -> create session, set cookie, return expiry + encryptedSession
app.post("/validate-token", (req, res) => {
  try {
    const { token } = req.body || {};
    if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    useToken(token);
    const { sessionId, expiry } = createSession();

    // secure flag only if request is secure or in production
    const isSecureReq = req.secure || req.headers["x-forwarded-proto"] === "https" || process.env.NODE_ENV === "production";
    const secureFlag = isSecureReq ? "Secure; " : "";

    // cookie: HttpOnly + SameSite=Lax (allows top-level navigation) + Path + Max-Age
    const cookieStr = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; ${secureFlag}SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`;
    res.setHeader("Set-Cookie", cookieStr);

    // encrypted session token for embedding
    const enc = aesEncrypt(sessionId);

    res.json({ success: true, expiry, encryptedSession: enc });
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

// verify-encrypted (POST) — validates encryptedSession value
app.post("/verify-encrypted", (req, res) => {
  try {
    const enc = req.headers["x-encrypted-session"] || req.body?.encryptedSession;
    if (!enc) return res.status(400).json({ success: false, error: "Missing token" });
    const dec = aesDecrypt(enc);
    if (!dec) return res.status(401).json({ success: false, error: "Invalid token" });
    if (!validateSession(dec)) return res.status(401).json({ success: false, error: "Session invalid" });
    return res.json({ success: true, expiry: sessions[dec] });
  } catch (e) {
    console.error("verify-encrypted error:", e);
    return res.status(500).json({ success: false });
  }
});

/* ---------- Serve IPTV (inject secure obfuscated script) ---------- */
app.get("/iptv", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.redirect("/");

  try {
    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");

    // embed encrypted session and random id
    const encryptedSession = aesEncrypt(sid);
    const barId = "sbar_" + crypto.randomBytes(4).toString("hex");
    const nonce = res.locals.nonce;

    // obfuscated compact script: array-based keys to make it harder to read
    const obf = `
      (function(){
        try{
          var _=['getElementById','verify-encrypted','then','json','success','expiry','innerText','refresh-session','POST','contextmenu','keydown','top','self','preventDefault','freeze','replaceState','popstate'];
          // avoid back-button cache showing content
          try{ history.replaceState(null,'',location.pathname+location.search); window.addEventListener(_[16],function(){ location.href='/'; }); }catch(e){}
          var B=document[_[0]]('${barId}');
          var E=0;
          function v(){return fetch('/'+_[1],{method:'POST',headers:{'Content-Type':'application/json','x-encrypted-session':'${encryptedSession}'},cache:'no-store'}).then(function(r){return r[_[2]]();}).catch(function(){return {success:false};});}
          function s(){setInterval(function(){var n=Date.now(),d=E-n;if(!E||d<=0){try{alert('Session expired');}catch(e){}location.href='/';return;}var h=Math.floor((d/3600000)%24),m=Math.floor((d/60000)%60),s=Math.floor((d/1000)%60);B[_[6]]='Session expires in: '+h+'h '+m+'m '+s+'s';},1000);}
          async function r(){try{await fetch('/'+_[7],{method:_[8]});}catch(e){}}
          v().then(function(j){ if(!j[_[4]]){ location.href='/'; return; } E=j[_[5]]; s(); setInterval(r,5*60*1000); });
          // devtools detection via debugger timing
          setInterval(function(){ var t=Date.now(); debugger; if(Date.now()-t>200){ try{ alert('DevTools detected — returning to login'); }catch(e){} location.href='/'; }},1500);
          // basic keyboard/context blockers
          document.addEventListener(_[9],function(e){ e[_[13]](); });
          document.addEventListener(_[10],function(e){ if(e.key==='F12' || (e.ctrlKey && e.shiftKey && (e.key==='I'||e.key==='J'||e.key==='C')) || (e.ctrlKey && e.key==='U')) e[_[13]](); });
          if(window[_[11]]!==window[_[12]]){ try{ window.top.location=window.self.location; }catch(e){ location.href='/'; } }
          try{ Object[_[14]](window); }catch(e){}
        }catch(err){ try{ console.error('injected error',err);}catch(e){} location.href='/'; }
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
      <script nonce="${nonce}">${obf}</script>
    `;

    if (html.includes("</body>")) html = html.replace("</body>", injection + "</body>");
    else html += injection;

    // explicit no-store
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.send(html);
  } catch (err) {
    console.error("iptv serve error:", err);
    return res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});

/* ---------- Login fallback page (uses nonce so CSP allows inline) ---------- */
app.get("*", (req, res) => {
  const nonce = res.locals.nonce;
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen flex items-center justify-center bg-gray-100"><div class="w-full max-w-md bg-white p-6 rounded shadow"><h1 class="text-xl font-bold mb-4 text-center">Access IPTV</h1><div class="mb-4"><button id="gbtn" class="w-full bg-green-600 text-white py-2 rounded">Generate Token</button></div><div class="mb-3"><input id="t" type="password" placeholder="Paste token" class="w-full border px-3 py-2 rounded"/></div><div><button id="lbtn" class="w-full bg-blue-600 text-white py-2 rounded">Login</button></div><p id="m" class="text-sm mt-3 text-center text-gray-600"></p></div><script nonce="${nonce}">(function(){const g=document.getElementById('gbtn'),l=document.getElementById('lbtn'),m=document.getElementById('m');g.onclick=async()=>{try{const r=await fetch('/generate-token');const j=await r.json();if(j.token){try{await navigator.clipboard.writeText(j.token);}catch(e){}m.innerText='Token copied to clipboard';}else m.innerText='Failed';}catch(e){m.innerText='Error';}};l.onclick=async()=>{const token=document.getElementById('t').value.trim();if(!token){m.innerText='Paste token';return;}try{const r=await fetch('/validate-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const j=await r.json();if(j.success){m.innerText='Logged in — redirecting';setTimeout(()=>location.href='/iptv',900);}else{m.innerText=j.error||'Invalid token';}}catch(e){m.innerText='Server error';}}})();</script></body></html>`;
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

/* ---------- Start server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
