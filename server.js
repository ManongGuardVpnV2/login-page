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
app.use(express.static(path.join(__dirname, "public"))); // serve static files (images, css, etc.)

/* -----------------------
   CONFIG
   ----------------------- */
const TOKEN_DURATION = 60 * 60 * 1000;        // 1 hour token life
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours session life
const CLEANUP_INTERVAL = 30 * 60 * 1000;      // cleanup every 30 min

// AES keys for encrypting sessionId embedded into HTML.
// For production, set process.env.AES_KEY / AES_IV to fixed values so restarts keep same key.
// Here we fallback to generated values (works across single instance runs).
const AES_KEY = process.env.AES_KEY ? Buffer.from(process.env.AES_KEY, "hex") : crypto.randomBytes(32);
const AES_IV = process.env.AES_IV ? Buffer.from(process.env.AES_IV, "hex") : crypto.randomBytes(16);

function aesEncrypt(str) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let enc = cipher.update(String(str), "utf8", "hex");
  enc += cipher.final("hex");
  // include iv if key is constant; here we store iv separately, but we can prefix it
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

/* -----------------------
   In-memory storage (replace with Redis for multi-instance)
   ----------------------- */
let tokens = {};   // token => expiry
let sessions = {}; // sessionId => expiry
let usedTokens = new Set();

/* -----------------------
   Helpers
   ----------------------- */
function now() { return Date.now(); }

function createToken() {
  const t = crypto.randomBytes(6).toString("hex"); // 12 chars
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
function getCookie(req, name) {
  const c = req.headers.cookie;
  if (!c) return null;
  const m = c.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return m ? m.split("=")[1] : null;
}

/* Periodic cleanup */
setInterval(() => {
  const n = now();
  for (const k in tokens) if (tokens[k] < n) delete tokens[k];
  for (const k in sessions) if (sessions[k] < n) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x => x in tokens));
}, CLEANUP_INTERVAL);

/* -----------------------
   Per-request security headers + nonce
   ----------------------- */
app.use((req, res, next) => {
  // generate random nonce per request for CSP
  const nonce = crypto.randomBytes(12).toString("base64");
  res.locals.nonce = nonce;

  // Basic security headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "interest-cohort=()"); // disable FLoC
  // no caching
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  // CSP - allow only scripts with this nonce and tailwind CDN (login uses tailwind)
  // We DO NOT allow 'unsafe-inline' or 'unsafe-eval'.
  res.setHeader("Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; frame-ancestors 'none';`
  );

  next();
});

/* -----------------------
   API: generate token (GET)
   ----------------------- */
app.get("/generate-token", (req, res) => {
  const t = createToken();
  // return token; in UI we copy to clipboard; token is short-lived & single-use
  res.json({ token: t.token, expiry: t.expiry });
});

/* -----------------------
   API: validate token (POST)
   - marks token used, creates session, sets HttpOnly cookie
   - returns encryptedSession to embed into HTML (client may post it back to /verify-encrypted)
   ----------------------- */
app.post("/validate-token", (req, res) => {
  try {
    const { token } = req.body || {};
    if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    useToken(token);
    const s = createSession();

    // set HttpOnly cookie for server-side checks
    // Secure flag requires HTTPS (Render provides HTTPS). For local testing remove Secure.
    res.setHeader("Set-Cookie",
      `sessionId=${s.sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`);

    // encrypted session token (sent to client for extra verification; server can validate later)
    const enc = aesEncrypt(s.sessionId);
    res.json({ success: true, expiry: s.expiry, encryptedSession: enc });
  } catch (err) {
    console.error("validate-token error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* -----------------------
   API: refresh session (POST)
   ----------------------- */
app.post("/refresh-session", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.status(400).json({ success: false });
  refreshSession(sid);
  res.json({ success: true });
});

/* -----------------------
   API: check session (GET)
   - server uses cookie-based session check for true source of truth
   ----------------------- */
app.get("/check-session", (req, res) => {
  const sid = getCookie(req, "sessionId");
  if (!sid || !validateSession(sid)) return res.status(401).json({ success: false });
  return res.json({ success: true, expiry: sessions[sid] });
});

/* -----------------------
   API: verify encrypted session (POST)
   - client sends the encryptedSession string (from server-injected HTML)
   - server decrypts and checks it matches a valid session
   - this ensures copied HTML with embedded encrypted token cannot be used if token/session expired/invalid
   ----------------------- */
app.post("/verify-encrypted", (req, res) => {
  try {
    const enc = req.headers["x-encrypted-session"] || req.body?.encryptedSession;
    if (!enc) return res.status(400).json({ success: false, error: "Missing token" });
    const dec = aesDecrypt(enc);
    if (!dec) return res.status(401).json({ success: false, error: "Invalid token" });
    if (!validateSession(dec)) return res.status(401).json({ success: false, error: "Session not valid" });
    return res.json({ success: true, expiry: sessions[dec] });
  } catch (e) {
    console.error("verify-encrypted error:", e);
    return res.status(500).json({ success: false });
  }
});

/* -----------------------
   Serve IPTV HTML untouched but inject a secure, minified, hard-to-read script
   - script uses nonce (res.locals.nonce)
   - embeds encryptedSession (from cookie / query) into HTML so client-side can call /verify-encrypted
   ----------------------- */
app.get("/iptv", (req, res) => {
  try {
    const sid = getCookie(req, "sessionId");
    if (!sid || !validateSession(sid)) return res.redirect("/");

    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");

    // encrypted token to embed (server-side encrypted)
    const encryptedSession = aesEncrypt(sid);

    // random id to make it hard to target
    const barId = "sbar_" + crypto.randomBytes(4).toString("hex");

    // minified/hard-to-read script (IIFE). Keep it short and self-contained, uses nonce to pass CSP.
    // It performs:
    //  - verify encryptedSession with server (/verify-encrypted)
    //  - starts countdown using server-provided expiry
    //  - auto-refresh /verify periodically
    //  - devtools detection (debugger timing) redirect
    //  - prevents right-click and common shortcuts
    const nonce = res.locals.nonce;
    const injected = `
      <div id="${barId}" style="position:fixed;bottom:0;left:0;right:0;height:44px;background:linear-gradient(90deg,#0b5fff,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-family:monospace;z-index:99999;"></div>
      <script nonce="${nonce}">(function(){try{
        var e='${encryptedSession}';
        var B=document.getElementById('${barId}');
        function goOut(){try{location.href='/';}catch(e){}}
        function verify(){return fetch('/verify-encrypted',{method:'POST',headers:{'Content-Type':'application/json','x-encrypted-session':e},cache:'no-store'}).then(r=>r.json()).catch(()=>({success:false}));}
        function startClock(expiry){var iv=setInterval(function(){var d=expiry-Date.now();if(d<=0){clearInterval(iv);goOut();return;}var h=Math.floor((d/(3600000))%24),m=Math.floor((d/60000)%60),s=Math.floor((d/1000)%60);B.innerText='Session expires in: '+h+'h '+m+'m '+s+'s';},1000);}
        (function init(){
          verify().then(function(r){if(!r.success){goOut();return;}startClock(r.expiry);setInterval(function(){verify().then(function(rr){if(!rr.success)goOut();});},5*60*1000);});
          // devtools detection
          setInterval(function(){var t=Date.now();debugger; if(Date.now()-t>200){try{alert('DevTools detected. Returning to login.');}catch(e){} goOut();}},1500);
          // basic keyboard / context blockers
          document.addEventListener('contextmenu',function(e){e.preventDefault();});
          document.addEventListener('keydown',function(e){if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&(e.key==='I'||e.key==='J'))|| (e.ctrlKey&&e.key==='U')){e.preventDefault();}});
          // prevent iframe embedding
          if(window.top!==window.self){try{window.top.location=window.self.location;}catch(e){goOut();}}
          try{Object.freeze(window);}catch(e){}
        })();
      }catch(z) {try{console.error(z);}catch(e){};try{location.href='/';}catch(e){}}})();</script>`;

    // inject before </body> but keep rest of HTML untouched
    if (html.includes("</body>")) html = html.replace("</body>", injected + "</body>");
    else html = html + injected;

    // no-cache headers (already set at middleware but ensure)
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.send(html);
  } catch (err) {
    console.error("iptv serve error:", err);
    return res.status(500).send("Internal Server Error");
  }
});

/* -----------------------
   Login page (simple, inline with nonce so CSP allows)
   ----------------------- */
app.get("*", (req, res) => {
  const nonce = res.locals.nonce;
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen flex items-center justify-center bg-gray-100"><div class="w-full max-w-md bg-white p-6 rounded shadow"><h1 class="text-xl font-bold mb-4 text-center">Access IPTV</h1><div class="mb-4"><button id="gbtn" class="w-full bg-green-600 text-white py-2 rounded">Generate Token</button></div><div class="mb-3"><input id="t" type="password" placeholder="Paste token" class="w-full border px-3 py-2 rounded"/></div><div><button id="lbtn" class="w-full bg-blue-600 text-white py-2 rounded">Login</button></div><p id="m" class="text-sm mt-3 text-center text-gray-600"></p></div><script nonce="${nonce}">(function(){const g=document.getElementById('gbtn'),l=document.getElementById('lbtn'),m=document.getElementById('m');g.onclick=async()=>{try{const r=await fetch('/generate-token');const j=await r.json();if(j.token){navigator.clipboard.writeText(j.token).catch(()=>{});m.innerText='Token copied to clipboard.';}else m.innerText='Failed';}catch(e){m.innerText='Error';}};l.onclick=async()=>{const token=document.getElementById('t').value.trim();if(!token){m.innerText='Paste token';return;}try{const r=await fetch('/validate-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const j=await r.json();if(j.success){m.innerText='Logged in';setTimeout(()=>location.href='/iptv',800);}else m.innerText=j.error||'Invalid';}catch(e){m.innerText='Server error';}}})();</script></body></html>`;
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

/* -----------------------
   Start server
   ----------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
