import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- Security Keys ---
const AES_KEY = crypto.randomBytes(32); // 256-bit key
const AES_IV = crypto.randomBytes(16);  // 128-bit IV

function encrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decrypt(encrypted) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch {
    return null;
  }
}

// --- Token & Session Settings ---
const TOKEN_DURATION = 60 * 60 * 1000; // 1 hour
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 min cleanup

let tokens = {};
let sessions = {};
let usedTokens = new Set();

// --- Helpers ---
function createToken() {
  const token = crypto.randomBytes(8).toString("hex");
  const expiry = Date.now() + TOKEN_DURATION;
  tokens[token] = expiry;
  return { token, expiry };
}

function validateToken(token) {
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
  usedTokens = new Set([...usedTokens].filter(t => tokens[t]));
}
setInterval(cleanupExpired, CLEANUP_INTERVAL);

// --- API Routes ---
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

  useToken(token);
  const { sessionId, expiry } = createSession();
  const encryptedSession = encrypt(sessionId);

  res.setHeader("Set-Cookie",
    `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION/1000}`
  );

  res.json({ success: true, expiry, encryptedSession });
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

// --- Serve IPTV HTML with encrypted session and countdown ---
app.get("/iptv", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.redirect("/");

  try {
    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");
    const countdownId = "cd_" + crypto.randomBytes(4).toString("hex");
    const encryptedToken = encrypt(sessionId);

    html = html.replace("</body>", `
      <div id="${countdownId}" style="
        position:fixed;bottom:0;left:0;width:100%;height:40px;
        background:linear-gradient(90deg,#1E40AF 0%,#3B82F6 100%);
        color:white;display:flex;justify-content:center;align-items:center;
        font-family:monospace;font-weight:bold;font-size:16px;z-index:9999;
        transition:width 0.5s ease;
      ">Loading session...</div>
      <script>
        (function(){
          const bar=document.getElementById("${countdownId}");
          let expiryTime;
          const encryptedToken="${encryptedToken}";
          
          // Verify encrypted token with server
          fetch('/check-session',{headers:{'Authorization':encryptedToken}})
            .then(r=>r.json()).then(d=>{
              if(!d.success){ location.href='/'; return;}
              expiryTime=d.expiry;
              startCountdown();
              setInterval(refreshSession,5*60*1000);
            });

          function startCountdown(){
            setInterval(()=>{
              const now=Date.now();
              const dist=expiryTime-now;
              if(dist<=0){ alert("Session expired"); location.href='/'; return;}
              const h=Math.floor((dist/(1000*60*60))%24);
              const m=Math.floor((dist/(1000*60))%60);
              const s=Math.floor((dist/1000)%60);
              bar.innerText="Session expires in: "+h+"h "+m+"m "+s+"s";
            },1000);
          }

          async function refreshSession(){
            await fetch('/refresh-session',{method:'POST'});
          }

          // Prevent devtools and copying
          document.addEventListener('contextmenu', e=>e.preventDefault());
          document.addEventListener('keydown', e=>{
            if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))) e.preventDefault();
            if(e.ctrlKey && e.key==='U') e.preventDefault();
          });
          if(window.top !== window.self){ window.top.location = window.self.location; }
          Object.freeze(window);
        })();
      </script>
    </body>`);

    res.send(html);
  } catch (err) {
    console.error("Error reading IPTV HTML:", err);
    res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});

// --- Login Page ---
app.get("*", (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure IPTV Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="flex items-center justify-center min-h-screen bg-gray-100">
<div id="loginCard" class="w-full max-w-sm bg-white rounded-2xl shadow-lg p-6">
  <h2 class="text-2xl font-bold text-center mb-4">Access IPTV</h2>
  <button id="generateBtn" class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg mb-4">Generate Token</button>
  <input id="tokenInput" type="password" placeholder="Enter token" class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 mb-4">
  <button id="loginBtn" class="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg">Login</button>
  <p id="errorMsg" class="text-red-500 text-sm mt-2 hidden"></p>
</div>

<script>
document.getElementById("generateBtn").onclick=async()=>{
  const res=await fetch("/generate-token");
  const data=await res.json();
  document.getElementById("tokenInput").value=data.token;
};

document.getElementById("loginBtn").onclick=async()=>{
  const token=document.getElementById("tokenInput").value;
  const errorMsg=document.getElementById("errorMsg");
  errorMsg.classList.add("hidden");
  try{
    const res=await fetch("/validate-token",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({token})
    });
    const data=await res.json();
    if(data.success){ setTimeout(()=>{ window.location.href="/iptv"; },2000); }
    else{ errorMsg.innerText=data.error; errorMsg.classList.remove("hidden"); }
  }catch{ errorMsg.innerText="Server error. Try again."; errorMsg.classList.remove("hidden"); }
};
</script>
</body>
</html>`;
  res.send(html);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`✅ Server running on port ${PORT}`));
