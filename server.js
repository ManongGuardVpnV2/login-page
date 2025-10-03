import express from "express";
import crypto from "crypto";
import fs from "fs";

const app = express();
app.use(express.json());

const TOKEN_DURATION = 60 * 60 * 1000; // 1 hour tokens
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours sessions
const CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 min cleanup

let tokens = {};   // token: expiry
let sessions = {}; // sessionId: expiry
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

function useToken(token) {
  usedTokens.add(token);
  delete tokens[token];
}

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

  res.setHeader("Set-Cookie",
    `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION/1000}`
  );

  res.json({ success: true, expiry });
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

// --- IPTV Page ---
app.get("/iptv", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.redirect("/");

  try {
    const htmlPath = new URL('./public/myiptv.html', import.meta.url);
    let html = fs.readFileSync(htmlPath, "utf8");

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    html = html.replace("</body>", `
      <div id="countdownBar" style="height:40px;background:#1E40AF;color:white;display:flex;justify-content:center;align-items:center;font-family:monospace;font-weight:bold;font-size:16px;position:fixed;bottom:0;left:0;right:0;z-index:9999;">Loading session...</div>
      <script>
        let expiryTime;
        fetch('/check-session').then(r=>r.json()).then(d=>{
          if(!d.success){location.href='/';return;}
          expiryTime=d.expiry; startCountdown();
          setInterval(refreshSession, 5*60*1000);
        });
        function startCountdown(){
          setInterval(()=>{
            const now=Date.now();
            const dist=expiryTime-now;
            if(dist<=0){alert("Session expired");location.href='/';return;}
            const h=Math.floor((dist/(1000*60*60))%24);
            const m=Math.floor((dist/(1000*60))%60);
            const s=Math.floor((dist/1000)%60);
            document.getElementById("countdownBar").innerText="Session expires in: "+h+"h "+m+"m "+s+"s";
          },1000);
        }
        async function refreshSession(){await fetch('/refresh-session',{method:'POST'});}
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

<div id="successCard" class="hidden w-full max-w-sm bg-white rounded-2xl shadow-lg p-6 text-center">
  <h2 class="text-2xl font-bold mb-4">Access Granted ✅</h2>
  <p class="mb-2">Redirecting to IPTV...</p>
  <p id="countdown" class="text-xl font-mono font-bold text-blue-600"></p>
</div>

<script>
let expiryTime; let countdownInterval;

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
    const res=await fetch("/validate-token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
    const data=await res.json();
    if(data.success){
      expiryTime=data.expiry;
      showSuccess();
      setTimeout(()=>{ window.location.href="/iptv"; },2000);
    }else{
      errorMsg.innerText=data.error;
      errorMsg.classList.remove("hidden");
    }
  }catch{
    errorMsg.innerText="Server error. Try again.";
    errorMsg.classList.remove("hidden");
  }
};

function showSuccess(){
  document.getElementById("loginCard").classList.add("hidden");
  document.getElementById("successCard").classList.remove("hidden");
  startCountdown();
}

function startCountdown(){
  clearInterval(countdownInterval);
  countdownInterval=setInterval(()=>{
    const now=Date.now();
    const distance=expiryTime-now;
    if(distance<=0){
      clearInterval(countdownInterval);
      alert("Session expired. Returning to login.");
      location.reload();
      return;
    }
    const h=Math.floor((distance/(1000*60*60))%24);
    const m=Math.floor((distance/(1000*60))%60);
    const s=Math.floor((distance/1000)%60);
    document.getElementById("countdown").innerText=h+"h "+m+"m "+s+"s";
  },1000);
}
</script>
</body>
</html>`;
  res.send(html);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log("✅ Server running on port "+PORT));
