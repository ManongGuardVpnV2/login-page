import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24h
const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1h

let tokens = {};       // token: expiry
let sessions = {};     // sessionId: expiry
let usedTokens = new Set();

// --- Helper Functions ---
function createToken() {
  const token = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + SESSION_DURATION;
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

// --- Automatic Cleanup ---
function cleanupExpired() {
  const now = Date.now();
  for (const t in tokens) if (tokens[t] < now) delete tokens[t];
  for (const s in sessions) if (sessions[s] < now) delete sessions[s];
  usedTokens = new Set([...usedTokens].filter(token => tokens[token])); 
}
setInterval(cleanupExpired, CLEANUP_INTERVAL);

// --- Routes ---
// Generate token
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

// Validate token & create session
app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });
  useToken(token);
  const { sessionId, expiry } = createSession();
  res.setHeader("Set-Cookie", `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=${SESSION_DURATION/1000}`);
  res.json({ success: true, expiry });
});

// Refresh session
app.post("/refresh-session", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.status(400).json({ success: false, error: "No valid session" });
  refreshSession(sessionId);
  res.json({ success: true });
});

// Check session (used by IPTV page)
app.get("/check-session", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.status(401).json({ success: false });
  const expiry = sessions[sessionId];
  res.json({ success: true, expiry });
});

// IPTV wrapper page
app.get("/iptv", (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPTV Access</title>
<style>
  body, html { margin:0; padding:0; height:100%; display:flex; flex-direction:column; }
  iframe { flex:1; border:none; width:100%; }
  #countdownBar { height:40px; background:#1E40AF; color:white; display:flex; justify-content:center; align-items:center; font-family:monospace; font-weight:bold; font-size:16px; }
</style>
</head>
<body>
<div id="countdownBar">Loading session...</div>
<iframe id="iptvFrame"></iframe>

<script>
let expiryTime;

// Check session and get expiry
fetch('/check-session')
.then(res => { if(!res.ok){ window.location.href='/'; throw 'No session'; } return res.json(); })
.then(data => {
  if(data.success){
    document.getElementById('iptvFrame').src='https://tambaynoodtv.site/';
    expiryTime = data.expiry;
    startCountdown();
    setInterval(refreshSession, 5*60*1000);
  } else { window.location.href='/'; }
})
.catch(err => console.log(err));

// Countdown
function startCountdown(){
  const countdownEl = document.getElementById('countdownBar');
  setInterval(()=>{
    const now = Date.now();
    const distance = expiryTime - now;
    if(distance <= 0){
      alert('Session expired. Returning to login.');
      window.location.href='/';
      return;
    }
    const hours = Math.floor((distance/(1000*60*60))%24);
    const minutes = Math.floor((distance/(1000*60))%60);
    const seconds = Math.floor((distance/1000)%60);
    countdownEl.innerText = \`Session expires in: \${hours}h \${minutes}m \${seconds}s\`;
  },1000);
}

// Auto-refresh
async function refreshSession(){
  try{ 
    const res = await fetch('/refresh-session',{method:'POST'});
    if(!res.ok){ window.location.href='/'; }
  } catch { window.location.href='/'; }
}
</script>
</body>
</html>`;
  res.send(html);
});

// Login page
app.get("*", (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Token Login</title>
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
      setInterval(refreshSession,5*60*1000);
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
    const hours=Math.floor((distance/(1000*60*60))%24);
    const minutes=Math.floor((distance/(1000*60))%60);
    const seconds=Math.floor((distance/1000)%60);
    document.getElementById("countdown").innerText=hours+"h "+minutes+"m "+seconds+"s";
  },1000);
}

async function refreshSession(){
  try{await fetch("/refresh-session",{method:"POST"});}catch{location.reload();}
}
</script>
</body>
</html>`;
  res.send(html);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log("✅ Server running on port "+PORT));
