import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24h

let tokens = {};       // token: expiry
let sessions = {};     // sessionId: expiry
let usedTokens = new Set();

// Generate token
function createToken() {
  const token = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + SESSION_DURATION;
  tokens[token] = expiry;
  return { token, expiry };
}

// Validate token
function validateToken(token) {
  if (!tokens[token]) return false;
  if (Date.now() > tokens[token]) { delete tokens[token]; return false; }
  if (usedTokens.has(token)) return false;
  return true;
}

// Mark token as used
function useToken(token) {
  usedTokens.add(token);
  delete tokens[token];
}

// Create session
function createSession() {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + SESSION_DURATION;
  sessions[sessionId] = expiry;
  return { sessionId, expiry };
}

// Validate session
function validateSession(sessionId) {
  if (!sessions[sessionId]) return false;
  if (Date.now() > sessions[sessionId]) { delete sessions[sessionId]; return false; }
  return true;
}

// Refresh session
function refreshSession(sessionId) {
  if (!sessions[sessionId]) return false;
  sessions[sessionId] = Date.now() + SESSION_DURATION;
  return true;
}

// Helper to get cookie by name
function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const match = cookies.split(";").find(c => c.trim().startsWith(name + "="));
  return match ? match.split("=")[1] : null;
}

// --- Routes ---

app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (!validateToken(token)) return res.status(400).json({ success: false, error: "Invalid or expired token" });

  useToken(token);
  const { sessionId, expiry } = createSession();

  // Set HTTP-only cookie
  res.setHeader("Set-Cookie", `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=${SESSION_DURATION/1000}`);
  res.json({ success: true, expiry });
});

app.post("/refresh-session", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.status(400).json({ success: false, error: "No valid session" });

  refreshSession(sessionId);
  res.json({ success: true });
});

// IPTV route protected by session cookie
app.get("/iptv", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.redirect("/"); // redirect if no session
  res.redirect("https://tambaynoodtv.site/");
});

// Serve login page
app.get("*", (req, res) => {
  const html = '<!DOCTYPE html>\
<html lang="en">\
<head>\
<meta charset="UTF-8">\
<meta name="viewport" content="width=device-width, initial-scale=1.0">\
<title>Secure Token Login</title>\
<script src="https://cdn.tailwindcss.com"></script>\
</head>\
<body class="flex items-center justify-center min-h-screen bg-gray-100">\
<div id="loginCard" class="w-full max-w-sm bg-white rounded-2xl shadow-lg p-6">\
<h2 class="text-2xl font-bold text-center mb-4">Access IPTV</h2>\
<button id="generateBtn" class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg mb-2">Generate Token</button>\
<div class="flex mb-4">\
<input id="tokenInput" type="password" placeholder="Enter token" class="flex-1 px-4 py-2 border rounded-l-lg focus:outline-none focus:ring-2 focus:ring-blue-500">\
<button id="copyBtn" class="bg-gray-300 hover:bg-gray-400 px-3 rounded-r-lg">Copy</button>\
</div>\
<button id="loginBtn" class="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg">Login</button>\
<p id="errorMsg" class="text-red-500 text-sm mt-2 hidden"></p>\
<p id="demoToken" class="text-xs text-gray-600 mt-2"></p>\
</div>\
<div id="successCard" class="hidden w-full max-w-sm bg-white rounded-2xl shadow-lg p-6 text-center">\
<h2 class="text-2xl font-bold mb-4">Access Granted ✅</h2>\
<p class="mb-2">Session valid for:</p>\
<p id="countdown" class="text-xl font-mono font-bold text-blue-600"></p>\
</div>\
<script>\
let expiryTime; let countdownInterval;\
document.getElementById("generateBtn").onclick=async()=>{const res=await fetch("/generate-token");const data=await res.json();document.getElementById("demoToken").innerText="Token: "+data.token;document.getElementById("tokenInput").value=data.token;};\
document.getElementById("copyBtn").onclick=()=>{const val=document.getElementById("tokenInput").value;navigator.clipboard.writeText(val);alert("Token copied!");};\
document.getElementById("loginBtn").onclick=async()=>{const token=document.getElementById("tokenInput").value;const errorMsg=document.getElementById("errorMsg");errorMsg.classList.add("hidden");try{const res=await fetch("/validate-token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});const data=await res.json();if(data.success){expiryTime=data.expiry;showSuccess();window.location.href="/iptv";setInterval(refreshSession,5*60*1000);}else{errorMsg.innerText=data.error;errorMsg.classList.remove("hidden");}}catch{errorMsg.innerText="Server error. Try again.";errorMsg.classList.remove("hidden");}};\
function showSuccess(){document.getElementById("loginCard").classList.add("hidden");document.getElementById("successCard").classList.remove("hidden");startCountdown();}\
function startCountdown(){clearInterval(countdownInterval);countdownInterval=setInterval(()=>{const now=Date.now();const distance=expiryTime-now;if(distance<=0){clearInterval(countdownInterval);alert("Session expired. Returning to login.");location.reload();return;}const hours=Math.floor((distance/(1000*60*60))%24);const minutes=Math.floor((distance/(1000*60))%60);const seconds=Math.floor((distance/1000)%60);document.getElementById("countdown").innerText=hours+"h "+minutes+"m "+seconds+"s";},1000);}\
async function refreshSession(){try{await fetch("/refresh-session",{method:"POST"});}catch{location.reload();}}\
</script>\
</body></html>';
  res.send(html);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log("✅ Server running on port "+PORT));
