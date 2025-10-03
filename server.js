// server.js
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 3000;

const TOKEN_DURATION = 60*60*1000;
const SESSION_DURATION = 24*60*60*1000;

let tokens = {};
let sessions = {};
let usedTokens = new Set();

const now = ()=>Date.now();

function createToken(){
  const t = crypto.randomBytes(8).toString("hex");
  tokens[t] = now()+TOKEN_DURATION;
  return {token:t, expiry:tokens[t]};
}
function validateToken(t){ return t && tokens[t] && now()<=tokens[t] && !usedTokens.has(t); }
function useToken(t){ usedTokens.add(t); delete tokens[t]; }

function createSession(){
  const id = crypto.randomBytes(16).toString("hex");
  sessions[id] = now()+SESSION_DURATION;
  return {sessionId:id, expiry:sessions[id]};
}
function validateSession(id){ return id && sessions[id] && now()<=sessions[id]; }

function refreshSession(id){ if(!validateSession(id)) return false; sessions[id]=now()+SESSION_DURATION; return true; }

function getCookie(req, name){
  const raw = req.headers.cookie;
  if(!raw) return null;
  const parts = raw.split(";").map(s=>s.trim());
  for(const p of parts){
    const [k,...v] = p.split("=");
    if(k===name) return decodeURIComponent(v.join("="));
  }
  return null;
}

// Cleanup expired
setInterval(()=>{
  const t = now();
  for(const k in tokens) if(tokens[k]<t) delete tokens[k];
  for(const k in sessions) if(sessions[k]<t) delete sessions[k];
  usedTokens = new Set([...usedTokens].filter(x=>x in tokens));
},30*60*1000);

const server = http.createServer((req,res)=>{
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // Generate token
  if(url.pathname==='/generate-token' && method==='GET'){
    const t=createToken();
    res.writeHead(200, {'Content-Type':'application/json'});
    return res.end(JSON.stringify(t));
  }

  // Validate token -> set session cookie
  if(url.pathname==='/validate-token' && method==='POST'){
    let body='';
    req.on('data',c=>body+=c);
    req.on('end',()=>{
      try{
        const {token} = JSON.parse(body||"{}");
        if(!validateToken(token)) return res.end(JSON.stringify({success:false,error:"Invalid"}));
        useToken(token);
        const {sessionId,expiry} = createSession();
        res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_DURATION/1000)}`);
        res.writeHead(200, {'Content-Type':'application/json'});
        return res.end(JSON.stringify({success:true,expiry}));
      }catch(e){
        res.writeHead(500,{'Content-Type':'application/json'});
        return res.end(JSON.stringify({success:false,error:"Server error"}));
      }
    });
    return;
  }

  // Check session
  if(url.pathname==='/check-session'){
    const sid=getCookie(req,'sessionId');
    if(!validateSession(sid)) return res.writeHead(401,{'Content-Type':'application/json'}),res.end(JSON.stringify({success:false}));
    return res.end(JSON.stringify({success:true,expiry:sessions[sid]}));
  }

  // Refresh session
  if(url.pathname==='/refresh-session' && method==='POST'){
    const sid=getCookie(req,'sessionId');
    if(!validateSession(sid)) return res.end(JSON.stringify({success:false}));
    refreshSession(sid);
    return res.end(JSON.stringify({success:true}));
  }

  // Serve IPTV page
  if(url.pathname==='/iptv'){
    const sid=getCookie(req,'sessionId');
    if(!validateSession(sid)) return res.writeHead(302,{Location:'/'}),res.end();

    const htmlPath=path.join(__dirname,'public','myiptv.html');
    if(!fs.existsSync(htmlPath)) return res.writeHead(404),res.end("Not found");
    let html=fs.readFileSync(htmlPath,'utf8');
    const barId="sbar_"+crypto.randomBytes(3).toString("hex");

    const injection=`
<div id="${barId}" style="position:fixed;bottom:0;width:100%;height:44px;background:#0b5fff;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:bold;z-index:9999;">Loading session...</div>
<script>
(async function(){
  const bar=document.getElementById("${barId}");
  async function check(){ 
    try{
      const r=await fetch('/check-session',{cache:'no-store',credentials:'include'});
      const j=await r.json();
      if(!j.success){location.href='/'; return;}
      let expiry=j.expiry;
      setInterval(async()=>{ await fetch('/refresh-session',{method:'POST',credentials:'include'}); },5*60*1000);
      setInterval(()=>{
        const d=expiry-Date.now();
        if(d<=0){location.href='/'; return;}
        const h=Math.floor((d/3600000)%24), m=Math.floor((d/60000)%60), s=Math.floor((d/1000)%60);
        bar.innerText='Session expires in: '+h+'h '+m+'m '+s+'s';
      },1000);
    }catch(e){ location.href='/'; }
  }
  check();
  document.addEventListener('contextmenu',e=>e.preventDefault());
  document.addEventListener('keydown',e=>{
    if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U')) e.preventDefault();
  });
})();
</script>
`;

    if(html.includes('</body>')) html=html.replace('</body>',injection+'</body>');
    else html+=injection;

    res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});
    return res.end(html);
  }

  // Login page
  if(url.pathname==='/' || url.pathname==='/login'){
    const html=fs.existsSync(path.join(__dirname,'public','login.html')) ? 
      fs.readFileSync(path.join(__dirname,'public','login.html'),'utf8') :
`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IPTV Login</title></head>
<body>
<h2>Access IPTV</h2>
<button id="gen">Generate Token</button>
<input type="password" id="token" placeholder="Paste token">
<button id="loginBtn">Login</button>
<p id="msg"></p>
<script>
const gen=document.getElementById('gen'),loginBtn=document.getElementById('loginBtn'),tokenInput=document.getElementById('token'),msg=document.getElementById('msg');
gen.onclick=async()=>{ const r=await fetch('/generate-token'); const j=await r.json(); tokenInput.value=j.token||''; msg.innerText='Token generated'; };
loginBtn.onclick=async()=>{ 
  const t=tokenInput.value.trim(); if(!t){msg.innerText='Paste token';return;}
  try{
    const r=await fetch('/validate-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t}),credentials:'include'});
    const j=await r.json();
    if(j.success){ msg.innerText='Access granted'; setTimeout(()=>location.href='/iptv',500); }
    else msg.innerText=j.error||'Invalid';
  }catch(e){ msg.innerText='Server error'; }
};
document.addEventListener('contextmenu',e=>e.preventDefault());
document.addEventListener('keydown',e=>{
if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U')) e.preventDefault();
});
</script>
</body></html>`;
    res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});
    return res.end(html);
  }

  // Not found
  res.writeHead(404,{'Content-Type':'text/plain'});
  res.end("Not found");
});

server.listen(PORT,()=>console.log(`✅ Server running on port ${PORT}`));
