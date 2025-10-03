app.get("/iptv", (req, res) => {
  const sessionId = getCookie(req, "sessionId");
  if (!sessionId || !validateSession(sessionId)) return res.redirect("/");

  try {
    const htmlPath = path.join(__dirname, "public", "myiptv.html");
    let html = fs.readFileSync(htmlPath, "utf8");
    const countdownId = "sessionCountdown_" + crypto.randomBytes(4).toString("hex");

    // Obfuscated JS script
    const obfuscatedScript = `
      (function(){
        const _0x1a2b=['getElementById','check-session','then','success','expiry','innerText','fetch','alert','location','setInterval','top','self','contextmenu','keydown','freeze'];
        const bar=document[_0x1a2b[0]]('${countdownId}');
        let expiryTime;
        fetch('/'+_0x1a2b[1])[_0x1a2b[2]](r=>r.json())[_0x1a2b[2]](d=>{
          if(!d[_0x1a2b[3]]){ window[_0x1a2b[8]]='/' ; return; }
          expiryTime=d[_0x1a2b[4]];
          startCountdown();
          setInterval(refreshSession,5*60*1000);
        });
        function startCountdown(){
          setInterval(()=>{
            const now=Date.now(), dist=expiryTime-now;
            if(dist<=0){ alert("Session expired"); window.location='/'; return; }
            const h=Math.floor((dist/(1000*60*60))%24);
            const m=Math.floor((dist/(1000*60))%60);
            const s=Math.floor((dist/1000)%60);
            bar[_0x1a2b[5]]="Session expires in: "+h+"h "+m+"m "+s+"s";
          },1000);
        }
        async function refreshSession(){ await fetch('/refresh-session',{method:'POST'}); }
        document.addEventListener(_0x1a2b[12],e=>e.preventDefault());
        document.addEventListener(_0x1a2b[13], e=>{
          if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U')) e.preventDefault();
        });
        if(window[_0x1a2b[10]]!==window[_0x1a2b[11]]) window[_0x1a2b[10]].location=window[_0x1a2b[11]].location;
        try{ Object[_0x1a2b[14]](window);}catch(e){}
      })();
    `;

    html = html.replace("</body>", `
      <div id="${countdownId}" style="
        position:fixed;bottom:0;left:0;width:100%;height:40px;
        background:linear-gradient(90deg,#1E40AF,#3B82F6);
        color:white;display:flex;justify-content:center;align-items:center;
        font-family:monospace;font-weight:bold;font-size:16px;z-index:9999;
        transition:width 0.5s ease;">Loading session...</div>
      <script>${obfuscatedScript}</script>
    </body>`);

    res.send(html);
  } catch (err) {
    console.error("Error reading IPTV HTML:", err);
    res.status(500).send("Internal Server Error: cannot load IPTV page.");
  }
});
