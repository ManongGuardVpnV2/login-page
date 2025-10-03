const injected = `
  <div id="${countdownId}" style="
    position:fixed;bottom:0;left:0;width:100%;height:44px;
    background:linear-gradient(90deg,#1E40AF,#3B82F6);color:white;
    display:flex;align-items:center;justify-content:center;
    font-family:monospace;font-weight:bold;z-index:2147483647;
  ">Loading session...</div>
  <script>
  (function(){
    var _0x1a2b=['getElementById','check-session','json','success','expiry','fetch','POST','Session expires in: ','Date','innerText','alert','top','self','contextmenu','keydown','preventDefault','F12','shiftKey','ctrlKey','U','includes'];
    (function(_0xabc,_0xdef){var _0xghi=function(_0xjkl){while(--_0xjkl){_0xabc.push(_0xabc.shift());}};_0xghi(++_0xdef);})(_0x1a2b,0x1f4);
    var bar=document[_0x1a2b[0]]('${countdownId}');
    function goLogin(){location.href='/';}
    fetch('/'+_0x1a2b[1],{cache:'no-store',credentials:'include'}).then(r=>r[_0x1a2b[2]]()).then(j=>{
      if(!j[_0x1a2b[3]]){goLogin();return;}
      var expiry=j[_0x1a2b[4]];
      setInterval(()=>{fetch('/refresh-session',{method:_0x1a2b[6],credentials:'include'}).catch(()=>{});},5*60*1000);
      setInterval(()=>{
        var d=expiry-Date.now();
        if(d<=0){alert('Session expired');goLogin();return;}
        var h=Math.floor((d/(1000*60*60))%24),m=Math.floor((d/(1000*60))%60),s=Math.floor((d/1000)%60);
        bar[_0x1a2b[9]]=_0x1a2b[7]+h+'h '+m+'m '+s+'s';
      },1000);
    }).catch(goLogin);
    document.addEventListener(_0x1a2b[14],e=>e[_0x1a2b[15]]());
    document.addEventListener(_0x1a2b[16],e=>{
      if(e[_0x1a2b[19]]===_0x1a2b[17]||(e[_0x1a2b[18]]&&e[_0x1a2b[20]]&&[_0x1a2b[21],_0x1a2b[22],_0x1a2b[23]].includes(e.key))||(e[_0x1a2b[18]]&&e.key===_0x1a2b[24]))e.preventDefault();
    });
    if(window[_0x1a2b[25]]!==window[_0x1a2b[26]]){window.top.location=window.self.location;}
  })();
  </script>
`;
