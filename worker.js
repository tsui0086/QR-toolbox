// Workers + Static Assets; server-side password gate, HttpOnly session cookie.
const COOKIE = '__Host-qr_session';
const enc = new TextEncoder();
const LOGIN_HTML = "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>登录 QR Studio</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;font-family:system-ui,sans-serif}.card{width:min(380px,calc(100vw - 32px));background:white;border-radius:18px;padding:30px}h1{font-size:24px;margin:0 0 8px}p{color:#64748b}input[type=password]{width:100%;height:46px;border:1px solid #cbd5e1;border-radius:9px;padding:12px;font-size:16px}label{display:block;margin:16px 0;font-size:14px}button{width:100%;padding:12px;background:#2563eb;border:0;border-radius:9px;color:white;font-size:16px}#error{color:#dc2626;min-height:24px;font-size:14px}</style><main class=\"card\"><h1>QR Studio</h1><p>请输入访问密码</p><form id=\"form\"><input aria-label=\"访问密码\" type=\"password\" id=\"password\" autocomplete=\"current-password\" required autofocus><label><input type=\"checkbox\" id=\"remember\" checked>记住此设备（7 天）</label><button id=\"submit\">进入</button><p id=\"error\" role=\"alert\"></p></form></main><script>document.getElementById('form').addEventListener('submit',async function(e){e.preventDefault();var b=document.getElementById('submit'),err=document.getElementById('error');b.disabled=true;err.textContent='';try{var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value,remember:document.getElementById('remember').checked})});var d=await r.json();if(!r.ok)throw new Error(d.error||'登录失败');location.reload()}catch(e){err.textContent=e.message}finally{b.disabled=false}});</script></html>";
const headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
function json(data,status=200,extra={}){return Response.json(data,{status,headers:{...headers,...extra}})}
async function key(secret,usage){return crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,[usage])}
function hex(bytes){return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('')}
async function sign(text,secret){return hex(await crypto.subtle.sign('HMAC',await key(secret,'sign'),enc.encode(text)))}
async function authenticated(request,env){
 if(!env.TOKEN_SECRET||!env.ACCESS_PASSWORD)return false;
 const token=(request.headers.get('Cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(COOKIE+'='));
 if(!token)return false;
 const parts=token.slice(COOKIE.length+1).split('.');
 if(parts.length!==3)return false;
 const [exp,nonce,sig]=parts;
 if(!/^\d{13}$/.test(exp)||Number(exp)<=Date.now()||! /^[0-9a-f-]{36}$/.test(nonce)||! /^[0-9a-f]{64}$/.test(sig))return false;
 const bytes=new Uint8Array(sig.match(/../g).map(x=>parseInt(x,16)));
 return crypto.subtle.verify('HMAC',await key(env.TOKEN_SECRET,'verify'),bytes,enc.encode(exp+'.'+nonce+'.'+env.ACCESS_PASSWORD));
}
function noCache(response){const r=new Response(response.body,response);for(const [k,v] of Object.entries(headers))r.headers.set(k,v);return r}
export default {
 async fetch(request,env){
  const u=new URL(request.url);
  if((request.method==='POST')&&request.headers.get('Origin')&&request.headers.get('Origin')!==u.origin)return json({error:'禁止跨域操作'},403);
  if(u.pathname==='/api/login'){
   if(request.method!=='POST')return json({error:'请使用 POST'},405);
   if(!env.ACCESS_PASSWORD||!env.TOKEN_SECRET)return json({error:'请配置 ACCESS_PASSWORD 和 TOKEN_SECRET'},503);
   if(Number(request.headers.get('Content-Length')||0)>4096)return json({error:'请求过大'},413);
   const body=await request.json().catch(()=>null);
   if(!body||typeof body.password!=='string'||body.password.length>1024)return json({error:'请输入密码'},400);
   const probe=await crypto.subtle.sign('HMAC',await key(env.TOKEN_SECRET,'sign'),enc.encode(body.password));
   const ok=await crypto.subtle.verify('HMAC',await key(env.TOKEN_SECRET,'verify'),probe,enc.encode(env.ACCESS_PASSWORD));
   if(!ok)return json({error:'密码错误'},401);
   const seconds=body.remember?604800:28800;
   const payload=String(Date.now()+seconds*1000)+'.'+crypto.randomUUID();
   const token=payload+'.'+await sign(payload+'.'+env.ACCESS_PASSWORD,env.TOKEN_SECRET);
   return json({ok:true},200,{'Set-Cookie':COOKIE+'='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict'+(body.remember?'; Max-Age='+seconds:'')});
  }
  if(u.pathname==='/api/logout'){
   if(request.method!=='POST')return json({error:'请使用 POST'},405);
   return json({ok:true},200,{'Set-Cookie':COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});
  }
  const ok=await authenticated(request,env);
  if(u.pathname==='/api/verify')return json({ok},ok?200:401);
  if(!ok){
   if(request.method==='GET'&&(u.pathname==='/'||u.pathname==='/index.html'))return new Response(LOGIN_HTML,{headers:{...headers,'Content-Type':'text/html; charset=utf-8'}});
   return json({error:'请先登录'},401);
  }
  if(u.searchParams.has('url'))return noCache(await imageProxy.fetch(request));
  if(u.pathname.startsWith('/api/'))return json({error:'接口不存在'},404);
  return noCache(await env.ASSETS.fetch(request));
 }
};

// Cloudflare Worker: CORS image proxy for QR Studio ChromaCode
// Deploy at: https://workers.cloudflare.com
// Free tier: 100,000 requests/day
//
// Usage: https://your-worker.your-subdomain.workers.dev/?url=https://example.com/favicon.ico

const imageProxy = {
  async fetch(request) {
    const url = new URL(request.url);
    const target = url.searchParams.get("url");

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(request),
      });
    }

    if (!target) {
      return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders(request) },
      });
    }

    // Validate URL
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return new Response(JSON.stringify({ error: "Invalid URL" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders(request) },
      });
    }

    // Only allow image-related fetches (security)
    try {
      const resp = await fetch(target, {
        headers: {
          "User-Agent": "QRStudio-Favicon-Proxy/1.0",
          "Accept": "image/*,*/*;q=0.8",
        },
        redirect: "follow",
      });

      // Only proxy successful responses
      if (!resp.ok) {
        return new Response(JSON.stringify({ error: `Upstream returned ${resp.status}` }), {
          status: resp.status,
          headers: { "Content-Type": "application/json", ...corsHeaders(request) },
        });
      }

      // Check content type — only allow images
      const ct = resp.headers.get("content-type") || "";
      if (!ct.includes("image") && !ct.includes("octet-stream") && !ct.includes("icon")) {
        return new Response(JSON.stringify({ error: "Not an image" }), {
          status: 415,
          headers: { "Content-Type": "application/json", ...corsHeaders(request) },
        });
      }

      // Stream the image back with CORS headers
      const body = await resp.arrayBuffer();
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": ct,
          "Cache-Control": "public, max-age=86400",
          ...corsHeaders(request),
        },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: "Fetch failed: " + err.message }), {
        status: 502,
        headers: { "Content-Type": "application/json", ...corsHeaders(request) },
      });
    }
  },
};

function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}
