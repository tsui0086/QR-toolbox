// Cloudflare Worker: CORS image proxy for QR Studio ChromaCode
// Deploy at: https://workers.cloudflare.com
// Free tier: 100,000 requests/day
//
// Usage: https://your-worker.your-subdomain.workers.dev/?url=https://example.com/favicon.ico

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const target = url.searchParams.get("url");

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(request),
      });
    }

    // ---- 登录 API (新增) ----
    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!env.ACCESS_PASSWORD || !env.TOKEN_SECRET) {
        return jsonResp({ error: "服务端未配置 ACCESS_PASSWORD / TOKEN_SECRET" }, 500, request);
      }
      const body = await request.json().catch(() => ({}));
      if (!body.password || !(await safeEqual(String(body.password), env.ACCESS_PASSWORD))) {
        return jsonResp({ error: "密码错误" }, 401, request);
      }
      const exp = Date.now() + 7 * 24 * 3600 * 1000;
      return jsonResp({ token: await signToken(String(exp), env.TOKEN_SECRET), exp }, 200, request);
    }
    if (url.pathname === "/api/verify") {
      const ok = !!env.TOKEN_SECRET && (await verifyToken(request.headers.get("Authorization"), env.TOKEN_SECRET));
      return jsonResp({ ok }, ok ? 200 : 401, request);
    }
    // ---- 以下为原有图片代理逻辑 ----

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
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

// ---- 登录辅助函数 (新增) ----
const _enc = new TextEncoder();
const _hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hmacHex(msg, secret) {
  const key = await crypto.subtle.importKey("raw", _enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return _hex(await crypto.subtle.sign("HMAC", key, _enc.encode(msg)));
}
async function signToken(payload, secret) {
  return payload + "." + (await hmacHex(payload, secret));
}
async function verifyToken(header, secret) {
  const t = (header || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmacHex(exp, secret));
}
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([hmacHex(a, "cmp"), hmacHex(b || "", "cmp")]);
  return x === y;
}
function jsonResp(obj, status, request) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(request) },
  });
}
