// 放置路径: functions/api/login.js  ->  POST /api/login
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmacHex(msg, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([hmacHex(a, "cmp"), hmacHex(b || "", "cmp")]);
  return x === y;
}
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

export async function onRequestPost({ request, env }) {
  if (!env.ACCESS_PASSWORD || !env.TOKEN_SECRET) {
    return json({ error: "服务端未配置 ACCESS_PASSWORD / TOKEN_SECRET" }, 500);
  }
  const body = await request.json().catch(() => ({}));
  if (!body.password || !(await safeEqual(String(body.password), env.ACCESS_PASSWORD))) {
    return json({ error: "密码错误" }, 401);
  }
  const exp = String(Date.now() + 7 * 24 * 3600 * 1000);
  return json({ token: exp + "." + (await hmacHex(exp, env.TOKEN_SECRET)), exp: Number(exp) });
}
