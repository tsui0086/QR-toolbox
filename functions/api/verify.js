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

export async function onRequestGet({ request, env }) {
  if (!env.TOKEN_SECRET) return json({ ok: false }, 401);
  const t = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return json({ ok: false }, 401);
  const ok = await safeEqual(sig, await hmacHex(exp, env.TOKEN_SECRET));
  return json({ ok }, ok ? 200 : 401);
}
