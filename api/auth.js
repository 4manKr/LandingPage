const TAB_INDIA_AUTH_BASE = "https://www.tabindia.org/api/auth/phone";
const ACTIONS = new Map([
  ["send-otp", "send-otp"],
  ["signup", "signup"],
]);

export default async function handler(request, response) {
  response.setHeader("Cache-Control", "private, no-store, max-age=0");
  response.setHeader("X-Content-Type-Options", "nosniff");

  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ error: "Method not allowed" });
  }

  if (request.headers.origin !== "https://predict.tabindia.org") {
    return response.status(403).json({ error: "Forbidden" });
  }

  const action = ACTIONS.get(String(request.query.action || ""));
  if (!action) return response.status(400).json({ error: "Invalid authentication action" });

  try {
    const upstream = await fetch(`${TAB_INDIA_AUTH_BASE}/${action}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://predict.tabindia.org",
        "User-Agent": "TAB-India-Landing-Auth/1.0",
      },
      body: JSON.stringify(request.body || {}),
      redirect: "manual",
    });

    const contentType = upstream.headers.get("content-type");
    if (contentType) response.setHeader("Content-Type", contentType);

    const setCookies = typeof upstream.headers.getSetCookie === "function"
      ? upstream.headers.getSetCookie()
      : [upstream.headers.get("set-cookie")].filter(Boolean);
    if (setCookies.length) response.setHeader("Set-Cookie", setCookies);

    const body = await upstream.text();
    return response.status(upstream.status).send(body);
  } catch (error) {
    console.error("[landing auth relay] upstream request failed", error);
    return response.status(502).json({
      error: "TAB India login is temporarily unavailable. Please try again in a moment.",
    });
  }
}
