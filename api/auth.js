// Call the canonical host directly: tabindia.org answers with a 308 to www.
const TAB_INDIA_AUTH_BASE = "https://www.tabindia.org/api/auth/phone";
const ALLOWED_ORIGIN = "https://predict.tabindia.org";
const ACTIONS = new Map([
  ["send-otp", "send-otp"],
  ["signup", "signup"],
]);
const UNAVAILABLE = "TAB India login is temporarily unavailable. Please try again in a moment.";

function safeErrorMessage(data, status) {
  const error = data?.error;
  const message = typeof error === "string" ? error : error?.message || data?.message;
  if (typeof message === "string" && message.trim()) return message.trim().slice(0, 300);
  return status === 429 ? "Too many attempts. Please wait a moment and try again." : "Authentication failed. Please try again.";
}

export default async function handler(request, response) {
  response.setHeader("Cache-Control", "private, no-store, max-age=0");
  response.setHeader("X-Content-Type-Options", "nosniff");

  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ error: "Method not allowed" });
  }

  const origin = request.headers.origin;
  if (origin !== ALLOWED_ORIGIN) {
    return response.status(403).json({ error: "Forbidden" });
  }

  const action = ACTIONS.get(String(request.query.action || ""));
  if (!action) return response.status(400).json({ error: "Invalid authentication action" });

  try {
    const upstream = await fetch(`${TAB_INDIA_AUTH_BASE}/${action}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": origin,
        "User-Agent": "TAB-India-Landing-Auth/1.0",
      },
      body: JSON.stringify(request.body || {}),
      redirect: "manual",
    });

    // Never follow or relay redirects; a 3xx means the endpoint moved.
    if (upstream.status >= 300 && upstream.status < 400) {
      console.error("[landing auth relay] unexpected upstream redirect", {
        action,
        status: upstream.status,
        location: upstream.headers.get("location"),
      });
      return response.status(502).json({ error: UNAVAILABLE });
    }

    const contentType = upstream.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
      console.error("[landing auth relay] unexpected upstream response", {
        action,
        status: upstream.status,
        contentType,
      });
      return response.status(upstream.ok ? 502 : upstream.status).json({ error: UNAVAILABLE });
    }

    // Relay each cookie as its own header, byte-for-byte, so Domain=.tabindia.org,
    // Path, SameSite, Secure, HttpOnly and expiry survive. Never fall back to
    // headers.get("set-cookie"), which merges cookies into one comma-joined value.
    if (typeof upstream.headers.getSetCookie === "function") {
      const setCookies = upstream.headers.getSetCookie();
      if (setCookies.length) response.setHeader("Set-Cookie", setCookies);
    } else if (upstream.headers.has("set-cookie")) {
      console.error("[landing auth relay] runtime cannot read individual Set-Cookie headers");
    }

    const body = await upstream.text();

    if (!upstream.ok) {
      let data = null;
      try { data = JSON.parse(body); } catch { /* Non-JSON error body. */ }
      return response.status(upstream.status).json({ error: safeErrorMessage(data, upstream.status) });
    }

    response.setHeader("Content-Type", contentType);
    return response.status(upstream.status).send(body);
  } catch (error) {
    console.error("[landing auth relay] upstream request failed", error);
    return response.status(502).json({ error: UNAVAILABLE });
  }
}
