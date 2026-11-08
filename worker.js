
const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

function decodeJson(value) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

async function verifyAccess(request, env) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) throw new Error("Missing Access token");

  const team = env.CF_ACCESS_TEAM_DOMAIN;
  const audience = env.CF_ACCESS_AUD;

  if (!team || !audience ||
      !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(team)) {
    throw new Error("Invalid Access configuration");
  }

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");

  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Unsupported token");
  }

  const now = Math.floor(Date.now() / 1000);
  const issuer = `https://${team}`;

  if (
    payload.iss !== issuer ||
    !Array.isArray(payload.aud) ||
    !payload.aud.includes(audience) ||
    typeof payload.exp !== "number" ||
    payload.exp <= now ||
    typeof payload.iat !== "number" ||
    payload.iat > now + 60 ||
    (payload.nbf !== undefined &&
      (typeof payload.nbf !== "number" || payload.nbf > now))
  ) {
    throw new Error("Token claims invalid");
  }

  const response = await fetch(`${issuer}/cdn-cgi/access/certs`);
  if (!response.ok) throw new Error("Cannot load signing keys");

  const certificates = await response.json();
  const jwk = certificates.keys?.find(
    key => key.kid === header.kid &&
      key.kty === "RSA" &&
      (!key.alg || key.alg === "RS256") &&
      (!key.use || key.use === "sig")
  );

  if (!jwk) throw new Error("Signing key not found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(
    `${parts[0]}.${parts[1]}`
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    decodeBase64Url(parts[2]),
    signedData
  );

  if (!valid) throw new Error("Invalid signature");

  return payload;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return json({
          status: "ok",
          database: result?.connected === 1
            ? "connected"
            : "unavailable"
        });
      } catch {
        return json({
          status: "error",
          database: "unavailable"
        }, 503);
      }
    }

    if (url.pathname === "/api/admin/status") {
      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        await verifyAccess(request, env);
      } catch {
        return json({ error: "Unauthorized" }, 401);
      }

      try {
        const result = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM league_publications"
        ).first();

        return json({
          status: "ready",
          authenticated: true,
          database: "connected",
          publications: result.total
        });
      } catch {
        return json({
          status: "error",
          database: "unavailable"
        }, 503);
      }
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not found" }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};
