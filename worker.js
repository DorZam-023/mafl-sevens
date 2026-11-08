
const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });

// Decode Base64URL data.
function decodeBase64Url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64.padEnd(
    Math.ceil(base64.length / 4) * 4,
    "="
  );

  return Uint8Array.from(
    atob(padded),
    c => c.charCodeAt(0)
  );
}

// Decode a JWT JSON component.
function decodeJson(value) {
  return JSON.parse(
    new TextDecoder().decode(
      decodeBase64Url(value)
    )
  );
}

// Verify Cloudflare Access JWT.
async function verifyAccess(request, env) {
  const token = request.headers.get(
    "Cf-Access-Jwt-Assertion"
  );

  if (!token) {
    throw new Error("Missing Access token");
  }

  const team = String(
    env.CF_ACCESS_TEAM_DOMAIN || ""
  )
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");

  const audience = String(
    env.CF_ACCESS_AUD || ""
  ).trim();

  if (
    !team ||
    !audience ||
    !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(team)
  ) {
    throw new Error("Invalid Access configuration");
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error(
      "Unsupported JWT algorithm or key ID"
    );
  }

  const issuer = `https://${team}`;
  const now = Math.floor(Date.now() / 1000);

  // Check issuer.
  if (payload.iss !== issuer) {
    throw new Error("JWT issuer mismatch");
  }

  // Check application audience.
  const audiences = Array.isArray(payload.aud)
    ? payload.aud
    : typeof payload.aud === "string"
      ? [payload.aud]
      : [];

  // Temporary audience diagnostics.
  // Do not log the JWT or actual audience values.
  if (!audiences.includes(audience)) {
    console.error("MAFL AUD DIAGNOSTIC:", {
      audienceMatches: false,
      tokenAudienceCount: audiences.length,
      configuredAudienceLength: audience.length,
      tokenAudienceLengths: audiences.map(
        value =>
          typeof value === "string"
            ? value.length
            : null
      )
    });

    throw new Error("JWT audience mismatch");
  }

  // Check expiration.
  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now
  ) {
    throw new Error(
      "JWT expired or missing expiration"
    );
  }

  // Check issued-at time.
  if (
    typeof payload.iat !== "number" ||
    payload.iat > now + 60
  ) {
    throw new Error("JWT issued-at time invalid");
  }

  // Check not-before time.
  if (
    payload.nbf !== undefined &&
    (
      typeof payload.nbf !== "number" ||
      payload.nbf > now
    )
  ) {
    throw new Error("JWT not yet valid");
  }

  // Retrieve Cloudflare public signing keys.
  let response;

  try {
    response = await fetch(
      `${issuer}/cdn-cgi/access/certs`
    );
  } catch {
    throw new Error(
      "Cannot connect to Access certificates endpoint"
    );
  }

  if (!response.ok) {
    throw new Error(
      `Access certificates request failed: HTTP ${response.status}`
    );
  }

  let certificates;

  try {
    certificates = await response.json();
  } catch {
    throw new Error(
      "Invalid Access certificates response"
    );
  }

  const jwk = certificates.keys?.find(
    key =>
      key.kid === header.kid &&
      key.kty === "RSA" &&
      (!key.alg || key.alg === "RS256") &&
      (!key.use || key.use === "sig")
  );

  if (!jwk) {
    throw new Error(
      "JWT signing key not found"
    );
  }

  let key;

  try {
    key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );
  } catch {
    throw new Error(
      "Unable to import JWT signing key"
    );
  }

  const signedData = new TextEncoder().encode(
    `${parts[0]}.${parts[1]}`
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    decodeBase64Url(parts[2]),
    signedData
  );

  if (!valid) {
    throw new Error(
      "JWT signature verification failed"
    );
  }

  return payload;
}

// Cloudflare Worker.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Database health check.
    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return json({
          status: "ok",
          database:
            result?.connected === 1
              ? "connected"
              : "unavailable"
        });
      } catch (error) {
        console.error(
          "Database health check failed:",
          error instanceof Error
            ? error.message
            : "Unknown database error"
        );

        return json({
          status: "error",
          database: "unavailable"
        }, 503);
      }
    }

    // Protected administrator status endpoint.
    if (url.pathname === "/api/admin/status") {
      if (request.method !== "GET") {
        return json({
          error: "Method not allowed"
        }, 405);
      }

      // Authenticate administrator.
      try {
        await verifyAccess(request, env);
      } catch (error) {
        // Log the error reason internally.
        // Never log JWTs or authentication cookies.
        console.error(
          "MAFL ACCESS AUTH ERROR:",
          error instanceof Error
            ? error.message
            : "Unknown authentication error"
        );

        return json({
          error: "Unauthorized"
        }, 401);
      }

      // Check publication storage.
      try {
        const result = await env.DB
          .prepare(
            "SELECT COUNT(*) AS total FROM league_publications"
          )
          .first();

        return json({
          status: "ready",
          authenticated: true,
          database: "connected",
          publications: result?.total ?? 0
        });
      } catch (error) {
        console.error(
          "MAFL DATABASE ERROR:",
          error instanceof Error
            ? error.message
            : "Unknown database error"
        );

        return json({
          status: "error",
          database: "unavailable"
        }, 503);
      }
    }

    // Reject unknown API routes.
    if (url.pathname.startsWith("/api/")) {
      return json({
        error: "Not found"
      }, 404);
    }

    // Preserve existing static website and dashboard.
    return env.ASSETS.fetch(request);
  }
};
