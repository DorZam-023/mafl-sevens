
const json = (data, status = 200, extraHeaders = {}) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });

const fail = (message, status) =>
  json({ error: message }, status);

// Decode Base64URL data.
function decodeBase64Url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  return Uint8Array.from(
    atob(
      base64.padEnd(
        Math.ceil(base64.length / 4) * 4,
        "="
      )
    ),
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

// Verify Cloudflare Access authentication.
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

  if (
    header.alg !== "RS256" ||
    typeof header.kid !== "string"
  ) {
    throw new Error("Unsupported JWT");
  }

  const now = Math.floor(Date.now() / 1000);
  const issuer = `https://${team}`;

  const audiences = Array.isArray(payload.aud)
    ? payload.aud
    : [payload.aud];

  // Validate JWT claims.
  if (
    p// Validate JWT claims with safe diagnostics.
const claimChecks = {
  issuerMatches: payload.iss === issuer,
  audienceMatches: audiences.includes(audience),
  expirationValid:
    Number.isFinite(payload.exp) &&
    payload.exp > now,
  issuedAtValid:
    Number.isFinite(payload.iat) &&
    payload.iat <= now + 60,
  notBeforeValid:
    payload.nbf === undefined ||
    (
      Number.isFinite(payload.nbf) &&
      payload.nbf <= now
    )
};

if (Object.values(claimChecks).some(value => !value)) {
  console.error("MAFL JWT CLAIM CHECK:", claimChecks);
  throw new Error("JWT claims invalid");
}

  // Retrieve Cloudflare signing keys.
  const response = await fetch(
    `${issuer}/cdn-cgi/access/certs`
  );

  if (!response.ok) {
    throw new Error("Signing keys unavailable");
  }

  const certs = await response.json();

  const jwk = certs.keys?.find(
    k =>
      k.kid === header.kid &&
      k.kty === "RSA" &&
      (!k.alg || k.alg === "RS256") &&
      (!k.use || k.use === "sig")
  );

  if (!jwk) {
    throw new Error("Signing key not found");
  }

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(
      `${parts[0]}.${parts[1]}`
    )
  );

  if (!valid) {
    throw new Error("JWT signature invalid");
  }

  return payload;
}

// Validate imported league data.
function validateLeague(data) {
  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    throw new Error("Expected a JSON object");
  }

  const fields = [
    "teams",
    "players",
    "competitions",
    "fixtures"
  ];

  for (const field of fields) {
    if (!Array.isArray(data[field])) {
      throw new Error(`Missing array: ${field}`);
    }
  }

  const performances =
    Array.isArray(data.matchPerformance)
      ? data.matchPerformance
      : Array.isArray(data.match_performance)
        ? data.match_performance
        : null;

  const counts = {
    teams: data.teams.length,
    players: data.players.length,
    competitions: data.competitions.length,
    fixtures: data.fixtures.length,
    performances: performances?.length ?? 0
  };

  if (!counts.teams || !counts.competitions) {
    throw new Error(
      "Teams and competitions cannot be empty"
    );
  }

  return counts;
}

// Maximum JSON upload size: 8 MB.
const MAX_JSON_BYTES = 8 * 1024 * 1024;

// Main Cloudflare Worker.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --------------------------------
    // DATABASE HEALTH CHECK
    // --------------------------------

    if (path === "/api/health") {
      if (request.method !== "GET") {
        return fail("Method not allowed", 405);
      }

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
          "Health check failed:",
          error.message
        );

        return json({
          status: "error",
          database: "unavailable"
        }, 503);
      }
    }

    // --------------------------------
    // PUBLIC LEAGUE DATA
    // --------------------------------

    if (path === "/api/public/league") {
      if (request.method !== "GET") {
        return fail("Method not allowed", 405);
      }

      try {
        const result = await env.DB.prepare(
          "SELECT data_json, published_at " +
          "FROM league_publications " +
          "WHERE status = 'published' " +
          "ORDER BY published_at DESC, id DESC " +
          "LIMIT 1"
        ).first();

        if (!result) {
          return fail(
            "No published league data yet",
            404
          );
        }

        return json({
          publishedAt: result.published_at,
          league: JSON.parse(result.data_json)
        });
      } catch (error) {
        console.error(
          "Public league retrieval failed:",
          error.message
        );

        return fail(
          "Database unavailable",
          503
        );
      }
    }

    // --------------------------------
    // PROTECTED ADMIN API
    // --------------------------------

    if (path.startsWith("/api/admin/")) {
      if (
        !["GET", "POST"].includes(request.method)
      ) {
        return fail(
          "Method not allowed",
          405
        );
      }

      // Authenticate the administrator.
      try {
        await verifyAccess(request, env);
      } catch (error) {
        console.error(
          "MAFL ACCESS AUTH ERROR:",
          error instanceof Error
            ? error.message
            : "Unknown error"
        );

        return fail("Unauthorized", 401);
      }

      // --------------------------------
      // ADMIN STATUS
      // --------------------------------

      if (
        path === "/api/admin/status" &&
        request.method === "GET"
      ) {
        try {
          const result = await env.DB.prepare(
            "SELECT COUNT(*) AS total " +
            "FROM league_publications"
          ).first();

          return json({
            status: "ready",
            authenticated: true,
            database: "connected",
            publications: result?.total ?? 0
          });
        } catch (error) {
          console.error(
            "Status query failed:",
            error.message
          );

          return fail(
            "Database unavailable",
            503
          );
        }
      }

      // --------------------------------
      // UPLOAD LEAGUE JSON AS DRAFT
      // --------------------------------

      if (
        path === "/api/admin/publications" &&
        request.method === "POST"
      ) {
        const contentType =
          request.headers.get("content-type") || "";

        if (
          !/^application\/json(?:\s*;|\s*$)/i.test(
            contentType
          )
        ) {
          return fail(
            "Content-Type must be application/json",
            415
          );
        }

        const length = Number(
          request.headers.get("content-length") || 0
        );

        if (length > MAX_JSON_BYTES) {
          return fail(
            "JSON file is too large (8 MB limit)",
            413
          );
        }

        let body;

        try {
          const raw = await request.text();

          if (
            new TextEncoder().encode(raw).length >
            MAX_JSON_BYTES
          ) {
            return fail(
              "JSON file is too large (8 MB limit)",
              413
            );
          }

          body = JSON.parse(raw);
        } catch {
          return fail(
            "Invalid JSON body",
            400
          );
        }

        let counts;

        try {
          counts = validateLeague(body);
        } catch (error) {
          return fail(
            error.message,
            400
          );
        }

        try {
          const result = await env.DB.prepare(
            "INSERT INTO league_publications " +
            "(status, data_json, source_filename, " +
            "record_counts_json) " +
            "VALUES ('draft', ?, ?, ?)"
          )
            .bind(
              JSON.stringify(body),
              "league.json",
              JSON.stringify(counts)
            )
            .run();

          return json({
            status: "draft",
            id: result.meta.last_row_id,
            recordCounts: counts
          }, 201);
        } catch (error) {
          console.error(
            "Draft insert failed:",
            error.message
          );

          return fail(
            "Could not save draft",
            503
          );
        }
      }

      // --------------------------------
      // PUBLISH A SAVED DRAFT
      // --------------------------------

      const match = path.match(
        /^\/api\/admin\/publications\/(\d+)\/publish$/
      );

      if (
        match &&
        request.method === "POST"
      ) {
        const id = Number(match[1]);

        if (
          !Number.isSafeInteger(id) ||
          id < 1
        ) {
          return fail(
            "Invalid publication ID",
            400
          );
        }

        try {
          const result = await env.DB.prepare(
            "UPDATE league_publications " +
            "SET status = 'published', " +
            "published_at = CURRENT_TIMESTAMP " +
            "WHERE id = ? AND status = 'draft'"
          )
            .bind(id)
            .run();

          if (result.meta.changes !== 1) {
            return fail(
              "Draft not found or already published",
              404
            );
          }

          return json({
            status: "published",
            id
          });
        } catch (error) {
          console.error(
            "Publish failed:",
            error.message
          );

          return fail(
            "Could not publish draft",
            503
          );
        }
      }

      return fail("Not found", 404);
    }

    // --------------------------------
    // UNKNOWN API ROUTES
    // --------------------------------

    if (path.startsWith("/api/")) {
      return fail("Not found", 404);
    }

    // --------------------------------
    // STATIC WEBSITE / ADMIN DASHBOARD
    // --------------------------------

    return env.ASSETS.fetch(request);
  }
};
