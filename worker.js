
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return Response.json({
          status: "ok",
          database: result?.connected === 1
            ? "connected"
            : "unavailable"
        }, {
          headers: { "Cache-Control": "no-store" }
        });
      } catch {
        return Response.json({
          status: "error",
          database: "unavailable"
        }, {
          status: 503,
          headers: { "Cache-Control": "no-store" }
        });
      }
    }

    if (url.pathname.startsWith("/api/")) {
      return new Response("Not found", { status: 404 });
    }

    return env.ASSETS.fetch(request);
  }
};
