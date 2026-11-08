
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
        });
      } catch {
        return Response.json(
          { status: "error", database: "unavailable" },
          { status: 503 }
        );
      }
    }

    if (url.pathname.startsWith("/api/") ||
        url.pathname.startsWith("/admin")) {
      return new Response("Not found", { status: 404 });
    }

    return env.ASSETS.fetch(request);
  }
};
