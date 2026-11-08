// MAFL Sevens admin Worker — Stage 1 (no write APIs)
// Protect the entire admin Worker using Cloudflare Access.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB.prepare("SELECT 1 AS connected").first();
        return Response.json({status: "ok", database: result?.connected === 1 ? "connected" : "unavailable"}, {headers: {"Cache-Control": "no-store"}});
      } catch {
        return Response.json({status: "error", database: "unavailable"}, {status: 503, headers: {"Cache-Control": "no-store"}});
      }
    }
    if (url.pathname === "/admin") return Response.redirect(new URL("/admin/", request.url), 302);
    if (url.pathname === "/admin/") {
      const page = await env.ASSETS.fetch(new Request(new URL("/admin/index.html", request.url), request));
      const headers = new Headers(page.headers);
      headers.set("Cache-Control", "no-store");
      headers.set("X-Content-Type-Options", "nosniff");
      headers.set("Referrer-Policy", "same-origin");
      return new Response(page.body, {status: page.status, headers});
    }
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/admin/")) {
      return new Response("Not found", {status: 404});
    }
    return env.ASSETS.fetch(request);
  }
};
