export default {
  async fetch(request, env, ctx) {
    // Map of prefix -> upstream origin
    const API_MAP = {
      "mal": "https://myanimelist.net",
    };

    // Optional: lock down who can call your proxy (recommended).
    // If empty, it will mirror any Origin.
    const ALLOWED_ORIGINS = [
      // "https://anibridge.eliasbenb.dev"
      // "http://localhost:8000",
    ];

    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return handleOptions(request, ALLOWED_ORIGINS);
    }

    const allowedMethods = new Set(["GET", "HEAD", "POST"]);
    if (!allowedMethods.has(request.method)) {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const { prefix, restPath } = parsePrefixPath(url.pathname);
    if (!prefix || !restPath) {
      return new Response(
        `Bad request. Use /<prefix>/<path...>. Known prefixes: ${Object.keys(API_MAP).join(", ")}`,
        { status: 400 }
      );
    }

    const baseOrigin = API_MAP[prefix];
    if (!baseOrigin) {
      return new Response(
        `Unknown prefix "${prefix}". Known prefixes: ${Object.keys(API_MAP).join(", ")}`,
        { status: 400 }
      );
    }

    const upstreamUrl = new URL(baseOrigin);
    upstreamUrl.pathname = restPath;
    upstreamUrl.search = url.search;

    const upstreamReq = new Request(upstreamUrl.toString(), request);
    const sanitizedHeaders = new Headers(upstreamReq.headers);

    sanitizedHeaders.delete("host");
    sanitizedHeaders.delete("origin");
    sanitizedHeaders.delete("referer");
    sanitizedHeaders.delete("cf-connecting-ip");
    sanitizedHeaders.delete("cf-ipcountry");
    sanitizedHeaders.delete("cf-ray");
    sanitizedHeaders.delete("x-forwarded-for");
    sanitizedHeaders.delete("x-forwarded-proto");
    sanitizedHeaders.delete("x-real-ip");

    const finalUpstreamReq = new Request(upstreamReq, { headers: sanitizedHeaders });

    // Fetch upstream
    const upstreamResp = await fetch(finalUpstreamReq);

    // Return upstream response + CORS headers
    return withCors(upstreamResp, request, ALLOWED_ORIGINS);
  },
};

function parsePrefixPath(pathname) {
  // pathname: "/mal/v1/oauth2/token" -> prefix "mal", rest "/v1/oauth2/token"
  const parts = pathname.split("/");
  // ["", "mal", "v1", ...]
  const prefix = parts[1] || "";
  const rest = "/" + parts.slice(2).join("/");
  if (!prefix || rest === "/") return { prefix: "", restPath: "" };
  return { prefix, restPath: rest };
}

function handleOptions(request, allowedOrigins) {
  const origin = request.headers.get("Origin");
  const reqMethod = request.headers.get("Access-Control-Request-Method");
  const reqHeaders = request.headers.get("Access-Control-Request-Headers") || "";

  if (origin && reqMethod) {
    const allowOrigin = pickAllowedOrigin(origin, allowedOrigins);
    if (!allowOrigin) return new Response(null, { status: 403 });

    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": allowOrigin,
        "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
        "Access-Control-Allow-Headers": reqHeaders,
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin",
      },
    });
  }

  return new Response(null, { headers: { Allow: "GET, HEAD, POST, OPTIONS" } });
}

function withCors(response, request, allowedOrigins) {
  const origin = request.headers.get("Origin");
  const headers = new Headers(response.headers);

  if (origin) {
    const allowOrigin = pickAllowedOrigin(origin, allowedOrigins);
    if (!allowOrigin) return new Response("Forbidden", { status: 403 });
    headers.set("Access-Control-Allow-Origin", allowOrigin);
    headers.append("Vary", "Origin");
  } else {
    headers.set("Access-Control-Allow-Origin", "*");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function pickAllowedOrigin(origin, allowedOrigins) {
  if (!allowedOrigins || allowedOrigins.length === 0) return origin;
  return allowedOrigins.includes(origin) ? origin : "";
}
