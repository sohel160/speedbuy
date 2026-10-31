// Cloudflare Worker: Secure VPN SOCKS5 config API
// Required binding: KV namespace named PROXY_KV
// Recommended secrets: SIGNING_KEY, CLASH_TOKEN
//
// Routes:
// POST /v1/session
// GET  /v1/config
// POST /v1/heartbeat
// POST /v1/refresh
// POST /v1/revoke
// GET  /v1/ip
// GET  /proxies
// GET  /config

const SERVERS = [
  {
    id: "proxy1",
    region: "Bangladesh-1",
    endpoint: "103.178.73.1:9169",
    host: "103.178.73.1",
    port: 9169,
    protocol: "socks5",
    weight: 100,
    enabled: true,
    supportsUdp: true,
    healthy: true,
    latencyMs: 45,
    load: 0.30,
    username: "movip21",
    password: "movip21",
  },
  {
    id: "proxy2",
    region: "Bangladesh-2",
    endpoint: "103.146.134.225:9169",
    host: "103.146.134.225",
    port: 9169,
    protocol: "socks5",
    weight: 95,
    enabled: true,
    supportsUdp: true,
    healthy: true,
    latencyMs: 50,
    load: 0.35,
    username: "movip21",
    password: "movip21",
  },
  {
    id: "proxy3",
    region: "Bangladesh-3",
    endpoint: "103.118.152.36:9169",
    host: "103.118.152.36",
    port: 9169,
    protocol: "socks5",
    weight: 90,
    enabled: true,
    supportsUdp: true,
    healthy: true,
    latencyMs: 55,
    load: 0.40,
    username: "movip21",
    password: "movip21",
  },
  {
    id: "proxy4",
    region: "Bangladesh-4",
    endpoint: "103.111.224.46:9169",
    host: "103.111.224.46",
    port: 9169,
    protocol: "socks5",
    weight: 85,
    enabled: true,
    supportsUdp: true,
    healthy: true,
    latencyMs: 60,
    load: 0.45,
    username: "movip21",
    password: "movip21",
  },
  {
    id: "proxy5",
    region: "US-West",
    endpoint: "202.5.36.149:9169",
    host: "202.5.36.149",
    port: 9169,
    protocol: "socks5",
    weight: 80,
    enabled: true,
    supportsUdp: true,
    healthy: true,
    latencyMs: 180,
    load: 0.50,
    username: "movieproxy",
    password: "movieproxy",
  },
];

const SESSION_TTL_SECONDS = 60 * 60;
const CONFIG_TTL_SECONDS = 5 * 60;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX = 60;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Version",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function errorResponse(message, status = 400) {
  return json({ error: message }, status);
}

function getServers() {
  return SERVERS.filter(server => server.enabled && server.healthy);
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function bearerToken(request) {
  const value = request.headers.get("Authorization") || "";
  const match = value.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function getSession(request, env) {
  const token = bearerToken(request);
  if (!token) return null;

  const raw = await env.PROXY_KV.get(`session:${token}`);
  if (!raw) return null;

  let session;
  try {
    session = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!session.expiresAt || session.expiresAt <= Date.now()) {
    await env.PROXY_KV.delete(`session:${token}`);
    return null;
  }

  return { token, ...session };
}

async function requireSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return { error: errorResponse("Invalid or expired session", 401) };
  return { session };
}

async function rateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucket = Math.floor(Date.now() / (RATE_LIMIT_WINDOW_SECONDS * 1000));
  const key = `rate:${ip}:${bucket}`;

  const current = Number(await env.PROXY_KV.get(key) || 0);
  if (current >= RATE_LIMIT_MAX) {
    return errorResponse("Rate limit exceeded", 429);
  }

  await env.PROXY_KV.put(key, String(current + 1), {
    expirationTtl: RATE_LIMIT_WINDOW_SECONDS + 5,
  });
  return null;
}

async function signPayload(payload, env) {
  const keyText = env.SIGNING_KEY;
  if (!keyText) throw new Error("Missing SIGNING_KEY Worker secret");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyText),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const bytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(JSON.stringify(payload))
  );

  return Array.from(new Uint8Array(bytes), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function publicServer(server) {
  return {
    id: server.id,
    region: server.region,
    endpoint: server.endpoint,
    host: server.host,
    port: server.port,
    protocol: server.protocol,
    weight: server.weight,
    supportsUdp: server.supportsUdp,
    latencyMs: server.latencyMs,
    load: server.load,
  };
}

function chooseServer(preferredId) {
  const servers = getServers();
  if (!servers.length) return null;

  if (preferredId) {
    const preferred = servers.find(server => server.id === preferredId);
    if (preferred) return preferred;
  }

  // Prefer lower latency and load, while retaining weight as a factor.
  return [...servers].sort((a, b) => {
    const scoreA = (a.latencyMs * 0.6) + (a.load * 100 * 0.4) - (a.weight * 0.05);
    const scoreB = (b.latencyMs * 0.6) + (b.load * 100 * 0.4) - (b.weight * 0.05);
    return scoreA - scoreB;
  })[0];
}

async function createSession(request, env) {
  const body = await request.json().catch(() => ({}));
  const deviceId = String(body.deviceId || "").trim();

  if (!deviceId || deviceId.length > 200) {
    return errorResponse("A valid deviceId is required");
  }

  const token = randomToken();
  const now = Date.now();
  const session = {
    deviceId,
    createdAt: now,
    expiresAt: now + SESSION_TTL_SECONDS * 1000,
    selectedServerId: null,
  };

  await env.PROXY_KV.put(`session:${token}`, JSON.stringify(session), {
    expirationTtl: SESSION_TTL_SECONDS,
  });

  return json({
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: SESSION_TTL_SECONDS,
  });
}

async function getConfig(request, env) {
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;

  const selected = new URL(request.url).searchParams.get("serverId");
  const server = chooseServer(selected || auth.session.selectedServerId);

  if (!server) return errorResponse("No healthy proxy servers available", 503);

  const now = Date.now();
  const expiresAt = now + CONFIG_TTL_SECONDS * 1000;

  const config = {
    server: {
      ...publicServer(server),
      username: server.username,
      password: server.password,
    },
    issuedAt: now,
    expiresAt,
  };

  // Signature covers the complete config payload, including credentials.
  const signature = await signPayload(config, env);

  return json({
    config,
    signature,
    signatureAlgorithm: "HMAC-SHA256",
  }, 200, {
    "Cache-Control": "no-store",
  });
}

async function heartbeat(request, env) {
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;

  const body = await request.json().catch(() => ({}));
  const session = {
    deviceId: auth.session.deviceId,
    createdAt: auth.session.createdAt,
    expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000,
    selectedServerId: body.serverId || auth.session.selectedServerId || null,
    lastHeartbeatAt: Date.now(),
  };

  await env.PROXY_KV.put(`session:${auth.session.token}`, JSON.stringify(session), {
    expirationTtl: SESSION_TTL_SECONDS,
  });

  return json({ ok: true, expiresIn: SESSION_TTL_SECONDS });
}

async function refreshSession(request, env) {
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;

  const token = randomToken();
  const now = Date.now();
  const session = {
    deviceId: auth.session.deviceId,
    createdAt: now,
    expiresAt: now + SESSION_TTL_SECONDS * 1000,
    selectedServerId: auth.session.selectedServerId || null,
  };

  await env.PROXY_KV.put(`session:${token}`, JSON.stringify(session), {
    expirationTtl: SESSION_TTL_SECONDS,
  });
  await env.PROXY_KV.delete(`session:${auth.session.token}`);

  return json({
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: SESSION_TTL_SECONDS,
  });
}

async function revokeSession(request, env) {
  const token = bearerToken(request);
  if (!token) return errorResponse("Missing bearer token", 401);

  await env.PROXY_KV.delete(`session:${token}`);
  return json({ ok: true });
}

async function getIp(request) {
  return json({
    ip: request.headers.get("CF-Connecting-IP") || null,
    country: request.cf?.country || null,
    colo: request.cf?.colo || null,
  });
}

function clashConfig() {
  const proxies = getServers().map(server => ({
    name: server.region,
    type: "socks5",
    server: server.host,
    port: server.port,
    username: server.username,
    password: server.password,
    udp: server.supportsUdp,
  }));

  return {
    "mixed-port": 7890,
    "allow-lan": false,
    mode: "rule",
    "log-level": "warning",
    proxies,
    "proxy-groups": [{
      name: "SecureVPN",
      type: "url-test",
      proxies: proxies.map(proxy => proxy.name),
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
    }],
    rules: ["MATCH,SecureVPN"],
  };
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const limited = await rateLimit(request, env);
  if (limited) return limited;

  if (path === "/v1/session" && request.method === "POST") {
    return createSession(request, env);
  }

  if (path === "/v1/config" && request.method === "GET") {
    return getConfig(request, env);
  }

  if (path === "/v1/heartbeat" && request.method === "POST") {
    return heartbeat(request, env);
  }

  if (path === "/v1/refresh" && request.method === "POST") {
    return refreshSession(request, env);
  }

  if (path === "/v1/revoke" && request.method === "POST") {
    return revokeSession(request, env);
  }

  if (path === "/v1/ip" && request.method === "GET") {
    return getIp(request);
  }

  if ((path === "/proxies" || path === "/config") && request.method === "GET") {
    const expected = env.CLASH_TOKEN;
    const supplied = url.searchParams.get("token");

    if (!expected || supplied !== expected) {
      return errorResponse("Unauthorized", 401);
    }

    return new Response(JSON.stringify(clashConfig(), null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        ...corsHeaders(),
        "Cache-Control": "no-store",
      },
    });
  }

  return errorResponse("Not found", 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      // Avoid logging request headers, tokens, or proxy credentials.
      console.error("Worker request failed:", error?.message || "Unknown error");
      return errorResponse("Internal server error", 500);
    }
  },
};
