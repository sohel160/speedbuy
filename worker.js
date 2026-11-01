// Secure VPN — Cloudflare Worker
// Configure these Worker secrets: SIGNING_KEY and CLASH_TOKEN.
// Optional variables: TOKEN_TTL_MS, CONFIG_TTL_MS, RATE_LIMIT_WINDOW_MS,
// RATE_LIMIT_MAX.
//
// NOTE: sessions and rate limits below are in-memory demo stores.
// Use Durable Objects or another persistent store before production use.

const SERVERS = [
  {
    id: "proxy1", region: "Bangladesh-1", endpoint: "103.178.73.1:9169",
    host: "103.178.73.1", port: 9169, protocol: "socks5",
    weight: 100, enabled: true, supportsUdp: true, healthy: true,
    latencyMs: 45, load: 0.30, username: "movip21", password: "movip21",
  },
  {
    id: "proxy2", region: "Bangladesh-2", endpoint: "103.146.134.225:9169",
    host: "103.146.134.225", port: 9169, protocol: "socks5",
    weight: 95, enabled: true, supportsUdp: true, healthy: true,
    latencyMs: 50, load: 0.35, username: "movip21", password: "movip21",
  },
  {
    id: "proxy3", region: "Bangladesh-3", endpoint: "103.118.152.36:9169",
    host: "103.118.152.36", port: 9169, protocol: "socks5",
    weight: 90, enabled: true, supportsUdp: true, healthy: true,
    latencyMs: 55, load: 0.40, username: "movip21", password: "movip21",
  },
  {
    id: "proxy4", region: "Bangladesh-4", endpoint: "103.111.224.46:9169",
    host: "103.111.224.46", port: 9169, protocol: "socks5",
    weight: 85, enabled: true, supportsUdp: true, healthy: true,
    latencyMs: 60, load: 0.45, username: "movip21", password: "movip21",
  },
  {
    id: "proxy5", region: "US-West", endpoint: "202.5.36.149:9169",
    host: "202.5.36.149", port: 9169, protocol: "socks5",
    weight: 80, enabled: true, supportsUdp: true, healthy: true,
    latencyMs: 180, load: 0.50, username: "movieproxy", password: "movieproxy",
  },
].map((server) => ({ ...server, failures: 0, lastFailure: 0 }));

const MAX_FAILURES = 3;
const FAIL_COOLDOWN_MS = 2 * 60 * 1000;

// Demo-only in-memory stores. They are not shared across Worker instances.
const sessions = new Map(); // token -> session
const rateLimit = new Map(); // IP -> { count, resetAt }

function now() {
  return Date.now();
}

function randomToken() {
  return crypto.randomUUID().replace(/-/g, "") +
    crypto.randomUUID().replace(/-/g, "");
}

async function hmacSha256(key, data) {
  const encoder = new TextEncoder();
  const keyData = typeof key === "string" ? encoder.encode(key) : key;
  const messageData = typeof data === "string" ? encoder.encode(data) : data;

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
  const bytes = Array.from(new Uint8Array(signature));

  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signPayload(payload, signingKey) {
  return hmacSha256(signingKey, JSON.stringify(payload));
}

function cors(headers = {}) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    ...headers,
  };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: cors({
      "Content-Type": "application/json; charset=utf-8",
      ...headers,
    }),
  });
}

function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

function rateLimited(ip, windowMs, maxRequests) {
  const currentTime = now();
  let entry = rateLimit.get(ip);

  if (!entry || currentTime > entry.resetAt) {
    entry = { count: 0, resetAt: currentTime + windowMs };
  }

  entry.count += 1;
  rateLimit.set(ip, entry);
  return entry.count > maxRequests;
}

function requireAuth(authorization) {
  if (!authorization?.startsWith("Bearer ")) return null;

  const token = authorization.slice(7);
  const session = sessions.get(token);

  if (!session || session.expiresAt <= now()) {
    sessions.delete(token);
    return null;
  }

  return session;
}

function selectServer(preferredRegion, forceServerId) {
  const enabled = SERVERS.filter((server) => server.enabled);
  if (!enabled.length) return null;

  if (forceServerId) {
    const manual = enabled.find((server) => server.id === forceServerId);
    if (manual) return { server: manual, reason: "manual selection" };
  }

  const currentTime = now();
  const available = enabled.filter((server) =>
    server.healthy &&
    server.failures < MAX_FAILURES &&
    !(server.failures > 0 &&
      currentTime - server.lastFailure < FAIL_COOLDOWN_MS)
  );

  const pool = available.length ? available : enabled;
  const matchingRegion = preferredRegion
    ? pool.filter(
        (server) =>
          server.region.toLowerCase() === preferredRegion.toLowerCase()
      )
    : [];

  const regionPool = matchingRegion.length ? matchingRegion : pool;

  const score = (server) => {
    const loadFactor = 1 + Math.min(Math.max(server.load ?? 0, 0), 10);
    const latencySeconds = Math.min(
      Math.max((server.latencyMs ?? 0) / 1000, 0),
      60
    );
    return (Math.max(server.weight, 1) / loadFactor) /
      (1 + latencySeconds);
  };

  const best = regionPool.reduce((a, b) => score(a) >= score(b) ? a : b);

  return {
    server: best,
    reason: best.healthy
      ? "weighted health/load/latency selection"
      : "fallback (no healthy servers)",
  };
}

function publicServer(server) {
  return {
    id: server.id,
    region: server.region,
    endpoint: server.endpoint,
    host: server.host,
    port: Number(server.port),
    protocol: server.protocol,
    weight: Number(server.weight),
    enabled: Boolean(server.enabled),
    supportsUdp: Boolean(server.supportsUdp),
    latencyMs: server.latencyMs ?? null,
    load: server.load ?? null,
    healthy: Boolean(server.healthy),
  };
}

function generateClashProxies() {
  return SERVERS.filter((server) => server.enabled).map((server) => ({
    name: server.id,
    type: "socks5",
    server: server.host,
    port: server.port,
    username: server.username,
    password: server.password,
    udp: server.supportsUdp,
  }));
}

function generateClashConfig(request, clashToken) {
  const origin = new URL(request.url).origin;

  return `
mixed-port: 7893
allow-lan: true
mode: rule
log-level: info
ipv6: false

proxy-providers:
  myprovider:
    type: http
    url: "${origin}/proxies?token=${encodeURIComponent(clashToken)}"
    interval: 3600
    path: ./proxies.yaml
    health-check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 60

proxy-groups:
  - name: LOAD-BALANCE
    type: load-balance
    strategy: consistent-hashing
    url: http://www.gstatic.com/generate_204
    interval: 120
    lazy: true
    use:
      - myprovider

  - name: AUTO
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 180
    tolerance: 100
    lazy: true
    use:
      - myprovider

  - name: HYBRID
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 120
    proxies:
      - LOAD-BALANCE
      - AUTO
      - DIRECT

  - name: SPEED
    type: select
    proxies:
      - HYBRID
      - LOAD-BALANCE
      - AUTO
      - DIRECT

rules:
  - GEOIP,BD,DIRECT
  - DOMAIN-SUFFIX,googlevideo.com,SPEED
  - DOMAIN-SUFFIX,youtube.com,SPEED
  - DOMAIN-SUFFIX,ytimg.com,SPEED
  - DOMAIN-SUFFIX,gstatic.com,SPEED
  - DOMAIN-SUFFIX,googleapis.com,SPEED
  - DOMAIN-SUFFIX,cloudflare.com,SPEED
  - DOMAIN-SUFFIX,cloudflare-dns.com,SPEED
  - DOMAIN-SUFFIX,akamaihd.net,SPEED
  - DOMAIN-SUFFIX,fastly.net,SPEED
  - DOMAIN-SUFFIX,cdn.jsdelivr.net,SPEED
  - DOMAIN-SUFFIX,openai.com,SPEED
  - DOMAIN-SUFFIX,chatgpt.com,SPEED
  - DOMAIN-SUFFIX,facebook.com,SPEED
  - DOMAIN-SUFFIX,fbcdn.net,SPEED
  - DOMAIN-SUFFIX,whatsapp.net,SPEED
  - DOMAIN-SUFFIX,telegram.org,SPEED
  - DOMAIN-SUFFIX,epicgames.com,SPEED
  - DOMAIN-SUFFIX,riotgames.com,SPEED
  - DOMAIN-SUFFIX,pubgmobile.com,SPEED
  - DOMAIN-SUFFIX,tencent.com,SPEED
  - MATCH,SPEED
`.trim();
}

function verifyAttestation(attestation) {
  // Placeholder only. This does NOT cryptographically verify attestation.
  return typeof attestation === "string" && attestation.length > 0
    ? true
    : null;
}

function allowedClashUserAgent(request) {
  const ua = request.headers.get("User-Agent") || "";
  return ["Clash", "clash", "Meta", "FiClash", "Stash", "okhttp", "Dalvik"]
    .some((value) => ua.includes(value));
}

function yamlQuote(value) {
  return JSON.stringify(String(value));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = clientIp(request);

    // Worker environment bindings must be read inside fetch(), not globally.
    const SIGNING_KEY = env.SIGNING_KEY;
    const CLASH_TOKEN = env.CLASH_TOKEN;
    const TOKEN_TTL_MS = Number(env.TOKEN_TTL_MS || "900000");
    const CONFIG_TTL_MS = Number(env.CONFIG_TTL_MS || "3600000");
    const RATE_LIMIT_WINDOW_MS = Number(env.RATE_LIMIT_WINDOW_MS || "60000");
    const RATE_LIMIT_MAX = Number(env.RATE_LIMIT_MAX || "60");

    if (!SIGNING_KEY || !CLASH_TOKEN) {
      return json({ error: "Worker secrets are not configured" }, 500);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors() });
    }

    if (rateLimited(ip, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX)) {
      return json({ error: "rate limited", retryable: true }, 429);
    }

    // POST /v1/session
    if (path === "/v1/session" && request.method === "POST") {
      try {
        const body = await request.json();
        const { deviceId, attestation, appVersion } = body || {};

        if (typeof deviceId !== "string" || !deviceId.trim()) {
          return json({ error: "device_id required" }, 400);
        }

        const token = randomToken();
        const expiresAt = now() + TOKEN_TTL_MS;

        sessions.set(token, {
          deviceId: deviceId.trim(),
          registered: true,
          expiresAt,
          integrityOk: verifyAttestation(attestation),
          appVersion: appVersion || null,
        });

        return json({
          token,
          accessToken: token,
          tokenType: "Bearer",
          expiresIn: Math.floor(TOKEN_TTL_MS / 1000),
          expiresAt: new Date(expiresAt).toISOString(),
          deviceId: deviceId.trim(),
          registered: true,
        });
      } catch {
        return json({ error: "invalid request" }, 400);
      }
    }

    // GET or POST /v1/config
    if (
      path === "/v1/config" &&
      (request.method === "GET" || request.method === "POST")
    ) {
      let session = requireAuth(request.headers.get("Authorization"));
      let preferredRegion = url.searchParams.get("region") || undefined;
      let forceServerId = url.searchParams.get("server") || undefined;

      if (request.method === "POST") {
        try {
          const body = await request.clone().json();

          if (body) {
            if (!session && body.token) {
              session = sessions.get(body.token) || null;
              if (session && session.expiresAt <= now()) session = null;
            }

            preferredRegion = body.preferredRegion || preferredRegion;
            forceServerId = body.forceServerId || forceServerId;
          }
        } catch {
          // Ignore an absent or invalid optional JSON body.
        }
      }

      if (!session) return json({ error: "unauthenticated" }, 401);

      const selection = selectServer(preferredRegion, forceServerId);
      if (!selection?.server) {
        return json({ error: "no servers available" }, 503);
      }

      const server = selection.server;
      const signedAt = new Date(now()).toISOString();
      const expiresAt = new Date(now() + CONFIG_TTL_MS).toISOString();
      const signature = await signPayload(
        { server: server.id, expiresAt, signedAt },
        SIGNING_KEY
      );

      const newToken = randomToken();
      const tokenExpiresAt = now() + TOKEN_TTL_MS;

      sessions.set(newToken, {
        ...session,
        expiresAt: tokenExpiresAt,
        serverId: server.id,
      });

      return json({
        server: publicServer(server),
        username: server.username,
        password: server.password,
        expiresAt,
        signedAt,
        signature,
        servers: SERVERS.map(publicServer),
        token: newToken,
        tokenExpiresAt: new Date(tokenExpiresAt).toISOString(),
        selectionReason: selection.reason,
      });
    }

    // POST /v1/heartbeat
    if (path === "/v1/heartbeat" && request.method === "POST") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);

      try {
        const body = await request.json();
        const server = SERVERS.find((item) => item.id === body?.serverId);

        if (server) {
          server.load = Math.min(1, (server.load || 0) + 0.01);
        }

        return json({
          ok: true,
          tokenExpiresAt: new Date(session.expiresAt).toISOString(),
          serverHealthy: server ? server.healthy : false,
        });
      } catch {
        return json({ error: "invalid request" }, 400);
      }
    }

    // POST /v1/refresh
    if (path === "/v1/refresh" && request.method === "POST") {
      const oldToken = request.headers.get("Authorization")?.slice(7);
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);

      const newToken = randomToken();
      const expiresAt = now() + TOKEN_TTL_MS;

      sessions.set(newToken, { ...session, expiresAt });
      sessions.delete(oldToken);

      return json({
        token: newToken,
        expiresAt: new Date(expiresAt).toISOString(),
      });
    }

    // POST /v1/revoke
    if (path === "/v1/revoke" && request.method === "POST") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);

      try {
        const body = await request.json();

        if (body?.deviceId && body.deviceId !== session.deviceId) {
          return json({ error: "device_id mismatch" }, 403);
        }

        for (const [token, storedSession] of sessions.entries()) {
          if (storedSession.deviceId === session.deviceId) {
            sessions.delete(token);
          }
        }

        return json({ revoked: true });
      } catch {
        return json({ error: "invalid request" }, 400);
      }
    }

    // GET /v1/ip
    if (path === "/v1/ip" && request.method === "GET") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);
      return json({ ip });
    }

    // GET /proxies — Clash-format proxy provider
    if (path === "/proxies" && request.method === "GET") {
      if (url.searchParams.get("token") !== CLASH_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }

      if (!allowedClashUserAgent(request)) {
        return new Response("Not Found", { status: 404 });
      }

      const proxies = generateClashProxies();
      const yaml = "proxies:\n" + proxies.map((proxy) =>
        `  - {name: ${yamlQuote(proxy.name)}, type: ${proxy.type}, ` +
        `server: ${proxy.server}, port: ${proxy.port}, ` +
        `username: ${yamlQuote(proxy.username)}, ` +
        `password: ${yamlQuote(proxy.password)}, udp: ${proxy.udp}}`
      ).join("\n") + "\n";

      return new Response(yaml, {
        headers: cors({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    }

    // GET /config — full Clash config
    if (path === "/config" && request.method === "GET") {
      if (url.searchParams.get("token") !== CLASH_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }

      if (!allowedClashUserAgent(request)) {
        return new Response("Not Found", { status: 404 });
      }

      return new Response(generateClashConfig(request, CLASH_TOKEN), {
        headers: cors({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    }

    return json({ error: "not found" }, 404);
  },
};
