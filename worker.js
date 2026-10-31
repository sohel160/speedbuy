// Secure VPN — Cloudflare Worker
// Configuration API, authentication backend, and server-selection service.
//
// Endpoints:
//   POST /v1/session        - register device + issue short-lived access token
//   GET  /v1/config         - fetch signed SOCKS5 config (auto or manual selection)
//   POST /v1/heartbeat      - report bytes + server health
//   POST /v1/refresh        - rotate short-lived token
//   POST /v1/revoke         - revoke a device/session
//   GET  /v1/ip             - get client's public IP
//   GET  /proxies           - Clash-format proxy list (for external clients)
//   GET  /config            - Clash-format full config (for external clients)
//
// Security design:
//   - No permanent secret is embedded in the client. The app proves itself via a short-lived
//     bearer token issued after device registration (+ optional integrity attestation).
//   - Config responses are signed (HMAC-SHA256) and carry an expiration; the app verifies both.
//   - Rate limiting is applied per device/IP.
//   - HTTPS only (enforced by Cloudflare).

import { createHmac, timingSafeEqual } from "crypto";

// ---------------------------------------------------------------------------
// Configuration (tuned via environment variables / Cloudflare secrets)
// ---------------------------------------------------------------------------
const SIGNING_KEY = envOrDefault("SIGNING_KEY", crypto.randomUUID());
const TOKEN_TTL_MS = Number(envOrDefault("TOKEN_TTL_MS", "900000")); // 15 min default
const CONFIG_TTL_MS = Number(envOrDefault("CONFIG_TTL_MS", "3600000")); // 1 h
const RATE_LIMIT_WINDOW_MS = Number(envOrDefault("RATE_LIMIT_WINDOW_MS", "60000"));
const RATE_LIMIT_MAX = Number(envOrDefault("RATE_LIMIT_MAX", "60"));

// Clash config token (for external clients)
const CLASH_TOKEN = envOrDefault("CLASH_TOKEN", "abc123");

function envOrDefault(name, fallback) {
  try {
    const v = env[name];
    if (v !== undefined && v !== null && v !== "") return v;
  } catch (e) { /* env may not exist in local preview */ }
  return fallback;
}

// ---------------------------------------------------------------------------
// VPN server pool (from user's config-script.txt)
// ---------------------------------------------------------------------------
// These are the user's actual proxy servers.
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
].map((s) => ({ ...s, failures: 0, lastFailure: 0 }));

const MAX_FAILURES = 3;
const FAIL_COOLDOWN_MS = 2 * 60 * 1000;

// ---------------------------------------------------------------------------
// In-memory session / rate-limit stores (dev demo; use KV/Durable Objects in prod)
// ---------------------------------------------------------------------------
const sessions = new Map(); // token -> { deviceId, expiresAt, registered }
const rateLimit = new Map(); // key -> { count, resetAt }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function now() { return Date.now(); }

function hmacSha256(key, data) {
  return createHmac("sha256", key).update(data).digest("base64url");
}

function randomToken() {
  return crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
}

function rateLimited(ip) {
  const entry = rateLimit.get(ip) || { count: 0, resetAt: now() + RATE_LIMIT_WINDOW_MS };
  if (now() > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now() + RATE_LIMIT_WINDOW_MS;
  }
  entry.count++;
  rateLimit.set(ip, entry);
  return entry.count > RATE_LIMIT_MAX;
}

function selectServer(preferredRegion, forceServerId) {
  const enabled = SERVERS.filter((s) => s.enabled);
  if (enabled.length === 0) return null;

  // Manual override.
  if (forceServerId) {
    const manual = SERVERS.find((s) => s.id === forceServerId);
    if (manual) return { server: manual, reason: "manual selection" };
  }

  // Exclude failed / cooling-down servers.
  const n = now();
  const available = enabled.filter(
    (s) =>
      s.healthy &&
      !(s.failures >= MAX_FAILURES) &&
      !(s.failures > 0 && n - s.lastFailure < FAIL_COOLDOWN_MS)
  );
  const pool = available.length ? available : enabled;

  // Region preference.
  const regionPool =
    preferredRegion && pool.some((s) => s.region.toLowerCase() === preferredRegion.toLowerCase())
      ? pool.filter((s) => s.region.toLowerCase() === preferredRegion.toLowerCase())
      : pool;

  // Weighted health/load/latency selection.
  const score = (s) => {
    const loadFactor = 1 + Math.min(Math.max(s.load ?? 0, 0), 10);
    const latencySec = Math.min(Math.max((s.latencyMs ?? 0) / 1000, 0), 60);
    return (Math.max(s.weight, 1) / loadFactor) / (1 + latencySec);
  };

  const best = regionPool.reduce((a, b) => (score(a) >= score(b) ? a : b));
  return {
    server: best,
    reason: best.healthy ? "weighted health/load/latency selection" : "fallback (no healthy servers)",
  };
}

function signPayload(payload) {
  return hmacSha256(SIGNING_KEY, JSON.stringify(payload));
}

function cors(init = {}) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    ...init,
  };
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...cors(extra) },
  });
}

function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

// ---------------------------------------------------------------------------
// Clash-format helpers
// ---------------------------------------------------------------------------
function generateClashProxies() {
  return SERVERS.filter(s => s.enabled).map(s => ({
    name: s.id,
    type: "socks5",
    server: s.host,
    port: s.port,
    username: s.username,
    password: s.password,
    udp: s.supportsUdp,
  }));
}

function generateClashConfig(request) {
  const url = new URL(request.url);
  const origin = url.origin;
  const proxies = generateClashProxies();
  const proxyNames = proxies.map(p => p.name);
  
  return `
mixed-port: 7893
allow-lan: true
mode: rule
log-level: info
ipv6: false

proxy-providers:
  myprovider:
    type: http
    url: "${origin}/proxies?token=${CLASH_TOKEN}"
    interval: 3600
    path: ./proxies.yaml
    health-check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 60

proxy-groups:

  # ⚡ Max speed (parallel)
  - name: LOAD-BALANCE
    type: load-balance
    strategy: consistent-hashing
    url: http://www.gstatic.com/generate_204
    interval: 120
    lazy: true
    use:
      - myprovider

  # 🔥 Smart fastest
  - name: AUTO
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 180
    tolerance: 100
    lazy: true
    use:
      - myprovider

  # 🛡 Hybrid (speed + stability)
  - name: HYBRID
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 120
    proxies:
      - LOAD-BALANCE
      - AUTO
      - DIRECT

  # 🎯 Final selector
  - name: SPEED🔥
    type: select
    proxies:
      - HYBRID
      - LOAD-BALANCE
      - AUTO
      - DIRECT

rules:

  # 🇧🇩 Local traffic bypass (BIG SPEED BOOST)
  - GEOIP,BD,DIRECT

  # 🚀 Streaming / CDN
  - DOMAIN-SUFFIX,googlevideo.com,SPEED🔥
  - DOMAIN-SUFFIX,youtube.com,SPEED🔥
  - DOMAIN-SUFFIX,ytimg.com,SPEED🔥
  - DOMAIN-SUFFIX,gstatic.com,SPEED🔥
  - DOMAIN-SUFFIX,googleapis.com,SPEED🔥
  - DOMAIN-SUFFIX,cloudflare.com,SPEED🔥
  - DOMAIN-SUFFIX,cloudflare-dns.com,SPEED🔥
  - DOMAIN-SUFFIX,akamaihd.net,SPEED🔥
  - DOMAIN-SUFFIX,fastly.net,SPEED🔥
  - DOMAIN-SUFFIX,cdn.jsdelivr.net,SPEED🔥

  # ⚡ Apps / API
  - DOMAIN-SUFFIX,openai.com,SPEED🔥
  - DOMAIN-SUFFIX,chatgpt.com,SPEED🔥
  - DOMAIN-SUFFIX,facebook.com,SPEED🔥
  - DOMAIN-SUFFIX,fbcdn.net,SPEED🔥
  - DOMAIN-SUFFIX,whatsapp.net,SPEED🔥
  - DOMAIN-SUFFIX,telegram.org,SPEED🔥

  # 🎮 Gaming
  - DOMAIN-SUFFIX,epicgames.com,SPEED🔥
  - DOMAIN-SUFFIX,riotgames.com,SPEED🔥
  - DOMAIN-SUFFIX,pubgmobile.com,SPEED🔥
  - DOMAIN-SUFFIX,tencent.com,SPEED🔥

  # 🧠 Default
  - MATCH,SPEED🔥
`.trim();
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function requireAuth(authorization) {
  if (!authorization || !authorization.startsWith("Bearer ")) return null;
  const token = authorization.slice(7);
  const session = sessions.get(token);
  if (!session || session.expiresAt < now()) return null;
  return session;
}

// ---------------------------------------------------------------------------
// Worker entry point
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = clientIp(request);

    // Rate limit applies to all mutating/config endpoints.
    if (rateLimited(ip)) {
      return json({ error: "rate limited", retryable: true }, 429);
    }

    // CORS preflight.
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors() });
    }

    // ---- POST /v1/session ------------------------------------------------
    if (path === "/v1/session" && request.method === "POST") {
      try {
        const { deviceId, attestation, appVersion } = await request.json();
        if (!deviceId) {
          return json({ error: "device_id required" }, 400);
        }

        // App integrity verification (where supported). `attestation` is an opaque
        // JWT-like attestation (e.g. Play Integrity). We accept it but do not trust
        // client headers for identity; identity is the server-issued deviceId/token.
        const integrityOk = attestation ? verifyAttestation(attestation) : null;

        const token = randomToken();
        sessions.set(token, {
          deviceId,
          registered: true,
          expiresAt: now() + TOKEN_TTL_MS,
          integrityOk,
          appVersion,
        });

        return json({
          token,
          expiresAt: new Date(now() + TOKEN_TTL_MS).toISOString(),
          deviceId,
          registered: true,
        });
      } catch (e) {
        return json({ error: "invalid request" }, 400);
      }
    }

    // ---- GET /v1/config --------------------------------------------------
    if (path === "/v1/config" && request.method === "GET") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) {
        return json({ error: "unauthenticated" }, 401);
      }

      const preferredRegion = url.searchParams.get("region") || undefined;
      const forceServerId = url.searchParams.get("server") || undefined;
      const selection = selectServer(preferredRegion, forceServerId);
      if (!selection.server) {
        return json({ error: "no servers available" }, 503);
      }

      const server = selection.server;
      // Use the server's pre-configured credentials
      const username = server.username;
      const password = server.password;
      const expiresAt = new Date(now() + CONFIG_TTL_MS).toISOString();
      const signedAt = new Date(now()).toISOString();

      const payload = {
        server: {
          id: server.id,
          region: server.region,
          endpoint: server.endpoint,
          protocol: server.protocol,
          weight: server.weight,
          enabled: server.enabled,
          supportsUdp: server.supportsUdp,
          latencyMs: server.latencyMs,
          load: server.load,
          healthy: server.healthy,
        },
        username,
        password,
        expiresAt,
        signature: signPayload({ server: server.id, expiresAt, signedAt }),
        signedAt,
        servers: SERVERS.map((s) => ({
          id: s.id,
          region: s.region,
          endpoint: s.endpoint,
          protocol: s.protocol,
          weight: s.weight,
          enabled: s.enabled,
          supportsUdp: s.supportsUdp,
          latencyMs: s.latencyMs,
          load: s.load,
          healthy: s.healthy,
        })),
      };

      // Rotate the token (short-lived) and bind it to this config session.
      const newToken = randomToken();
      sessions.set(newToken, {
        ...session,
        expiresAt: now() + TOKEN_TTL_MS,
        serverId: server.id,
      });

      return json({
        ...payload,
        token: newToken,
        tokenExpiresAt: new Date(now() + TOKEN_TTL_MS).toISOString(),
        selectionReason: selection.reason,
      });
    }

    // ---- POST /v1/heartbeat ----------------------------------------------
    if (path === "/v1/heartbeat" && request.method === "POST") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);

      try {
        const { serverId, bytesUp, bytesDown } = await request.json();
        const server = SERVERS.find((s) => s.id === serverId);
        const healthy = server ? server.healthy : false;
        if (server) {
          // Simulate load drift based on traffic.
          server.load = Math.min(1, (server.load || 0) + 0.01);
        }
        return json({
          ok: true,
          tokenExpiresAt: new Date(now() + TOKEN_TTL_MS).toISOString(),
          serverHealthy: healthy,
        });
      } catch (e) {
        return json({ error: "invalid request" }, 400);
      }
    }

    // ---- POST /v1/refresh ------------------------------------------------
    if (path === "/v1/refresh" && request.method === "POST") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);
      const newToken = randomToken();
      sessions.set(newToken, { ...session, expiresAt: now() + TOKEN_TTL_MS });
      sessions.delete(request.headers.get("Authorization")?.slice(7));
      return json({
        token: newToken,
        expiresAt: new Date(now() + TOKEN_TTL_MS).toISOString(),
      });
    }

    // ---- POST /v1/revoke -------------------------------------------------
    if (path === "/v1/revoke" && request.method === "POST") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);
      try {
        const { deviceId } = await request.json();
        if (deviceId && deviceId !== session.deviceId) {
          return json({ error: "device_id mismatch" }, 403);
        }
        // Drop all tokens for this device.
        for (const [token, s] of sessions.entries()) {
          if (s.deviceId === session.deviceId) sessions.delete(token);
        }
        return json({ revoked: true });
      } catch (e) {
        return json({ error: "invalid request" }, 400);
      }
    }

    // ---- GET /v1/ip -------------------------------------------------------
    if (path === "/v1/ip" && request.method === "GET") {
      const session = requireAuth(request.headers.get("Authorization"));
      if (!session) return json({ error: "unauthenticated" }, 401);
      // Return the client's public IP as seen by Cloudflare.
      return json({ ip: ip });
    }

    // ---- GET /proxies (Clash format) -------------------------------------
    if (path === "/proxies" && request.method === "GET") {
      // Token protection for external clients
      if (url.searchParams.get("token") !== CLASH_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }

      // Allow only Clash-based clients
      const ua = request.headers.get("User-Agent") || "";
      const allowedUA = [
        "Clash", "clash", "Meta", "FiClash", "Stash", "okhttp", "Dalvik"
      ];
      if (!allowedUA.some(a => ua.includes(a))) {
        return new Response("404 Not Found", { status: 404 });
      }

      const proxies = generateClashProxies();
      const yaml = `proxies:\n${proxies.map(p => 
        `  - {name: ${p.name}, type: ${p.type}, server: ${p.server}, port: ${p.port}, username: ${p.username}, password: ${p.password}, udp: ${p.udp}}`
      ).join('\n')}\n`;
      
      return new Response(yaml, {
        headers: { "Content-Type": "text/plain" }
      });
    }

    // ---- GET /config (Clash full config) ---------------------------------
    if (path === "/config" && request.method === "GET") {
      // Token protection for external clients
      if (url.searchParams.get("token") !== CLASH_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }

      // Allow only Clash-based clients
      const ua = request.headers.get("User-Agent") || "";
      const allowedUA = [
        "Clash", "clash", "Meta", "FiClash", "Stash", "okhttp", "Dalvik"
      ];
      if (!allowedUA.some(a => ua.includes(a))) {
        return new Response("404 Not Found", { status: 404 });
      }

      const config = generateClashConfig(request);
      
      return new Response(config, {
        headers: { "Content-Type": "text/plain" }
      });
    }

    return json({ error: "not found" }, 404);
  },
};

// ---------------------------------------------------------------------------
// Integrity verification stub
// ---------------------------------------------------------------------------
// In production this validates a Play Integrity / DeviceCheck / App Attest JWT against the
// platform's public keys and checks the nonce matches the app's request.
function verifyAttestation(attestation) {
  if (!attestation || typeof attestation !== "string") return null;
  // Stub: accept non-empty attestation as "present but not cryptographically verified here."
  // Wire real verification (e.g. JWT signature + Google Play Integrity API) in production.
  return true;
}
