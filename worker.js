
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // ==========================================
    // TOKEN PROTECTION
    // ==========================================
    const WORKER_TOKEN = "abc123";

    if (url.searchParams.get("token") !== WORKER_TOKEN) {
      return new Response("Forbidden", { status: 403 });
    }

    // ==========================================
    // ALLOW CLASH-BASED CLIENTS
    // ==========================================
    const ua = request.headers.get("User-Agent") || "";

    const allowedUA = [
      "Clash",
      "clash",
      "Meta",
      "FiClash",
      "Stash",
      "okhttp",
      "Dalvik"
    ];

    if (!allowedUA.some(a => ua.includes(a))) {
      return new Response("404 Not Found", { status: 404 });
    }

    // ==========================================
    // PROXY PROVIDER ENDPOINT
    // ==========================================
    if (url.pathname === "/proxies") {
      const proxies = `
proxies:
  - { name: proxy1, type: http, server: 182.48.72.8, port: 9890 }
  - { name: proxy2, type: http, server: 182.48.72.9, port: 9890 }
  - { name: proxy3, type: http, server: 182.48.65.221, port: 9890 }
  - { name: proxy4, type: http, server: 182.48.65.220, port: 9890 }
  - { name: proxy5, type: http, server: 182.48.72.221, port: 5871 }
  - { name: proxy6, type: http, server: 182.48.78.114, port: 7626 }
  - { name: proxy7, type: http, server: 182.48.78.114, port: 4742 }
  - { name: proxy8, type: http, server: 182.48.65.221, port: 9890 }
`;

      return new Response(proxies.trim() + "\n", {
        status: 200,
        headers: {
          "Content-Type": "application/yaml; charset=utf-8",
          "Cache-Control": "no-store, no-cache, must-revalidate"
        }
      });
    }

    // ==========================================
    // MAIN CONFIGURATION ENDPOINT
    // ==========================================
    if (url.pathname !== "/") {
      return new Response("Not Found", { status: 404 });
    }

    const config = `
port: 7890
socks-port: 7891
mixed-port: 7892

allow-lan: true
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
inbound-mptcp: true
find-process-mode: off

tun:
  enable: true
  stack: mixed
  dns-hijack:
    - 0.0.0.0:53
    - tcp://0.0.0.0:53
  auto-route: true
  auto-detect-interface: true
  mtu: 1500
  endpoint-independent-nat: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 119.40.90.1
    - https://dns.google/dns-query

proxy-providers:
  xrorx-cloudflare:
    type: http
    url: "${url.origin}/proxies?token=${WORKER_TOKEN}"
    interval: 60
    path: ./providers/xrorx-cloudflare.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 60
      timeout: 5000
      lazy: false

proxy-groups:
  - name: "⚡ UNITE-ALL-BANDWIDTH"
    type: load-balance
    strategy: round-robin
    url: https://www.gstatic.com/generate_204
    interval: 30
    tolerance: 100
    lazy: false
    use:
      - xrorx-cloudflare

  - name: "🎯 BEST-PING"
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 30
    tolerance: 50
    lazy: false
    use:
      - xrorx-cloudflare

  - name: "MANUAL-SELECT"
    type: select
    proxies:
      - "⚡ UNITE-ALL-BANDWIDTH"
      - "🎯 BEST-PING"
    use:
      - xrorx-cloudflare

rules:
  - GEOIP,BD,DIRECT
  - NETWORK,UDP,DIRECT
  - MATCH,⚡ UNITE-ALL-BANDWIDTH
`;

    return new Response(config.trim() + "\n", {
      status: 200,
      headers: {
        "Content-Type": "application/yaml; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate"
      }
    });
  }
};
