export default {
  async fetch(request) {

    const url = new URL(request.url)

    // 🔐 Token protection
    if (url.searchParams.get("token") !== "abc123") {
      return new Response("Forbidden", { status: 403 })
    }

    // 🔍 Allow only Clash-based clients
    const ua = request.headers.get("User-Agent") || ""

    const allowedUA = [
      "Clash",
      "clash",
      "Meta",
      "FiClash",
      "Stash",
      "okhttp",
      "Dalvik"
    ]

    if (!allowedUA.some(a => ua.includes(a))) {
      return new Response("404 Not Found", { status: 404 })
    }

    // =========================
    // 📦 PROXY LIST ENDPOINT
    // =========================
    if (url.pathname === "/proxies") {

      const proxies = `
proxies:
  - {name: proxy1, type: socks5, server: 103.178.73.1, port: 9169, username: movip21, password: movip21 }
  - {name: proxy2, type: socks5, server: 103.146.134.225, port: 9169, username: movip21, password: movip21 }
  - {name: proxy3, type: socks5, server: 103.118.152.36, port: 9169, username: movip21, password: movip21 }
  - {name: proxy4, type: socks5, server: 103.111.224.46, port: 9169, username: movip21, password: movip21 }
  - {name: proxy5, type: socks5, server: 202.5.36.149, port: 9169, username: movieproxy, password: movieproxy }
  
`

      return new Response(proxies.trim(), {
        headers: { "Content-Type": "text/plain" }
      })
    }

    // =========================
    // ⚡ MAIN CLASH CONFIG
    // =========================
    const config = `
mixed-port: 7893
allow-lan: true
mode: rule
log-level: info
ipv6: false

proxy-providers:
  myprovider:
    type: http
    url: "${url.origin}/proxies?token=abc123"
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
`

    return new Response(config.trim(), {
      headers: { "Content-Type": "text/plain" }
    })
  }
}
