export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Token protection
    if (url.searchParams.get("token") !== "abc123") {
      return new Response("Forbidden", { status: 403 });
    }

    // Allow only specified clients
    const ua = request.headers.get("User-Agent") || "";

    const allowedUA = [
      "Clash",
      "clash",
      "Meta",
      "FiClash",
      "Stash",
      "okhttp"
    ];

    if (!allowedUA.some(a => ua.includes(a))) {
      return new Response("404 Not Found", { status: 404 });
    }

    // PROXY LIST ENDPOINT
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

      return new Response(proxies, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }

    // MAIN CONFIG
    const config = `
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
  - name: "SELECTOR🔥"
    type: select
    proxies:
      - LOAD-BALANCE
      - STABLE

  - name: STABLE
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    use:
      - myprovider

  - name: LOAD-BALANCE
    type: load-balance
    strategy: round-robin
    url: http://www.gstatic.com/generate_204
    interval: 60
    use:
      - myprovider

  - name: ALL
    type: select
    use:
      - myprovider

rules:
  # Google services → DIRECT
  - DOMAIN-SUFFIX,google.com,DIRECT
  - DOMAIN-SUFFIX,googleapis.com,DIRECT
  - DOMAIN-SUFFIX,gstatic.com,DIRECT
  - DOMAIN-SUFFIX,googlevideo.com,DIRECT
  - DOMAIN-SUFFIX,youtube.com,DIRECT
  - DOMAIN-SUFFIX,ytimg.com,DIRECT
  - DOMAIN-SUFFIX,ggpht.com,DIRECT
  - DOMAIN-SUFFIX,gvt1.com,DIRECT
  - DOMAIN-SUFFIX,gvt2.com,DIRECT
  - DOMAIN-SUFFIX,gvt3.com,DIRECT
  - DOMAIN-SUFFIX,android.com,DIRECT
  - DOMAIN-SUFFIX,gmail.com,DIRECT
  - DOMAIN-SUFFIX,googleusercontent.com,DIRECT

  # Chrome
  - DOMAIN-SUFFIX,chrome.com,DIRECT
  - DOMAIN-SUFFIX,chromium.org,DIRECT
  - DOMAIN-SUFFIX,googlezip.net,DIRECT

  # Firefox
  - DOMAIN-SUFFIX,mozilla.org,DIRECT
  - DOMAIN-SUFFIX,mozilla.com,DIRECT
  - DOMAIN-SUFFIX,mozilla.net,DIRECT
  - DOMAIN-SUFFIX,firefox.com,DIRECT
  - DOMAIN-SUFFIX,firefox.net,DIRECT

  # Everything else
  - MATCH,SELECTOR🔥
`;

    return new Response(config, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store"
      }
    });
  }
};
