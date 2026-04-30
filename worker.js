export default {
  async fetch(request) {

    const url = new URL(request.url)

    if (url.searchParams.get("token") !== "abc123") {
      return new Response("Forbidden", { status: 403 })
    }

    const ua = request.headers.get("User-Agent") || ""

    const allowedUA = [
      "Clash",
      "clash",
      "ClashMeta",
      "ClashforWindows",
      "ClashX",
      "Stash",
      "FiClash"
    ]

    let allowed = false

    for (const a of allowedUA) {
      if (ua.includes(a)) {
        allowed = true
        break
      }
    }

    if (!allowed) {
      return new Response("404 Not Found", { status: 404 })
    }

    const proxies = `
proxies:


- name: proxy1
  type: http
  server: 144.48.108.121
  port: 5452
- name: proxy2
  type: http
  server: 144.48.108.122
  port: 5452
- name: proxy3
  type: http
  server: 203.76.108.222
  port: 27271
- name: proxy4
  type: http
  server: 103.167.17.220
  port: 2610
- name: proxy5
  type: http
  server: 27.147.195.166
  port: 27271
- name: proxy6
  type: http
  server: 203.76.112.42
  port: 27271
- name: proxy7
  type: http
  server: 203.76.115.98
  port: 27271
- name: proxy8
  type: http
  server: 203.76.123.234
  port: 27271
- name: proxy9
  type: http
  server: 27.147.195.166
  port: 27271
- name: proxy10
  type: http
  server: 203.76.126.162
  port: 27271
  
`

    return new Response(proxies, {
      headers: {
        "Content-Type": "text/plain"
      }
    })

  }
}
