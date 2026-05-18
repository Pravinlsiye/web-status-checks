# webstatus

Site connectivity + intelligence checker. Given one or more URLs, fetches each and reports:

- HTTP status, reason, HTTP version, redirect chain, final URL
- latency + TTFB (time to first byte)
- all resolved IPs (v4 + v6), reverse DNS (PTR)
- GeoIP: country, region, city, coords, timezone, ISP, ASN (via ip-api.com)
- SSL cert: issuer, subject, expiry days left, SAN list
- TLS version + cipher in use
- Server header, content-type, content-encoding, size
- Page `<title>`, meta description, og:*, twitter:*, canonical, html lang
- Security headers present/missing (HSTS, CSP, X-Frame-Options, etc.)
- Cache headers (Cache-Control, ETag, Last-Modified, Age, Vary)
- Cookies: count + Secure / HttpOnly / SameSite flags
- Tech fingerprint (Cloudflare, Netlify, Vercel, Fastly, etc.)
- Optional TCP port probe (opt-in, only for hosts you own/control)

Both sync and async modes.


## Install

```sh
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS/Linux

pip install -e .                # installs `webstatus` console script
# or just:
pip install -r requirements.txt
```

## Usage

```sh
webstatus -u python.org
webstatus -u https://github.com https://example.com -a
webstatus -f examples/sample-urls.txt -a
webstatus -f examples/sample-urls.txt -a -j        # JSON output
webstatus -u python.org -t 5 --no-emoji            # 5s timeout, ascii
webstatus -u https://github.com -a -v              # verbose: cookies, SAN, full meta, redirect hops
webstatus -u https://github.com -a --no-geo        # skip GeoIP lookup
webstatus -u my-own-server.com --ports -a          # probe common TCP ports
webstatus -u my-own-server.com --ports-full -a     # probe ports 1-1024 (slow)
webstatus -u my-own-server.com --ports-list 22,80,443,5432 -a
```

Equivalent module form (no install needed):

```sh
python -m webstatus -u python.org
```

## Flags

| Flag | Purpose |
|------|---------|
| `-u, --urls` | one or more URLs |
| `-f, --input-file` | file with one URL per line |
| `-a, --asynchronous` | run checks concurrently |
| `-j, --json` | JSON output instead of pretty text |
| `-t, --timeout` | request timeout in seconds (default 10) |
| `-v, --verbose` | extra sections (full cookie list, SAN list, meta tags, redirect chain) |
| `--no-emoji` | ASCII markers instead of emoji |
| `--no-geo` | skip GeoIP lookup |
| `--ports` | probe common TCP ports (21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443) |
| `--ports-full` | probe ports 1-1024 |
| `--ports-list` | custom comma-separated port list |
| `--port-timeout` | per-port connect timeout in seconds (default 1.0) |

### Port scanning ethics

Port probing connects to TCP ports on the target host. **Only use `--ports`, `--ports-full`, or `--ports-list` against hosts you own or have explicit permission to scan.** Unsolicited port scanning of third-party hosts may violate computer-misuse laws in your jurisdiction.

### GeoIP

GeoIP data comes from `http://ip-api.com` (no API key, free tier ~45 req/min). Pass `--no-geo` to skip the lookup.

## Sample output

```
🟢 UP  https://github.com
  status       : 200 OK
  http         : HTTP/1.1
  latency      : 126.9 ms (ttfb 126.6 ms)
  host         : github.com:443  (20.207.73.82)
  location     : Pune, Maharashtra, India
  coords       : 18.5144, 73.864235
  timezone     : Asia/Kolkata
  isp          : Microsoft Corporation
  asn          : AS8075 Microsoft Corporation
  server       : github.com
  content-type : text/html; charset=utf-8
  encoding     : gzip
  size         : 42.2 KB
  title        : GitHub · Change is constant. GitHub keeps you ahead.
  lang         : en
  ssl          : Sectigo Limited  [TLSv1.3 / TLS_AES_128_GCM_SHA256]  (expires in 76d)
  security     : 5 present
  cache        : Cache-Control=max-age=0, private, must-revalidate, ETag=...
  cookies      : 3 (3 secure, 2 httponly)
  tech         : server=github.com, host=github-pages
----------------------------------------
summary: 1/1 up, 0 down, avg latency 126.9 ms
```
