# webstatus

Site connectivity + info checker. Given one or more URLs, fetches each and reports HTTP status, latency, resolved IP, server/headers, SSL cert info, page title, content size, and detected tech (Cloudflare, Netlify, Vercel, etc.). Supports sync and async modes.


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
| `--no-emoji` | ASCII markers instead of emoji |

## Sample output

```
🟢 UP  https://github.com
  status       : 200 OK
  latency      : 86.0 ms
  host         : github.com:443  (20.207.73.82)
  server       : github.com
  content-type : text/html; charset=utf-8
  size         : 38.4 KB
  title        : GitHub · Change is constant. GitHub keeps you ahead.
  ssl          : Sectigo Limited  (expires in 76d)
  tech         : server=github.com, host=github-pages
----------------------------------------
summary: 1/1 up, 0 down, avg latency 86.0 ms
```
