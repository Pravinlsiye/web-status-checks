"""Connectivity + site info collection (sync and async)."""

import asyncio
import gzip
import json as _json
import re
import socket
import ssl
import time
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

import aiohttp


_BODY_READ_CAP = 64 * 1024  # bytes scanned for meta tags
_DEFAULT_TIMEOUT = 10

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_RE = re.compile(
    rb"<meta\b[^>]*?(?:name|property|http-equiv)\s*=\s*['\"]([^'\"]+)['\"][^>]*?content\s*=\s*['\"]([^'\"]*)['\"][^>]*>",
    re.IGNORECASE,
)
_META_RE_REV = re.compile(
    rb"<meta\b[^>]*?content\s*=\s*['\"]([^'\"]*)['\"][^>]*?(?:name|property|http-equiv)\s*=\s*['\"]([^'\"]+)['\"][^>]*>",
    re.IGNORECASE,
)
_HTML_LANG_RE = re.compile(rb"<html\b[^>]*\blang\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_CANONICAL_RE = re.compile(
    rb"<link\b[^>]*?rel\s*=\s*['\"]canonical['\"][^>]*?href\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
)
CACHE_HEADERS = ("Cache-Control", "ETag", "Last-Modified", "Age", "Expires", "Vary")

COMMON_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080, 8443)


# ---------- dataclass ----------

@dataclass
class SiteInfo:
    url: str
    online: bool = False
    error: str = ""

    # HTTP
    status_code: Optional[int] = None
    reason: str = ""
    final_url: str = ""
    redirected: bool = False
    redirect_chain: list = field(default_factory=list)
    http_version: str = ""
    content_type: str = ""
    content_length: Optional[int] = None
    content_encoding: str = ""

    # timing
    latency_ms: Optional[float] = None
    ttfb_ms: Optional[float] = None

    # host
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    ip: str = ""
    ips: list = field(default_factory=list)
    ptr: str = ""

    # tls
    ssl_issuer: str = ""
    ssl_subject: str = ""
    ssl_expires: str = ""
    ssl_days_left: Optional[int] = None
    ssl_san: list = field(default_factory=list)
    tls_version: str = ""
    tls_cipher: str = ""

    # fingerprints
    server: str = ""
    tech: list = field(default_factory=list)

    # html
    title: str = ""
    meta: dict = field(default_factory=dict)

    # headers
    security_headers: dict = field(default_factory=dict)
    cache_headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)

    # geo
    geo: dict = field(default_factory=dict)

    # ports
    open_ports: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ---------- url helpers ----------

def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url


def _maybe_decompress(body: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        return body
    return body


# ---------- html parsing ----------

def _decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _extract_title(body: bytes) -> str:
    m = _TITLE_RE.search(body)
    return _decode(m.group(1)) if m else ""


def _extract_meta(body: bytes) -> dict:
    """Pull common meta tags into a flat dict (description, og:*, twitter:*, viewport, canonical, lang)."""
    out = {}
    wanted = {
        "description",
        "viewport",
        "robots",
        "author",
        "generator",
        "theme-color",
        "og:title",
        "og:description",
        "og:image",
        "og:site_name",
        "og:type",
        "og:url",
        "twitter:card",
        "twitter:title",
        "twitter:description",
        "twitter:image",
    }
    for rx in (_META_RE, _META_RE_REV):
        for m in rx.finditer(body):
            if rx is _META_RE:
                name, content = m.group(1), m.group(2)
            else:
                content, name = m.group(1), m.group(2)
            key = _decode(name).lower()
            if key in wanted and key not in out:
                out[key] = _decode(content)
    can = _CANONICAL_RE.search(body)
    if can:
        out["canonical"] = _decode(can.group(1))
    lang = _HTML_LANG_RE.search(body)
    if lang:
        out["lang"] = _decode(lang.group(1))
    return out


# ---------- header parsing ----------

def _collect_named(headers, names):
    out = {}
    for h in names:
        val = headers.get(h)
        if val:
            out[h] = val
    return out


def _collect_named_multi(get_all, names):
    out = {}
    for h in names:
        vals = get_all(h)
        if vals:
            out[h] = vals[0] if len(vals) == 1 else vals
    return out


def _parse_cookies(set_cookie_values: Iterable[str]) -> list:
    cookies = []
    for raw in set_cookie_values:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0]
        attrs = {p.lower(): True for p in parts[1:] if "=" not in p}
        kv = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                kv[k.strip().lower()] = v.strip()
        cookies.append(
            {
                "name": name,
                "secure": bool(attrs.get("secure")),
                "httponly": bool(attrs.get("httponly")),
                "samesite": kv.get("samesite", ""),
                "domain": kv.get("domain", ""),
                "path": kv.get("path", ""),
                "expires": kv.get("expires", ""),
                "max_age": kv.get("max-age", ""),
            }
        )
    return cookies


def _detect_tech(headers) -> list:
    tech = []
    keys = {k.lower(): v for k, v in headers.items()}
    if "server" in keys:
        tech.append(f"server={keys['server']}")
    if "x-powered-by" in keys:
        tech.append(f"powered-by={keys['x-powered-by']}")
    if "cf-ray" in keys or "cloudflare" in keys.get("server", "").lower():
        tech.append("cdn=cloudflare")
    if "x-vercel-id" in keys:
        tech.append("host=vercel")
    if "x-nf-request-id" in keys or "netlify" in keys.get("server", "").lower():
        tech.append("host=netlify")
    if "x-github-request-id" in keys:
        tech.append("host=github-pages")
    if "x-amz-cf-id" in keys:
        tech.append("cdn=cloudfront")
    if "x-fastly-request-id" in keys or "fastly" in keys.get("server", "").lower():
        tech.append("cdn=fastly")
    if "x-served-by" in keys:
        tech.append(f"served-by={keys['x-served-by']}")
    return tech


# ---------- dns ----------

def _resolve_all_ips(host: str) -> list:
    if not host:
        return []
    ips = []
    try:
        for fam, *_rest, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _reverse_dns(ip: str) -> str:
    if not ip:
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------- tls ----------

def _fetch_ssl_info(host: str, port: int, timeout: float) -> dict:
    """Return dict: issuer, subject, expires, days_left, san, tls_version, tls_cipher."""
    empty = {
        "issuer": "",
        "subject": "",
        "expires": "",
        "days_left": None,
        "san": [],
        "tls_version": "",
        "tls_cipher": "",
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_ver = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter", "")
        expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        return {
            "issuer": issuer.get("organizationName", "") or issuer.get("commonName", ""),
            "subject": subject.get("commonName", ""),
            "expires": expires_dt.isoformat(),
            "days_left": (expires_dt - datetime.now(timezone.utc)).days,
            "san": san,
            "tls_version": tls_ver,
            "tls_cipher": cipher[0] if cipher else "",
        }
    except Exception:
        return empty


# ---------- geoip ----------

_GEO_FIELDS = "status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"


def _fetch_geo_sync(ip: str, timeout: float) -> dict:
    if not ip:
        return {}
    from urllib.request import Request, urlopen

    url = f"http://ip-api.com/json/{ip}?fields={_GEO_FIELDS}"
    try:
        with urlopen(Request(url), timeout=timeout) as resp:
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
        if data.get("status") != "success":
            return {}
        return _shape_geo(data)
    except Exception:
        return {}


async def _fetch_geo_async(ip: str, timeout: float) -> dict:
    if not ip:
        return {}
    url = f"http://ip-api.com/json/{ip}?fields={_GEO_FIELDS}"
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as s:
            async with s.get(url) as r:
                data = await r.json(content_type=None)
        if data.get("status") != "success":
            return {}
        return _shape_geo(data)
    except Exception:
        return {}


def _shape_geo(d: dict) -> dict:
    return {
        "country": d.get("country", ""),
        "country_code": d.get("countryCode", ""),
        "region": d.get("regionName", ""),
        "city": d.get("city", ""),
        "lat": d.get("lat"),
        "lon": d.get("lon"),
        "timezone": d.get("timezone", ""),
        "isp": d.get("isp", ""),
        "org": d.get("org", ""),
        "asn": d.get("as", ""),
    }


# ---------- ports ----------

def _probe_port_sync(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports_sync(host: str, ports: Iterable[int], timeout: float = 1.0) -> list:
    return [p for p in ports if _probe_port_sync(host, p, timeout)]


async def _probe_port_async(host: str, port: int, timeout: float) -> Optional[int]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def scan_ports_async(host: str, ports: Iterable[int], timeout: float = 1.0) -> list:
    sem = asyncio.Semaphore(128)

    async def _one(p):
        async with sem:
            return await _probe_port_async(host, p, timeout)

    results = await asyncio.gather(*(_one(p) for p in ports))
    return [p for p in results if p is not None]


# ---------- sync check ----------

class _RedirectRecorder:
    """Wraps urllib redirect handling to capture the hop chain."""

    def __init__(self):
        self.chain = []

    def __call__(self):
        from urllib.request import HTTPRedirectHandler

        recorder = self

        class Handler(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                recorder.chain.append(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        return Handler()


def check_site(
    url: str,
    timeout: float = _DEFAULT_TIMEOUT,
    *,
    with_geo: bool = True,
    ports: Optional[Iterable[int]] = None,
    port_timeout: float = 1.0,
) -> SiteInfo:
    from urllib.request import Request, build_opener
    from urllib.error import HTTPError, URLError

    url = _normalize_url(url)
    info = SiteInfo(url=url)
    parsed = urlparse(url)
    info.scheme = parsed.scheme
    info.host = parsed.hostname or ""
    info.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    info.ips = _resolve_all_ips(info.host)
    info.ip = info.ips[0] if info.ips else ""
    info.ptr = _reverse_dns(info.ip)

    req = Request(
        url,
        method="GET",
        headers={
            "User-Agent": "webstatus/0.3 (+https://example.local)",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    recorder = _RedirectRecorder()
    opener = build_opener(recorder())
    start = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            info.ttfb_ms = round((time.perf_counter() - start) * 1000, 1)
            info.online = True
            info.status_code = resp.status
            info.reason = resp.reason or ""
            info.final_url = resp.geturl()
            info.redirect_chain = list(recorder.chain)
            info.redirected = bool(recorder.chain) or (
                info.final_url.rstrip("/") != url.rstrip("/")
            )
            ver = getattr(resp, "version", None)
            info.http_version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(ver, str(ver or ""))

            info.server = resp.headers.get("Server", "")
            info.content_type = resp.headers.get("Content-Type", "")
            info.content_encoding = resp.headers.get("Content-Encoding", "")
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit():
                info.content_length = int(cl)
            raw = resp.read(_BODY_READ_CAP)
            body = _maybe_decompress(raw, info.content_encoding)
            info.title = _extract_title(body)
            info.meta = _extract_meta(body)
            if info.content_length is None:
                info.content_length = len(raw)
            hdrs_dict = dict(resp.headers.items())
            info.tech = _detect_tech(hdrs_dict)
            info.security_headers = _collect_named(resp.headers, SECURITY_HEADERS)
            info.cache_headers = _collect_named(resp.headers, CACHE_HEADERS)
            info.cookies = _parse_cookies(resp.headers.get_all("Set-Cookie") or [])
            info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
    except HTTPError as e:
        info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
        info.online = False
        info.status_code = e.code
        info.reason = e.reason or ""
        info.error = f"HTTP {e.code} {e.reason}"
    except URLError as e:
        info.online = False
        info.error = str(e.reason)
    except Exception as e:
        info.online = False
        info.error = str(e) or "unknown error"

    if info.scheme == "https" and info.host:
        s = _fetch_ssl_info(info.host, info.port or 443, timeout)
        info.ssl_issuer = s["issuer"]
        info.ssl_subject = s["subject"]
        info.ssl_expires = s["expires"]
        info.ssl_days_left = s["days_left"]
        info.ssl_san = s["san"]
        info.tls_version = s["tls_version"]
        info.tls_cipher = s["tls_cipher"]

    if with_geo:
        info.geo = _fetch_geo_sync(info.ip, timeout)

    if ports and info.host:
        info.open_ports = scan_ports_sync(info.host, ports, timeout=port_timeout)

    return info


# ---------- async check ----------

async def check_site_async(
    url: str,
    timeout: float = _DEFAULT_TIMEOUT,
    *,
    with_geo: bool = True,
    ports: Optional[Iterable[int]] = None,
    port_timeout: float = 1.0,
) -> SiteInfo:
    url = _normalize_url(url)
    info = SiteInfo(url=url)
    parsed = urlparse(url)
    info.scheme = parsed.scheme
    info.host = parsed.hostname or ""
    info.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    info.ips = await asyncio.to_thread(_resolve_all_ips, info.host)
    info.ip = info.ips[0] if info.ips else ""
    info.ptr = await asyncio.to_thread(_reverse_dns, info.ip)

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "webstatus/0.3 (+https://example.local)"}

    start = time.perf_counter()
    try:
        async with aiohttp.ClientSession(
            timeout=client_timeout, headers=headers
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                info.ttfb_ms = round((time.perf_counter() - start) * 1000, 1)
                info.online = resp.status < 400
                info.status_code = resp.status
                info.reason = resp.reason or ""
                info.final_url = str(resp.url)
                info.redirect_chain = [str(r.url) for r in resp.history]
                info.redirected = bool(resp.history) or (
                    info.final_url.rstrip("/") != url.rstrip("/")
                )
                v = resp.version
                info.http_version = f"HTTP/{v.major}.{v.minor}" if v else ""
                hdrs = dict(resp.headers.items())
                info.server = hdrs.get("Server", "")
                info.content_type = hdrs.get("Content-Type", "")
                info.content_encoding = hdrs.get("Content-Encoding", "")
                cl = hdrs.get("Content-Length")
                if cl and cl.isdigit():
                    info.content_length = int(cl)
                body = await resp.content.read(_BODY_READ_CAP)
                info.title = _extract_title(body)
                info.meta = _extract_meta(body)
                if info.content_length is None:
                    info.content_length = len(body)
                info.tech = _detect_tech(hdrs)
                info.security_headers = {
                    h: resp.headers.get(h) for h in SECURITY_HEADERS if resp.headers.get(h)
                }
                info.cache_headers = {
                    h: resp.headers.get(h) for h in CACHE_HEADERS if resp.headers.get(h)
                }
                info.cookies = _parse_cookies(resp.headers.getall("Set-Cookie", []))
                info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
                if not info.online and not info.error:
                    info.error = f"HTTP {resp.status} {resp.reason}"
    except asyncio.TimeoutError:
        info.online = False
        info.error = "timed out"
    except aiohttp.ClientError as e:
        info.online = False
        info.error = str(e) or e.__class__.__name__
    except Exception as e:
        info.online = False
        info.error = str(e) or "unknown error"

    tasks = []
    if info.scheme == "https" and info.host:
        tasks.append(("ssl", asyncio.to_thread(_fetch_ssl_info, info.host, info.port or 443, timeout)))
    if with_geo and info.ip:
        tasks.append(("geo", _fetch_geo_async(info.ip, timeout)))
    if ports and info.host:
        tasks.append(("ports", scan_ports_async(info.host, ports, timeout=port_timeout)))

    if tasks:
        results = await asyncio.gather(*(t for _, t in tasks), return_exceptions=True)
        for (name, _), res in zip(tasks, results):
            if isinstance(res, Exception):
                continue
            if name == "ssl":
                info.ssl_issuer = res["issuer"]
                info.ssl_subject = res["subject"]
                info.ssl_expires = res["expires"]
                info.ssl_days_left = res["days_left"]
                info.ssl_san = res["san"]
                info.tls_version = res["tls_version"]
                info.tls_cipher = res["tls_cipher"]
            elif name == "geo":
                info.geo = res
            elif name == "ports":
                info.open_ports = res

    return info
