"""Connectivity + site info collection (sync and async)."""

import asyncio
import gzip
import re
import socket
import ssl
import time
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import aiohttp


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BODY_READ_CAP = 64 * 1024  # bytes scanned for <title>
_DEFAULT_TIMEOUT = 10


@dataclass
class SiteInfo:
    url: str
    online: bool = False
    error: str = ""
    status_code: Optional[int] = None
    reason: str = ""
    final_url: str = ""
    redirected: bool = False
    latency_ms: Optional[float] = None
    ip: str = ""
    server: str = ""
    content_type: str = ""
    content_length: Optional[int] = None
    title: str = ""
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    ssl_issuer: str = ""
    ssl_subject: str = ""
    ssl_expires: str = ""
    ssl_days_left: Optional[int] = None
    tech: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url


def _extract_title(body: bytes) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    try:
        return m.group(1).decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


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
    return tech


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _fetch_ssl_info(host: str, port: int, timeout: float):
    """Return (issuer, subject, expires_iso, days_left) or empty values."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter", "")
        expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expires_dt - datetime.now(timezone.utc)).days
        return (
            issuer.get("organizationName", "") or issuer.get("commonName", ""),
            subject.get("commonName", ""),
            expires_dt.isoformat(),
            days_left,
        )
    except Exception:
        return ("", "", "", None)


# ------------------------- SYNC -------------------------

def check_site(url: str, timeout: float = _DEFAULT_TIMEOUT) -> SiteInfo:
    """Sync site check using urllib + ssl/socket."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    url = _normalize_url(url)
    info = SiteInfo(url=url)
    parsed = urlparse(url)
    info.scheme = parsed.scheme
    info.host = parsed.hostname or ""
    info.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    info.ip = _resolve_ip(info.host)

    req = Request(
        url,
        method="GET",
        headers={
            "User-Agent": "webstatus/0.2 (+https://example.local)",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    start = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout) as resp:
            info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
            info.online = True
            info.status_code = resp.status
            info.reason = resp.reason or ""
            info.final_url = resp.geturl()
            info.redirected = info.final_url.rstrip("/") != url.rstrip("/")
            info.server = resp.headers.get("Server", "")
            info.content_type = resp.headers.get("Content-Type", "")
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit():
                info.content_length = int(cl)
            raw = resp.read(_BODY_READ_CAP)
            body = _maybe_decompress(raw, resp.headers.get("Content-Encoding", ""))
            info.title = _extract_title(body)
            if info.content_length is None:
                info.content_length = len(raw)
            info.tech = _detect_tech(dict(resp.headers.items()))
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
        issuer, subject, expires, days = _fetch_ssl_info(
            info.host, info.port or 443, timeout
        )
        info.ssl_issuer = issuer
        info.ssl_subject = subject
        info.ssl_expires = expires
        info.ssl_days_left = days

    return info


# ------------------------- ASYNC -------------------------

async def check_site_async(
    url: str, timeout: float = _DEFAULT_TIMEOUT
) -> SiteInfo:
    url = _normalize_url(url)
    info = SiteInfo(url=url)
    parsed = urlparse(url)
    info.scheme = parsed.scheme
    info.host = parsed.hostname or ""
    info.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    info.ip = await asyncio.to_thread(_resolve_ip, info.host)

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "webstatus/0.2 (+https://example.local)"}
    start = time.perf_counter()
    try:
        async with aiohttp.ClientSession(
            timeout=client_timeout, headers=headers
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
                info.online = resp.status < 400
                info.status_code = resp.status
                info.reason = resp.reason or ""
                info.final_url = str(resp.url)
                info.redirected = info.final_url.rstrip("/") != url.rstrip("/")
                hdrs = dict(resp.headers.items())
                info.server = hdrs.get("Server", "")
                info.content_type = hdrs.get("Content-Type", "")
                cl = hdrs.get("Content-Length")
                if cl and cl.isdigit():
                    info.content_length = int(cl)
                body = await resp.content.read(_BODY_READ_CAP)
                info.title = _extract_title(body)
                if info.content_length is None:
                    info.content_length = len(body)
                info.tech = _detect_tech(hdrs)
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

    if info.scheme == "https" and info.host:
        issuer, subject, expires, days = await asyncio.to_thread(
            _fetch_ssl_info, info.host, info.port or 443, timeout
        )
        info.ssl_issuer = issuer
        info.ssl_subject = subject
        info.ssl_expires = expires
        info.ssl_days_left = days

    return info
