"""CLI argument parsing + result rendering for webstatus."""

import argparse
import json


def read_user_cli_args():
    parser = argparse.ArgumentParser(
        prog="webstatus",
        description="check availability and gather info about websites",
    )
    parser.add_argument(
        "-u", "--urls", metavar="URLs", nargs="+", type=str, default=[],
        help="one or more website URLs",
    )
    parser.add_argument(
        "-f", "--input-file", metavar="FILE", type=str, default="",
        help="read URLs from a file (one per line)",
    )
    parser.add_argument(
        "-a", "--asynchronous", action="store_true",
        help="run checks asynchronously",
    )
    parser.add_argument(
        "-j", "--json", action="store_true",
        help="output results as JSON",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=10.0,
        help="request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-emoji", action="store_true",
        help="disable emoji in pretty output",
    )
    parser.add_argument(
        "--no-geo", action="store_true",
        help="skip GeoIP lookup (ip-api.com)",
    )
    parser.add_argument(
        "--ports", action="store_true",
        help="probe common TCP ports (21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443). Only use on hosts you own or have permission to scan.",
    )
    parser.add_argument(
        "--ports-full", action="store_true",
        help="probe TCP ports 1-1024 (slow). Same legal caveat as --ports.",
    )
    parser.add_argument(
        "--ports-list", type=str, default="",
        help="comma-separated custom port list, e.g. 80,443,8080",
    )
    parser.add_argument(
        "--port-timeout", type=float, default=1.0,
        help="per-port connect timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="show extended sections (cookies, SAN list, meta, redirect chain)",
    )
    return parser.parse_args()


def resolve_ports(args):
    if args.ports_list:
        try:
            return [int(p.strip()) for p in args.ports_list.split(",") if p.strip()]
        except ValueError:
            return None
    if args.ports_full:
        return list(range(1, 1025))
    if args.ports:
        from webstatus.checker import COMMON_PORTS
        return list(COMMON_PORTS)
    return None


def _fmt_bytes(n):
    if n is None:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _row(rows, key, val):
    if val in (None, "", [], {}):
        return
    rows.append((key, val))


def display_site_info(info, use_emoji=True, verbose=False):
    up = "UP" if info.online else "DOWN"
    mark = ("\U0001f7e2 " if info.online else "\U0001f534 ") if use_emoji else (
        "[OK] " if info.online else "[!!] "
    )
    print(f"{mark}{up}  {info.url}")
    rows = []

    if info.status_code is not None:
        _row(rows, "status", f"{info.status_code} {info.reason}".strip())
    if info.http_version:
        _row(rows, "http", info.http_version)
    if info.latency_ms is not None:
        t = f"{info.latency_ms} ms"
        if info.ttfb_ms is not None:
            t += f" (ttfb {info.ttfb_ms} ms)"
        _row(rows, "latency", t)
    if info.redirected:
        _row(rows, "final url", info.final_url)
    if verbose and info.redirect_chain:
        _row(rows, "redirects", " -> ".join(info.redirect_chain))

    if info.host:
        host_line = info.host
        if info.port:
            host_line += f":{info.port}"
        if info.ip:
            host_line += f"  ({info.ip})"
        _row(rows, "host", host_line)
    if info.ips and len(info.ips) > 1:
        _row(rows, "all ips", ", ".join(info.ips))
    if info.ptr:
        _row(rows, "ptr", info.ptr)

    if info.geo:
        g = info.geo
        loc = ", ".join(p for p in (g.get("city"), g.get("region"), g.get("country")) if p)
        _row(rows, "location", loc)
        if g.get("lat") is not None and g.get("lon") is not None:
            _row(rows, "coords", f"{g['lat']}, {g['lon']}")
        if g.get("timezone"):
            _row(rows, "timezone", g["timezone"])
        if g.get("isp") or g.get("org"):
            isp_line = g.get("isp", "")
            if g.get("org") and g["org"] != isp_line:
                isp_line = f"{isp_line} ({g['org']})" if isp_line else g["org"]
            _row(rows, "isp", isp_line)
        if g.get("asn"):
            _row(rows, "asn", g["asn"])

    if info.server:
        _row(rows, "server", info.server)
    if info.content_type:
        _row(rows, "content-type", info.content_type)
    if info.content_encoding:
        _row(rows, "encoding", info.content_encoding)
    if info.content_length is not None:
        _row(rows, "size", _fmt_bytes(info.content_length))

    if info.title:
        title = info.title if len(info.title) <= 120 else info.title[:117] + "..."
        _row(rows, "title", title)
    if info.meta:
        desc = info.meta.get("description") or info.meta.get("og:description")
        if desc:
            desc = desc if len(desc) <= 140 else desc[:137] + "..."
            _row(rows, "description", desc)
        if info.meta.get("og:site_name"):
            _row(rows, "site", info.meta["og:site_name"])
        if info.meta.get("lang"):
            _row(rows, "lang", info.meta["lang"])
        if verbose:
            for k in ("viewport", "robots", "generator", "author", "canonical", "og:image", "twitter:card"):
                v = info.meta.get(k)
                if v:
                    _row(rows, f"meta.{k}", v if len(v) <= 120 else v[:117] + "...")

    if info.tls_version or info.ssl_issuer:
        line = info.ssl_issuer or "-"
        if info.tls_version:
            line += f"  [{info.tls_version}"
            if info.tls_cipher:
                line += f" / {info.tls_cipher}"
            line += "]"
        if info.ssl_days_left is not None:
            line += f"  (expires in {info.ssl_days_left}d)"
        _row(rows, "ssl", line)
    if verbose and info.ssl_san:
        sans = info.ssl_san
        shown = sans if len(sans) <= 6 else sans[:6] + [f"... (+{len(sans)-6} more)"]
        _row(rows, "san", ", ".join(shown))

    if info.security_headers:
        present = list(info.security_headers.keys())
        missing = [h for h in (
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        ) if h not in info.security_headers]
        line = f"{len(present)} present"
        if missing:
            line += f"; missing: {', '.join(missing)}"
        _row(rows, "security", line)
    if info.cache_headers:
        _row(rows, "cache", ", ".join(f"{k}={v}" for k, v in info.cache_headers.items()))
    if info.cookies:
        secure = sum(1 for c in info.cookies if c["secure"])
        http_only = sum(1 for c in info.cookies if c["httponly"])
        _row(
            rows, "cookies",
            f"{len(info.cookies)} ({secure} secure, {http_only} httponly)",
        )
        if verbose:
            for c in info.cookies:
                flags = []
                if c["secure"]:
                    flags.append("Secure")
                if c["httponly"]:
                    flags.append("HttpOnly")
                if c["samesite"]:
                    flags.append(f"SameSite={c['samesite']}")
                _row(rows, f"  cookie.{c['name']}", ", ".join(flags) or "-")

    if info.tech:
        _row(rows, "tech", ", ".join(info.tech))

    if info.open_ports:
        _row(rows, "open ports", ", ".join(str(p) for p in info.open_ports))

    if info.error:
        _row(rows, "error", info.error)

    width = max((len(k) for k, _ in rows), default=0)
    for k, v in rows:
        print(f"  {k.ljust(width)} : {v}")
    print()


def display_results(infos, as_json=False, use_emoji=True, verbose=False):
    if as_json:
        print(json.dumps([i.to_dict() for i in infos], indent=2, default=str))
        return
    for info in infos:
        display_site_info(info, use_emoji=use_emoji, verbose=verbose)
    _print_summary(infos)


def _print_summary(infos):
    total = len(infos)
    up = sum(1 for i in infos if i.online)
    down = total - up
    lats = [i.latency_ms for i in infos if i.latency_ms is not None]
    avg = f"{sum(lats) / len(lats):.1f} ms" if lats else "-"
    print("-" * 40)
    print(f"summary: {up}/{total} up, {down} down, avg latency {avg}")
