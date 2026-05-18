"""CLI argument parsing + result rendering for RP Checker."""

import argparse
import json


def read_user_cli_args():
    parser = argparse.ArgumentParser(
        prog="webstatus",
        description="check availability and gather info about websites",
    )
    parser.add_argument(
        "-u",
        "--urls",
        metavar="URLs",
        nargs="+",
        type=str,
        default=[],
        help="one or more website URLs",
    )
    parser.add_argument(
        "-f",
        "--input-file",
        metavar="FILE",
        type=str,
        default="",
        help="read URLs from a file (one per line)",
    )
    parser.add_argument(
        "-a",
        "--asynchronous",
        action="store_true",
        help="run checks asynchronously",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="output results as JSON",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-emoji",
        action="store_true",
        help="disable emoji in pretty output",
    )
    return parser.parse_args()


def _fmt_bytes(n):
    if n is None:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def display_site_info(info, use_emoji: bool = True):
    """Pretty-print a single SiteInfo."""
    up = "UP" if info.online else "DOWN"
    mark = ("[OK] " if info.online else "[!!] ") if not use_emoji else (
        "\U0001f7e2 " if info.online else "\U0001f534 "
    )
    print(f"{mark}{up}  {info.url}")

    rows = []
    if info.status_code is not None:
        rows.append(("status", f"{info.status_code} {info.reason}".strip()))
    if info.latency_ms is not None:
        rows.append(("latency", f"{info.latency_ms} ms"))
    if info.final_url and info.redirected:
        rows.append(("final url", info.final_url))
    if info.host:
        host_line = info.host
        if info.port:
            host_line += f":{info.port}"
        if info.ip:
            host_line += f"  ({info.ip})"
        rows.append(("host", host_line))
    if info.server:
        rows.append(("server", info.server))
    if info.content_type:
        rows.append(("content-type", info.content_type))
    if info.content_length is not None:
        rows.append(("size", _fmt_bytes(info.content_length)))
    if info.title:
        title = info.title if len(info.title) <= 120 else info.title[:117] + "..."
        rows.append(("title", title))
    if info.ssl_issuer or info.ssl_expires:
        ssl_line = info.ssl_issuer or "-"
        if info.ssl_days_left is not None:
            ssl_line += f"  (expires in {info.ssl_days_left}d)"
        rows.append(("ssl", ssl_line))
    if info.tech:
        rows.append(("tech", ", ".join(info.tech)))
    if info.error:
        rows.append(("error", info.error))

    width = max((len(k) for k, _ in rows), default=0)
    for k, v in rows:
        print(f"  {k.ljust(width)} : {v}")
    print()


def display_results(infos, as_json: bool = False, use_emoji: bool = True):
    if as_json:
        print(json.dumps([i.to_dict() for i in infos], indent=2, default=str))
        return
    for info in infos:
        display_site_info(info, use_emoji=use_emoji)
    _print_summary(infos)


def _print_summary(infos):
    total = len(infos)
    up = sum(1 for i in infos if i.online)
    down = total - up
    avg_latency_vals = [i.latency_ms for i in infos if i.latency_ms is not None]
    avg = (
        f"{sum(avg_latency_vals) / len(avg_latency_vals):.1f} ms"
        if avg_latency_vals
        else "-"
    )
    print("-" * 40)
    print(f"summary: {up}/{total} up, {down} down, avg latency {avg}")
