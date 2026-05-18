"""webstatus entry point."""

import asyncio
import pathlib
import sys

from webstatus.checker import check_site, check_site_async
from webstatus.cli import display_results, read_user_cli_args, resolve_ports


def _ensure_utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    _ensure_utf8_stdout()
    args = read_user_cli_args()
    urls = _get_websites_urls(args)
    if not urls:
        print("Error: no URLs to check", file=sys.stderr)
        sys.exit(1)

    ports = resolve_ports(args)
    if (args.ports or args.ports_full or args.ports_list) and ports is None:
        print("Error: invalid --ports-list", file=sys.stderr)
        sys.exit(2)

    with_geo = not args.no_geo

    if args.asynchronous:
        infos = asyncio.run(_run_async(urls, args, with_geo, ports))
    else:
        infos = _run_sync(urls, args, with_geo, ports)

    display_results(
        infos,
        as_json=args.json,
        use_emoji=not args.no_emoji,
        verbose=args.verbose,
    )


def _get_websites_urls(args):
    urls = list(args.urls)
    if args.input_file:
        urls += _read_urls_from_file(args.input_file)
    return [u for u in (s.strip() for s in urls) if u]


def _read_urls_from_file(file):
    path = pathlib.Path(file)
    if not path.is_file():
        print("Error: input file not found", file=sys.stderr)
        return []
    with path.open(encoding="utf-8") as f:
        urls = [u.strip() for u in f if u.strip()]
    if not urls:
        print(f"Error: empty input file, {file}", file=sys.stderr)
    return urls


async def _run_async(urls, args, with_geo, ports):
    return await asyncio.gather(
        *(
            check_site_async(
                u,
                timeout=args.timeout,
                with_geo=with_geo,
                ports=ports,
                port_timeout=args.port_timeout,
            )
            for u in urls
        )
    )


def _run_sync(urls, args, with_geo, ports):
    return [
        check_site(
            u,
            timeout=args.timeout,
            with_geo=with_geo,
            ports=ports,
            port_timeout=args.port_timeout,
        )
        for u in urls
    ]


if __name__ == "__main__":
    main()
