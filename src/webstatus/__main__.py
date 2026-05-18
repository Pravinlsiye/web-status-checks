"""RP Checker entry point."""

import asyncio
import pathlib
import sys

from webstatus.checker import check_site, check_site_async
from webstatus.cli import display_results, read_user_cli_args


def _ensure_utf8_stdout():
    """Force UTF-8 on Windows consoles so emoji + unicode titles don't crash."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    _ensure_utf8_stdout()
    user_args = read_user_cli_args()
    urls = _get_websites_urls(user_args)
    if not urls:
        print("Error: no URLs to check", file=sys.stderr)
        sys.exit(1)

    if user_args.asynchronous:
        infos = asyncio.run(_asynchronous_check(urls, user_args.timeout))
    else:
        infos = _synchronous_check(urls, user_args.timeout)

    display_results(
        infos, as_json=user_args.json, use_emoji=not user_args.no_emoji
    )


def _get_websites_urls(user_args):
    urls = list(user_args.urls)
    if user_args.input_file:
        urls += _read_urls_from_file(user_args.input_file)
    return [u for u in (s.strip() for s in urls) if u]


def _read_urls_from_file(file):
    file_path = pathlib.Path(file)
    if not file_path.is_file():
        print("Error: input file not found", file=sys.stderr)
        return []
    with file_path.open(encoding="utf-8") as urls_file:
        urls = [url.strip() for url in urls_file if url.strip()]
    if not urls:
        print(f"Error: empty input file, {file}", file=sys.stderr)
    return urls


async def _asynchronous_check(urls, timeout):
    return await asyncio.gather(
        *(check_site_async(url, timeout=timeout) for url in urls)
    )


def _synchronous_check(urls, timeout):
    return [check_site(url, timeout=timeout) for url in urls]


if __name__ == "__main__":
    main()
