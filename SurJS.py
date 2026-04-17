#!/usr/bin/env python3
# ============================================================
#   ____            _ ____
#  / ___| _   _ _ _| / ___|
#  \___ \| | | | '__| \___ \
#   ___) | |_| | |  | |___) |
#  |____/ \__,_|_|  |_|____/
#
#  SurJS.py — JavaScript File & Endpoint Extractor
#  For Ethical Hacking / Bug Bounty Reconnaissance
#  Author  : Andwisakti
#  Version : 1.0.0
#  License : MIT
# ============================================================

import argparse
import asyncio
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

# ── Dependency check ──────────────────────────────────────
MISSING = []
try:
    import aiohttp
except ImportError:
    MISSING.append("aiohttp")
try:
    from bs4 import BeautifulSoup
except ImportError:
    MISSING.append("beautifulsoup4")
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    MISSING.append("colorama")

if MISSING:
    print(f"[!] Missing dependencies: {', '.join(MISSING)}")
    print(f"    Run: pip install {' '.join(MISSING)}")
    sys.exit(1)

# ── Banner ─────────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}
   ____            _ ____
  / ___| _   _ _ _| / ___|
  \\___ \\| | | | '__| \\___ \\
   ___) | |_| | |  | |___) |
  |____/ \\__,_|_|  |_|____/
{Style.RESET_ALL}
{Fore.YELLOW}  JS File & Endpoint Extractor v1.0.0{Style.RESET_ALL}
{Fore.WHITE}  For Ethical Hacking / Bug Bounty Recon{Style.RESET_ALL}
{Fore.RED}  Use only on authorized targets!{Style.RESET_ALL}
  {'─' * 44}
"""

# ── Constants ──────────────────────────────────────────────
DEFAULT_RATE   = 3          # requests/second
DEFAULT_TIMEOUT = 15        # seconds
DEFAULT_UA     = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Regex patterns
RE_JS_TAG     = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
RE_JS_INLINE  = re.compile(r'["\`]((?:https?://|/)[^\s"\'`<>]*\.js(?:\?[^\s"\'`<>]*)?)["\`]', re.I)
RE_ENDPOINT   = re.compile(
    r'["\`]((?:https?://[^\s"\'`<>]{4,}|'         # absolute URLs
    r'/[a-zA-Z0-9_\-/.]{2,}(?:\?[^\s"\'`<>]*)?|'  # relative paths /...
    r'[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/.]+))["\`]',  # partial paths
    re.I
)
RE_API_KEY    = re.compile(
    r'(?:api[_\-]?key|apikey|secret|token|password|passwd|auth|bearer|aws_access|aws_secret'
    r'|firebase|slack|stripe|twilio|sendgrid|github[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-./+]{8,})["\']',
    re.I
)
RE_EMAIL      = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
RE_IP         = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')

# Paths/extensions to skip (noise reduction)
SKIP_EXT = {'.png','.jpg','.jpeg','.gif','.svg','.woff','.woff2','.ttf','.eot','.ico','.mp4','.webp'}
SKIP_PREFIXES = ('data:','blob:','#','mailto:','tel:','javascript:')


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def normalize_url(target: str) -> str:
    """Ensure URL has a scheme."""
    target = target.strip().rstrip('/')
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    return target


def is_valid_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)


def resolve_url(base: str, path: str) -> str:
    """Resolve a potentially relative URL against the base."""
    if path.startswith(SKIP_PREFIXES):
        return None
    ext = Path(urllib.parse.urlparse(path).path).suffix.lower()
    if ext in SKIP_EXT:
        return None
    return urllib.parse.urljoin(base, path)


def clean_endpoint(ep: str, base_domain: str) -> str | None:
    """Filter and normalize extracted endpoint strings."""
    ep = ep.strip()
    if any(ep.startswith(p) for p in SKIP_PREFIXES):
        return None
    ext = Path(urllib.parse.urlparse(ep).path).suffix.lower()
    if ext in SKIP_EXT:
        return None
    if len(ep) < 3 or ep in ('/', '//'):
        return None
    # Skip pure filenames without slash
    if '/' not in ep and not ep.startswith('http'):
        return None
    return ep


def tag(color, label: str, msg: str):
    print(f"{color}[{label}]{Style.RESET_ALL} {msg}")


# ═══════════════════════════════════════════════════════════
#  RATE LIMITER
# ═══════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, rate: float):
        self._interval = 1.0 / rate
        self._last     = 0.0
        self._lock     = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now   = time.monotonic()
            sleep = self._interval - (now - self._last)
            if sleep > 0:
                await asyncio.sleep(sleep)
            self._last = time.monotonic()


# ═══════════════════════════════════════════════════════════
#  FETCHER
# ═══════════════════════════════════════════════════════════

async def fetch(session: aiohttp.ClientSession,
                url: str,
                limiter: RateLimiter,
                timeout: int) -> tuple[str, int, str | None]:
    """Fetch a URL and return (url, status, body)."""
    await limiter.wait()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as resp:
            body = await resp.text(errors='replace')
            return url, resp.status, body
    except asyncio.TimeoutError:
        return url, 0, None
    except Exception as e:
        return url, -1, None


# ═══════════════════════════════════════════════════════════
#  CORE LOGIC
# ═══════════════════════════════════════════════════════════

async def extract_js_urls_from_html(html: str, base_url: str) -> set[str]:
    """Extract JS file URLs from an HTML page."""
    js_urls = set()
    soup    = BeautifulSoup(html, 'html.parser')

    # 1. <script src="...">
    for tag_el in soup.find_all('script', src=True):
        src = tag_el['src']
        resolved = resolve_url(base_url, src)
        if resolved:
            js_urls.add(resolved)

    # 2. Regex fallback (catches encoded / unusual patterns)
    for match in RE_JS_TAG.finditer(html):
        resolved = resolve_url(base_url, match.group(1))
        if resolved:
            js_urls.add(resolved)

    # 3. Inline string references to .js
    for match in RE_JS_INLINE.finditer(html):
        resolved = resolve_url(base_url, match.group(1))
        if resolved:
            js_urls.add(resolved)

    return js_urls


async def extract_from_js(js_body: str, base_domain: str) -> dict:
    """Extract endpoints, API keys, emails, and IPs from JS content."""
    results = {
        'endpoints': set(),
        'api_keys' : [],
        'emails'   : set(),
        'ips'      : set(),
    }

    # Endpoints
    for match in RE_ENDPOINT.finditer(js_body):
        ep = clean_endpoint(match.group(1), base_domain)
        if ep:
            results['endpoints'].add(ep)

    # Potential secrets / API keys
    for match in RE_API_KEY.finditer(js_body):
        full_match = match.group(0)
        value      = match.group(1)
        results['api_keys'].append((full_match[:80], value))

    # Emails
    for match in RE_EMAIL.finditer(js_body):
        results['emails'].add(match.group(0))

    # IPs
    for match in RE_IP.finditer(js_body):
        results['ips'].add(match.group(0))

    return results


async def run_scan(target_url: str,
                   rate: float,
                   timeout: int,
                   output_file: str | None,
                   verbose: bool):

    base_domain = urllib.parse.urlparse(target_url).netloc
    limiter     = RateLimiter(rate)
    headers     = {'User-Agent': DEFAULT_UA,
                   'Accept-Language': 'en-US,en;q=0.9'}

    all_js_urls   = set()
    all_endpoints = set()
    all_keys      = []
    all_emails    = set()
    all_ips       = set()
    pages_crawled = []

    tag(Fore.CYAN,  '*', f"Target   : {target_url}")
    tag(Fore.CYAN,  '*', f"Rate     : {rate} req/s  |  Timeout: {timeout}s")
    tag(Fore.CYAN,  '*', f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    async with aiohttp.ClientSession(headers=headers) as session:

        # ── Phase 1: Fetch main page ──────────────────────
        tag(Fore.YELLOW, '~', f"Phase 1 — Fetching main page ...")
        url, status, html = await fetch(session, target_url, limiter, timeout)

        if not html:
            tag(Fore.RED, '!', f"Failed to fetch {url} (status={status})")
            return

        tag(Fore.GREEN, '+', f"[{status}] {url}")
        pages_crawled.append(url)

        js_urls = await extract_js_urls_from_html(html, target_url)
        all_js_urls.update(js_urls)
        tag(Fore.WHITE, 'i', f"Found {len(js_urls)} JS file(s) on main page")

        # ── Phase 2: Also crawl common sub-pages ─────────
        tag(Fore.YELLOW, '~', f"\nPhase 2 — Checking common sub-pages ...")
        common_paths = ['/', '/app', '/assets', '/static', '/js', '/dist',
                        '/build', '/bundle', '/vendor', '/public']
        parsed = urllib.parse.urlparse(target_url)
        sub_tasks = []
        for path in common_paths:
            sub_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            if sub_url not in pages_crawled:
                sub_tasks.append(fetch(session, sub_url, limiter, timeout))

        sub_results = await asyncio.gather(*sub_tasks)
        for sub_url, sub_status, sub_html in sub_results:
            if sub_html and sub_status == 200:
                tag(Fore.GREEN, '+', f"[{sub_status}] {sub_url}")
                pages_crawled.append(sub_url)
                sub_js = await extract_js_urls_from_html(sub_html, sub_url)
                new_js = sub_js - all_js_urls
                if new_js:
                    tag(Fore.WHITE, 'i', f"  └─ {len(new_js)} new JS file(s)")
                all_js_urls.update(sub_js)
            elif verbose and sub_html is not None:
                tag(Fore.WHITE, '-', f"[{sub_status}] {sub_url}")

        # ── Phase 3: Fetch & analyse all JS files ─────────
        print()
        tag(Fore.YELLOW, '~', f"Phase 3 — Analysing {len(all_js_urls)} JS file(s) ...")
        print()

        js_tasks = [fetch(session, js_url, limiter, timeout) for js_url in all_js_urls]
        js_results = await asyncio.gather(*js_tasks)

        for js_url, js_status, js_body in js_results:
            if not js_body:
                if verbose:
                    tag(Fore.RED, '!', f"[FAIL] {js_url}")
                continue

            tag(Fore.CYAN, 'JS', f"[{js_status}] {js_url}")
            extracted = await extract_from_js(js_body, base_domain)

            n_ep  = len(extracted['endpoints'])
            n_key = len(extracted['api_keys'])
            n_em  = len(extracted['emails'])
            n_ip  = len(extracted['ips'])

            if n_ep:
                tag(Fore.WHITE, 'i', f"  ├─ Endpoints : {n_ep}")
            if n_key:
                tag(Fore.MAGENTA, 'i', f"  ├─ Secrets   : {n_key}  ⚠")
            if n_em:
                tag(Fore.WHITE, 'i', f"  ├─ Emails    : {n_em}")
            if n_ip:
                tag(Fore.WHITE, 'i', f"  └─ IPs       : {n_ip}")

            all_endpoints.update(extracted['endpoints'])
            all_keys.extend(extracted['api_keys'])
            all_emails.update(extracted['emails'])
            all_ips.update(extracted['ips'])

    # ── Phase 4: Print Summary ─────────────────────────────
    print()
    print(f"{Fore.CYAN}{'═'*55}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SCAN SUMMARY — {base_domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*55}{Style.RESET_ALL}")
    print(f"  Pages crawled  : {len(pages_crawled)}")
    print(f"  JS files found : {len(all_js_urls)}")
    print(f"  Endpoints      : {len(all_endpoints)}")
    print(f"  Emails         : {len(all_emails)}")
    print(f"  Internal IPs   : {len(all_ips)}")
    if all_keys:
        print(f"  {Fore.MAGENTA}Potential Secrets: {len(all_keys)}  ⚠  Review carefully!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*55}{Style.RESET_ALL}")

    # ── Print detailed results ─────────────────────────────
    if all_js_urls:
        print(f"\n{Fore.YELLOW}[JS FILES]{Style.RESET_ALL}")
        for url in sorted(all_js_urls):
            print(f"  {url}")

    if all_endpoints:
        print(f"\n{Fore.GREEN}[ENDPOINTS / PATHS]{Style.RESET_ALL}")
        for ep in sorted(all_endpoints):
            print(f"  {ep}")

    if all_emails:
        print(f"\n{Fore.WHITE}[EMAILS]{Style.RESET_ALL}")
        for em in sorted(all_emails):
            print(f"  {em}")

    if all_ips:
        print(f"\n{Fore.WHITE}[IPs]{Style.RESET_ALL}")
        for ip in sorted(all_ips):
            print(f"  {ip}")

    if all_keys:
        print(f"\n{Fore.MAGENTA}[POTENTIAL SECRETS — REVIEW CAREFULLY]{Style.RESET_ALL}")
        for context, value in all_keys:
            print(f"  {Fore.MAGENTA}>>>{Style.RESET_ALL} {context}")

    # ── Save output ────────────────────────────────────────
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"SurJS Scan Report\n")
            f.write(f"Target  : {target_url}\n")
            f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*55 + "\n\n")

            f.write("[JS FILES]\n")
            for url in sorted(all_js_urls):
                f.write(f"  {url}\n")

            f.write("\n[ENDPOINTS / PATHS]\n")
            for ep in sorted(all_endpoints):
                f.write(f"  {ep}\n")

            f.write("\n[EMAILS]\n")
            for em in sorted(all_emails):
                f.write(f"  {em}\n")

            f.write("\n[IPs]\n")
            for ip in sorted(all_ips):
                f.write(f"  {ip}\n")

            f.write("\n[POTENTIAL SECRETS]\n")
            for context, value in all_keys:
                f.write(f"  >>> {context}\n")

        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Output saved to: {output_file}")

    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan completed at {datetime.now().strftime('%H:%M:%S')}\n")


# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog='SurJS',
        description='JS File & Endpoint Extractor for Ethical Hacking / Bug Bounty',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'target',
        help='Target URL or domain\n  e.g.  example.com\n        https://sub.example.com'
    )
    parser.add_argument(
        '-r', '--rate',
        type=float,
        default=DEFAULT_RATE,
        metavar='N',
        help=f'Max requests per second (default: {DEFAULT_RATE})'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar='SEC',
        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Save results to a file (e.g. -o results.txt)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show failed/skipped requests too'
    )

    args   = parser.parse_args()
    target = normalize_url(args.target)

    if not is_valid_url(target):
        tag(Fore.RED, '!', f"Invalid target URL: {target}")
        sys.exit(1)

    try:
        asyncio.run(run_scan(
            target_url  = target,
            rate        = args.rate,
            timeout     = args.timeout,
            output_file = args.output,
            verbose     = args.verbose,
        ))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Scan interrupted by user.\n")
        sys.exit(0)


if __name__ == '__main__':
    main()
