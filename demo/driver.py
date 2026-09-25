#!/usr/bin/env python3
"""Live REST driver for the Abuse & Scraping Classifier (S7).

Drives the governed Orders API with two clients, each keyed by its own
`x-api-key` (the policy's `clientKeyExpression: header:x-api-key`):

  * NORMAL client  — fetches its own order a handful of times, slowly.
                     Never trips the trigger, so the judge is never called and
                     no `x-jev-abuse` header is set.
  * SCRAPER client — walks GET /orders/{id} over sequential ids as fast as it
                     can. It only owns id 1001, so every other id returns 403.
                     Sequential ids + a high 4xx share + high rate trip the
                     trigger; the judge classifies `enumeration`; the gateway
                     sets `x-jev-abuse: enumeration` and (with enumeration in
                     blockVerdicts) starts returning 429 Retry-After.

Only depends on the stdlib. Usage:
    python3 driver.py <base-url>            # governed endpoint
    python3 driver.py <base-url> --raw      # label output as the ungoverned mock
"""
import sys
import time
import urllib.error
import urllib.request

NORMAL_KEY = "cust-1001-normal"
SCRAPER_KEY = "scraper-9f"


def call(base, path, api_key):
    req = urllib.request.Request(base.rstrip("/") + path, method="GET")
    req.add_header("x-api-key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("x-jev-abuse"), r.headers.get("retry-after")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("x-jev-abuse"), e.headers.get("retry-after")
    except urllib.error.URLError as e:
        return f"ERR({e.reason})", None, None


def row(label, path, status, abuse, retry):
    tag = f"  x-jev-abuse: {abuse}" if abuse else ""
    tag += f"  Retry-After: {retry}" if retry else ""
    print(f"  [{label:>7}] GET {path:<16} -> {str(status):<12}{tag}")


def normal_client(base):
    print("\n── NORMAL client (own orders, slow) ─────────────────────────────")
    for _ in range(4):
        s, a, r = call(base, "/orders/1001", NORMAL_KEY)
        row("normal", "/orders/1001", s, a, r)
        s, a, r = call(base, "/profile", NORMAL_KEY)
        row("normal", "/profile", s, a, r)
        time.sleep(0.4)
    print("  => expected: all 200, no x-jev-abuse header (judge never called).")


def scraper_client(base):
    print("\n── SCRAPER client (sequential id walk, fast) ────────────────────")
    blocked = False
    for i in range(1001, 1031):
        s, a, r = call(base, f"/orders/{i}", SCRAPER_KEY)
        row("scraper", f"/orders/{i}", s, a, r)
        if str(s) == "429":
            blocked = True
    print("  => expected: 403s accumulate -> x-jev-abuse: enumeration -> 429 Retry-After.")
    if not blocked:
        print("     (no 429 seen — check mode=enforce and enumeration in blockVerdicts;")
        print("      in shadow mode the verdict is logged only, never enforced.)")


def main():
    if len(sys.argv) < 2:
        print("usage: driver.py <base-url> [--raw]", file=sys.stderr)
        sys.exit(1)
    base = sys.argv[1]
    raw = "--raw" in sys.argv[2:]
    print("════════════════════════════════════════════════════════════════════")
    print(f" Abuse & Scraping Classifier — {'UNGOVERNED mock' if raw else 'governed endpoint'}")
    print(f" base: {base}")
    print("════════════════════════════════════════════════════════════════════")
    normal_client(base)
    scraper_client(base)


if __name__ == "__main__":
    main()
