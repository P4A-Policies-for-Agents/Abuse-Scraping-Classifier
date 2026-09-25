#!/usr/bin/env bash
# One-shot live demo driver for the Abuse & Scraping Classifier (S7).
#
#   source demo/env.local.sh   # sets S7_GW_URL (+ optional S7_RAW_URL) — see env.local.sh.example
#   ./demo/demo.sh
#
# Drives the governed Orders API with a normal client and a sequential-id
# scraper. The normal client passes cleanly (no x-jev-abuse header, no judge
# call); the scraper is classified `enumeration` and starts getting 429s.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${S7_GW_URL:-}" ]]; then
  echo "S7_GW_URL is not set. Run:  source demo/env.local.sh" >&2
  exit 1
fi

python3 "${HERE}/driver.py" "${S7_GW_URL}"

if [[ -n "${S7_RAW_URL:-}" ]]; then
  echo
  echo "── Contrast: same scraper against the UNGOVERNED upstream mock ──────────"
  python3 "${HERE}/driver.py" "${S7_RAW_URL}" --raw
fi
