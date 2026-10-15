# app/sources/shodan.py
# ---------------------------------------------------------------------------
# Shodan ingestion module
# Provides CVE-specific exposure intelligence + recent discovery.
# ---------------------------------------------------------------------------

import os
import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

CVE_SEARCH_URL = "https://api.shodan.io/shodan/host/search?key={key}&query={query}"
RECENT_SEARCH_URL = "https://api.shodan.io/shodan/host/search?key={key}&query=CVE-20"


# ---------------------------------------------------------------------------
# Fetch Shodan CVE-specific exposure
# ---------------------------------------------------------------------------
async def fetch_shodan(cve_id: str) -> Dict[str, Any]:
    if not SHODAN_API_KEY:
        logger.warning("SHODAN_API_KEY not set — Shodan disabled.")
        return {}

    url = CVE_SEARCH_URL.format(key=SHODAN_API_KEY, query=cve_id)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

            return {
                "exposure_count": data.get("total", 0),
                "matches": data.get("matches", []),
            }

    except Exception as exc:
        logger.warning("Shodan CVE fetch failed", extra={"error": str(exc)})
        return {}


# ---------------------------------------------------------------------------
# Fetch recent Shodan CVE exposures (for trending)
# ---------------------------------------------------------------------------
async def fetch_shodan_recent(limit: int = 50) -> List[Dict[str, Any]]:
    if not SHODAN_API_KEY:
        return []

    url = RECENT_SEARCH_URL.format(key=SHODAN_API_KEY)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("Shodan recent fetch failed", extra={"error": str(exc)})
        return []

    results = []
    for item in data.get("matches", [])[:limit]:
        cve_id = None
        vulns = item.get("vulns", [])
        if vulns:
            cve_id = vulns[0]

        results.append({
            "cve_id": cve_id,
            "title": f"Shodan exposure: {cve_id}",
            "published": item.get("timestamp"),
            "url": "",
            "source": "shodan",
        })

    return results
