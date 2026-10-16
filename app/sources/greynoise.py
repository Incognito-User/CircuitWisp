# app/sources/greynoise.py
# ---------------------------------------------------------------------------
# GreyNoise ingestion module
# Provides CVE-specific noise intelligence + recent scanning discovery.
# ---------------------------------------------------------------------------

import os
import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

PRIMARY_URL = "https://api.greynoise.io/v3/community/cve/{cve}"
RECENT_URL = "https://api.greynoise.io/v3/community/scan/activity"


# ---------------------------------------------------------------------------
# Fetch GreyNoise CVE-specific intelligence
# ---------------------------------------------------------------------------
async def fetch_greynoise(cve_id: str) -> Dict[str, Any]:
    if not GREYNOISE_API_KEY:
        logger.warning("GREYNOISE_API_KEY not set — GreyNoise disabled.")
        return {}

    url = PRIMARY_URL.format(cve=cve_id)
    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            return {
                "ip_count": len(data.get("ips", [])),
                "ips": data.get("ips", []),
            }

    except Exception as exc:
        logger.warning("GreyNoise CVE fetch failed", extra={"error": str(exc)})
        return {}


# ---------------------------------------------------------------------------
# Fetch recent GreyNoise scanning activity (for trending)
# ---------------------------------------------------------------------------
async def fetch_greynoise_recent(limit: int = 50) -> List[Dict[str, Any]]:
    if not GREYNOISE_API_KEY:
        return []

    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(RECENT_URL, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("GreyNoise recent fetch failed", extra={"error": str(exc)})
        return []

    results = []
    for item in data.get("activity", [])[:limit]:
        cve_id = item.get("cve")
        results.append({
            "cve_id": cve_id,
            "title": f"GreyNoise scan: {cve_id}",
            "published": item.get("first_seen"),
            "url": "",
            "source": "greynoise",
        })

    return results
