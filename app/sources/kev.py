# app/sources/kev.py
# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV) ingestion module
# Provides CVE-specific KEV lookup + recent discovery.
# ---------------------------------------------------------------------------

import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# Fetch KEV entry for a specific CVE
# ---------------------------------------------------------------------------
async def fetch_kev(cve_id: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("KEV fetch failed", extra={"error": str(exc)})
        return {}

    for vuln in data.get("vulnerabilities", []):
        if vuln.get("cveID") == cve_id:
            return {
                "cveID": vuln.get("cveID"),
                "dateAdded": vuln.get("dateAdded"),
                "shortDescription": vuln.get("shortDescription"),
                "requiredAction": vuln.get("requiredAction"),
            }

    return {}


# ---------------------------------------------------------------------------
# Fetch recent KEV entries (for trending)
# ---------------------------------------------------------------------------
async def fetch_kev_recent(limit: int = 50) -> List[Dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("KEV recent fetch failed", extra={"error": str(exc)})
        return []

    results = []
    for vuln in data.get("vulnerabilities", [])[:limit]:
        results.append({
            "cve_id": vuln.get("cveID"),
            "title": vuln.get("shortDescription"),
            "published": vuln.get("dateAdded"),
            "url": "",
            "source": "kev",
        })

    return results
