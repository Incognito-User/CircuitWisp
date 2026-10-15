# app/sources/cisa.py
# ---------------------------------------------------------------------------
# CISA SOURCE MODULE
# Provides:
# - Known Exploited Vulnerabilities (KEV) advisory ingestion
# - CISA campaign / alert ingestion (fetch_cisa_campaigns)
#
# Both functions return actor‑enrichment compatible records.
# ---------------------------------------------------------------------------

import httpx
import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# KEV Feed (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------
CISA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_cisa_advisories() -> List[Dict[str, Any]]:
    """
    Fetch CISA KEV advisories and return actor‑enrichment compatible records.
    Each advisory contains:
      - title
      - date
      - cves
      - actors (if present)
    Safe fallback: empty list.
    """

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(CISA_FEED_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"CISA advisory fetch failed: {exc}")
        return []

    advisories = []

    for item in data.get("vulnerabilities", []):
        cves = [item.get("cveID")] if item.get("cveID") else []
        actors = item.get("knownRansomwareCampaigns", "") or ""
        title = item.get("shortDescription", "CISA Advisory")
        date = item.get("dateAdded") or datetime.utcnow().isoformat()

        advisories.append({
            "title": title,
            "date": date,
            "cves": cves,
            "actors": actors,
        })

    return advisories


# ---------------------------------------------------------------------------
# CISA Alerts / Campaign Feed
# ---------------------------------------------------------------------------
# This is the function your actors.py imports:
#     from app.sources.cisa import fetch_cisa_campaigns
#
# Without this function, FastAPI cannot start.
# ---------------------------------------------------------------------------

CISA_ALERTS_URL = "https://www.cisa.gov/sites/default/files/feeds/alerts.json"


async def fetch_cisa_campaigns() -> List[Dict[str, Any]]:
    """
    Fetch CISA alerts/campaigns.
    Returns a list of dicts containing:
      - title
      - date
      - cves
      - actors (if present)
    Safe fallback: empty list.
    """

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(CISA_ALERTS_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"CISA campaign fetch failed: {exc}")
        return []

    campaigns = []

    for item in data.get("alerts", []):
        campaigns.append({
            "title": item.get("title", "CISA Campaign"),
            "date": item.get("date", datetime.utcnow().isoformat()),
            "cves": item.get("cves", []),
            "actors": item.get("actors", []),
        })

    return campaigns
