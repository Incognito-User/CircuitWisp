# app/sources/epss.py
# ---------------------------------------------------------------------------
# EPSS SOURCE MODULE
# Fetches Exploit Prediction Scoring System (EPSS) scores for CVEs.
# Returns percentile, score, and date metadata.
# ---------------------------------------------------------------------------

import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"


# ---------------------------------------------------------------------------
# Fetch EPSS Score
# ---------------------------------------------------------------------------
async def fetch_epss(cve_id: str) -> Dict[str, Any]:
    """
    Fetch EPSS score for a CVE.
    Returns dict: {"epss": float, "percentile": float, "date": str}
    Safe fallback: returns empty dict on failure.
    """

    params = {"cve": cve_id}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(EPSS_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"EPSS fetch failed for {cve_id}: {exc}")
        return {}

    entries = data.get("data") or []
    if not entries:
        return {}

    entry = entries[0]

    return {
        "epss": float(entry.get("epss", 0.0)),
        "percentile": float(entry.get("percentile", 0.0)),
        "date": entry.get("date"),
    }
