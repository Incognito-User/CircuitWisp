import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

SHODAN_URL = "https://api.shodan.io/shodan/host/search"


async def fetch_shodan(cve_id: str) -> Dict[str, Any]:
    """
    Fetch Shodan exposure for a CVE (via search query).
    Returns a dict: {"exposure_count": int, ...}
    """

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.info("Shodan token not configured; skipping Shodan fetch")
        return {}

    params = {
        "key": api_key,
        "query": cve_id,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(SHODAN_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"Shodan fetch failed for {cve_id}: {exc}")
        return {}

    matches = data.get("matches") or []
    return {
        "exposure_count": len(matches),
    }
