import httpx
import logging
from typing import Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)

SHODAN_SEARCH_API = "https://api.shodan.io/shodan/host/search"


async def fetch_shodan(cve_id: str) -> Dict[str, Any]:
    """
    Fetch Shodan exposure data for a CVE.

    Returns:
        {
            "cve": str,
            "exposure_count": int | None,
        }
    """
    if not getattr(settings, "shodan_token", None):
        logger.warning("Shodan token not configured; skipping Shodan fetch")
        return {
            "cve": cve_id,
            "exposure_count": None,
        }

    params = {
        "query": cve_id,
        "key": settings.shodan_token,
    }

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(SHODAN_SEARCH_API, params=params)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"Shodan fetch failed for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "exposure_count": None,
            }

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"Shodan returned non-JSON for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "exposure_count": None,
            }

    total = data.get("total")
    return {
        "cve": cve_id,
        "exposure_count": total,
    }
