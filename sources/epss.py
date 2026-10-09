import httpx
import logging
from datetime import datetime
from typing import Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"


async def fetch_epss(cve_id: str) -> Dict[str, Any]:
    """
    Fetch EPSS score for a CVE.

    Returns:
        {
            "cve": str,
            "epss": float | None,
            "percentile": float | None,
            "date": str | None,
        }
    """
    params = {"cve": cve_id}

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(EPSS_API, params=params)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"EPSS fetch failed for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "epss": None,
                "percentile": None,
                "date": None,
            }

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"EPSS returned non-JSON for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "epss": None,
                "percentile": None,
                "date": None,
            }

    entries = data.get("data", [])
    if not entries:
        return {
            "cve": cve_id,
            "epss": None,
            "percentile": None,
            "date": None,
        }

    entry = entries[0]
    return {
        "cve": cve_id,
        "epss": float(entry.get("epss")) if entry.get("epss") is not None else None,
        "percentile": float(entry.get("percentile")) if entry.get("percentile") is not None else None,
        "date": entry.get("date"),
    }
