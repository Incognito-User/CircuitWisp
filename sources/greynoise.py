import httpx
import logging
from typing import Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)

GREYNOISE_API = "https://api.greynoise.io/v3/community/cve/"


async def fetch_greynoise(cve_id: str) -> Dict[str, Any]:
    """
    Fetch GreyNoise community data for a CVE.

    Returns:
        {
            "cve": str,
            "classification": str | None,
            "ip_count": int | None,
            "tags": list[str],
        }
    """
    headers = {}
    if getattr(settings, "greynoise_token", None):
        headers["key"] = settings.greynoise_token

    url = GREYNOISE_API + cve_id

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"GreyNoise fetch failed for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "classification": None,
                "ip_count": None,
                "tags": [],
            }

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"GreyNoise returned non-JSON for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "classification": None,
                "ip_count": None,
                "tags": [],
            }

    return {
        "cve": cve_id,
        "classification": data.get("classification"),
        "ip_count": data.get("ip_count"),
        "tags": data.get("tags") or [],
    }
