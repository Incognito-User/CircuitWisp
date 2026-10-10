import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

GREYNOISE_URL = "https://api.greynoise.io/v3/community/cve/"


async def fetch_greynoise(cve_id: str) -> Dict[str, Any]:
    """
    Fetch GreyNoise exploitation activity for a CVE.
    Returns a dict: {"ip_count": int, ...}
    """

    url = f"{GREYNOISE_URL}{cve_id}"

    headers = {}
    # If you have a token, set it via env and add here.
    # token = os.getenv("GREYNOISE_API_KEY")
    # if token:
    #     headers["key"] = token

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"GreyNoise fetch failed for {cve_id}: {exc}")
        return {}

    return {
        "ip_count": int(data.get("ip_count", 0)),
    }
