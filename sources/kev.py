import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev(cve_id: str) -> Dict[str, Any]:
    """
    Fetch CISA KEV entry for a CVE.
    Returns a dict with at least {"cve_id": ..., "date_added": ...} if present.
    """

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(KEV_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"KEV fetch failed for {cve_id}: {exc}")
        return {}

    vulns = data.get("vulnerabilities") or []
    for v in vulns:
        if v.get("cveID") == cve_id:
            return {
                "cve_id": cve_id,
                "date_added": v.get("dateAdded"),
                "short_description": v.get("shortDescription"),
                "required_action": v.get("requiredAction"),
            }

    return {}
