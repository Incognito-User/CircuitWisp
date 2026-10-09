import httpx
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Check if a CVE is in CISA KEV.

    Returns:
        None if not present, or:
        {
            "cve": str,
            "date_added": str,
            "required_action": str,
            "due_date": str | None,
        }
    """
    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(KEV_FEED)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"KEV fetch failed: {exc}")
            return None

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"KEV returned non-JSON: {exc}")
            return None

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        if v.get("cveID") == cve_id:
            return {
                "cve": cve_id,
                "date_added": v.get("dateAdded"),
                "required_action": v.get("requiredAction"),
                "due_date": v.get("dueDate"),
            }

    return None
