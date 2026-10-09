import httpx
import logging
from datetime import datetime, timezone

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

VENDOR_ENDPOINTS = {
    "microsoft": "https://api.msrc.microsoft.com/cvrf/v2.0/cve/",
    # Cisco does NOT have a CVE API; we fall back to HTML advisory search
    "cisco": "https://tools.cisco.com/security/center/search.x?keyword=",
}


async def fetch_vendor_advisories(cve_id: str) -> list[ExploitRecord]:
    """
    Hardened vendor advisory ingestion:
    - Safe JSON parsing (MSRC)
    - Safe HTML fallback (Cisco)
    - Safe timestamp handling
    - Safe reliability scoring
    """

    results: list[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for vendor, base_url in VENDOR_ENDPOINTS.items():
            try:
                resp = await client.get(f"{base_url}{cve_id}")
                resp.raise_for_status()

                # Try JSON first (MSRC)
                try:
                    data = resp.json()
                except Exception:
                    data = None

            except httpx.HTTPError as exc:
                logger.warning("Vendor advisory fetch failed", vendor=vendor, cve=cve_id, error=str(exc))
                continue

            # Microsoft MSRC CVRF
            if vendor == "microsoft" and isinstance(data, dict):
                url = _extract_msrc_url(data)
                published = _extract_msrc_timestamp(data)
                reliability = 0.95

            # Cisco fallback (HTML search results)
            elif vendor == "cisco":
                url = f"https://tools.cisco.com/security/center/search.x?keyword={cve_id}"
                published = datetime.now(timezone.utc)
                reliability = 0.85

            else:
                # Unknown vendor format
                url = ""
                published = datetime.now(timezone.utc)
                reliability = 0.7

            record = ExploitRecord(
                source="vendor",
                cve_id=cve_id,
                title=f"{vendor} advisory for {cve_id}",
                url=url,
                published=published,
                reliability=reliability,
            )
            results.append(record)

    return results


def _extract_msrc_url(data: dict) -> str:
    """
    Extract advisory URL from MSRC CVRF JSON.
    """
    try:
        refs = data.get("DocumentReferences", [])
        for ref in refs:
            if ref.get("Url"):
                return ref["Url"]
    except Exception:
        pass
    return ""


def _extract_msrc_timestamp(data: dict) -> datetime:
    """
    Extract published timestamp from MSRC CVRF JSON.
    """
    try:
        tracking = data.get("DocumentTracking", {})
        date_str = tracking.get("CurrentReleaseDate")
        if date_str:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        pass
    return datetime.now(timezone.utc)
